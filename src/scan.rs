use crate::indexer::{apply_staging, Candidate, DeletedIndex};
use crossbeam_channel::{Receiver, Sender};
use ntfs_reader::{DeletedPathCache, DeletedPathMarker, FIRST_NORMAL_RECORD, FileInfo, Mft};
use parking_lot::RwLock;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tauri::Manager;

pub static CANCEL: AtomicBool = AtomicBool::new(false);

/// The name of the folder under the reserved `_unresolved` top-level container that an
/// incomplete `DeletedPath`'s real names are placed under, in place of the marker's `<...>`
/// text (illegal in a Win32 name; see the ntfs-reader 0.5.3 CHANGELOG). `Lost`'s record number
/// needs no sanitizing: a bare integer is already a legal Win32 name component.
fn marker_container_name(marker: DeletedPathMarker) -> String {
    match marker {
        DeletedPathMarker::Lost(record_number) => format!("lost {record_number}"),
        DeletedPathMarker::Deleted => "renamed on delete".to_string(),
        DeletedPathMarker::TooLong => "path too long".to_string(),
        _ => "unresolved".to_string(),
    }
}

pub fn start_scanner_pool(
    shared_mft: Arc<RwLock<Mft>>,
    tx: Sender<Candidate>,
    processed: Arc<AtomicU64>,
    max_record: u64,
) -> Vec<std::thread::JoinHandle<()>> {
    let mut threads = ((num_cpus::get() as f64) * 0.7).round() as usize;
    if threads < 2 {
        threads = 2;
    }
    if let Ok(s) = std::env::var("UNUNLINK_SCAN_THREADS") {
        if let Ok(v) = s.parse::<usize>() {
            threads = v.max(1);
        }
    }
    let start = FIRST_NORMAL_RECORD;
    let end = max_record;
    let span = (end - start + threads as u64 - 1) / threads as u64;
    let mut handles = Vec::with_capacity(threads);
    for i in 0..threads {
        let range_start = start + span * i as u64;
        let range_end = std::cmp::min(end, range_start + span);
        if range_start >= range_end {
            break;
        }
        let mft_arc = shared_mft.clone();
        let tx_cloned = tx.clone();
        let processed_cloned = processed.clone();
        let h = std::thread::spawn(move || {
            // Only deleted files are ever turned into candidates, so a live DefaultPathCache is
            // never needed here; a DeletedPathCache is, shared for the thread's whole range so
            // each freed directory on the way is walked about once (see the paths-and-caches
            // guide).
            let mut deleted_cache = DeletedPathCache::new();
            for number in range_start..range_end {
                if CANCEL.load(Ordering::Relaxed) {
                    break;
                }
                let cand_opt = {
                    let mft_read = mft_arc.read();
                    if let Some(file) = mft_read.record(number) {
                        processed_cloned.fetch_add(1, Ordering::Relaxed);
                        // is_deleted() is the correct test (0.5.2 CHANGELOG): unlike !is_used(),
                        // it excludes a freed extension record of a live file, and excluding
                        // is_extension() here in turn avoids yielding a deleted file's own
                        // extension records as separate candidates.
                        if !file.is_deleted() || file.is_extension() {
                            None
                        } else {
                            let infox = FileInfo::with_caches(&file, &mut (), &mut deleted_cache);
                            // FileInfo::path is Some only for a *complete* deleted path; fall
                            // back to Mft::resolve_deleted_path's own path, so a file under a
                            // freed directory still gets a place in the tree instead of being
                            // dropped (0.3 walked freed parents too). ntfs-reader 0.5.3 stopped
                            // putting the marker's `<...>` text inside DeletedPath::path (`<` and
                            // `>` are illegal in a Win32 name, so the old text form could not be
                            // recreated on disk); an incomplete path is routed under the reserved
                            // `_unresolved` top-level folder, keyed by marker, instead.
                            let path = file
                                .best_name()
                                .map(|name| {
                                    let dp =
                                        mft_read.resolve_deleted_path(&name, &mut deleted_cache);
                                    if dp.is_complete() {
                                        dp.path.display().to_string()
                                    } else {
                                        let container =
                                            marker_container_name(dp.marker.expect(
                                                "is_complete() is false, so marker is Some",
                                            ));
                                        format!(r"_unresolved\{container}\{}", dp.path.display())
                                    }
                                })
                                .unwrap_or_default();
                            Some(Candidate {
                                mft_no: number,
                                path,
                                size: infox.size,
                                is_dir: file.is_directory(),
                                created: infox.created.map(|t| t.unix_timestamp()),
                                modified: infox.modified.map(|t| t.unix_timestamp()),
                                accessed: infox.accessed.map(|t| t.unix_timestamp()),
                            })
                        }
                    } else {
                        processed_cloned.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                };
                if let Some(cand) = cand_opt {
                    if tx_cloned.send(cand).is_err() {
                        break;
                    }
                }
            }
        });
        handles.push(h);
    }
    handles
}

pub fn indexer_worker(
    rx: Receiver<Candidate>,
    found_counter: Arc<AtomicU64>,
    flush_every: usize,
) -> DeletedIndex {
    let mut idx = DeletedIndex::default();
    idx.ensure_dirs_from_root("\\");
    let mut staging: Vec<Candidate> = Vec::with_capacity(flush_every * 2);
    loop {
        if CANCEL.load(Ordering::Relaxed) {
            break;
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(c) => {
                staging.push(c);
                if staging.len() >= flush_every {
                    apply_staging(&mut idx, &mut staging, &found_counter);
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                if !staging.is_empty() {
                    apply_staging(&mut idx, &mut staging, &found_counter);
                }
                continue;
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }
    apply_staging(&mut idx, &mut staging, &found_counter);
    idx
}

#[derive(Clone, serde::Serialize)]
pub struct ProgressPayload {
    pub processed: u64,
    pub found: u64,
    pub total: u64,
    pub percent: f64,
    pub eta_secs: f64,
    pub msg: String,
}

pub fn progress_loop_emit(
    app: tauri::AppHandle,
    processed: Arc<AtomicU64>,
    found: Arc<AtomicU64>,
    total: u64,
    running: Arc<AtomicBool>,
    start: Instant,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while running.load(Ordering::Relaxed) && !CANCEL.load(Ordering::Relaxed) {
            let p = processed.load(Ordering::Relaxed);
            let f = found.load(Ordering::Relaxed);
            let elapsed = start.elapsed().as_secs_f64();
            let speed = if elapsed > 0.0 {
                p as f64 / elapsed
            } else {
                0.0
            };
            let remain = if speed > 0.0 {
                ((total.saturating_sub(p as u64)) as f64 / speed).max(0.0)
            } else {
                0.0
            };
            let percent = if total > 0 {
                (p as f64) * 100.0 / (total as f64)
            } else {
                0.0
            };
            let msg = if p == 0 {
                "preloading $MFT...".to_string()
            } else {
                format!(
                    "deleted indexed: {}  |  speed: {:.0} rec/s  |  ETA: {:.0}s",
                    f, speed, remain
                )
            };
            let _ = app.emit_all(
                "progress",
                ProgressPayload {
                    processed: p as u64,
                    found: f as u64,
                    total,
                    percent,
                    eta_secs: remain,
                    msg,
                },
            );
            std::thread::sleep(Duration::from_millis(250));
        }
        let p = processed.load(Ordering::Relaxed);
        let _ = app.emit_all(
            "progress",
            ProgressPayload {
                processed: p as u64,
                found: found.load(Ordering::Relaxed) as u64,
                total,
                percent: 100.0,
                eta_secs: 0.0,
                msg: if CANCEL.load(Ordering::Relaxed) {
                    "aborted".to_string()
                } else {
                    "scan completed".to_string()
                },
            },
        );
    })
}
