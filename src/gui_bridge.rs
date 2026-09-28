use crate::drives::enum_ntfs_drives;
use crate::fs::UnUnlinkFs;
use crate::indexer::DeletedIndex;
use crate::scan::{CANCEL, indexer_worker, progress_loop_emit, start_scanner_pool};
use crate::util::{humanize_bytes, normalize_device};
use anyhow::{Context, Result};
use dokan::{FileSystemMounter, MountOptions, shutdown, unmount};
use ntfs_reader::{FIRST_NORMAL_RECORD, Mft, Volume};
use parking_lot::RwLock;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Instant;
use std::{mem, os::windows::ffi::OsStrExt, ptr::null_mut};
use tauri::{AppHandle, Manager};
use tracing::info;
use widestring::U16CString;
use winapi::um::{
    handleapi::CloseHandle,
    processthreadsapi::{GetCurrentProcess, OpenProcessToken},
    securitybaseapi::GetTokenInformation,
    shellapi::ShellExecuteW,
    winnt::{HANDLE, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
    winuser::SW_SHOW,
};

#[derive(Default)]
pub struct AppState {
    pub mounted: AtomicBool,
}

#[tauri::command]
pub fn list_drives_cmd() -> Vec<DriveView> {
    enum_ntfs_drives()
        .into_iter()
        .map(|d| DriveView {
            letter: d.letter,
            fs_name: d.fs_name,
            total: humanize_bytes(d.total_bytes),
            free: humanize_bytes(d.free_bytes),
        })
        .collect()
}

#[derive(Serialize)]
pub struct DriveView {
    pub letter: char,
    pub fs_name: String,
    pub total: String,
    pub free: String,
}

#[tauri::command]
pub fn eject_cmd(app: AppHandle, state: tauri::State<AppState>) -> Result<(), String> {
    CANCEL.store(true, Ordering::Relaxed);
    let mp = U16CString::from_str("R:").unwrap();
    if unmount(mp.as_ucstr()) {
        let _ = app.emit_all("state", serde_json::json!({"state": "ejected"}));
    }
    shutdown();
    state.mounted.store(false, Ordering::Relaxed);
    Ok(())
}

// Tauriのエントリーポイント
#[tauri::command]
pub fn start_mount_cmd(
    letter: String,
    app: AppHandle,
    state: tauri::State<AppState>,
) -> Result<(), String> {
    if state.mounted.load(Ordering::Relaxed) {
        return Err("already mounted or in progress".into());
    }

    // 管理者として実行されていない場合は再起動
    // その場合は自分自身を自動で終了
    unsafe {
        let mut tok: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) != 0 {
            let mut elev: TOKEN_ELEVATION = mem::zeroed();
            let mut len: u32 = 0;
            let ok = GetTokenInformation(
                tok,
                TokenElevation,
                &mut elev as *mut _ as _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            );
            CloseHandle(tok);
            if ok != 0 && elev.TokenIsElevated == 0 {
                if let Ok(exe) = std::env::current_exe() {
                    let exe_w: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
                    let op: Vec<u16> = "runas\0".encode_utf16().collect();
                    ShellExecuteW(
                        null_mut(),
                        op.as_ptr(),
                        exe_w.as_ptr(),
                        std::ptr::null(),
                        std::ptr::null(),
                        SW_SHOW,
                    );
                }
                return Err("relaunching as administrator".into());
            }
        }
    }

    state.mounted.store(true, Ordering::Relaxed);
    CANCEL.store(false, Ordering::Relaxed);

    let app_for_thread = app.clone();
    let letter_for_thread = letter.clone();
    std::thread::spawn(move || {
        let st = app_for_thread.state::<AppState>();
        match do_mount(letter_for_thread, app_for_thread.clone()) {
            Ok(()) => {
                st.mounted.store(false, Ordering::Relaxed);
            }
            Err(e) => {
                st.mounted.store(false, Ordering::Relaxed);
                let _ = app_for_thread.emit_all(
                    "state",
                    serde_json::json!({"state":"error","error": e.to_string()}),
                );
            }
        }
    });

    Ok(())
}

// マウント開始
fn do_mount(letter: String, app: AppHandle) -> Result<()> {
    let device = normalize_device(&letter)?;
    info!(device = %device, "selected device");

    let volume = Volume::new(&device).with_context(|| format!("failed to open {}", device))?;
    let mft_for_scan = Mft::new(volume.clone()).context("failed to open $MFT for scan")?;
    let shared_mft = Arc::new(RwLock::new(mft_for_scan));
    let max_record = { shared_mft.read().record_count() };
    {
        let _ = shared_mft.read().record(FIRST_NORMAL_RECORD);
    }

    let total_records = max_record - FIRST_NORMAL_RECORD;
    let processed = Arc::new(AtomicU64::new(0));
    let found = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));
    let start_time = Instant::now();

    let (tx, rx) = crossbeam_channel::unbounded();
    let scan_threads = start_scanner_pool(
        shared_mft.clone(),
        tx.clone(),
        processed.clone(),
        max_record,
    );
    drop(tx);
    let found_for_worker = found.clone();
    let idx_handle = std::thread::spawn(move || indexer_worker(rx, found_for_worker, 4096));

    let prog_thr = progress_loop_emit(
        app.clone(),
        processed.clone(),
        found.clone(),
        total_records,
        running.clone(),
        start_time,
    );

    for h in scan_threads {
        let _ = h.join();
    }
    let built_index: DeletedIndex = idx_handle.join().unwrap();
    running.store(false, Ordering::Relaxed);
    let _ = prog_thr.join();

    let mft_for_fs: Mft = Arc::try_unwrap(shared_mft)
        .map(|rw| rw.into_inner())
        .unwrap_or_else(|_| panic!("shared_mft still has strong refs at FS handoff"));

    // ntfs-reader 0.5.2's NtfsFile::open_stream opens its own volume handle lazily, so
    // UnUnlinkFs no longer needs a device handle of its own for reading file data.
    let idx_arc = Arc::new(RwLock::new(built_index));
    let fs = UnUnlinkFs::new(device.clone(), volume, mft_for_fs, idx_arc.clone());

    let mut flags = dokan::MountFlags::ALT_STREAM | dokan::MountFlags::REMOVABLE;
    #[cfg(debug_assertions)]
    {
        flags |= dokan::MountFlags::STDERR;
    }
    let options = MountOptions {
        single_thread: false,
        flags,
        ..Default::default()
    };

    dokan::init();
    let mount_point_u16 = U16CString::from_str("R:").unwrap();
    let mut mounter = FileSystemMounter::new(&fs, mount_point_u16.as_ucstr(), &options);
    let _file_system = mounter.mount().context("failed to mount with Dokan")?;

    let _ = app.emit_all(
        "state",
        serde_json::json!({"state":"mounted","mountPoint":"R:\\"}),
    );

    let _ = std::process::Command::new("explorer").arg("R:\\").spawn();

    // CANCEL が立つまで待機
    loop {
        if CANCEL.load(Ordering::Relaxed) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    Ok(())
}

#[derive(Serialize)]
pub struct FileListItem {
    pub name: String,
    pub path: String,
    pub ext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_opened_ts: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified_ts: Option<i64>,
}

#[tauri::command]
pub fn build_filelist_cmd(
    app: AppHandle,
    state: tauri::State<AppState>,
    limit: Option<usize>,
) -> Result<Vec<FileListItem>, String> {
    if !state.mounted.load(Ordering::Relaxed) {
        return Err("not mounted".into());
    }
    let limit = limit.unwrap_or(50_000);
    let root = Path::new(r"R:\");
    if !root.exists() {
        return Err("mount point not found".into());
    }

    let mut out: Vec<FileListItem> = Vec::with_capacity(4096);
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        if out.len() >= limit {
            break;
        }
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for entry_res in rd {
            if out.len() >= limit {
                break;
            }
            let entry = match entry_res {
                Ok(e) => e,
                Err(_) => continue,
            };
            let p = entry.path();
            let md = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if md.is_dir() {
                stack.push(p);
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let mut path_str = p.to_string_lossy().to_string();
            if let Some(stripped) = path_str.strip_prefix(r"\\?\") {
                path_str = stripped.to_string();
            }
            let ext = p
                .extension()
                .map(|e| format!(".{}", e.to_string_lossy()))
                .unwrap_or_else(|| "".to_string());
            let last_opened_ts = md
                .accessed()
                .ok()
                .and_then(|st| st.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64);
            let last_modified_ts = md
                .modified()
                .ok()
                .and_then(|st| st.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64);

            out.push(FileListItem {
                name,
                path: path_str,
                ext,
                last_opened_ts,
                last_modified_ts,
            });

            if out.len() % 5000 == 0 {
                let _ = app.emit_all("log", format!("filelist: {} items...", out.len()));
            }
        }
    }

    Ok(out)
}

#[tauri::command]
pub fn open_path_cmd(path: String) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err("empty path".into());
    }
    std::process::Command::new("explorer")
        .arg(&path)
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn copy_to_desktop_cmd(path: String) -> Result<String, String> {
    if path.trim().is_empty() {
        return Err("empty path".into());
    }
    let src = Path::new(&path);
    if !src.exists() {
        return Err("source not found".into());
    }
    let md = std::fs::metadata(src).map_err(|e| e.to_string())?;
    if md.is_dir() {
        return Err("directory copy is not supported".into());
    }

    let desktop = std::env::var("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("Desktop");
    let dst_dir = if desktop.exists() {
        desktop
    } else {
        PathBuf::from(".")
    };

    let file_name = src
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .ok_or_else(|| "invalid file name".to_string())?;

    let mut base = file_name.clone();
    let mut ext = String::new();
    if let Some(dot) = file_name.rfind('.') {
        base = file_name[..dot].to_string();
        ext = file_name[dot..].to_string();
    }
    let mut cand = dst_dir.join(&file_name);
    let mut n = 2usize;
    while cand.exists() {
        cand = dst_dir.join(format!("{} ({}){}", base, n, ext));
        n += 1;
    }

    std::fs::copy(src, &cand).map_err(|e| e.to_string())?;
    Ok(cand.to_string_lossy().to_string())
}

#[tauri::command]
pub fn reveal_in_explorer_cmd(path: String) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err("empty path".into());
    }
    let p = Path::new(&path);
    if !p.exists() {
        return Err("path not found".into());
    }
    let display_path = match p.canonicalize() {
        Ok(c) => {
            let mut s = c.to_string_lossy().to_string();
            if let Some(stripped) = s.strip_prefix(r"\\?\") {
                s = stripped.to_string();
            }
            s
        }
        Err(_) => path.clone(),
    };

    std::process::Command::new("explorer")
        .arg(format!("/select,{}", display_path))
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}
