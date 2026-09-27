use crate::indexer::{DeletedIndex, EntryMeta, EntryOrDir, path_key_lc_from_u16};
use crate::util::normalize_and_canonicalize_for_key;
use dokan::{
    CreateFileInfo, DiskSpaceInfo, FileInfo as DokanFileInfo, FileSystemHandler, FileTimeOperation,
    FillDataError, FillDataResult, FindData, OperationInfo, OperationResult, VolumeInfo,
};
use ntfs_reader::{Mft, NtfsReaderError, Volume};
use parking_lot::RwLock;
use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use tracing::debug;
use widestring::{U16CStr, U16CString, U16Str, U16String};
use winapi::shared::ntstatus::{
    STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW, STATUS_DATA_ERROR, STATUS_INVALID_DEVICE_REQUEST,
    STATUS_IO_DEVICE_ERROR, STATUS_NOT_IMPLEMENTED, STATUS_OBJECT_NAME_NOT_FOUND,
};
use winapi::um::winnt::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY};

// Dokanの利用に必要な構造体/関数/諸々の実装

#[derive(Clone)]
pub struct HandleCtx {
    pub is_dir: bool,
    pub mft_no: Option<u64>,
    pub _path_u16: U16String,
}

pub struct UnUnlinkFs {
    pub _device_path: String,
    pub volume: Volume,
    pub mft: Mft,
    pub index: Arc<RwLock<DeletedIndex>>,
}

impl UnUnlinkFs {
    pub fn new(
        device_path: String,
        volume: Volume,
        mft: Mft,
        index: Arc<RwLock<DeletedIndex>>,
    ) -> Self {
        Self {
            _device_path: device_path,
            volume,
            mft,
            index,
        }
    }

    fn open_dir_ctx(&self, full: &U16CStr) -> OperationResult<CreateFileInfo<HandleCtx>> {
        Ok(CreateFileInfo {
            context: HandleCtx {
                is_dir: true,
                mft_no: None,
                _path_u16: U16String::from_vec(full.as_slice().to_vec()),
            },
            is_dir: true,
            new_file_created: false,
        })
    }
    fn open_file_ctx(
        &self,
        full: &U16CStr,
        mft_no: u64,
    ) -> OperationResult<CreateFileInfo<HandleCtx>> {
        Ok(CreateFileInfo {
            context: HandleCtx {
                is_dir: false,
                mft_no: Some(mft_no),
                _path_u16: U16String::from_vec(full.as_slice().to_vec()),
            },
            is_dir: false,
            new_file_created: false,
        })
    }

    // ntfs-reader 0.5.2 restores non-resident reads via NtfsFile::open_stream, a Read + Seek
    // StreamReader over the default stream (live or deleted, resident or not). Seek to `offset`
    // and read only what the caller asked for, instead of loading the whole file into memory.
    fn read_all_data(&self, mft_no: u64, offset: i64, buffer: &mut [u8]) -> OperationResult<u32> {
        let file = self
            .mft
            .record(mft_no)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let mut stream = file.open_stream(None).map_err(map_open_stream_error)?;
        if stream.data_lost() {
            // Deleted file with an $ATTRIBUTE_LIST: NTFS zeroed the non-resident stream's size
            // and cluster list on delete, so there is nothing left to locate.
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        let size = stream.size();
        let off = if offset < 0 { 0 } else { offset as u64 };
        if off >= size {
            return Ok(0);
        }
        stream
            .seek(SeekFrom::Start(off))
            .map_err(|_| STATUS_IO_DEVICE_ERROR)?;
        let want = std::cmp::min(buffer.len() as u64, size - off) as usize;
        let mut total = 0usize;
        while total < want {
            match stream.read(&mut buffer[total..want]) {
                Ok(0) => break,
                Ok(n) => total += n,
                // A missing extent (a deleted file's extension record was freed and reused)
                // still leaves the bytes read before it usable; anything else is a hard error
                // only when nothing at all came back.
                Err(_) if total > 0 => break,
                Err(err) => return Err(map_stream_read_error(&err)),
            }
        }
        if off == 0 {
            // 先頭オフセットから読み出した結果が全部ゼロなら、既にTRIMコマンドで消されてしまったとみなす
            if total > 0 && !buffer[..total].iter().any(|&b| b != 0) {
                return Err(STATUS_OBJECT_NAME_NOT_FOUND);
            }
        }
        Ok(total as u32)
    }
}

// StreamNotFound is treated like a missing file, the compressed/encrypted/WOF cases like
// unsupported operations (this crate does not decompress or decrypt), and anything else (e.g.
// InvalidDataRun) as a data error.
fn map_open_stream_error(err: NtfsReaderError) -> i32 {
    match err {
        NtfsReaderError::StreamNotFound { .. } => STATUS_OBJECT_NAME_NOT_FOUND,
        NtfsReaderError::CompressedStream
        | NtfsReaderError::EncryptedStream
        | NtfsReaderError::WofCompressedStream => STATUS_NOT_IMPLEMENTED,
        _ => STATUS_DATA_ERROR,
    }
}

// NtfsReaderError::StreamExtentMissing travels inside the io::Error a StreamReader read
// returns; anything else is a genuine I/O failure.
fn map_stream_read_error(err: &std::io::Error) -> i32 {
    match err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<NtfsReaderError>())
    {
        Some(NtfsReaderError::StreamExtentMissing { .. }) => STATUS_DATA_ERROR,
        _ => STATUS_IO_DEVICE_ERROR,
    }
}

// FileSystemHandlerの実装
impl<'a> FileSystemHandler<'a, 'a> for UnUnlinkFs {
    type Context = HandleCtx;

    // ファイル作成 (実際にはファイル作成以外のときも呼ばれるので注意)
    fn create_file(
        &'a self,
        file_name: &U16CStr,
        _security_context: &dokan_sys::DOKAN_IO_SECURITY_CONTEXT,
        _desired_access: u32,
        _file_attributes: u32,
        _share_access: u32,
        create_disposition: u32,
        create_options: u32,
        _info: &mut OperationInfo<'a, 'a, Self>,
    ) -> OperationResult<CreateFileInfo<Self::Context>> {
        use dokan_sys::win32::{
            FILE_CREATE, FILE_DELETE_ON_CLOSE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE,
            FILE_OPEN, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT, FILE_OVERWRITE, FILE_OVERWRITE_IF,
            FILE_SUPERSEDE,
        };
        let name_dbg = file_name.to_string_lossy();
        let passed_key = path_key_lc_from_u16(file_name);
        let open_key = key_for_dir_listing(file_name);
        if matches!(
            create_disposition,
            FILE_CREATE | FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF
        ) || (create_options & FILE_DELETE_ON_CLOSE) != 0
        {
            // debug!("create_file: DENY write/create name='{}' passed_key='{}' open_key='{}' disp=0x{:x} opt=0x{:x}", name_dbg, passed_key, open_key, create_disposition, create_options);
            return Err(STATUS_ACCESS_DENIED);
        }
        if is_root_key(&open_key) {
            return self.open_dir_ctx(file_name);
        }
        let _ignore_reparse_point = (create_options & FILE_OPEN_REPARSE_POINT) != 0;
        let idx = self.index.read();
        match idx.get(&open_key) {
            Some(EntryOrDir::Dir) => {
                if (create_options & FILE_NON_DIRECTORY_FILE) != 0 {
                    return Err(winapi::shared::ntstatus::STATUS_FILE_IS_A_DIRECTORY);
                }
                self.open_dir_ctx(file_name)
            }
            Some(EntryOrDir::File(m)) => {
                if (create_options & FILE_DIRECTORY_FILE) != 0 {
                    return Err(winapi::shared::ntstatus::STATUS_NOT_A_DIRECTORY);
                }
                if !matches!(create_disposition, FILE_OPEN | FILE_OPEN_IF) {
                    return Err(STATUS_ACCESS_DENIED);
                }
                self.open_file_ctx(file_name, m.mft_no)
            }
            None => {
                if matches!(create_disposition, FILE_OPEN | FILE_OPEN_IF) {
                    Err(STATUS_OBJECT_NAME_NOT_FOUND)
                } else {
                    Err(STATUS_ACCESS_DENIED)
                }
            }
        }
    }

    fn cleanup(
        &'a self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'a, 'a, Self>,
        _context: &'a Self::Context,
    ) {
    }
    fn close_file(
        &'a self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'a, 'a, Self>,
        _context: &'a Self::Context,
    ) {
    }

    // ファイルの情報取得
    fn get_file_information(
        &'a self,
        file_name: &U16CStr,
        _info: &OperationInfo<'a, 'a, Self>,
        _context: &'a Self::Context,
    ) -> OperationResult<DokanFileInfo> {
        let key = key_for_dir_listing(file_name);
        let idx = self.index.read();
        if is_root_key(&key) {
            return Ok(DokanFileInfo {
                attributes: FILE_ATTRIBUTE_DIRECTORY,
                creation_time: UNIX_EPOCH,
                last_access_time: UNIX_EPOCH,
                last_write_time: UNIX_EPOCH,
                file_size: 0,
                number_of_links: 1,
                file_index: file_index_from_key("\\"),
            });
        }
        match idx.get(&key) {
            Some(EntryOrDir::Dir) => Ok(DokanFileInfo {
                attributes: FILE_ATTRIBUTE_DIRECTORY,
                creation_time: UNIX_EPOCH,
                last_access_time: UNIX_EPOCH,
                last_write_time: UNIX_EPOCH,
                file_size: 0,
                number_of_links: 1,
                file_index: file_index_from_key(&key),
            }),
            Some(EntryOrDir::File(m)) => {
                let mut fi = m.to_file_info();
                if fi.number_of_links == 0 {
                    fi.number_of_links = 1;
                }
                if fi.file_index == 0 {
                    fi.file_index = file_index_from_key(&key);
                }
                Ok(fi)
            }
            None => Err(STATUS_OBJECT_NAME_NOT_FOUND),
        }
    }

    // ファイル検索
    fn find_files(
        &'a self,
        file_name: &U16CStr,
        mut fill_find_data: impl FnMut(&FindData) -> FillDataResult,
        _info: &OperationInfo<'a, 'a, Self>,
        context: &'a Self::Context,
    ) -> OperationResult<()> {
        let ctx_cstr = U16CString::from_ustr(context._path_u16.as_ustr()).unwrap();
        let ctx_path_ucstr: &U16CStr = ctx_cstr.as_ucstr();
        let parent_key = key_for_dir_listing(ctx_path_ucstr);
        let passed_key = path_key_lc_from_u16(file_name);
        let treat_as_dir = if context.is_dir {
            true
        } else if is_root_key(&parent_key) {
            true
        } else {
            let idx = self.index.read();
            matches!(idx.get(&parent_key), Some(EntryOrDir::Dir))
        };
        /* debug!(
            "find_files: ctx='{}' parent_key='{}' passed_key='{}' is_dir_ctx={} treat_as_dir={}",
            ctx_path_ucstr.to_string_lossy(),
            parent_key,
            passed_key,
            context.is_dir,
            treat_as_dir
        ); */
        if !treat_as_dir {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        let mut out: Vec<FindData> = vec![mk_dir_entry("."), mk_dir_entry("..")];
        let mut children = {
            let idx = self.index.read();
            idx.list_children(&parent_key)
        };
        if children.is_empty() && is_root_key(&parent_key) {
            let idx = self.index.read();
            let mut first_level: BTreeSet<U16String> = BTreeSet::new();
            for node_key in idx.nodes.keys() {
                if node_key == "\\" {
                    continue;
                }
                if let Some(rest) = node_key.strip_prefix('\\') {
                    let first = match rest.find('\\') {
                        Some(p) => &rest[..p],
                        None => rest,
                    };
                    if !first.is_empty() {
                        first_level.insert(U16String::from_str(first));
                    }
                }
            }
            children = first_level.into_iter().collect();
        }
        {
            let idx = self.index.read();
            for name in children {
                let child_key = if is_root_key(&parent_key) {
                    normalize_and_canonicalize_for_key(&format!(r"\{}", name.to_string_lossy()))
                } else {
                    normalize_and_canonicalize_for_key(&format!(
                        r"{}\{}",
                        parent_key,
                        name.to_string_lossy()
                    ))
                };
                if let Some(entry) = idx.get(&child_key) {
                    match entry {
                        EntryOrDir::Dir => out.push(FindData {
                            attributes: FILE_ATTRIBUTE_DIRECTORY,
                            creation_time: UNIX_EPOCH,
                            last_access_time: UNIX_EPOCH,
                            last_write_time: UNIX_EPOCH,
                            file_size: 0,
                            file_name: U16CString::from_ustr(name.as_ustr()).unwrap(),
                        }),
                        EntryOrDir::File(m) => out.push(m.to_find_data()),
                    }
                } else if is_root_key(&parent_key) {
                    out.push(FindData {
                        attributes: FILE_ATTRIBUTE_DIRECTORY,
                        creation_time: UNIX_EPOCH,
                        last_access_time: UNIX_EPOCH,
                        last_write_time: UNIX_EPOCH,
                        file_size: 0,
                        file_name: U16CString::from_ustr(name.as_ustr()).unwrap(),
                    });
                }
            }
        }
        for d in out {
            match fill_find_data(&d) {
                Ok(_) => {}
                Err(FillDataError::BufferFull) => return Err(STATUS_BUFFER_OVERFLOW),
                Err(FillDataError::NameTooLong) => continue,
            }
        }
        Ok(())
    }

    // ファイル検索 (パターンマッチング)
    fn find_files_with_pattern(
        &'a self,
        _file_name: &U16CStr,
        search_pattern: &U16CStr,
        mut fill_find_data: impl FnMut(&FindData) -> FillDataResult,
        _info: &OperationInfo<'a, 'a, Self>,
        context: &'a Self::Context,
    ) -> OperationResult<()> {
        let ctx_cstr = U16CString::from_ustr(context._path_u16.as_ustr()).unwrap();
        let ctx_path_ucstr: &U16CStr = ctx_cstr.as_ucstr();
        let parent_key = key_for_dir_listing(ctx_path_ucstr);
        let pat = search_pattern.to_string_lossy();
        let pat_is_all = pat.is_empty() || pat == "*" || pat == "*.*";
        let literal = is_literal_pattern(&pat);
        let is_dir_ok = if context.is_dir {
            true
        } else {
            let idx = self.index.read();
            matches!(idx.get(&parent_key), Some(EntryOrDir::Dir)) || is_root_key(&parent_key)
        };
        if !is_dir_ok {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        let items: Vec<FindData> = {
            let idx = self.index.read();
            let mut out: Vec<FindData> = Vec::new();
            let mut children = idx.list_children(&parent_key);
            if children.is_empty() && is_root_key(&parent_key) {
                let mut first_level: BTreeSet<U16String> = BTreeSet::new();
                for node_key in idx.nodes.keys() {
                    if node_key == "\\" {
                        continue;
                    }
                    if let Some(rest) = node_key.strip_prefix('\\') {
                        let first = match rest.find('\\') {
                            Some(p) => &rest[..p],
                            None => rest,
                        };
                        if !first.is_empty() {
                            first_level.insert(U16String::from_str(first));
                        }
                    }
                }
                children = first_level.into_iter().collect();
            }
            if pat_is_all {
                let [dot, dotdot] = dot_entries();
                out.push(dot);
                out.push(dotdot);
            }
            for name in children {
                if !pat_is_all && !glob_match_ci(&name.to_string_lossy(), &pat) {
                    continue;
                }
                let child_key = if is_root_key(&parent_key) {
                    normalize_and_canonicalize_for_key(&format!(r"\{}", name.to_string_lossy()))
                } else {
                    normalize_and_canonicalize_for_key(&format!(
                        r"{}\{}",
                        parent_key,
                        name.to_string_lossy()
                    ))
                };
                if let Some(entry) = idx.get(&child_key) {
                    let d = match entry {
                        EntryOrDir::Dir => FindData {
                            attributes: FILE_ATTRIBUTE_DIRECTORY,
                            creation_time: UNIX_EPOCH,
                            last_access_time: UNIX_EPOCH,
                            last_write_time: UNIX_EPOCH,
                            file_size: 0,
                            file_name: U16CString::from_ustr(name.as_ustr()).unwrap(),
                        },
                        EntryOrDir::File(m) => m.to_find_data(),
                    };
                    out.push(d);
                    if literal {
                        break;
                    }
                } else if is_root_key(&parent_key) {
                    let d = FindData {
                        attributes: FILE_ATTRIBUTE_DIRECTORY,
                        creation_time: UNIX_EPOCH,
                        last_access_time: UNIX_EPOCH,
                        last_write_time: UNIX_EPOCH,
                        file_size: 0,
                        file_name: U16CString::from_ustr(name.as_ustr()).unwrap(),
                    };
                    out.push(d);
                    if literal {
                        break;
                    }
                }
            }
            out
        };
        for d in items {
            match fill_find_data(&d) {
                Ok(_) => {}
                Err(FillDataError::BufferFull) => return Err(STATUS_BUFFER_OVERFLOW),
                Err(FillDataError::NameTooLong) => continue,
            }
        }
        Ok(())
    }

    // ファイル読み込み
    // MFTからデータ位置を決めて読み取る
    fn read_file(
        &'a self,
        file_name: &U16CStr,
        offset: i64,
        buffer: &mut [u8],
        _info: &OperationInfo<'a, 'a, Self>,
        context: &'a Self::Context,
    ) -> OperationResult<u32> {
        let key_lc = path_key_lc_from_u16(file_name);
        if context.is_dir || is_root_key(&key_lc) {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        let mft_no = match context.mft_no {
            Some(n) => n,
            None => return Err(STATUS_INVALID_DEVICE_REQUEST),
        };

        // panicが発生してもシステムクラッシュしないようにcatch_unwindで囲む
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.read_all_data(mft_no, offset, buffer)
        }))
        .map_err(|_| STATUS_INVALID_DEVICE_REQUEST)?
    }

    fn set_file_time(
        &'a self,
        _file_name: &U16CStr,
        _creation_time: FileTimeOperation,
        _last_access_time: FileTimeOperation,
        _last_write_time: FileTimeOperation,
        _info: &OperationInfo<'a, 'a, Self>,
        _context: &'a Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }
    fn delete_file(
        &'a self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'a, 'a, Self>,
        _context: &'a Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }
    fn delete_directory(
        &'a self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'a, 'a, Self>,
        _context: &'a Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }
    fn move_file(
        &'a self,
        _file_name: &U16CStr,
        _new_file_name: &U16CStr,
        _replace_if_existing: bool,
        _info: &OperationInfo<'a, 'a, Self>,
        _context: &'a Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }
    fn set_end_of_file(
        &'a self,
        _file_name: &U16CStr,
        _offset: i64,
        _info: &OperationInfo<'a, 'a, Self>,
        _context: &'a Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }
    fn set_allocation_size(
        &'a self,
        _file_name: &U16CStr,
        _alloc_size: i64,
        _info: &OperationInfo<'a, 'a, Self>,
        _context: &'a Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    // ドライブの情報は固定値を返しておく
    fn get_disk_free_space(
        &'a self,
        _info: &OperationInfo<'a, 'a, Self>,
    ) -> OperationResult<DiskSpaceInfo> {
        Ok(DiskSpaceInfo {
            byte_count: 1024 * 1024 * 1024,
            free_byte_count: 1024 * 1024 * 1024,
            available_byte_count: 1024 * 1024 * 1024,
        })
    }
    fn get_volume_information(
        &'a self,
        _info: &OperationInfo<'a, 'a, Self>,
    ) -> OperationResult<VolumeInfo> {
        Ok(VolumeInfo {
            name: U16CString::from_str("RecMagic").unwrap(),
            serial_number: 0,
            max_component_length: 255,
            fs_flags: winapi::um::winnt::FILE_CASE_PRESERVED_NAMES
                | winapi::um::winnt::FILE_UNICODE_ON_DISK
                | winapi::um::winnt::FILE_PERSISTENT_ACLS
                | winapi::um::winnt::FILE_NAMED_STREAMS,
            fs_name: U16CString::from_str("NTFS").unwrap(),
        })
    }
    fn mounted(
        &'a self,
        _mount_point: &U16CStr,
        _info: &OperationInfo<'a, 'a, Self>,
    ) -> OperationResult<()> {
        Ok(())
    }
    fn unmounted(&'a self, _info: &OperationInfo<'a, 'a, Self>) -> OperationResult<()> {
        Ok(())
    }
    fn get_file_security(
        &'a self,
        _file_name: &U16CStr,
        _security_information: u32,
        _security_descriptor: winapi::um::winnt::PSECURITY_DESCRIPTOR,
        _buffer_length: u32,
        _info: &OperationInfo<'a, 'a, Self>,
        _context: &'a Self::Context,
    ) -> OperationResult<u32> {
        Err(STATUS_NOT_IMPLEMENTED)
    }
    fn set_file_security(
        &'a self,
        _file_name: &U16CStr,
        _security_information: u32,
        _security_descriptor: winapi::um::winnt::PSECURITY_DESCRIPTOR,
        _buffer_length: u32,
        _info: &OperationInfo<'a, 'a, Self>,
        _context: &'a Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }
}

fn mk_dir_entry(name: &str) -> FindData {
    FindData {
        attributes: FILE_ATTRIBUTE_DIRECTORY,
        creation_time: UNIX_EPOCH,
        last_access_time: UNIX_EPOCH,
        last_write_time: UNIX_EPOCH,
        file_size: 0,
        file_name: U16CString::from_str(name).unwrap(),
    }
}

fn is_literal_pattern(pat: &str) -> bool {
    !pat.contains('*') && !pat.contains('?')
}

fn glob_match_ci(name: &str, pat: &str) -> bool {
    fn inner(ns: &[u8], ps: &[u8]) -> bool {
        let (mut i, mut j) = (0usize, 0usize);
        let (mut star_i, mut star_j) = (None, None);
        while i < ns.len() {
            if j < ps.len() && (ps[j] == b'?' || ps[j].eq_ignore_ascii_case(&ns[i])) {
                i += 1;
                j += 1;
            } else if j < ps.len() && ps[j] == b'*' {
                star_i = Some(i);
                star_j = Some(j);
                j += 1;
            } else if let (Some(si), Some(sj)) = (star_i, star_j) {
                i = si + 1;
                star_i = Some(i);
                j = sj + 1;
            } else {
                return false;
            }
        }
        while j < ps.len() && ps[j] == b'*' {
            j += 1;
        }
        j == ps.len()
    }
    inner(
        &name.to_ascii_lowercase().as_bytes(),
        &pat.to_ascii_lowercase().as_bytes(),
    )
}

// 「.」と「..」のエントリを作成
fn dot_entries() -> [FindData; 2] {
    let epoch = UNIX_EPOCH;
    let dot = FindData {
        attributes: FILE_ATTRIBUTE_DIRECTORY,
        creation_time: epoch,
        last_access_time: epoch,
        last_write_time: epoch,
        file_size: 0,
        file_name: U16CString::from_str(".").unwrap(),
    };
    let dotdot = FindData {
        attributes: FILE_ATTRIBUTE_DIRECTORY,
        creation_time: epoch,
        last_access_time: epoch,
        last_write_time: epoch,
        file_size: 0,
        file_name: U16CString::from_str("..").unwrap(),
    };
    [dot, dotdot]
}

fn key_for_dir_listing(name: &U16CStr) -> String {
    let mut k = path_key_lc_from_u16(name);
    if k.ends_with("\\*.*") || k.ends_with("\\*") {
        if let Some(pos) = k.rfind('\\') {
            if pos == 0 {
                k = "\\".to_string();
            } else {
                k.truncate(pos);
            }
        }
    }
    if k == "\\." || k == "\\.." || k.is_empty() {
        k = "\\".to_string();
    }
    k
}
fn is_root_key(s: &str) -> bool {
    normalize_and_canonicalize_for_key(s) == "\\"
}

fn file_index_from_key(key: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in key.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    if h == 0 { 1 } else { h }
}

impl EntryMeta {
    pub fn to_find_data(&self) -> FindData {
        let attrs: u32 = if self.is_dir {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_READONLY
        };
        FindData {
            attributes: attrs,
            creation_time: self.created.unwrap_or(UNIX_EPOCH),
            last_access_time: self.accessed.unwrap_or(UNIX_EPOCH),
            last_write_time: self.modified.unwrap_or(UNIX_EPOCH),
            file_size: self.size,
            file_name: U16CString::from_ustr(self.name_u16.as_ustr()).unwrap(),
        }
    }
    pub fn to_file_info(&self) -> DokanFileInfo {
        let attrs: u32 = if self.is_dir {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_READONLY
        };
        DokanFileInfo {
            attributes: attrs,
            creation_time: self.created.unwrap_or(UNIX_EPOCH),
            last_access_time: self.accessed.unwrap_or(UNIX_EPOCH),
            last_write_time: self.modified.unwrap_or(UNIX_EPOCH),
            file_size: self.size,
            number_of_links: 1,
            file_index: self.mft_no,
        }
    }
}
