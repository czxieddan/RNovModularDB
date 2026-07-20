use std::{
    ffi::OsString,
    fs::{File, OpenOptions, remove_file, rename},
    io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use rnmdb_common::error::{ErrorKind, Result, RnovError};

use super::{
    PageCryptoKey, SINGLE_FILE_FORMAT_VERSION, SingleFileInspection, SingleFileMetadata,
    SingleFileProcessLock, SingleFileRekeyPageReport, SingleFileRekeyReport, finish_single_file_io,
    inspect_single_file_with_key_locked, read_single_file_metadata, read_single_file_page,
    single_file_access_lock_for, single_file_data_start, single_file_page_record_size,
    with_new_single_file_exclusive, write_single_file_header_with_roots, write_single_file_page,
};

static NEXT_REKEY_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceIdentity {
    namespace: u64,
    file: u64,
}

struct RekeySource<'a> {
    file: &'a mut File,
    inspection: &'a SingleFileInspection,
    metadata: &'a SingleFileMetadata,
    page_key: PageCryptoKey,
}

/// Re-encrypts every present page with a fresh key and atomically replaces the
/// current v2 single-file database after the replacement has been verified.
///
/// This is an offline operation. All `SingleFileBackend` values for `path` in
/// this process must be dropped, and other processes must be quiesced. The
/// target key must be fresh for this database; reusing a previously used key
/// can repeat page nonces across retained snapshots.
///
/// Before the final rename, failures leave the original path unchanged and
/// trigger best-effort temporary-file cleanup. The rename is the commit point:
/// a later parent-directory sync error means the new-key file is already
/// active and its crash durability is uncertain, so callers must inspect it
/// with the target key rather than retrying with the source key.
/// Platforms without portable directory syncing guarantee atomic visibility,
/// but not durable pathname replacement across sudden power loss.
pub fn rekey_single_file(
    path: impl AsRef<Path>,
    source_page_key: PageCryptoKey,
    target_page_key: PageCryptoKey,
) -> Result<SingleFileRekeyReport> {
    let path = path.as_ref();
    validate_rekey_keys(source_page_key, target_page_key)?;
    let access_lock = single_file_access_lock_for(path)?;
    let _access_guard = access_lock.lock().map_err(|_| {
        RnovError::new(
            ErrorKind::Internal,
            "single-file backend access lock poisoned",
        )
    })?;
    ensure_no_live_local_backend(&access_lock)?;

    let (source_file, source_identity) = open_rekey_source(path)?;
    let mut process_lock = SingleFileProcessLock::acquire_exclusive(&source_file)?;
    let result = rekey_single_file_locked(
        path,
        source_page_key,
        target_page_key,
        process_lock.file_mut(),
        &access_lock,
        source_identity,
    );
    let unlock_result = process_lock.release();
    match result {
        Ok(report) => Ok(report),
        Err(error) => finish_single_file_io(Err(error), unlock_result),
    }
}

fn validate_rekey_keys(
    source_page_key: PageCryptoKey,
    target_page_key: PageCryptoKey,
) -> Result<()> {
    if source_page_key == target_page_key {
        return Err(RnovError::new(
            ErrorKind::Security,
            "single-file rekey requires a different target page key",
        ));
    }
    Ok(())
}

fn open_rekey_source(path: &Path) -> Result<(File, SourceIdentity)> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    configure_rekey_source_open(&mut options);
    let file = options.open(path).map_err(rekey_source_open_error)?;
    let identity = validate_open_rekey_source(&file)?;
    Ok((file, identity))
}

#[cfg(unix)]
fn configure_rekey_source_open(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(windows)]
fn configure_rekey_source_open(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
fn configure_rekey_source_open(_options: &mut OpenOptions) {}

fn rekey_source_open_error(err: io::Error) -> RnovError {
    #[cfg(unix)]
    if err.raw_os_error() == Some(libc::ELOOP) {
        return RnovError::new(
            ErrorKind::InvalidInput,
            "rekey source cannot be a symbolic link",
        );
    }
    RnovError::new(
        ErrorKind::Io,
        format!("failed to open database file for rekey: {err}"),
    )
}

#[cfg(unix)]
fn validate_open_rekey_source(file: &File) -> Result<SourceIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata().map_err(rekey_source_metadata_error)?;
    validate_source_file_shape(metadata.is_file(), metadata.nlink())?;
    Ok(SourceIdentity {
        namespace: metadata.dev(),
        file: metadata.ino(),
    })
}

#[cfg(windows)]
fn validate_open_rekey_source(file: &File) -> Result<SourceIdentity> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let information = windows_file_information(file)?;
    let is_regular = information.dwFileAttributes
        & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
        == 0;
    validate_source_file_shape(is_regular, u64::from(information.nNumberOfLinks))?;
    Ok(SourceIdentity {
        namespace: u64::from(information.dwVolumeSerialNumber),
        file: u64::from(information.nFileIndexHigh) << 32 | u64::from(information.nFileIndexLow),
    })
}

#[cfg(windows)]
fn windows_file_information(
    file: &File,
) -> Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::{mem, os::windows::io::AsRawHandle};
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
    };

    // SAFETY: This C output structure permits an all-zero initial buffer.
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { mem::zeroed() };
    // SAFETY: The owned file handle remains live and the output pointer is valid.
    let result =
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut information) };
    if result != 0 {
        return Ok(information);
    }
    Err(rekey_source_metadata_error(io::Error::last_os_error()))
}

#[cfg(not(any(unix, windows)))]
fn validate_open_rekey_source(_file: &File) -> Result<SourceIdentity> {
    Err(RnovError::new(
        ErrorKind::Storage,
        "single-file rekey cannot verify source identity on this platform",
    ))
}

fn rekey_source_metadata_error(err: io::Error) -> RnovError {
    RnovError::new(
        ErrorKind::Io,
        format!("failed to inspect opened rekey source: {err}"),
    )
}

fn validate_source_file_shape(is_regular: bool, links: u64) -> Result<()> {
    if !is_regular {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "rekey source must be a regular file and cannot be a symbolic link",
        ));
    }
    if links > 1 {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "single-file rekey rejects hard links because another name would retain old-key ciphertext",
        ));
    }
    Ok(())
}

fn ensure_no_live_local_backend(access_lock: &Arc<std::sync::Mutex<()>>) -> Result<()> {
    if Arc::strong_count(access_lock) == 1 {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Storage,
        "single-file rekey requires every live single-file backend for the path to be dropped",
    ))
}

fn rekey_single_file_locked(
    path: &Path,
    source_page_key: PageCryptoKey,
    target_page_key: PageCryptoKey,
    source_file: &mut File,
    access_lock: &Arc<std::sync::Mutex<()>>,
    source_identity: SourceIdentity,
) -> Result<SingleFileRekeyReport> {
    let source_inspection =
        inspect_single_file_with_key_locked(path, source_page_key, source_file)?;
    let source_metadata = read_single_file_metadata(source_file)?;
    let mut source = RekeySource {
        file: source_file,
        inspection: &source_inspection,
        metadata: &source_metadata,
        page_key: source_page_key,
    };
    let (temporary_path, temporary_file) = create_rekey_temporary_file(path)?;
    let report = write_rekey_temporary_target(
        temporary_file,
        &temporary_path,
        &mut source,
        target_page_key,
    )?;
    commit_rekey_target(path, &temporary_path, access_lock, source_identity)?;
    sync_rekey_parent(path)?;
    Ok(report)
}

fn write_rekey_temporary_target(
    mut temporary_file: File,
    temporary_path: &Path,
    source: &mut RekeySource<'_>,
    target_page_key: PageCryptoKey,
) -> Result<SingleFileRekeyReport> {
    let result = with_new_single_file_exclusive(&mut temporary_file, |target_file| {
        write_rekey_target(target_file, temporary_path, source, target_page_key)
    });
    drop(temporary_file);
    result.map_err(|error| remove_temporary_after_error(temporary_path, error))
}

fn commit_rekey_target(
    path: &Path,
    temporary_path: &Path,
    access_lock: &Arc<std::sync::Mutex<()>>,
    source_identity: SourceIdentity,
) -> Result<()> {
    let result = (|| {
        ensure_no_live_local_backend(access_lock)?;
        ensure_rekey_source_unchanged(path, source_identity)?;
        rename(temporary_path, path).map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to atomically replace database after rekey: {err}"),
            )
        })?;
        Ok(())
    })();
    result.map_err(|error| remove_temporary_after_error(temporary_path, error))
}

fn ensure_rekey_source_unchanged(path: &Path, expected: SourceIdentity) -> Result<()> {
    let (_file, actual) = open_rekey_source(path)?;
    if actual == expected {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Storage,
        "rekey source pathname changed during the offline operation",
    ))
}

fn create_rekey_temporary_file(path: &Path) -> Result<(PathBuf, File)> {
    let parent = rekey_parent(path);
    let file_name = path.file_name().ok_or_else(|| {
        RnovError::new(
            ErrorKind::InvalidInput,
            "rekey source path has no file name",
        )
    })?;
    for _ in 0..128 {
        let id = NEXT_REKEY_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(format!(".rekey-{}-{id}.tmp", std::process::id()));
        let temporary_path = parent.join(temporary_name);
        match open_rekey_temporary_file(&temporary_path) {
            Ok(file) => return Ok((temporary_path, file)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(RnovError::new(
                    ErrorKind::Io,
                    format!("failed to create rekey temporary file: {err}"),
                ));
            }
        }
    }
    Err(RnovError::new(
        ErrorKind::Io,
        "failed to reserve a unique rekey temporary file name",
    ))
}

fn rekey_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn open_rekey_temporary_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn write_rekey_target(
    target_file: &mut File,
    target_path: &Path,
    source: &mut RekeySource<'_>,
    target_page_key: PageCryptoKey,
) -> Result<SingleFileRekeyReport> {
    initialize_rekey_target(target_file, source)?;
    let page_reports = write_rekey_pages(target_file, source, target_page_key)?;
    sync_rekey_target(target_file)?;
    let target_inspection =
        inspect_single_file_with_key_locked(target_path, target_page_key, target_file)?;
    let target_metadata = read_single_file_metadata(target_file)?;
    validate_rekey_target(
        source.inspection,
        source.metadata,
        &target_inspection,
        &target_metadata,
        page_reports.len() as u64,
    )?;
    validate_rekey_page_contents(target_file, source, target_page_key)?;
    Ok(build_rekey_report(
        source.inspection,
        &target_inspection,
        page_reports,
    ))
}

fn initialize_rekey_target(target_file: &mut File, source: &RekeySource<'_>) -> Result<()> {
    write_single_file_header_with_roots(
        target_file,
        source.metadata.page_size,
        source.metadata.superblock.generation,
        source.metadata.superblock.catalog_root,
        source.metadata.superblock.free_map_root,
    )?;
    target_file
        .set_len(source.inspection.file_len_bytes())
        .map_err(|err| {
            RnovError::new(ErrorKind::Io, format!("failed to size rekey target: {err}"))
        })?;
    Ok(())
}

fn sync_rekey_target(target_file: &File) -> Result<()> {
    target_file
        .sync_all()
        .map_err(|err| RnovError::new(ErrorKind::Io, format!("failed to sync rekey target: {err}")))
}

fn build_rekey_report(
    source: &SingleFileInspection,
    target: &SingleFileInspection,
    page_reports: Vec<SingleFileRekeyPageReport>,
) -> SingleFileRekeyReport {
    SingleFileRekeyReport {
        path: source.path().to_path_buf(),
        source_format_version: SINGLE_FILE_FORMAT_VERSION,
        target_format_version: SINGLE_FILE_FORMAT_VERSION,
        key_rotated: true,
        bytes_written: target.file_len_bytes(),
        page_size: target.page_size(),
        superblock_generation: target.superblock_generation(),
        page_record_slots: target.page_record_slots(),
        pages_rekeyed: page_reports.len() as u64,
        page_reports,
    }
}

fn validate_rekey_page_contents(
    target_file: &mut File,
    source: &mut RekeySource<'_>,
    target_page_key: PageCryptoKey,
) -> Result<()> {
    let page_size = source.inspection.page_size();
    for record in source
        .inspection
        .page_records()
        .iter()
        .filter(|record| record.is_present())
    {
        let source_page =
            read_single_file_page(source.file, page_size, source.page_key, record.page_id())?;
        let target_page =
            read_single_file_page(target_file, page_size, target_page_key, record.page_id())?;
        if source_page != target_page || source_page.is_none() {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "rekey target page content does not match the authenticated source",
            ));
        }
    }
    Ok(())
}

fn write_rekey_pages(
    target_file: &mut File,
    source: &mut RekeySource<'_>,
    target_page_key: PageCryptoKey,
) -> Result<Vec<SingleFileRekeyPageReport>> {
    let page_size = source.inspection.page_size();
    let data_start = single_file_data_start();
    let record_size = single_file_page_record_size(page_size);
    let mut reports = Vec::with_capacity(source.inspection.present_page_records() as usize);
    for record in source
        .inspection
        .page_records()
        .iter()
        .filter(|record| record.is_present())
    {
        let page =
            read_single_file_page(source.file, page_size, source.page_key, record.page_id())?
                .ok_or_else(|| {
                    RnovError::new(
                        ErrorKind::Corruption,
                        "authenticated source page disappeared during rekey",
                    )
                })?;
        write_single_file_page(target_file, target_page_key, page, data_start, record_size)?;
        reports.push(SingleFileRekeyPageReport {
            page_id: record.page_id(),
            source_counter: record
                .encryption_counter()
                .expect("present record has a counter"),
            target_counter: 1,
        });
    }
    Ok(reports)
}

fn validate_rekey_target(
    source: &SingleFileInspection,
    source_metadata: &SingleFileMetadata,
    target: &SingleFileInspection,
    target_metadata: &SingleFileMetadata,
    pages_rekeyed: u64,
) -> Result<()> {
    if rekey_metadata_matches(source_metadata, target_metadata)
        && rekey_layout_matches(source, target, pages_rekeyed)
        && rekey_counters_reset(target)
    {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        "rekey target validation does not match the source database",
    ))
}

fn rekey_metadata_matches(source: &SingleFileMetadata, target: &SingleFileMetadata) -> bool {
    source.page_size == target.page_size
        && source.superblock.generation == target.superblock.generation
        && source.superblock.catalog_root == target.superblock.catalog_root
        && source.superblock.free_map_root == target.superblock.free_map_root
}

fn rekey_layout_matches(
    source: &SingleFileInspection,
    target: &SingleFileInspection,
    pages_rekeyed: u64,
) -> bool {
    source.file_len_bytes() == target.file_len_bytes()
        && source.page_record_slots() == target.page_record_slots()
        && source.present_page_records() == target.present_page_records()
        && source.empty_page_slots() == target.empty_page_slots()
        && target.authenticated_page_records() == pages_rekeyed
        && target.checksum_verified_page_records() == pages_rekeyed
}

fn rekey_counters_reset(target: &SingleFileInspection) -> bool {
    target
        .page_records()
        .iter()
        .filter(|record| record.is_present())
        .all(|record| record.encryption_counter() == Some(1))
}

fn remove_temporary_after_error(path: &Path, primary: RnovError) -> RnovError {
    match remove_file(path) {
        Ok(()) => primary,
        Err(err) if err.kind() == io::ErrorKind::NotFound => primary,
        Err(err) => RnovError::new(
            primary.kind(),
            format!("{primary}; additionally failed to remove rekey temporary file: {err}"),
        ),
    }
}

#[cfg(unix)]
fn sync_rekey_parent(path: &Path) -> Result<()> {
    let parent = rekey_parent(path);
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|err| {
            RnovError::new(
                ErrorKind::Storage,
                format!("rekey replacement committed but parent directory sync failed: {err}"),
            )
        })
}

#[cfg(not(unix))]
fn sync_rekey_parent(_path: &Path) -> Result<()> {
    Ok(())
}
