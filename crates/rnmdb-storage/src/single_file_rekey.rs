use std::{
    ffi::OsString,
    fs::{File, Metadata, OpenOptions, remove_file, rename, symlink_metadata},
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
    validate_rekey_request(path, source_page_key, target_page_key)?;
    let access_lock = single_file_access_lock_for(path)?;
    let _access_guard = access_lock.lock().map_err(|_| {
        RnovError::new(
            ErrorKind::Internal,
            "single-file backend access lock poisoned",
        )
    })?;
    ensure_no_live_local_backend(&access_lock)?;

    let source_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to open database file for rekey: {err}"),
            )
        })?;
    let mut process_lock = SingleFileProcessLock::acquire_exclusive(&source_file)?;
    let result = rekey_single_file_locked(
        path,
        source_page_key,
        target_page_key,
        process_lock.file_mut(),
        &access_lock,
    );
    let unlock_result = process_lock.release();
    finish_single_file_io(result, unlock_result)
}

fn validate_rekey_request(
    path: &Path,
    source_page_key: PageCryptoKey,
    target_page_key: PageCryptoKey,
) -> Result<()> {
    if source_page_key == target_page_key {
        return Err(RnovError::new(
            ErrorKind::Security,
            "single-file rekey requires a different target page key",
        ));
    }
    let metadata = symlink_metadata(path).map_err(|err| {
        RnovError::new(
            ErrorKind::InvalidInput,
            format!("rekey source must be a regular file: {err}"),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "rekey source must be a regular file and cannot be a symbolic link",
        ));
    }
    if has_multiple_hard_links(path, &metadata)? {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "single-file rekey rejects hard links because another name would retain old-key ciphertext",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn has_multiple_hard_links(_path: &Path, metadata: &Metadata) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;

    Ok(metadata.nlink() > 1)
}

#[cfg(windows)]
fn has_multiple_hard_links(path: &Path, _metadata: &Metadata) -> Result<bool> {
    use std::{mem, os::windows::io::AsRawHandle};
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
    };

    let file = File::open(path).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to inspect rekey source hard links: {err}"),
        )
    })?;
    // SAFETY: BY_HANDLE_FILE_INFORMATION is a C data structure for which an
    // all-zero value is a valid output buffer before the operating-system call.
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { mem::zeroed() };
    // SAFETY: `file` owns a live Windows handle for the duration of this call,
    // and `information` points to a writable buffer of the required type.
    let result =
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut information) };
    if result == 0 {
        return Err(RnovError::new(
            ErrorKind::Io,
            format!(
                "failed to inspect rekey source hard links: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    Ok(information.nNumberOfLinks > 1)
}

#[cfg(not(any(unix, windows)))]
fn has_multiple_hard_links(_path: &Path, _metadata: &Metadata) -> Result<bool> {
    Ok(false)
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
    let (temporary_path, mut temporary_file) = create_rekey_temporary_file(path)?;
    let result = with_new_single_file_exclusive(&mut temporary_file, |target_file| {
        write_rekey_target(target_file, &temporary_path, &mut source, target_page_key)
    });
    drop(temporary_file);
    let report = match result {
        Ok(report) => report,
        Err(error) => return Err(remove_temporary_after_error(&temporary_path, error)),
    };
    if let Err(error) = ensure_no_live_local_backend(access_lock) {
        return Err(remove_temporary_after_error(&temporary_path, error));
    }
    if let Err(err) = rename(&temporary_path, path) {
        let error = RnovError::new(
            ErrorKind::Io,
            format!("failed to atomically replace database after rekey: {err}"),
        );
        return Err(remove_temporary_after_error(&temporary_path, error));
    }
    sync_rekey_parent(path)?;
    Ok(report)
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
    let page_reports = write_rekey_pages(target_file, source, target_page_key)?;
    target_file.sync_all().map_err(|err| {
        RnovError::new(ErrorKind::Io, format!("failed to sync rekey target: {err}"))
    })?;
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
    Ok(SingleFileRekeyReport {
        path: source.inspection.path().to_path_buf(),
        source_format_version: SINGLE_FILE_FORMAT_VERSION,
        target_format_version: SINGLE_FILE_FORMAT_VERSION,
        key_rotated: true,
        bytes_written: target_inspection.file_len_bytes(),
        page_size: target_inspection.page_size(),
        superblock_generation: target_inspection.superblock_generation(),
        page_record_slots: target_inspection.page_record_slots(),
        pages_rekeyed: page_reports.len() as u64,
        page_reports,
    })
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
    let metadata_matches = source_metadata.page_size == target_metadata.page_size
        && source_metadata.superblock.generation == target_metadata.superblock.generation
        && source_metadata.superblock.catalog_root == target_metadata.superblock.catalog_root
        && source_metadata.superblock.free_map_root == target_metadata.superblock.free_map_root;
    let layout_matches = source.file_len_bytes() == target.file_len_bytes()
        && source.page_record_slots() == target.page_record_slots()
        && source.present_page_records() == target.present_page_records()
        && source.empty_page_slots() == target.empty_page_slots()
        && target.authenticated_page_records() == pages_rekeyed
        && target.checksum_verified_page_records() == pages_rekeyed;
    let counters_reset = target
        .page_records()
        .iter()
        .filter(|record| record.is_present())
        .all(|record| record.encryption_counter() == Some(1));
    if metadata_matches && layout_matches && counters_reset {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        "rekey target validation does not match the source database",
    ))
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
