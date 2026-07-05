use std::{
    fs::{File, OpenOptions, remove_file},
    io::{Seek, SeekFrom},
    path::{Path, PathBuf},
};

use rnmdb_common::error::{ErrorKind, Result, RnovError};

use super::{
    Page, PageCrypto, PageCryptoKey, PageNonce, SINGLE_FILE_FORMAT_VERSION,
    SingleFileUpgradeOptions, SingleFileUpgradePageReport, SingleFileUpgradeReport,
    next_page_counter, write_encrypted_page_record, write_single_file_header_with_roots,
};

mod legacy;

use legacy::{
    LegacyPageRecord, LegacySingleFileMetadata, collect_legacy_v1_page_records,
    decrypt_legacy_v1_record, read_legacy_v1_metadata,
};

#[derive(Clone, Copy)]
struct UpgradeKeys {
    source: PageCryptoKey,
    target: PageCryptoKey,
    rotated: bool,
}

pub fn upgrade_single_file(
    source: impl AsRef<Path>,
    target: impl AsRef<Path>,
) -> Result<SingleFileUpgradeReport> {
    upgrade_single_file_with_options(source, target, SingleFileUpgradeOptions::new())
}

pub fn upgrade_single_file_with_key(
    source: impl AsRef<Path>,
    target: impl AsRef<Path>,
    key: PageCryptoKey,
) -> Result<SingleFileUpgradeReport> {
    upgrade_single_file_with_options(
        source,
        target,
        SingleFileUpgradeOptions::new().with_page_key(key),
    )
}

pub fn upgrade_single_file_with_options(
    source: impl AsRef<Path>,
    target: impl AsRef<Path>,
    options: SingleFileUpgradeOptions,
) -> Result<SingleFileUpgradeReport> {
    let source = source.as_ref();
    let target = target.as_ref();
    validate_upgrade_paths(source, target)?;
    let mut source_file = open_upgrade_source(source)?;
    let metadata = read_legacy_v1_metadata(&mut source_file)?;
    let records = collect_legacy_v1_page_records(&mut source_file, metadata)?;
    let keys = resolve_upgrade_keys(records.len(), options)?;
    write_upgrade_target(source, target, metadata, &records, keys)
}

fn validate_upgrade_paths(source: &Path, target: &Path) -> Result<()> {
    if !source.is_file() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "upgrade source must be a file",
        ));
    }
    if comparable_path(source)? == comparable_path(target)? {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "upgrade source and target must be different paths",
        ));
    }
    if target.exists() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "upgrade target already exists",
        ));
    }
    Ok(())
}

fn comparable_path(path: &Path) -> Result<PathBuf> {
    if let Ok(path) = path.canonicalize() {
        return Ok(path);
    }
    if let Some(path) = comparable_path_from_parent(path) {
        return Ok(path);
    }
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(path))
        .map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to resolve database file path: {err}"),
            )
        })
}

fn comparable_path_from_parent(path: &Path) -> Option<PathBuf> {
    let parent = path.parent()?;
    let file_name = path.file_name()?;
    let canonical_parent = parent.canonicalize().ok()?;
    Some(canonical_parent.join(file_name))
}

fn open_upgrade_source(source: &Path) -> Result<File> {
    OpenOptions::new().read(true).open(source).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to open upgrade source: {err}"),
        )
    })
}

fn write_upgrade_target(
    source: &Path,
    target: &Path,
    metadata: LegacySingleFileMetadata,
    records: &[LegacyPageRecord],
    keys: Option<UpgradeKeys>,
) -> Result<SingleFileUpgradeReport> {
    let mut target_file = create_upgrade_target(target)?;
    let result =
        write_upgrade_target_file(&mut target_file, source, target, metadata, records, keys);
    if result.is_err() {
        drop(target_file);
        let _ = remove_file(target);
    }
    result
}

fn create_upgrade_target(target: &Path) -> Result<File> {
    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(target)
        .map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to create upgrade target: {err}"),
            )
        })
}

fn write_upgrade_target_file(
    target_file: &mut File,
    source: &Path,
    target: &Path,
    metadata: LegacySingleFileMetadata,
    records: &[LegacyPageRecord],
    keys: Option<UpgradeKeys>,
) -> Result<SingleFileUpgradeReport> {
    write_single_file_header_with_roots(
        target_file,
        metadata.page_size,
        metadata.superblock.generation,
        metadata.superblock.catalog_root,
        metadata.superblock.free_map_root,
    )?;
    let page_reports = write_upgrade_pages(target_file, metadata, records, keys)?;
    target_file.sync_all().map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to sync upgrade target: {err}"),
        )
    })?;
    let bytes_written = target_file
        .metadata()
        .map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to inspect upgrade target metadata: {err}"),
            )
        })?
        .len();
    Ok(SingleFileUpgradeReport {
        source_path: source.to_path_buf(),
        target_path: target.to_path_buf(),
        source_format_version: metadata.format_version,
        target_format_version: SINGLE_FILE_FORMAT_VERSION,
        bytes_written,
        page_size: metadata.page_size,
        superblock_generation: metadata.superblock.generation,
        page_record_slots: metadata.page_record_slots,
        pages_upgraded: page_reports.len() as u64,
        key_rotated: keys.is_some_and(|keys| keys.rotated),
        page_reports,
    })
}

fn resolve_upgrade_keys(
    present_pages: usize,
    options: SingleFileUpgradeOptions,
) -> Result<Option<UpgradeKeys>> {
    if present_pages == 0 {
        return Ok(None);
    }
    let source = options.source_page_key().ok_or_else(|| {
        RnovError::new(
            ErrorKind::Security,
            "legacy single-file upgrade requires a source page key when pages are present",
        )
    })?;
    let target = options.target_page_key().ok_or_else(|| {
        RnovError::new(
            ErrorKind::Security,
            "legacy single-file upgrade requires a target page key when pages are present",
        )
    })?;
    Ok(Some(UpgradeKeys {
        source,
        target,
        rotated: source != target,
    }))
}

fn write_upgrade_pages(
    target_file: &mut File,
    metadata: LegacySingleFileMetadata,
    records: &[LegacyPageRecord],
    keys: Option<UpgradeKeys>,
) -> Result<Vec<SingleFileUpgradePageReport>> {
    let Some(keys) = keys else {
        return Ok(Vec::new());
    };
    let mut reports = Vec::with_capacity(records.len());
    for record in records {
        let page = decrypt_legacy_v1_record(record, metadata.page_size, keys.source)?;
        let target_counter = upgrade_target_counter(record.counter, keys)?;
        write_v2_page_record(
            target_file,
            record.offset_bytes,
            keys.target,
            target_counter,
            &page,
        )?;
        reports.push(SingleFileUpgradePageReport {
            page_id: record.page_id,
            source_counter: record.counter,
            target_counter,
        });
    }
    Ok(reports)
}

fn upgrade_target_counter(source_counter: u32, keys: UpgradeKeys) -> Result<u32> {
    if keys.rotated {
        Ok(1)
    } else {
        next_page_counter(Some(source_counter))
    }
}

fn write_v2_page_record(
    file: &mut File,
    offset: u64,
    key: PageCryptoKey,
    counter: u32,
    page: &Page,
) -> Result<()> {
    let ciphertext =
        PageCrypto::encrypt(&key, PageNonce::from_page_counter(page.id(), counter), page)?;
    file.seek(SeekFrom::Start(offset)).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to seek upgrade page record: {err}"),
        )
    })?;
    write_encrypted_page_record(file, counter, &ciphertext)
}
