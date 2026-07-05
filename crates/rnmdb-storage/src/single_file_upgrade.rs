use std::{
    fs::{File, OpenOptions, remove_file},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use rnmdb_common::{
    error::{ErrorKind, Result, RnovError},
    ids::PageId,
};
use sha2::{Digest, Sha256};

use super::{
    Page, PageCrypto, PageCryptoKey, PageHeader, PageNonce, PageSize, SINGLE_FILE_FORMAT_VERSION,
    SingleFileUpgradeOptions, SingleFileUpgradePageReport, SingleFileUpgradeReport,
    next_page_counter, page_associated_data, write_encrypted_page_record,
    write_single_file_header_with_roots,
};

const SINGLE_FILE_LEGACY_V1_FORMAT_VERSION: u16 = 1;
const PAGE_LEGACY_V1_FORMAT_VERSION: u8 = 1;
const FILE_MAGIC: &[u8; 8] = b"RNOVDB01";
const PAGE_MAGIC: &[u8; 8] = b"RNOVPAGE";
const PAGE_RECORD_MAGIC: &[u8; 8] = b"RNOVPGR1";
const FILE_HEADER_LEN: usize = 36;
const SUPERBLOCK_LEN: usize = 32;
const PAGE_HEADER_LEN: usize = 41;
const PAGE_RECORD_HEADER_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LegacySingleFileMetadata {
    format_version: u16,
    file_len_bytes: u64,
    page_size: PageSize,
    superblock: LegacySuperblock,
    data_start_bytes: u64,
    page_record_size_bytes: u64,
    page_record_slots: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LegacySuperblock {
    generation: u64,
    catalog_root: u64,
    free_map_root: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LegacyPageRecord {
    page_id: PageId,
    offset_bytes: u64,
    counter: u32,
    ciphertext: Vec<u8>,
}

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
    validate_upgrade_keys(records.len(), options)?;
    write_upgrade_target(source, target, metadata, &records, options)
}

fn validate_upgrade_paths(source: &Path, target: &Path) -> Result<()> {
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

fn open_upgrade_source(source: &Path) -> Result<File> {
    OpenOptions::new().read(true).open(source).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to open upgrade source: {err}"),
        )
    })
}

fn validate_upgrade_keys(present_pages: usize, options: SingleFileUpgradeOptions) -> Result<()> {
    if present_pages == 0 || options.source_page_key().is_some() {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Security,
        "legacy single-file upgrade requires a source page key when pages are present",
    ))
}

fn read_legacy_v1_metadata(file: &mut File) -> Result<LegacySingleFileMetadata> {
    let header = read_legacy_file_header(file)?;
    let format_version = u16::from_be_bytes([header[8], header[9]]);
    ensure_legacy_upgrade_source_version(format_version)?;
    let page_size = PageSize::new(u64::from_be_bytes(read_fixed::<8>(&header, 12)?) as usize);
    let primary_offset = u64::from_be_bytes(read_fixed::<8>(&header, 20)?);
    let secondary_offset = u64::from_be_bytes(read_fixed::<8>(&header, 28)?);
    let superblock = read_best_legacy_v1_superblock(file, primary_offset, secondary_offset)?;
    let file_len_bytes = file
        .metadata()
        .map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to inspect upgrade source metadata: {err}"),
            )
        })?
        .len();
    let data_start_bytes = (FILE_HEADER_LEN + SUPERBLOCK_LEN * 2) as u64;
    let page_record_size_bytes = legacy_v1_page_record_size(page_size);
    let page_record_slots =
        page_record_slots_for_len(file_len_bytes, data_start_bytes, page_record_size_bytes);

    Ok(LegacySingleFileMetadata {
        format_version,
        file_len_bytes,
        page_size,
        superblock,
        data_start_bytes,
        page_record_size_bytes,
        page_record_slots,
    })
}

fn read_legacy_file_header(file: &mut File) -> Result<[u8; FILE_HEADER_LEN]> {
    file.seek(SeekFrom::Start(0)).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to seek upgrade source: {err}"),
        )
    })?;
    let mut header = [0_u8; FILE_HEADER_LEN];
    file.read_exact(&mut header).map_err(|err| {
        RnovError::new(
            ErrorKind::Corruption,
            format!("failed to read upgrade source header: {err}"),
        )
    })?;
    validate_legacy_file_magic(&header)?;
    Ok(header)
}

fn validate_legacy_file_magic(header: &[u8; FILE_HEADER_LEN]) -> Result<()> {
    if header[..8] == FILE_MAGIC[..] {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        "invalid database file magic",
    ))
}

fn ensure_legacy_upgrade_source_version(format_version: u16) -> Result<()> {
    if format_version == SINGLE_FILE_LEGACY_V1_FORMAT_VERSION {
        return Ok(());
    }
    if format_version == SINGLE_FILE_FORMAT_VERSION {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "database file is already at the current format version",
        ));
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        format!("no upgrade path for database format version {format_version}"),
    ))
}

fn read_best_legacy_v1_superblock(
    file: &mut File,
    primary_offset: u64,
    secondary_offset: u64,
) -> Result<LegacySuperblock> {
    let primary = read_legacy_v1_superblock(file, primary_offset);
    let secondary = read_legacy_v1_superblock(file, secondary_offset);
    match (primary, secondary) {
        (Ok(primary), Ok(secondary)) => Ok(newer_legacy_superblock(primary, secondary)),
        (Ok(primary), Err(_)) => Ok(primary),
        (Err(_), Ok(secondary)) => Ok(secondary),
        (Err(primary), Err(secondary)) => Err(RnovError::new(
            ErrorKind::Corruption,
            format!(
                "legacy database superblocks are invalid: primary: {primary}; secondary: {secondary}"
            ),
        )),
    }
}

fn newer_legacy_superblock(
    primary: LegacySuperblock,
    secondary: LegacySuperblock,
) -> LegacySuperblock {
    if primary.generation >= secondary.generation {
        primary
    } else {
        secondary
    }
}

fn read_legacy_v1_superblock(file: &mut File, offset: u64) -> Result<LegacySuperblock> {
    file.seek(SeekFrom::Start(offset)).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to seek legacy database superblock: {err}"),
        )
    })?;
    let mut block = [0_u8; SUPERBLOCK_LEN];
    file.read_exact(&mut block).map_err(|err| {
        RnovError::new(
            ErrorKind::Corruption,
            format!("failed to read legacy database superblock: {err}"),
        )
    })?;
    validate_legacy_v1_superblock_checksum(&block)?;
    Ok(LegacySuperblock {
        generation: u64::from_be_bytes(read_fixed::<8>(&block, 0)?),
        catalog_root: u64::from_be_bytes(read_fixed::<8>(&block, 8)?),
        free_map_root: u64::from_be_bytes(read_fixed::<8>(&block, 16)?),
    })
}

fn validate_legacy_v1_superblock_checksum(block: &[u8; SUPERBLOCK_LEN]) -> Result<()> {
    let checksum = u64::from_be_bytes(read_fixed::<8>(block, 24)?);
    let expected = legacy_v1_checksum_bytes(&block[0..24]);
    if checksum == expected {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        "legacy database superblock checksum mismatch",
    ))
}

fn legacy_v1_page_record_size(page_size: PageSize) -> u64 {
    (PAGE_RECORD_HEADER_LEN + PAGE_HEADER_LEN + page_size.bytes() + 16) as u64
}

fn page_record_slots_for_len(file_len_bytes: u64, data_start_bytes: u64, record_size: u64) -> u64 {
    if file_len_bytes <= data_start_bytes {
        0
    } else {
        (file_len_bytes - data_start_bytes).div_ceil(record_size)
    }
}

fn collect_legacy_v1_page_records(
    file: &mut File,
    metadata: LegacySingleFileMetadata,
) -> Result<Vec<LegacyPageRecord>> {
    let mut records = Vec::new();
    for slot in 0..metadata.page_record_slots {
        if let Some(record) = read_legacy_v1_page_record(file, metadata, slot)? {
            records.push(record);
        }
    }
    Ok(records)
}

fn read_legacy_v1_page_record(
    file: &mut File,
    metadata: LegacySingleFileMetadata,
    slot: u64,
) -> Result<Option<LegacyPageRecord>> {
    let offset = metadata.data_start_bytes + slot * metadata.page_record_size_bytes;
    ensure_legacy_record_header_in_bounds(offset, metadata.file_len_bytes)?;
    file.seek(SeekFrom::Start(offset)).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to seek legacy page record: {err}"),
        )
    })?;
    let mut header = [0_u8; PAGE_RECORD_HEADER_LEN];
    file.read_exact(&mut header).map_err(|err| {
        RnovError::new(
            ErrorKind::Corruption,
            format!("failed to read legacy page record header: {err}"),
        )
    })?;
    if header[..8].iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    validate_legacy_page_record_magic(&header)?;
    let ciphertext = read_legacy_page_ciphertext(file, metadata, offset, &header)?;
    Ok(Some(LegacyPageRecord {
        page_id: PageId::new(slot + 1),
        offset_bytes: offset,
        counter: u32::from_be_bytes(read_fixed::<4>(&header, 8)?),
        ciphertext,
    }))
}

fn ensure_legacy_record_header_in_bounds(offset: u64, file_len_bytes: u64) -> Result<()> {
    let Some(header_end) = offset.checked_add(PAGE_RECORD_HEADER_LEN as u64) else {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "legacy page record offset overflow",
        ));
    };
    if header_end <= file_len_bytes {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        "truncated legacy page record header",
    ))
}

fn validate_legacy_page_record_magic(header: &[u8; PAGE_RECORD_HEADER_LEN]) -> Result<()> {
    if header[..8] == PAGE_RECORD_MAGIC[..] {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        "invalid legacy page record magic",
    ))
}

fn read_legacy_page_ciphertext(
    file: &mut File,
    metadata: LegacySingleFileMetadata,
    offset: u64,
    header: &[u8; PAGE_RECORD_HEADER_LEN],
) -> Result<Vec<u8>> {
    let ciphertext_len = u32::from_be_bytes(read_fixed::<4>(header, 12)?) as u64;
    validate_legacy_ciphertext_len(metadata, offset, ciphertext_len)?;
    let mut ciphertext = vec![0_u8; ciphertext_len as usize];
    file.read_exact(&mut ciphertext).map_err(|err| {
        RnovError::new(
            ErrorKind::Corruption,
            format!("failed to read legacy page ciphertext: {err}"),
        )
    })?;
    Ok(ciphertext)
}

fn validate_legacy_ciphertext_len(
    metadata: LegacySingleFileMetadata,
    offset: u64,
    ciphertext_len: u64,
) -> Result<()> {
    if ciphertext_len > legacy_v1_max_page_ciphertext_len(metadata.page_size) as u64 {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "legacy page record length is too large",
        ));
    }
    let payload_end = offset
        .checked_add(PAGE_RECORD_HEADER_LEN as u64)
        .and_then(|start| start.checked_add(ciphertext_len))
        .ok_or_else(|| RnovError::new(ErrorKind::Corruption, "legacy page length overflow"))?;
    if payload_end <= metadata.file_len_bytes {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        "truncated legacy page record payload",
    ))
}

fn legacy_v1_max_page_ciphertext_len(page_size: PageSize) -> usize {
    PAGE_HEADER_LEN + page_size.bytes() + 16
}

fn write_upgrade_target(
    source: &Path,
    target: &Path,
    metadata: LegacySingleFileMetadata,
    records: &[LegacyPageRecord],
    options: SingleFileUpgradeOptions,
) -> Result<SingleFileUpgradeReport> {
    let mut target_file = create_upgrade_target(target)?;
    let result =
        write_upgrade_target_file(&mut target_file, source, target, metadata, records, options);
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
    options: SingleFileUpgradeOptions,
) -> Result<SingleFileUpgradeReport> {
    write_single_file_header_with_roots(
        target_file,
        metadata.page_size,
        metadata.superblock.generation,
        metadata.superblock.catalog_root,
        metadata.superblock.free_map_root,
    )?;
    let keys = resolve_upgrade_keys(records.len(), options)?;
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

fn decrypt_legacy_v1_record(
    record: &LegacyPageRecord,
    page_size: PageSize,
    key: PageCryptoKey,
) -> Result<Page> {
    let cipher = ChaCha20Poly1305::new(&key.to_key());
    let encoded = cipher
        .decrypt(
            &PageNonce::from_page_counter(record.page_id, record.counter).to_nonce(),
            Payload {
                msg: &record.ciphertext,
                aad: &page_associated_data(record.page_id),
            },
        )
        .map_err(|_| {
            RnovError::new(
                ErrorKind::Security,
                "legacy page authentication failed during upgrade",
            )
        })?;
    decode_legacy_v1_page(record.page_id, page_size, &encoded)
}

fn decode_legacy_v1_page(
    expected_page_id: PageId,
    expected_page_size: PageSize,
    bytes: &[u8],
) -> Result<Page> {
    if bytes.len() < PAGE_HEADER_LEN {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "legacy encoded page is shorter than header",
        ));
    }
    validate_legacy_page_header_prefix(bytes)?;
    let page_id = PageId::new(u64::from_be_bytes(read_fixed::<8>(bytes, 9)?));
    let lsn = u64::from_be_bytes(read_fixed::<8>(bytes, 17)?);
    let page_size = PageSize::new(u64::from_be_bytes(read_fixed::<8>(bytes, 25)?) as usize);
    let checksum = u64::from_be_bytes(read_fixed::<8>(bytes, 33)?);
    let payload = bytes[PAGE_HEADER_LEN..].to_vec();
    validate_legacy_page_metadata(
        expected_page_id,
        expected_page_size,
        page_id,
        page_size,
        &payload,
    )?;
    validate_legacy_v1_page_checksum(page_id, lsn, page_size, checksum, &payload)?;
    Page::new_with_header(PageHeader::new(page_id, lsn, page_size), payload)
}

fn validate_legacy_page_header_prefix(bytes: &[u8]) -> Result<()> {
    if bytes[..8] != PAGE_MAGIC[..] {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "invalid legacy page magic",
        ));
    }
    if bytes[8] == PAGE_LEGACY_V1_FORMAT_VERSION {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        format!("unsupported legacy page format version {}", bytes[8]),
    ))
}

fn validate_legacy_page_metadata(
    expected_page_id: PageId,
    expected_page_size: PageSize,
    page_id: PageId,
    page_size: PageSize,
    payload: &[u8],
) -> Result<()> {
    if page_id != expected_page_id {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "legacy page id does not match record slot",
        ));
    }
    if page_size != expected_page_size || payload.len() != page_size.bytes() {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "legacy page payload length does not match header",
        ));
    }
    Ok(())
}

fn validate_legacy_v1_page_checksum(
    page_id: PageId,
    lsn: u64,
    page_size: PageSize,
    checksum: u64,
    payload: &[u8],
) -> Result<()> {
    if checksum == legacy_v1_checksum_page(page_id, lsn, page_size, payload) {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        "legacy page checksum mismatch",
    ))
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

fn legacy_v1_checksum_page(page_id: PageId, lsn: u64, page_size: PageSize, payload: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(page_id.get().to_be_bytes());
    hasher.update(lsn.to_be_bytes());
    hasher.update((page_size.bytes() as u64).to_be_bytes());
    hasher.update([PAGE_LEGACY_V1_FORMAT_VERSION]);
    hasher.update(payload);
    checksum_from_sha256(hasher)
}

fn legacy_v1_checksum_bytes(bytes: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    checksum_from_sha256(hasher)
}

fn checksum_from_sha256(hasher: Sha256) -> u64 {
    let digest = hasher.finalize();
    let mut checksum = [0_u8; 8];
    checksum.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(checksum)
}

fn read_fixed<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let slice = bytes
        .get(offset..offset + N)
        .ok_or_else(|| RnovError::new(ErrorKind::Corruption, "encoded data ended unexpectedly"))?;
    let mut array = [0_u8; N];
    array.copy_from_slice(slice);
    Ok(array)
}
