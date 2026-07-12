use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
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

use super::super::{
    Page, PageCryptoKey, PageHeader, PageNonce, PageSize, SINGLE_FILE_FORMAT_VERSION,
    page_associated_data,
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
const LEGACY_PAGE_SIZE_MIN_BYTES: u64 = 512;
const LEGACY_PAGE_SIZE_MAX_BYTES: u64 = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LegacySingleFileMetadata {
    pub(super) format_version: u16,
    pub(super) file_len_bytes: u64,
    pub(super) page_size: PageSize,
    pub(super) superblock: LegacySuperblock,
    pub(super) data_start_bytes: u64,
    pub(super) page_record_size_bytes: u64,
    pub(super) page_record_slots: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LegacySuperblock {
    pub(super) generation: u64,
    pub(super) catalog_root: u64,
    pub(super) free_map_root: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LegacyPageRecord {
    pub(super) page_id: PageId,
    pub(super) offset_bytes: u64,
    pub(super) counter: u32,
    ciphertext: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LegacyPageHeader {
    page_id: PageId,
    lsn: u64,
    page_size: PageSize,
    checksum: u64,
}

pub(super) fn read_legacy_v1_metadata(file: &mut File) -> Result<LegacySingleFileMetadata> {
    let header = read_legacy_file_header(file)?;
    let format_version = u16::from_be_bytes([header[8], header[9]]);
    ensure_legacy_upgrade_source_version(format_version)?;
    let page_size = read_legacy_page_size(&header, 12, "database header")?;
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

pub(super) fn collect_legacy_v1_page_records(
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

pub(super) fn decrypt_legacy_v1_record(
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

fn read_legacy_page_size(bytes: &[u8], offset: usize, context: &str) -> Result<PageSize> {
    let page_size_bytes = u64::from_be_bytes(read_fixed::<8>(bytes, offset)?);
    validate_legacy_page_size_bytes(page_size_bytes, context)?;
    Ok(PageSize::new(page_size_bytes as usize))
}

fn validate_legacy_page_size_bytes(page_size_bytes: u64, context: &str) -> Result<()> {
    if is_supported_legacy_page_size(page_size_bytes) {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        format!("invalid or unsupported page size in legacy {context}: {page_size_bytes}"),
    ))
}

fn is_supported_legacy_page_size(page_size_bytes: u64) -> bool {
    (LEGACY_PAGE_SIZE_MIN_BYTES..=LEGACY_PAGE_SIZE_MAX_BYTES).contains(&page_size_bytes)
        && page_size_bytes.is_power_of_two()
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

fn decode_legacy_v1_page(
    expected_page_id: PageId,
    expected_page_size: PageSize,
    bytes: &[u8],
) -> Result<Page> {
    let header = read_legacy_page_header(bytes)?;
    let payload = legacy_page_payload(bytes)?;
    validate_legacy_page_metadata(expected_page_id, expected_page_size, header, &payload)?;
    validate_legacy_v1_page_checksum(header, &payload)?;
    Page::new_with_header(
        PageHeader::new(header.page_id, header.lsn, header.page_size),
        payload,
    )
}

fn read_legacy_page_header(bytes: &[u8]) -> Result<LegacyPageHeader> {
    ensure_legacy_page_header_len(bytes)?;
    validate_legacy_page_header_prefix(bytes)?;
    Ok(LegacyPageHeader {
        page_id: PageId::new(u64::from_be_bytes(read_fixed::<8>(bytes, 9)?)),
        lsn: u64::from_be_bytes(read_fixed::<8>(bytes, 17)?),
        page_size: read_legacy_page_size(bytes, 25, "page header")?,
        checksum: u64::from_be_bytes(read_fixed::<8>(bytes, 33)?),
    })
}

fn ensure_legacy_page_header_len(bytes: &[u8]) -> Result<()> {
    if bytes.len() >= PAGE_HEADER_LEN {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        "legacy encoded page is shorter than header",
    ))
}

fn legacy_page_payload(bytes: &[u8]) -> Result<Vec<u8>> {
    let payload = bytes
        .get(PAGE_HEADER_LEN..)
        .ok_or_else(|| RnovError::new(ErrorKind::Corruption, "legacy page payload missing"))?;
    Ok(payload.to_vec())
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
    header: LegacyPageHeader,
    payload: &[u8],
) -> Result<()> {
    if header.page_id != expected_page_id {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "legacy page id does not match record slot",
        ));
    }
    if header.page_size != expected_page_size || payload.len() != header.page_size.bytes() {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "legacy page payload length does not match header",
        ));
    }
    Ok(())
}

fn validate_legacy_v1_page_checksum(header: LegacyPageHeader, payload: &[u8]) -> Result<()> {
    if header.checksum == legacy_v1_checksum_page(header, payload) {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        "legacy page checksum mismatch",
    ))
}

fn legacy_v1_checksum_page(header: LegacyPageHeader, payload: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(header.page_id.get().to_be_bytes());
    hasher.update(header.lsn.to_be_bytes());
    hasher.update((header.page_size.bytes() as u64).to_be_bytes());
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
