use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use rnovdb_common::{
    error::{ErrorKind, Result, RnovError},
    ids::PageId,
};

pub use rnovdb_common::config::PageSize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendMode {
    MemoryOnly,
    DiskOnly,
    Hybrid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageCapability(u32);

impl StorageCapability {
    pub const VOLATILE: Self = Self(1 << 0);
    pub const WRITES_TO_DISK: Self = Self(1 << 1);
    pub const SINGLE_FILE: Self = Self(1 << 2);
    pub const ENCRYPTED: Self = Self(1 << 3);

    pub const fn contains(self, capability: Self) -> bool {
        self.0 & capability.0 == capability.0
    }
}

impl std::ops::BitOr for StorageCapability {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

fn read_header_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let slice = bytes.get(offset..offset + N).ok_or_else(|| {
        RnovError::new(
            ErrorKind::Corruption,
            "encoded page ended while reading header",
        )
    })?;
    let mut array = [0_u8; N];
    array.copy_from_slice(slice);
    Ok(array)
}

fn checksum_page(header: &PageHeader, payload: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    hash = fnv1a(hash, &header.page_id().get().to_be_bytes());
    hash = fnv1a(hash, &header.lsn().to_be_bytes());
    hash = fnv1a(hash, &(header.page_size().bytes() as u64).to_be_bytes());
    hash = fnv1a(hash, &[header.format_version()]);
    fnv1a(hash, payload)
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page {
    header: PageHeader,
    payload: Vec<u8>,
}

impl Page {
    pub fn new(id: PageId, payload: Vec<u8>) -> Result<Self> {
        let header = PageHeader::new(id, 0, PageSize::new(payload.len()));
        Self::new_with_header(header, payload)
    }

    pub fn new_with_header(header: PageHeader, payload: Vec<u8>) -> Result<Self> {
        if payload.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "page payload cannot be empty",
            ));
        }

        if payload.len() != header.page_size().bytes() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "page size mismatch: header declares {} bytes, payload has {} bytes",
                    header.page_size().bytes(),
                    payload.len()
                ),
            ));
        }

        Ok(Self { header, payload })
    }

    pub fn id(&self) -> PageId {
        self.header.page_id()
    }

    pub fn header(&self) -> &PageHeader {
        &self.header
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageHeader {
    page_id: PageId,
    lsn: u64,
    page_size: PageSize,
    format_version: u8,
    checksum: u64,
}

impl PageHeader {
    pub fn new(page_id: PageId, lsn: u64, page_size: PageSize) -> Self {
        Self {
            page_id,
            lsn,
            page_size,
            format_version: PageCodec::FORMAT_VERSION,
            checksum: 0,
        }
    }

    pub fn page_id(self) -> PageId {
        self.page_id
    }

    pub fn lsn(self) -> u64 {
        self.lsn
    }

    pub fn page_size(self) -> PageSize {
        self.page_size
    }

    pub fn format_version(self) -> u8 {
        self.format_version
    }

    pub fn checksum(self) -> u64 {
        self.checksum
    }

    fn with_checksum(mut self, checksum: u64) -> Self {
        self.checksum = checksum;
        self
    }
}

pub struct PageCodec;

impl PageCodec {
    pub const FORMAT_VERSION: u8 = 1;
    const MAGIC: [u8; 8] = *b"RNOVPAGE";
    const HEADER_LEN: usize = 8 + 1 + 8 + 8 + 8 + 8;

    pub fn encode(page: &Page) -> Result<Vec<u8>> {
        let mut header = page.header;
        header.format_version = Self::FORMAT_VERSION;
        header.checksum = checksum_page(&header, page.payload());

        let mut encoded = Vec::with_capacity(Self::HEADER_LEN + page.payload().len());
        encoded.extend_from_slice(&Self::MAGIC);
        encoded.push(header.format_version());
        encoded.extend_from_slice(&header.page_id().get().to_be_bytes());
        encoded.extend_from_slice(&header.lsn().to_be_bytes());
        encoded.extend_from_slice(&(header.page_size().bytes() as u64).to_be_bytes());
        encoded.extend_from_slice(&header.checksum().to_be_bytes());
        encoded.extend_from_slice(page.payload());
        Ok(encoded)
    }

    pub fn decode(bytes: &[u8]) -> Result<Page> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "encoded page is shorter than header",
            ));
        }

        if bytes[..8] != Self::MAGIC {
            return Err(RnovError::new(ErrorKind::Corruption, "invalid page magic"));
        }

        let format_version = bytes[8];
        if format_version != Self::FORMAT_VERSION {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                format!("unsupported page format version {format_version}"),
            ));
        }

        let page_id = PageId::new(u64::from_be_bytes(read_header_array::<8>(bytes, 9)?));
        let lsn = u64::from_be_bytes(read_header_array::<8>(bytes, 17)?);
        let page_size_bytes = u64::from_be_bytes(read_header_array::<8>(bytes, 25)?) as usize;
        let checksum = u64::from_be_bytes(read_header_array::<8>(bytes, 33)?);
        let payload = bytes[Self::HEADER_LEN..].to_vec();

        if payload.len() != page_size_bytes {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "encoded page payload length does not match header page size",
            ));
        }

        let header =
            PageHeader::new(page_id, lsn, PageSize::new(page_size_bytes)).with_checksum(checksum);
        let expected = checksum_page(&header, &payload);
        if checksum != expected {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "page checksum mismatch",
            ));
        }

        Page::new_with_header(header, payload)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncStatus {
    flushed_pages: usize,
    durable_pages: usize,
    mode: BackendMode,
}

impl SyncStatus {
    pub const fn new(flushed_pages: usize, durable_pages: usize, mode: BackendMode) -> Self {
        Self {
            flushed_pages,
            durable_pages,
            mode,
        }
    }

    pub const fn flushed_pages(self) -> usize {
        self.flushed_pages
    }

    pub const fn durable_pages(self) -> usize {
        self.durable_pages
    }

    pub const fn mode(self) -> BackendMode {
        self.mode
    }
}

pub trait StorageBackend: Send + Sync {
    fn read_page(&self, id: PageId) -> Result<Option<Page>>;
    fn write_page(&self, page: Page) -> Result<()>;
    fn sync(&self) -> Result<SyncStatus>;
    fn mode(&self) -> BackendMode;
    fn capabilities(&self) -> StorageCapability;
}

#[derive(Clone, Debug)]
pub struct MemoryBackend {
    page_size: PageSize,
    pages: Arc<RwLock<BTreeMap<PageId, MemoryPageEntry>>>,
}

#[derive(Clone, Debug)]
struct MemoryPageEntry {
    page: Page,
    dirty: bool,
    pin_count: usize,
}

impl MemoryBackend {
    pub fn new(page_size: PageSize) -> Self {
        Self {
            page_size,
            pages: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    pub fn page_size(&self) -> PageSize {
        self.page_size
    }

    pub fn dirty_page_count(&self) -> Result<usize> {
        let pages = self.read_pages()?;
        Ok(pages.values().filter(|entry| entry.dirty).count())
    }

    pub fn pinned_page_count(&self) -> Result<usize> {
        let pages = self.read_pages()?;
        Ok(pages.values().filter(|entry| entry.pin_count > 0).count())
    }

    pub fn mark_clean(&self, id: PageId) -> Result<bool> {
        let mut pages = self.write_pages()?;
        let Some(entry) = pages.get_mut(&id) else {
            return Ok(false);
        };
        entry.dirty = false;
        Ok(true)
    }

    pub fn pin_page(&self, id: PageId) -> Result<Option<PinnedPage>> {
        let mut pages = self.write_pages()?;
        let Some(entry) = pages.get_mut(&id) else {
            return Ok(None);
        };
        entry.pin_count += 1;
        Ok(Some(PinnedPage {
            backend_pages: Arc::clone(&self.pages),
            page_id: id,
            page: entry.page.clone(),
        }))
    }

    fn read_pages(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, BTreeMap<PageId, MemoryPageEntry>>> {
        self.pages.read().map_err(|_| {
            RnovError::new(ErrorKind::Internal, "memory backend page map lock poisoned")
        })
    }

    fn write_pages(
        &self,
    ) -> Result<std::sync::RwLockWriteGuard<'_, BTreeMap<PageId, MemoryPageEntry>>> {
        self.pages.write().map_err(|_| {
            RnovError::new(ErrorKind::Internal, "memory backend page map lock poisoned")
        })
    }
}

pub struct PinnedPage {
    backend_pages: Arc<RwLock<BTreeMap<PageId, MemoryPageEntry>>>,
    page_id: PageId,
    page: Page,
}

impl PinnedPage {
    pub fn page(&self) -> &Page {
        &self.page
    }
}

impl Drop for PinnedPage {
    fn drop(&mut self) {
        if let Ok(mut pages) = self.backend_pages.write()
            && let Some(entry) = pages.get_mut(&self.page_id)
        {
            entry.pin_count = entry.pin_count.saturating_sub(1);
        }
    }
}

impl StorageBackend for MemoryBackend {
    fn read_page(&self, id: PageId) -> Result<Option<Page>> {
        let pages = self.read_pages()?;
        Ok(pages.get(&id).map(|entry| entry.page.clone()))
    }

    fn write_page(&self, page: Page) -> Result<()> {
        if page.payload().len() != self.page_size.bytes() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "page size mismatch: expected {} bytes, got {} bytes",
                    self.page_size.bytes(),
                    page.payload().len()
                ),
            ));
        }

        let mut pages = self.write_pages()?;
        pages.insert(
            page.id(),
            MemoryPageEntry {
                page,
                dirty: true,
                pin_count: 0,
            },
        );
        Ok(())
    }

    fn sync(&self) -> Result<SyncStatus> {
        Ok(SyncStatus::new(0, 0, BackendMode::MemoryOnly))
    }

    fn mode(&self) -> BackendMode {
        BackendMode::MemoryOnly
    }

    fn capabilities(&self) -> StorageCapability {
        StorageCapability::VOLATILE
    }
}
