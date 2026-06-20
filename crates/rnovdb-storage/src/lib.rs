use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
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

    pub fn names(self) -> Vec<&'static str> {
        let mut names = Vec::new();
        for (capability, name) in [
            (Self::VOLATILE, "volatile"),
            (Self::WRITES_TO_DISK, "writes_to_disk"),
            (Self::SINGLE_FILE, "single_file"),
            (Self::ENCRYPTED, "encrypted"),
        ] {
            if self.contains(capability) {
                names.push(name);
            }
        }
        names
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

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PageCryptoKey([u8; 32]);

impl PageCryptoKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn to_key(self) -> Key {
        Key::try_from(&self.0[..]).expect("PageCryptoKey is always 32 bytes")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageNonce([u8; 12]);

impl PageNonce {
    pub fn from_page_counter(page_id: PageId, counter: u32) -> Self {
        let mut nonce = [0_u8; 12];
        nonce[0..8].copy_from_slice(&page_id.get().to_be_bytes());
        nonce[8..12].copy_from_slice(&counter.to_be_bytes());
        Self(nonce)
    }

    fn to_nonce(self) -> Nonce {
        Nonce::try_from(&self.0[..]).expect("PageNonce is always 12 bytes")
    }
}

pub struct PageCrypto;

impl PageCrypto {
    pub fn encrypt(key: &PageCryptoKey, nonce: PageNonce, page: &Page) -> Result<Vec<u8>> {
        let key = key.to_key();
        let nonce = nonce.to_nonce();
        let cipher = ChaCha20Poly1305::new(&key);
        cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: page.payload(),
                    aad: &page_associated_data(page.id()),
                },
            )
            .map_err(|_| RnovError::new(ErrorKind::Security, "page encryption failed"))
    }

    pub fn decrypt(
        key: &PageCryptoKey,
        nonce: PageNonce,
        page_id: PageId,
        ciphertext: &[u8],
    ) -> Result<Page> {
        let key = key.to_key();
        let nonce = nonce.to_nonce();
        let cipher = ChaCha20Poly1305::new(&key);
        let payload = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &page_associated_data(page_id),
                },
            )
            .map_err(|_| {
                RnovError::new(
                    ErrorKind::Security,
                    "page authentication failed during decryption",
                )
            })?;
        Page::new(page_id, payload)
    }
}

fn page_associated_data(page_id: PageId) -> [u8; 8] {
    page_id.get().to_be_bytes()
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HybridState {
    MemoryOnly,
    DiskOnly,
    HybridSyncing,
    HybridReady,
    Switching,
    Faulted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HybridSyncStatus {
    state: HybridState,
    dirty_pages: usize,
    mirrored_pages: usize,
    estimated_flush_bytes: usize,
}

impl HybridSyncStatus {
    pub const fn new(
        state: HybridState,
        dirty_pages: usize,
        mirrored_pages: usize,
        estimated_flush_bytes: usize,
    ) -> Self {
        Self {
            state,
            dirty_pages,
            mirrored_pages,
            estimated_flush_bytes,
        }
    }

    pub const fn state(self) -> HybridState {
        self.state
    }

    pub const fn dirty_pages(self) -> usize {
        self.dirty_pages
    }

    pub const fn mirrored_pages(self) -> usize {
        self.mirrored_pages
    }

    pub const fn estimated_flush_bytes(self) -> usize {
        self.estimated_flush_bytes
    }

    pub const fn can_switch_to_disk_in_millis(self) -> bool {
        matches!(self.state, HybridState::HybridReady) && self.dirty_pages == 0
    }
}

#[derive(Clone)]
pub struct HybridBackend {
    memory: MemoryBackend,
    disk: Arc<dyn StorageBackend>,
    dirty_pages: Arc<RwLock<BTreeSet<PageId>>>,
    mirrored_pages: Arc<RwLock<BTreeSet<PageId>>>,
}

impl HybridBackend {
    pub fn new(memory: MemoryBackend, disk: Arc<dyn StorageBackend>) -> Result<Self> {
        if !disk
            .capabilities()
            .contains(StorageCapability::WRITES_TO_DISK)
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "hybrid backend disk mirror target must write to disk",
            ));
        }

        Ok(Self {
            memory,
            disk,
            dirty_pages: Arc::new(RwLock::new(BTreeSet::new())),
            mirrored_pages: Arc::new(RwLock::new(BTreeSet::new())),
        })
    }

    pub fn sync_status(&self) -> Result<HybridSyncStatus> {
        let dirty_pages = self.read_dirty_pages()?.len();
        let mirrored_pages = self.read_mirrored_pages()?.len();
        let state = if dirty_pages == 0 {
            HybridState::HybridReady
        } else {
            HybridState::HybridSyncing
        };
        Ok(HybridSyncStatus::new(
            state,
            dirty_pages,
            mirrored_pages,
            dirty_pages.saturating_mul(self.memory.page_size().bytes()),
        ))
    }

    fn read_dirty_pages(&self) -> Result<std::sync::RwLockReadGuard<'_, BTreeSet<PageId>>> {
        self.dirty_pages.read().map_err(|_| {
            RnovError::new(
                ErrorKind::Internal,
                "hybrid backend dirty page set lock poisoned",
            )
        })
    }

    fn write_dirty_pages(&self) -> Result<std::sync::RwLockWriteGuard<'_, BTreeSet<PageId>>> {
        self.dirty_pages.write().map_err(|_| {
            RnovError::new(
                ErrorKind::Internal,
                "hybrid backend dirty page set lock poisoned",
            )
        })
    }

    fn read_mirrored_pages(&self) -> Result<std::sync::RwLockReadGuard<'_, BTreeSet<PageId>>> {
        self.mirrored_pages.read().map_err(|_| {
            RnovError::new(
                ErrorKind::Internal,
                "hybrid backend mirrored page set lock poisoned",
            )
        })
    }

    fn write_mirrored_pages(&self) -> Result<std::sync::RwLockWriteGuard<'_, BTreeSet<PageId>>> {
        self.mirrored_pages.write().map_err(|_| {
            RnovError::new(
                ErrorKind::Internal,
                "hybrid backend mirrored page set lock poisoned",
            )
        })
    }
}

impl StorageBackend for HybridBackend {
    fn read_page(&self, id: PageId) -> Result<Option<Page>> {
        if let Some(page) = self.memory.read_page(id)? {
            return Ok(Some(page));
        }
        self.disk.read_page(id)
    }

    fn write_page(&self, page: Page) -> Result<()> {
        let page_id = page.id();
        self.memory.write_page(page)?;
        self.write_dirty_pages()?.insert(page_id);
        Ok(())
    }

    fn sync(&self) -> Result<SyncStatus> {
        let pending = self.read_dirty_pages()?.iter().copied().collect::<Vec<_>>();

        for page_id in &pending {
            if let Some(page) = self.memory.read_page(*page_id)? {
                self.disk.write_page(page)?;
            }
        }
        self.disk.sync()?;

        {
            let mut dirty_pages = self.write_dirty_pages()?;
            let mut mirrored_pages = self.write_mirrored_pages()?;
            for page_id in &pending {
                dirty_pages.remove(page_id);
                mirrored_pages.insert(*page_id);
                self.memory.mark_clean(*page_id)?;
            }
        }

        Ok(SyncStatus::new(
            pending.len(),
            self.read_mirrored_pages()?.len(),
            BackendMode::Hybrid,
        ))
    }

    fn mode(&self) -> BackendMode {
        BackendMode::Hybrid
    }

    fn capabilities(&self) -> StorageCapability {
        StorageCapability::VOLATILE | self.disk.capabilities()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SingleFileOptions {
    page_size: PageSize,
    page_key: Option<PageCryptoKey>,
}

impl SingleFileOptions {
    pub fn new(page_size: PageSize) -> Self {
        Self {
            page_size,
            page_key: None,
        }
    }

    pub fn page_size(self) -> PageSize {
        self.page_size
    }

    pub fn page_key(self) -> Option<PageCryptoKey> {
        self.page_key
    }

    pub fn with_page_key(mut self, key: PageCryptoKey) -> Self {
        self.page_key = Some(key);
        self
    }
}

impl Default for SingleFileOptions {
    fn default() -> Self {
        Self::new(PageSize::default())
    }
}

pub struct SingleFileBackend {
    path: PathBuf,
    file: File,
    page_size: PageSize,
    superblock_generation: u64,
    page_key: Option<PageCryptoKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleFileInspection {
    path: PathBuf,
    file_len_bytes: u64,
    data_start_bytes: u64,
    page_size: PageSize,
    page_record_size_bytes: u64,
    superblock_generation: u64,
    page_record_slots: u64,
    present_page_records: u64,
    empty_page_slots: u64,
    capabilities: StorageCapability,
}

impl SingleFileInspection {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn file_len_bytes(&self) -> u64 {
        self.file_len_bytes
    }

    pub fn data_start_bytes(&self) -> u64 {
        self.data_start_bytes
    }

    pub fn page_size(&self) -> PageSize {
        self.page_size
    }

    pub fn page_record_size_bytes(&self) -> u64 {
        self.page_record_size_bytes
    }

    pub fn superblock_generation(&self) -> u64 {
        self.superblock_generation
    }

    pub fn page_record_slots(&self) -> u64 {
        self.page_record_slots
    }

    pub fn present_page_records(&self) -> u64 {
        self.present_page_records
    }

    pub fn empty_page_slots(&self) -> u64 {
        self.empty_page_slots
    }

    pub fn free_space_bytes(&self) -> u64 {
        self.empty_page_slots
            .saturating_mul(self.page_record_size_bytes)
    }

    pub fn capabilities(&self) -> StorageCapability {
        self.capabilities
    }

    pub fn mode(&self) -> BackendMode {
        BackendMode::DiskOnly
    }

    pub fn encrypted_pages(&self) -> bool {
        self.capabilities.contains(StorageCapability::ENCRYPTED)
    }
}

impl std::fmt::Debug for SingleFileBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleFileBackend")
            .field("path", &self.path)
            .field("page_size", &self.page_size)
            .field("superblock_generation", &self.superblock_generation)
            .field("page_key_present", &self.page_key.is_some())
            .finish()
    }
}

impl SingleFileBackend {
    const MAGIC: [u8; 8] = *b"RNOVDB01";
    const FORMAT_VERSION: u16 = 1;
    const HEADER_LEN: usize = 8 + 2 + 2 + 8 + 8 + 8;
    const SUPERBLOCK_LEN: usize = 8 + 8 + 8 + 8;
    const PAGE_RECORD_MAGIC: [u8; 8] = *b"RNOVPGR1";
    const PAGE_RECORD_HEADER_LEN: usize = 8 + 4 + 4;

    pub fn create(path: impl AsRef<Path>, options: SingleFileOptions) -> Result<Self> {
        let path = path.as_ref();
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .map_err(|err| {
                RnovError::new(
                    ErrorKind::Io,
                    format!("failed to create database file: {err}"),
                )
            })?;

        let superblock_generation = 1;
        write_single_file_header(&mut file, options.page_size(), superblock_generation)?;
        file.sync_all().map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to sync database file: {err}"),
            )
        })?;

        Ok(Self {
            path: path.to_path_buf(),
            file,
            page_size: options.page_size(),
            superblock_generation,
            page_key: options.page_key(),
        })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_internal(path.as_ref(), None)
    }

    pub fn open_with_key(path: impl AsRef<Path>, key: PageCryptoKey) -> Result<Self> {
        Self::open_internal(path.as_ref(), Some(key))
    }

    pub fn inspect(path: impl AsRef<Path>) -> Result<SingleFileInspection> {
        inspect_single_file(path)
    }

    fn open_internal(path: &Path, page_key: Option<PageCryptoKey>) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|err| {
                RnovError::new(
                    ErrorKind::Io,
                    format!("failed to open database file: {err}"),
                )
            })?;
        let (page_size, superblock_generation) = read_single_file_header(&mut file)?;

        Ok(Self {
            path: path.to_path_buf(),
            file,
            page_size,
            superblock_generation,
            page_key,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn page_size(&self) -> PageSize {
        self.page_size
    }

    pub fn superblock_generation(&self) -> u64 {
        self.superblock_generation
    }

    fn data_start(&self) -> u64 {
        (Self::HEADER_LEN + Self::SUPERBLOCK_LEN * 2) as u64
    }

    fn page_record_size(&self) -> u64 {
        (Self::PAGE_RECORD_HEADER_LEN + self.page_size.bytes() + 16) as u64
    }

    fn page_offset(&self, page_id: PageId) -> Result<u64> {
        if page_id.get() == 0 {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "page id must be greater than zero",
            ));
        }
        Ok(self.data_start() + (page_id.get() - 1) * self.page_record_size())
    }

    fn page_key(&self) -> Result<PageCryptoKey> {
        self.page_key.ok_or_else(|| {
            RnovError::new(
                ErrorKind::Security,
                "single-file page encryption key is required",
            )
        })
    }
}

impl StorageBackend for SingleFileBackend {
    fn read_page(&self, id: PageId) -> Result<Option<Page>> {
        let key = self.page_key()?;
        let mut file = self.file.try_clone().map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to clone database file handle: {err}"),
            )
        })?;
        let offset = self.page_offset(id)?;
        file.seek(SeekFrom::Start(offset)).map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to seek encrypted page record: {err}"),
            )
        })?;

        let mut header = [0_u8; Self::PAGE_RECORD_HEADER_LEN];
        let read = file.read(&mut header).map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to read encrypted page record header: {err}"),
            )
        })?;
        if read == 0 {
            return Ok(None);
        }
        if read != header.len() {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "truncated encrypted page record header",
            ));
        }
        if header[..8].iter().all(|byte| *byte == 0) {
            return Ok(None);
        }
        if header[..8] != Self::PAGE_RECORD_MAGIC {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "invalid encrypted page record magic",
            ));
        }

        let counter = u32::from_be_bytes(read_fixed::<4>(&header, 8)?);
        let ciphertext_len = u32::from_be_bytes(read_fixed::<4>(&header, 12)?) as usize;
        if ciphertext_len > self.page_size.bytes() + 16 {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "encrypted page record length is too large",
            ));
        }

        let mut ciphertext = vec![0_u8; ciphertext_len];
        file.read_exact(&mut ciphertext).map_err(|err| {
            RnovError::new(
                ErrorKind::Corruption,
                format!("failed to read encrypted page payload: {err}"),
            )
        })?;

        PageCrypto::decrypt(
            &key,
            PageNonce::from_page_counter(id, counter),
            id,
            &ciphertext,
        )
        .map(Some)
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

        let key = self.page_key()?;
        let mut file = self.file.try_clone().map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to clone database file handle: {err}"),
            )
        })?;
        let offset = self.page_offset(page.id())?;
        let counter = read_existing_page_counter(&mut file, offset)?.unwrap_or(0) + 1;
        let nonce = PageNonce::from_page_counter(page.id(), counter);
        let ciphertext = PageCrypto::encrypt(&key, nonce, &page)?;

        file.seek(SeekFrom::Start(offset)).map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to seek encrypted page record: {err}"),
            )
        })?;
        file.write_all(&Self::PAGE_RECORD_MAGIC).map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to write encrypted page record magic: {err}"),
            )
        })?;
        file.write_all(&counter.to_be_bytes()).map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to write encrypted page counter: {err}"),
            )
        })?;
        file.write_all(&(ciphertext.len() as u32).to_be_bytes())
            .map_err(|err| {
                RnovError::new(
                    ErrorKind::Io,
                    format!("failed to write encrypted page length: {err}"),
                )
            })?;
        file.write_all(&ciphertext).map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to write encrypted page payload: {err}"),
            )
        })?;
        Ok(())
    }

    fn sync(&self) -> Result<SyncStatus> {
        self.file.sync_all().map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to sync database file: {err}"),
            )
        })?;
        Ok(SyncStatus::new(0, 0, BackendMode::DiskOnly))
    }

    fn mode(&self) -> BackendMode {
        BackendMode::DiskOnly
    }

    fn capabilities(&self) -> StorageCapability {
        StorageCapability::WRITES_TO_DISK
            | StorageCapability::SINGLE_FILE
            | StorageCapability::ENCRYPTED
    }
}

pub fn inspect_single_file(path: impl AsRef<Path>) -> Result<SingleFileInspection> {
    let path = path.as_ref();
    let mut file = OpenOptions::new().read(true).open(path).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to inspect database file: {err}"),
        )
    })?;
    let file_len_bytes = file
        .metadata()
        .map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to inspect database file metadata: {err}"),
            )
        })?
        .len();
    let (page_size, superblock_generation) = read_single_file_header(&mut file)?;
    let data_start_bytes =
        (SingleFileBackend::HEADER_LEN + SingleFileBackend::SUPERBLOCK_LEN * 2) as u64;
    let page_record_size_bytes =
        (SingleFileBackend::PAGE_RECORD_HEADER_LEN + page_size.bytes() + 16) as u64;
    let page_record_slots = if file_len_bytes <= data_start_bytes {
        0
    } else {
        (file_len_bytes - data_start_bytes).div_ceil(page_record_size_bytes)
    };
    let mut present_page_records = 0_u64;
    let mut empty_page_slots = 0_u64;

    for slot in 0..page_record_slots {
        let offset = data_start_bytes + slot * page_record_size_bytes;
        let Some(header_end) = offset.checked_add(SingleFileBackend::PAGE_RECORD_HEADER_LEN as u64)
        else {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "encrypted page record offset overflow",
            ));
        };
        if header_end > file_len_bytes {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "truncated encrypted page record header",
            ));
        }

        file.seek(SeekFrom::Start(offset)).map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to seek encrypted page record during inspection: {err}"),
            )
        })?;
        let mut header = [0_u8; SingleFileBackend::PAGE_RECORD_HEADER_LEN];
        file.read_exact(&mut header).map_err(|err| {
            RnovError::new(
                ErrorKind::Corruption,
                format!("failed to read encrypted page record header: {err}"),
            )
        })?;

        if header[..8].iter().all(|byte| *byte == 0) {
            empty_page_slots += 1;
            continue;
        }
        if header[..8] != SingleFileBackend::PAGE_RECORD_MAGIC {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "invalid encrypted page record magic",
            ));
        }

        let ciphertext_len = u32::from_be_bytes(read_fixed::<4>(&header, 12)?) as u64;
        if ciphertext_len > page_size.bytes() as u64 + 16 {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "encrypted page record length is too large",
            ));
        }
        let Some(payload_end) = header_end.checked_add(ciphertext_len) else {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "encrypted page record length overflow",
            ));
        };
        if payload_end > file_len_bytes {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "truncated encrypted page record payload",
            ));
        }
        present_page_records += 1;
    }

    Ok(SingleFileInspection {
        path: path.to_path_buf(),
        file_len_bytes,
        data_start_bytes,
        page_size,
        page_record_size_bytes,
        superblock_generation,
        page_record_slots,
        present_page_records,
        empty_page_slots,
        capabilities: StorageCapability::WRITES_TO_DISK
            | StorageCapability::SINGLE_FILE
            | StorageCapability::ENCRYPTED,
    })
}

fn write_single_file_header(
    file: &mut File,
    page_size: PageSize,
    superblock_generation: u64,
) -> Result<()> {
    file.seek(SeekFrom::Start(0)).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to seek database file: {err}"),
        )
    })?;

    let mut header = Vec::with_capacity(SingleFileBackend::HEADER_LEN);
    header.extend_from_slice(&SingleFileBackend::MAGIC);
    header.extend_from_slice(&SingleFileBackend::FORMAT_VERSION.to_be_bytes());
    header.extend_from_slice(&0_u16.to_be_bytes());
    header.extend_from_slice(&(page_size.bytes() as u64).to_be_bytes());
    header.extend_from_slice(&(SingleFileBackend::HEADER_LEN as u64).to_be_bytes());
    header.extend_from_slice(
        &((SingleFileBackend::HEADER_LEN + SingleFileBackend::SUPERBLOCK_LEN) as u64).to_be_bytes(),
    );

    let primary = encode_superblock(superblock_generation, 0, 0);
    let secondary = encode_superblock(0, 0, 0);

    file.write_all(&header).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to write database file header: {err}"),
        )
    })?;
    file.write_all(&primary).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to write primary superblock: {err}"),
        )
    })?;
    file.write_all(&secondary).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to write secondary superblock: {err}"),
        )
    })?;
    Ok(())
}

fn read_single_file_header(file: &mut File) -> Result<(PageSize, u64)> {
    file.seek(SeekFrom::Start(0)).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to seek database file: {err}"),
        )
    })?;

    let mut header = [0_u8; SingleFileBackend::HEADER_LEN];
    file.read_exact(&mut header).map_err(|err| {
        RnovError::new(
            ErrorKind::Corruption,
            format!("failed to read database file header: {err}"),
        )
    })?;

    if header[..8] != SingleFileBackend::MAGIC {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "invalid database file magic",
        ));
    }

    let format_version = u16::from_be_bytes([header[8], header[9]]);
    if format_version != SingleFileBackend::FORMAT_VERSION {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            format!("unsupported database format version {format_version}"),
        ));
    }

    let page_size = PageSize::new(u64::from_be_bytes(read_fixed::<8>(&header, 12)?) as usize);
    let primary_offset = u64::from_be_bytes(read_fixed::<8>(&header, 20)?);
    let secondary_offset = u64::from_be_bytes(read_fixed::<8>(&header, 28)?);
    let primary = read_superblock(file, primary_offset)?;
    let secondary = read_superblock(file, secondary_offset)?;
    let generation = primary.0.max(secondary.0);

    Ok((page_size, generation))
}

fn encode_superblock(generation: u64, catalog_root: u64, free_map_root: u64) -> [u8; 32] {
    let mut block = [0_u8; 32];
    block[0..8].copy_from_slice(&generation.to_be_bytes());
    block[8..16].copy_from_slice(&catalog_root.to_be_bytes());
    block[16..24].copy_from_slice(&free_map_root.to_be_bytes());
    let checksum = fnv1a(FNV_OFFSET, &block[0..24]);
    block[24..32].copy_from_slice(&checksum.to_be_bytes());
    block
}

fn read_superblock(file: &mut File, offset: u64) -> Result<(u64, u64, u64)> {
    file.seek(SeekFrom::Start(offset)).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to seek database superblock: {err}"),
        )
    })?;
    let mut block = [0_u8; SingleFileBackend::SUPERBLOCK_LEN];
    file.read_exact(&mut block).map_err(|err| {
        RnovError::new(
            ErrorKind::Corruption,
            format!("failed to read database superblock: {err}"),
        )
    })?;
    let checksum = u64::from_be_bytes(read_fixed::<8>(&block, 24)?);
    let expected = fnv1a(FNV_OFFSET, &block[0..24]);
    if checksum != expected {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "database superblock checksum mismatch",
        ));
    }

    Ok((
        u64::from_be_bytes(read_fixed::<8>(&block, 0)?),
        u64::from_be_bytes(read_fixed::<8>(&block, 8)?),
        u64::from_be_bytes(read_fixed::<8>(&block, 16)?),
    ))
}

fn read_existing_page_counter(file: &mut File, offset: u64) -> Result<Option<u32>> {
    file.seek(SeekFrom::Start(offset)).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to seek encrypted page record: {err}"),
        )
    })?;

    let mut header = [0_u8; SingleFileBackend::PAGE_RECORD_HEADER_LEN];
    let read = file.read(&mut header).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to read encrypted page record counter: {err}"),
        )
    })?;
    if read == 0 || header[..8].iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    if read != header.len() {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "truncated encrypted page record header",
        ));
    }
    if header[..8] != SingleFileBackend::PAGE_RECORD_MAGIC {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "invalid encrypted page record magic",
        ));
    }
    Ok(Some(u32::from_be_bytes(read_fixed::<4>(&header, 8)?)))
}

fn read_fixed<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let slice = bytes
        .get(offset..offset + N)
        .ok_or_else(|| RnovError::new(ErrorKind::Corruption, "encoded data ended unexpectedly"))?;
    let mut array = [0_u8; N];
    array.copy_from_slice(slice);
    Ok(array)
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
