use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write, copy},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, RwLock, Weak},
    thread,
};

use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use crc::{CRC_64_ECMA_182, Crc};
use rnmdb_common::{
    error::{ErrorKind, Result, RnovError},
    ids::PageId,
};

pub use rnmdb_common::config::PageSize;
pub use single_file_upgrade::{
    upgrade_single_file, upgrade_single_file_with_key, upgrade_single_file_with_options,
};

mod single_file_upgrade;

pub const SINGLE_FILE_FORMAT_VERSION: u16 = 2;
pub const SINGLE_FILE_MIN_SUPPORTED_FORMAT_VERSION: u16 = SINGLE_FILE_FORMAT_VERSION;
pub const SINGLE_FILE_MAX_SUPPORTED_FORMAT_VERSION: u16 = SINGLE_FILE_FORMAT_VERSION;

const PAGE_CRC64: Crc<u64> = Crc::<u64>::new(&CRC_64_ECMA_182);
type SingleFileWriteLock = Arc<Mutex<()>>;
type SingleFileWriteLockRegistry = Mutex<BTreeMap<PathBuf, Weak<Mutex<()>>>>;

static SINGLE_FILE_WRITE_LOCKS: OnceLock<SingleFileWriteLockRegistry> = OnceLock::new();

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
    let mut digest = PAGE_CRC64.digest();
    digest.update(&header.page_id().get().to_be_bytes());
    digest.update(&header.lsn().to_be_bytes());
    digest.update(&(header.page_size().bytes() as u64).to_be_bytes());
    digest.update(&[header.format_version()]);
    digest.update(payload);
    digest.finalize()
}

fn checksum_bytes(bytes: &[u8]) -> u64 {
    PAGE_CRC64.checksum(bytes)
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
    pub const FORMAT_VERSION: u8 = 2;
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
        let encoded_page = PageCodec::encode(page)?;
        cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &encoded_page,
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
        let encoded_page = cipher
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
        let page = PageCodec::decode(&encoded_page)?;
        if page.id() != page_id {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "encrypted page metadata does not match requested page id",
            ));
        }
        Ok(page)
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemorySnapshot {
    page_size: PageSize,
    pages: Vec<Page>,
}

impl MemorySnapshot {
    pub fn new(page_size: PageSize, pages: Vec<Page>) -> Self {
        Self { page_size, pages }
    }

    pub fn page_size(&self) -> PageSize {
        self.page_size
    }

    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    pub fn pages(&self) -> &[Page] {
        &self.pages
    }

    pub fn export_to_single_file(
        &self,
        destination: impl AsRef<Path>,
        options: SingleFileOptions,
    ) -> Result<MemoryCheckpointReport> {
        if options.page_key().is_none() {
            return Err(RnovError::new(
                ErrorKind::Security,
                "memory checkpoint export requires a page encryption key",
            ));
        }
        if options.page_size() != self.page_size {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "memory checkpoint page size must match the destination page size",
            ));
        }

        let destination = destination.as_ref();
        let backend = SingleFileBackend::create(destination, options)?;
        for page in &self.pages {
            backend.write_page(page.clone())?;
        }
        backend.sync()?;
        let verification = backend.verify_with_key()?;

        Ok(MemoryCheckpointReport {
            destination_path: destination.to_path_buf(),
            pages_exported: self.pages.len(),
            bytes_written: verification.file_len_bytes(),
            page_size: self.page_size,
            superblock_generation: backend.superblock_generation(),
            page_record_slots: verification.page_record_slots(),
            present_page_records: verification.present_page_records(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryCheckpointReport {
    destination_path: PathBuf,
    pages_exported: usize,
    bytes_written: u64,
    page_size: PageSize,
    superblock_generation: u64,
    page_record_slots: u64,
    present_page_records: u64,
}

impl MemoryCheckpointReport {
    pub fn destination_path(&self) -> &Path {
        &self.destination_path
    }

    pub fn pages_exported(&self) -> usize {
        self.pages_exported
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    pub fn page_size(&self) -> PageSize {
        self.page_size
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

    pub fn snapshot_pages(&self) -> Result<Vec<Page>> {
        Ok(self.snapshot()?.pages)
    }

    pub fn snapshot(&self) -> Result<MemorySnapshot> {
        let pages = self.read_pages()?;
        Ok(MemorySnapshot::new(
            self.page_size,
            pages.values().map(|entry| entry.page.clone()).collect(),
        ))
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
pub enum HybridSyncTarget {
    Memory,
    Disk,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchDataMovement {
    MetadataOnly,
    PreSynchronized,
    FullDataMovement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HybridSyncStatus {
    state: HybridState,
    active_target: HybridSyncTarget,
    dirty_pages: usize,
    dirty_bytes: usize,
    mirrored_pages: usize,
    estimated_flush_bytes: usize,
    memory_lsn: u64,
    disk_lsn: u64,
    last_mirrored_lsn: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HybridSyncStatusParts {
    pub state: HybridState,
    pub active_target: HybridSyncTarget,
    pub dirty_pages: usize,
    pub dirty_bytes: usize,
    pub mirrored_pages: usize,
    pub estimated_flush_bytes: usize,
    pub memory_lsn: u64,
    pub disk_lsn: u64,
    pub last_mirrored_lsn: u64,
}

impl HybridSyncStatus {
    pub const fn new(parts: HybridSyncStatusParts) -> Self {
        Self {
            state: parts.state,
            active_target: parts.active_target,
            dirty_pages: parts.dirty_pages,
            dirty_bytes: parts.dirty_bytes,
            mirrored_pages: parts.mirrored_pages,
            estimated_flush_bytes: parts.estimated_flush_bytes,
            memory_lsn: parts.memory_lsn,
            disk_lsn: parts.disk_lsn,
            last_mirrored_lsn: parts.last_mirrored_lsn,
        }
    }

    pub const fn state(self) -> HybridState {
        self.state
    }

    pub const fn active_target(self) -> HybridSyncTarget {
        self.active_target
    }

    pub const fn dirty_pages(self) -> usize {
        self.dirty_pages
    }

    pub const fn dirty_bytes(self) -> usize {
        self.dirty_bytes
    }

    pub const fn mirrored_pages(self) -> usize {
        self.mirrored_pages
    }

    pub const fn estimated_flush_bytes(self) -> usize {
        self.estimated_flush_bytes
    }

    pub const fn memory_lsn(self) -> u64 {
        self.memory_lsn
    }

    pub const fn disk_lsn(self) -> u64 {
        self.disk_lsn
    }

    pub const fn last_mirrored_lsn(self) -> u64 {
        self.last_mirrored_lsn
    }

    pub const fn can_switch_to_disk_in_millis(self) -> bool {
        matches!(
            self.switch_data_movement(HybridSyncTarget::Disk),
            SwitchDataMovement::MetadataOnly | SwitchDataMovement::PreSynchronized
        )
    }

    pub const fn switch_data_movement(self, target: HybridSyncTarget) -> SwitchDataMovement {
        if matches!(
            (self.active_target, target),
            (HybridSyncTarget::Memory, HybridSyncTarget::Memory)
                | (HybridSyncTarget::Disk, HybridSyncTarget::Disk)
        ) {
            return SwitchDataMovement::MetadataOnly;
        }
        if matches!(self.state, HybridState::HybridReady)
            && self.dirty_pages == 0
            && self.memory_lsn == self.disk_lsn
        {
            return SwitchDataMovement::PreSynchronized;
        }
        SwitchDataMovement::FullDataMovement
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HybridWarmupReport {
    requested_pages: usize,
    warmed_pages: usize,
    missing_pages: usize,
    memory_resident_pages: usize,
}

impl HybridWarmupReport {
    pub const fn new(
        requested_pages: usize,
        warmed_pages: usize,
        missing_pages: usize,
        memory_resident_pages: usize,
    ) -> Self {
        Self {
            requested_pages,
            warmed_pages,
            missing_pages,
            memory_resident_pages,
        }
    }

    pub const fn requested_pages(self) -> usize {
        self.requested_pages
    }

    pub const fn warmed_pages(self) -> usize {
        self.warmed_pages
    }

    pub const fn missing_pages(self) -> usize {
        self.missing_pages
    }

    pub const fn memory_resident_pages(self) -> usize {
        self.memory_resident_pages
    }
}

pub struct HybridMirrorHandle {
    handle: thread::JoinHandle<Result<SyncStatus>>,
}

impl HybridMirrorHandle {
    pub fn join(self) -> Result<SyncStatus> {
        self.handle.join().map_err(|_| {
            RnovError::new(
                ErrorKind::Internal,
                "hybrid backend background mirror thread panicked",
            )
        })?
    }
}

#[derive(Clone)]
pub struct HybridBackend {
    memory: MemoryBackend,
    disk: Arc<dyn StorageBackend>,
    active_target: Arc<RwLock<HybridSyncTarget>>,
    dirty_pages: Arc<RwLock<BTreeSet<PageId>>>,
    mirrored_pages: Arc<RwLock<BTreeSet<PageId>>>,
    lsn_status: Arc<RwLock<HybridLsnStatus>>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct HybridLsnStatus {
    memory_lsn: u64,
    disk_lsn: u64,
    last_mirrored_lsn: u64,
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
            active_target: Arc::new(RwLock::new(HybridSyncTarget::Memory)),
            dirty_pages: Arc::new(RwLock::new(BTreeSet::new())),
            mirrored_pages: Arc::new(RwLock::new(BTreeSet::new())),
            lsn_status: Arc::new(RwLock::new(HybridLsnStatus::default())),
        })
    }

    pub fn attach_memory_to_disk(
        memory: MemoryBackend,
        disk: Arc<dyn StorageBackend>,
    ) -> Result<(Self, HybridMirrorHandle)> {
        let backend = Self::new(memory, disk)?;
        let memory_pages = backend.memory.snapshot_pages()?;
        let mut max_memory_lsn = 0_u64;

        {
            let mut dirty_pages = backend.write_dirty_pages()?;
            for page in &memory_pages {
                dirty_pages.insert(page.id());
                max_memory_lsn = max_memory_lsn.max(page.header().lsn());
            }
        }
        if !memory_pages.is_empty() {
            let mut lsn_status = backend.write_lsn_status()?;
            lsn_status.memory_lsn = max_memory_lsn;
        }

        let mirror = backend.start_background_mirror();
        Ok((backend, mirror))
    }

    pub fn start_background_mirror(&self) -> HybridMirrorHandle {
        let backend = self.clone();
        HybridMirrorHandle {
            handle: thread::spawn(move || backend.sync()),
        }
    }

    pub fn active_target(&self) -> Result<HybridSyncTarget> {
        self.read_active_target()
    }

    pub fn switch_active_target(&self, target: HybridSyncTarget) -> Result<SwitchDataMovement> {
        let status = self.sync_status()?;
        let movement = status.switch_data_movement(target);
        if matches!(movement, SwitchDataMovement::FullDataMovement) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "hybrid switch to {target:?} requires full data movement: dirty {} bytes, estimated flush {} bytes, memory LSN {}, disk LSN {}",
                    status.dirty_bytes(),
                    status.estimated_flush_bytes(),
                    status.memory_lsn(),
                    status.disk_lsn()
                ),
            ));
        }
        *self.write_active_target()? = target;
        Ok(movement)
    }

    pub fn warmup_pages<I>(&self, page_ids: I) -> Result<HybridWarmupReport>
    where
        I: IntoIterator<Item = PageId>,
    {
        let requested_pages = page_ids.into_iter().collect::<BTreeSet<_>>();

        {
            let dirty_pages = self.read_dirty_pages()?;
            if let Some(page_id) = requested_pages
                .iter()
                .find(|page_id| dirty_pages.contains(page_id))
            {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("cannot warm up dirty page {}", page_id.get()),
                ));
            }
        }

        let mut warmed_pages = 0_usize;
        let mut missing_pages = 0_usize;
        let mut max_warmed_lsn = 0_u64;

        for page_id in &requested_pages {
            let Some(page) = self.disk.read_page(*page_id)? else {
                missing_pages += 1;
                continue;
            };
            let page_lsn = page.header().lsn();
            self.memory.write_page(page)?;
            self.memory.mark_clean(*page_id)?;
            self.write_dirty_pages()?.remove(page_id);
            self.write_mirrored_pages()?.insert(*page_id);
            max_warmed_lsn = max_warmed_lsn.max(page_lsn);
            warmed_pages += 1;
        }

        if warmed_pages > 0 {
            let mut lsn_status = self.write_lsn_status()?;
            lsn_status.memory_lsn = lsn_status.memory_lsn.max(max_warmed_lsn);
            lsn_status.disk_lsn = lsn_status.disk_lsn.max(max_warmed_lsn);
            lsn_status.last_mirrored_lsn = lsn_status.last_mirrored_lsn.max(max_warmed_lsn);
        }

        Ok(HybridWarmupReport::new(
            requested_pages.len(),
            warmed_pages,
            missing_pages,
            self.read_mirrored_pages()?.len(),
        ))
    }

    pub fn promote_working_set_to_memory<I>(&self, page_ids: I) -> Result<HybridWarmupReport>
    where
        I: IntoIterator<Item = PageId>,
    {
        let report = self.warmup_pages(page_ids)?;
        self.switch_active_target(HybridSyncTarget::Memory)?;
        Ok(report)
    }

    pub fn sync_status(&self) -> Result<HybridSyncStatus> {
        let dirty_pages = self.read_dirty_pages()?.len();
        let mirrored_pages = self.read_mirrored_pages()?.len();
        let dirty_bytes = dirty_pages.saturating_mul(self.memory.page_size().bytes());
        let lsn_status = self.read_lsn_status()?;
        let active_target = self.read_active_target()?;
        let state = if dirty_pages == 0 {
            HybridState::HybridReady
        } else {
            HybridState::HybridSyncing
        };
        Ok(HybridSyncStatus::new(HybridSyncStatusParts {
            state,
            active_target,
            dirty_pages,
            dirty_bytes,
            mirrored_pages,
            estimated_flush_bytes: dirty_bytes,
            memory_lsn: lsn_status.memory_lsn,
            disk_lsn: lsn_status.disk_lsn,
            last_mirrored_lsn: lsn_status.last_mirrored_lsn,
        }))
    }

    fn read_dirty_pages(&self) -> Result<std::sync::RwLockReadGuard<'_, BTreeSet<PageId>>> {
        self.dirty_pages.read().map_err(|_| {
            RnovError::new(
                ErrorKind::Internal,
                "hybrid backend dirty page set lock poisoned",
            )
        })
    }

    fn read_active_target(&self) -> Result<HybridSyncTarget> {
        self.active_target
            .read()
            .map(|target| *target)
            .map_err(|_| {
                RnovError::new(
                    ErrorKind::Internal,
                    "hybrid backend active target lock poisoned",
                )
            })
    }

    fn write_active_target(&self) -> Result<std::sync::RwLockWriteGuard<'_, HybridSyncTarget>> {
        self.active_target.write().map_err(|_| {
            RnovError::new(
                ErrorKind::Internal,
                "hybrid backend active target lock poisoned",
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

    fn read_lsn_status(&self) -> Result<HybridLsnStatus> {
        self.lsn_status
            .read()
            .map(|status| *status)
            .map_err(|_| RnovError::new(ErrorKind::Internal, "hybrid backend LSN lock poisoned"))
    }

    fn write_lsn_status(&self) -> Result<std::sync::RwLockWriteGuard<'_, HybridLsnStatus>> {
        self.lsn_status
            .write()
            .map_err(|_| RnovError::new(ErrorKind::Internal, "hybrid backend LSN lock poisoned"))
    }
}

impl StorageBackend for HybridBackend {
    fn read_page(&self, id: PageId) -> Result<Option<Page>> {
        match self.read_active_target()? {
            HybridSyncTarget::Memory => {
                if let Some(page) = self.memory.read_page(id)? {
                    return Ok(Some(page));
                }
                self.disk.read_page(id)
            }
            HybridSyncTarget::Disk => {
                if let Some(page) = self.disk.read_page(id)? {
                    return Ok(Some(page));
                }
                self.memory.read_page(id)
            }
        }
    }

    fn write_page(&self, page: Page) -> Result<()> {
        let page_id = page.id();
        let page_lsn = page.header().lsn();
        match self.read_active_target()? {
            HybridSyncTarget::Memory => {
                self.memory.write_page(page)?;
                self.write_dirty_pages()?.insert(page_id);
            }
            HybridSyncTarget::Disk => {
                self.disk.write_page(page.clone())?;
                self.memory.write_page(page)?;
                self.memory.mark_clean(page_id)?;
                self.write_mirrored_pages()?.insert(page_id);
                let mut lsn_status = self.write_lsn_status()?;
                lsn_status.disk_lsn = lsn_status.disk_lsn.max(page_lsn);
                lsn_status.last_mirrored_lsn = lsn_status.last_mirrored_lsn.max(page_lsn);
            }
        }
        let mut lsn_status = self.write_lsn_status()?;
        lsn_status.memory_lsn = lsn_status.memory_lsn.max(page_lsn);
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
        {
            let mut lsn_status = self.write_lsn_status()?;
            lsn_status.disk_lsn = lsn_status.memory_lsn;
            lsn_status.last_mirrored_lsn = lsn_status.memory_lsn;
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

fn single_file_write_locks() -> &'static SingleFileWriteLockRegistry {
    SINGLE_FILE_WRITE_LOCKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn single_file_write_lock_for(path: &Path) -> Result<SingleFileWriteLock> {
    let lock_path = canonical_lock_path(path)?;
    let mut locks = single_file_write_locks().lock().map_err(|_| {
        RnovError::new(
            ErrorKind::Internal,
            "single-file write lock registry poisoned",
        )
    })?;
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&lock_path).and_then(Weak::upgrade) {
        return Ok(lock);
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(lock_path, Arc::downgrade(&lock));
    Ok(lock)
}

fn canonical_lock_path(path: &Path) -> Result<PathBuf> {
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

pub struct SingleFileBackend {
    path: PathBuf,
    file: File,
    page_size: PageSize,
    superblock_generation: u64,
    page_key: Option<PageCryptoKey>,
    write_lock: SingleFileWriteLock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SingleFileFormatCompatibilityStatus {
    Supported,
    UnsupportedOlder,
    UnsupportedNewer,
}

impl SingleFileFormatCompatibilityStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::UnsupportedOlder => "unsupported_older",
            Self::UnsupportedNewer => "unsupported_newer",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleFileFormatCompatibility {
    path: PathBuf,
    format_version: u16,
    min_supported_format_version: u16,
    max_supported_format_version: u16,
    status: SingleFileFormatCompatibilityStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleFileInspection {
    path: PathBuf,
    file_len_bytes: u64,
    data_start_bytes: u64,
    page_size: PageSize,
    page_record_size_bytes: u64,
    format_version: u16,
    superblock_generation: u64,
    superblock_checksum_verified: bool,
    page_record_slots: u64,
    present_page_records: u64,
    empty_page_slots: u64,
    authenticated_page_records: u64,
    checksum_verified_page_records: u64,
    page_records: Vec<SingleFilePageRecordInspection>,
    capabilities: StorageCapability,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleFilePageRecordInspection {
    slot_index: u64,
    page_id: PageId,
    offset_bytes: u64,
    present: bool,
    encryption_counter: Option<u32>,
    encrypted_payload_bytes: Option<u64>,
    encryption_authenticated: bool,
    page_checksum_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleFileBackupReport {
    source_path: PathBuf,
    destination_path: PathBuf,
    bytes_copied: u64,
    superblock_generation: u64,
    page_size: PageSize,
    page_record_slots: u64,
    present_page_records: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleFileVerificationReport {
    path: PathBuf,
    format_version: u16,
    min_supported_format_version: u16,
    max_supported_format_version: u16,
    format_compatibility: SingleFileFormatCompatibilityStatus,
    file_len_bytes: u64,
    page_record_slots: u64,
    present_page_records: u64,
    empty_page_slots: u64,
    authenticated_page_records: u64,
    encryption_authenticated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleFileRestoreDryRun {
    backup_path: PathBuf,
    target_path: PathBuf,
    target_exists: bool,
    backup_valid: bool,
    bytes_to_restore: u64,
    page_record_slots: u64,
    present_page_records: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleFileRestoreReport {
    backup_path: PathBuf,
    target_path: PathBuf,
    bytes_restored: u64,
    page_record_slots: u64,
    present_page_records: u64,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct SingleFileUpgradeOptions {
    source_page_key: Option<PageCryptoKey>,
    target_page_key: Option<PageCryptoKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleFileUpgradePageReport {
    page_id: PageId,
    source_counter: u32,
    target_counter: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleFileUpgradeReport {
    source_path: PathBuf,
    target_path: PathBuf,
    source_format_version: u16,
    target_format_version: u16,
    bytes_written: u64,
    page_size: PageSize,
    superblock_generation: u64,
    page_record_slots: u64,
    pages_upgraded: u64,
    key_rotated: bool,
    page_reports: Vec<SingleFileUpgradePageReport>,
}

impl SingleFileFormatCompatibility {
    fn new(path: PathBuf, format_version: u16) -> Self {
        Self {
            path,
            format_version,
            min_supported_format_version: SINGLE_FILE_MIN_SUPPORTED_FORMAT_VERSION,
            max_supported_format_version: SINGLE_FILE_MAX_SUPPORTED_FORMAT_VERSION,
            status: single_file_format_compatibility_status(format_version),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn format_version(&self) -> u16 {
        self.format_version
    }

    pub fn min_supported_format_version(&self) -> u16 {
        self.min_supported_format_version
    }

    pub fn max_supported_format_version(&self) -> u16 {
        self.max_supported_format_version
    }

    pub fn status(&self) -> SingleFileFormatCompatibilityStatus {
        self.status
    }

    pub fn is_supported(&self) -> bool {
        matches!(self.status, SingleFileFormatCompatibilityStatus::Supported)
    }

    pub fn migration_required(&self) -> bool {
        matches!(
            self.status,
            SingleFileFormatCompatibilityStatus::UnsupportedOlder
        )
    }

    pub fn requires_newer_engine(&self) -> bool {
        matches!(
            self.status,
            SingleFileFormatCompatibilityStatus::UnsupportedNewer
        )
    }
}

const fn single_file_format_compatibility_status(
    format_version: u16,
) -> SingleFileFormatCompatibilityStatus {
    if format_version < SINGLE_FILE_MIN_SUPPORTED_FORMAT_VERSION {
        SingleFileFormatCompatibilityStatus::UnsupportedOlder
    } else if format_version > SINGLE_FILE_MAX_SUPPORTED_FORMAT_VERSION {
        SingleFileFormatCompatibilityStatus::UnsupportedNewer
    } else {
        SingleFileFormatCompatibilityStatus::Supported
    }
}

impl SingleFileRestoreDryRun {
    pub fn backup_path(&self) -> &Path {
        &self.backup_path
    }

    pub fn target_path(&self) -> &Path {
        &self.target_path
    }

    pub fn target_exists(&self) -> bool {
        self.target_exists
    }

    pub fn backup_valid(&self) -> bool {
        self.backup_valid
    }

    pub fn bytes_to_restore(&self) -> u64 {
        self.bytes_to_restore
    }

    pub fn page_record_slots(&self) -> u64 {
        self.page_record_slots
    }

    pub fn present_page_records(&self) -> u64 {
        self.present_page_records
    }
}

impl SingleFileRestoreReport {
    pub fn backup_path(&self) -> &Path {
        &self.backup_path
    }

    pub fn target_path(&self) -> &Path {
        &self.target_path
    }

    pub fn bytes_restored(&self) -> u64 {
        self.bytes_restored
    }

    pub fn page_record_slots(&self) -> u64 {
        self.page_record_slots
    }

    pub fn present_page_records(&self) -> u64 {
        self.present_page_records
    }
}

impl SingleFileUpgradeOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_page_key(mut self, key: PageCryptoKey) -> Self {
        self.source_page_key = Some(key);
        self.target_page_key = Some(key);
        self
    }

    pub fn with_source_page_key(mut self, key: PageCryptoKey) -> Self {
        self.source_page_key = Some(key);
        self
    }

    pub fn with_target_page_key(mut self, key: PageCryptoKey) -> Self {
        self.target_page_key = Some(key);
        self
    }

    pub fn source_page_key(self) -> Option<PageCryptoKey> {
        self.source_page_key
    }

    pub fn target_page_key(self) -> Option<PageCryptoKey> {
        self.target_page_key.or(self.source_page_key)
    }

    pub fn key_rotated(self) -> bool {
        self.source_page_key
            .zip(self.target_page_key)
            .is_some_and(|(source, target)| source != target)
    }
}

impl SingleFileUpgradePageReport {
    pub fn page_id(&self) -> PageId {
        self.page_id
    }

    pub fn source_counter(&self) -> u32 {
        self.source_counter
    }

    pub fn target_counter(&self) -> u32 {
        self.target_counter
    }
}

impl SingleFileUpgradeReport {
    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    pub fn target_path(&self) -> &Path {
        &self.target_path
    }

    pub fn source_format_version(&self) -> u16 {
        self.source_format_version
    }

    pub fn target_format_version(&self) -> u16 {
        self.target_format_version
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    pub fn page_size(&self) -> PageSize {
        self.page_size
    }

    pub fn superblock_generation(&self) -> u64 {
        self.superblock_generation
    }

    pub fn page_record_slots(&self) -> u64 {
        self.page_record_slots
    }

    pub fn pages_upgraded(&self) -> u64 {
        self.pages_upgraded
    }

    pub fn key_rotated(&self) -> bool {
        self.key_rotated
    }

    pub fn page_reports(&self) -> &[SingleFileUpgradePageReport] {
        &self.page_reports
    }
}

impl SingleFileVerificationReport {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn format_version(&self) -> u16 {
        self.format_version
    }

    pub fn min_supported_format_version(&self) -> u16 {
        self.min_supported_format_version
    }

    pub fn max_supported_format_version(&self) -> u16 {
        self.max_supported_format_version
    }

    pub fn format_compatibility(&self) -> SingleFileFormatCompatibilityStatus {
        self.format_compatibility
    }

    pub fn format_supported(&self) -> bool {
        matches!(
            self.format_compatibility,
            SingleFileFormatCompatibilityStatus::Supported
        )
    }

    pub fn file_len_bytes(&self) -> u64 {
        self.file_len_bytes
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

    pub fn authenticated_page_records(&self) -> u64 {
        self.authenticated_page_records
    }

    pub fn encryption_authenticated(&self) -> bool {
        self.encryption_authenticated
    }

    pub fn is_valid(&self) -> bool {
        self.format_supported()
            && (!self.encryption_authenticated
                || self.authenticated_page_records == self.present_page_records)
    }
}

impl SingleFileBackupReport {
    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    pub fn destination_path(&self) -> &Path {
        &self.destination_path
    }

    pub fn bytes_copied(&self) -> u64 {
        self.bytes_copied
    }

    pub fn superblock_generation(&self) -> u64 {
        self.superblock_generation
    }

    pub fn page_size(&self) -> PageSize {
        self.page_size
    }

    pub fn page_record_slots(&self) -> u64 {
        self.page_record_slots
    }

    pub fn present_page_records(&self) -> u64 {
        self.present_page_records
    }
}

impl SingleFilePageRecordInspection {
    fn empty(slot_index: u64, page_id: PageId, offset_bytes: u64) -> Self {
        Self {
            slot_index,
            page_id,
            offset_bytes,
            present: false,
            encryption_counter: None,
            encrypted_payload_bytes: None,
            encryption_authenticated: false,
            page_checksum_verified: false,
        }
    }

    fn encrypted(
        slot_index: u64,
        page_id: PageId,
        offset_bytes: u64,
        encryption_counter: u32,
        encrypted_payload_bytes: u64,
    ) -> Self {
        Self {
            slot_index,
            page_id,
            offset_bytes,
            present: true,
            encryption_counter: Some(encryption_counter),
            encrypted_payload_bytes: Some(encrypted_payload_bytes),
            encryption_authenticated: false,
            page_checksum_verified: false,
        }
    }

    fn mark_authenticated(&mut self) {
        self.encryption_authenticated = true;
        self.page_checksum_verified = true;
    }

    pub fn slot_index(&self) -> u64 {
        self.slot_index
    }

    pub fn page_id(&self) -> PageId {
        self.page_id
    }

    pub fn offset_bytes(&self) -> u64 {
        self.offset_bytes
    }

    pub fn is_present(&self) -> bool {
        self.present
    }

    pub fn encryption_counter(&self) -> Option<u32> {
        self.encryption_counter
    }

    pub fn encrypted_payload_bytes(&self) -> Option<u64> {
        self.encrypted_payload_bytes
    }

    pub fn encryption_authenticated(&self) -> bool {
        self.encryption_authenticated
    }

    pub fn page_checksum_verified(&self) -> bool {
        self.page_checksum_verified
    }
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

    pub fn format_version(&self) -> u16 {
        self.format_version
    }

    pub fn superblock_generation(&self) -> u64 {
        self.superblock_generation
    }

    pub fn superblock_checksum_verified(&self) -> bool {
        self.superblock_checksum_verified
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

    pub fn authenticated_page_records(&self) -> u64 {
        self.authenticated_page_records
    }

    pub fn checksum_verified_page_records(&self) -> u64 {
        self.checksum_verified_page_records
    }

    pub fn page_records(&self) -> &[SingleFilePageRecordInspection] {
        &self.page_records
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
    const FORMAT_VERSION: u16 = SINGLE_FILE_FORMAT_VERSION;
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
        let write_lock = single_file_write_lock_for(path)?;

        Ok(Self {
            path: path.to_path_buf(),
            file,
            page_size: options.page_size(),
            superblock_generation,
            page_key: options.page_key(),
            write_lock,
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

    pub fn backup_to(&self, destination: impl AsRef<Path>) -> Result<SingleFileBackupReport> {
        self.file.sync_all().map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to sync source database before backup: {err}"),
            )
        })?;
        backup_single_file(&self.path, destination)
    }

    pub fn verify(&self) -> Result<SingleFileVerificationReport> {
        verify_single_file(&self.path)
    }

    pub fn verify_with_key(&self) -> Result<SingleFileVerificationReport> {
        verify_single_file_with_key(&self.path, self.page_key()?)
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
        let (_format_version, page_size, superblock_generation) =
            read_single_file_header(&mut file)?;
        let write_lock = single_file_write_lock_for(path)?;

        Ok(Self {
            path: path.to_path_buf(),
            file,
            page_size,
            superblock_generation,
            page_key,
            write_lock,
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
        (Self::PAGE_RECORD_HEADER_LEN + self.max_page_ciphertext_len()) as u64
    }

    fn max_page_ciphertext_len(&self) -> usize {
        PageCodec::HEADER_LEN + self.page_size.bytes() + 16
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
        if ciphertext_len > self.max_page_ciphertext_len() {
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

        let _write_guard = self.write_lock.lock().map_err(|_| {
            RnovError::new(
                ErrorKind::Internal,
                "single-file backend write lock poisoned",
            )
        })?;
        let key = self.page_key()?;
        let mut file = self.file.try_clone().map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to clone database file handle: {err}"),
            )
        })?;
        let offset = self.page_offset(page.id())?;
        let counter = next_page_counter(read_existing_page_counter(&mut file, offset)?)?;
        let nonce = PageNonce::from_page_counter(page.id(), counter);
        let ciphertext = PageCrypto::encrypt(&key, nonce, &page)?;

        file.seek(SeekFrom::Start(offset)).map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to seek encrypted page record: {err}"),
            )
        })?;
        write_encrypted_page_record(&mut file, counter, &ciphertext)?;
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

fn write_encrypted_page_record(file: &mut File, counter: u32, ciphertext: &[u8]) -> Result<()> {
    file.write_all(&SingleFileBackend::PAGE_RECORD_MAGIC)
        .map_err(|err| {
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
    file.write_all(ciphertext).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to write encrypted page payload: {err}"),
        )
    })
}

pub fn check_single_file_format_compatibility(
    path: impl AsRef<Path>,
) -> Result<SingleFileFormatCompatibility> {
    let path = path.as_ref();
    let mut file = OpenOptions::new().read(true).open(path).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to inspect database file compatibility: {err}"),
        )
    })?;
    let format_version = read_single_file_format_version(&mut file)?;
    Ok(SingleFileFormatCompatibility::new(
        path.to_path_buf(),
        format_version,
    ))
}

pub fn verify_single_file(path: impl AsRef<Path>) -> Result<SingleFileVerificationReport> {
    let inspection = inspect_single_file(path)?;
    Ok(SingleFileVerificationReport {
        path: inspection.path().to_path_buf(),
        format_version: inspection.format_version(),
        min_supported_format_version: SINGLE_FILE_MIN_SUPPORTED_FORMAT_VERSION,
        max_supported_format_version: SINGLE_FILE_MAX_SUPPORTED_FORMAT_VERSION,
        format_compatibility: single_file_format_compatibility_status(inspection.format_version()),
        file_len_bytes: inspection.file_len_bytes(),
        page_record_slots: inspection.page_record_slots(),
        present_page_records: inspection.present_page_records(),
        empty_page_slots: inspection.empty_page_slots(),
        authenticated_page_records: 0,
        encryption_authenticated: false,
    })
}

pub fn verify_single_file_with_key(
    path: impl AsRef<Path>,
    key: PageCryptoKey,
) -> Result<SingleFileVerificationReport> {
    let inspection = inspect_single_file_with_key(path.as_ref(), key)?;

    Ok(SingleFileVerificationReport {
        path: inspection.path().to_path_buf(),
        format_version: inspection.format_version(),
        min_supported_format_version: SINGLE_FILE_MIN_SUPPORTED_FORMAT_VERSION,
        max_supported_format_version: SINGLE_FILE_MAX_SUPPORTED_FORMAT_VERSION,
        format_compatibility: single_file_format_compatibility_status(inspection.format_version()),
        file_len_bytes: inspection.file_len_bytes(),
        page_record_slots: inspection.page_record_slots(),
        present_page_records: inspection.present_page_records(),
        empty_page_slots: inspection.empty_page_slots(),
        authenticated_page_records: inspection.authenticated_page_records(),
        encryption_authenticated: true,
    })
}

pub fn inspect_single_file_with_key(
    path: impl AsRef<Path>,
    key: PageCryptoKey,
) -> Result<SingleFileInspection> {
    let path = path.as_ref();
    let mut inspection = inspect_single_file(path)?;
    let backend = SingleFileBackend::open_with_key(path, key)?;
    let mut authenticated_page_records = 0_u64;
    let mut checksum_verified_page_records = 0_u64;

    for record in &mut inspection.page_records {
        if !record.is_present() {
            continue;
        }
        if backend.read_page(record.page_id())?.is_none() {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                format!(
                    "page record {} disappeared during authenticated inspection",
                    record.page_id().get()
                ),
            ));
        }
        record.mark_authenticated();
        authenticated_page_records += 1;
        checksum_verified_page_records += 1;
    }

    inspection.authenticated_page_records = authenticated_page_records;
    inspection.checksum_verified_page_records = checksum_verified_page_records;
    Ok(inspection)
}

pub fn backup_single_file(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
) -> Result<SingleFileBackupReport> {
    let source = source.as_ref();
    let destination = destination.as_ref();
    if source == destination {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "backup source and destination must be different paths",
        ));
    }

    let source_inspection = inspect_single_file(source)?;
    let mut source_file = OpenOptions::new().read(true).open(source).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to open backup source: {err}"),
        )
    })?;
    let mut destination_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to create backup destination: {err}"),
            )
        })?;
    let bytes_copied = copy(&mut source_file, &mut destination_file).map_err(|err| {
        RnovError::new(ErrorKind::Io, format!("failed to copy backup bytes: {err}"))
    })?;
    destination_file.sync_all().map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to sync backup destination: {err}"),
        )
    })?;
    drop(destination_file);

    let destination_inspection = inspect_single_file(destination)?;
    validate_backup_copy(&source_inspection, &destination_inspection)?;

    Ok(SingleFileBackupReport {
        source_path: source.to_path_buf(),
        destination_path: destination.to_path_buf(),
        bytes_copied,
        superblock_generation: destination_inspection.superblock_generation(),
        page_size: destination_inspection.page_size(),
        page_record_slots: destination_inspection.page_record_slots(),
        present_page_records: destination_inspection.present_page_records(),
    })
}

pub fn restore_single_file_dry_run(
    backup: impl AsRef<Path>,
    target: impl AsRef<Path>,
) -> Result<SingleFileRestoreDryRun> {
    let backup = backup.as_ref();
    let target = target.as_ref();
    let verification = verify_single_file(backup)?;

    Ok(SingleFileRestoreDryRun {
        backup_path: backup.to_path_buf(),
        target_path: target.to_path_buf(),
        target_exists: target.exists(),
        backup_valid: verification.is_valid(),
        bytes_to_restore: verification.file_len_bytes(),
        page_record_slots: verification.page_record_slots(),
        present_page_records: verification.present_page_records(),
    })
}

pub fn restore_single_file(
    backup: impl AsRef<Path>,
    target: impl AsRef<Path>,
) -> Result<SingleFileRestoreReport> {
    let backup = backup.as_ref();
    let target = target.as_ref();
    if backup == target {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "restore backup and target must be different paths",
        ));
    }
    if target.exists() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "restore target already exists",
        ));
    }

    let source_inspection = inspect_single_file(backup)?;
    let mut source = OpenOptions::new().read(true).open(backup).map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to open restore backup: {err}"),
        )
    })?;
    let mut destination = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(target)
        .map_err(|err| {
            RnovError::new(
                ErrorKind::Io,
                format!("failed to create restore target: {err}"),
            )
        })?;
    let bytes_restored = copy(&mut source, &mut destination)
        .map_err(|err| RnovError::new(ErrorKind::Io, format!("failed to restore bytes: {err}")))?;
    destination.sync_all().map_err(|err| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to sync restore target: {err}"),
        )
    })?;
    drop(destination);

    let target_inspection = inspect_single_file(target)?;
    validate_backup_copy(&source_inspection, &target_inspection)?;

    Ok(SingleFileRestoreReport {
        backup_path: backup.to_path_buf(),
        target_path: target.to_path_buf(),
        bytes_restored,
        page_record_slots: target_inspection.page_record_slots(),
        present_page_records: target_inspection.present_page_records(),
    })
}

fn validate_backup_copy(
    source: &SingleFileInspection,
    destination: &SingleFileInspection,
) -> Result<()> {
    if source.file_len_bytes() != destination.file_len_bytes() {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "backup validation failed: copied file length differs from source",
        ));
    }
    if source.page_size() != destination.page_size() {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "backup validation failed: page size differs from source",
        ));
    }
    if source.superblock_generation() != destination.superblock_generation() {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "backup validation failed: superblock generation differs from source",
        ));
    }
    if source.page_record_slots() != destination.page_record_slots()
        || source.present_page_records() != destination.present_page_records()
        || source.empty_page_slots() != destination.empty_page_slots()
    {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "backup validation failed: page record map differs from source",
        ));
    }
    Ok(())
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
    let (format_version, page_size, superblock_generation) = read_single_file_header(&mut file)?;
    let data_start_bytes =
        (SingleFileBackend::HEADER_LEN + SingleFileBackend::SUPERBLOCK_LEN * 2) as u64;
    let max_page_ciphertext_len = PageCodec::HEADER_LEN + page_size.bytes() + 16;
    let page_record_size_bytes =
        (SingleFileBackend::PAGE_RECORD_HEADER_LEN + max_page_ciphertext_len) as u64;
    let page_record_slots = if file_len_bytes <= data_start_bytes {
        0
    } else {
        (file_len_bytes - data_start_bytes).div_ceil(page_record_size_bytes)
    };
    let mut present_page_records = 0_u64;
    let mut empty_page_slots = 0_u64;
    let mut page_records = Vec::new();

    for slot in 0..page_record_slots {
        let offset = data_start_bytes + slot * page_record_size_bytes;
        let page_id = PageId::new(slot + 1);
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
            page_records.push(SingleFilePageRecordInspection::empty(slot, page_id, offset));
            continue;
        }
        if header[..8] != SingleFileBackend::PAGE_RECORD_MAGIC {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "invalid encrypted page record magic",
            ));
        }

        let counter = u32::from_be_bytes(read_fixed::<4>(&header, 8)?);
        let ciphertext_len = u32::from_be_bytes(read_fixed::<4>(&header, 12)?) as u64;
        if ciphertext_len > max_page_ciphertext_len as u64 {
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
        page_records.push(SingleFilePageRecordInspection::encrypted(
            slot,
            page_id,
            offset,
            counter,
            ciphertext_len,
        ));
    }

    Ok(SingleFileInspection {
        path: path.to_path_buf(),
        file_len_bytes,
        data_start_bytes,
        page_size,
        page_record_size_bytes,
        format_version,
        superblock_generation,
        superblock_checksum_verified: true,
        page_record_slots,
        present_page_records,
        empty_page_slots,
        authenticated_page_records: 0,
        checksum_verified_page_records: 0,
        page_records,
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
    write_single_file_header_with_roots(file, page_size, superblock_generation, 0, 0)
}

fn write_single_file_header_with_roots(
    file: &mut File,
    page_size: PageSize,
    superblock_generation: u64,
    catalog_root: u64,
    free_map_root: u64,
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

    let primary = encode_superblock(superblock_generation, catalog_root, free_map_root);
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

fn read_single_file_header(file: &mut File) -> Result<(u16, PageSize, u64)> {
    let header = read_single_file_header_bytes(file)?;
    let format_version = read_single_file_format_version_from_header(&header);
    ensure_single_file_format_supported(format_version)?;

    let page_size = PageSize::new(u64::from_be_bytes(read_fixed::<8>(&header, 12)?) as usize);
    let primary_offset = u64::from_be_bytes(read_fixed::<8>(&header, 20)?);
    let secondary_offset = u64::from_be_bytes(read_fixed::<8>(&header, 28)?);
    let primary = read_superblock(file, primary_offset);
    let secondary = read_superblock(file, secondary_offset);
    let generation = match (primary, secondary) {
        (Ok(primary), Ok(secondary)) => primary.0.max(secondary.0),
        (Ok(primary), Err(_)) => primary.0,
        (Err(_), Ok(secondary)) => secondary.0,
        (Err(primary), Err(secondary)) => {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                format!(
                    "database superblocks are invalid: primary: {primary}; secondary: {secondary}"
                ),
            ));
        }
    };

    Ok((format_version, page_size, generation))
}

fn read_single_file_format_version(file: &mut File) -> Result<u16> {
    let header = read_single_file_header_bytes(file)?;
    Ok(read_single_file_format_version_from_header(&header))
}

fn read_single_file_header_bytes(file: &mut File) -> Result<[u8; SingleFileBackend::HEADER_LEN]> {
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

    validate_single_file_magic(&header)?;
    Ok(header)
}

fn validate_single_file_magic(header: &[u8; SingleFileBackend::HEADER_LEN]) -> Result<()> {
    if header[..8] != SingleFileBackend::MAGIC {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "invalid database file magic",
        ));
    }
    Ok(())
}

fn read_single_file_format_version_from_header(
    header: &[u8; SingleFileBackend::HEADER_LEN],
) -> u16 {
    u16::from_be_bytes([header[8], header[9]])
}

fn ensure_single_file_format_supported(format_version: u16) -> Result<()> {
    if matches!(
        single_file_format_compatibility_status(format_version),
        SingleFileFormatCompatibilityStatus::Supported
    ) {
        return Ok(());
    }
    let upgrade_hint = if format_version < SINGLE_FILE_MIN_SUPPORTED_FORMAT_VERSION {
        "; run an explicit single-file upgrade before opening this database"
    } else {
        ""
    };
    Err(RnovError::new(
        ErrorKind::Corruption,
        format!(
            "unsupported database format version {format_version}; supported versions are {}..={}{}",
            SINGLE_FILE_MIN_SUPPORTED_FORMAT_VERSION,
            SINGLE_FILE_MAX_SUPPORTED_FORMAT_VERSION,
            upgrade_hint
        ),
    ))
}

fn encode_superblock(generation: u64, catalog_root: u64, free_map_root: u64) -> [u8; 32] {
    let mut block = [0_u8; 32];
    block[0..8].copy_from_slice(&generation.to_be_bytes());
    block[8..16].copy_from_slice(&catalog_root.to_be_bytes());
    block[16..24].copy_from_slice(&free_map_root.to_be_bytes());
    let checksum = checksum_bytes(&block[0..24]);
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
    let expected = checksum_bytes(&block[0..24]);
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

fn next_page_counter(current: Option<u32>) -> Result<u32> {
    match current {
        Some(u32::MAX) => Err(RnovError::new(
            ErrorKind::Security,
            "page encryption counter exhausted; rotate the page key before rewriting this page",
        )),
        Some(counter) => Ok(counter + 1),
        None => Ok(1),
    }
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
