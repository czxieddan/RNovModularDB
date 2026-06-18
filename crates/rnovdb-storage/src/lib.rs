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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page {
    id: PageId,
    payload: Vec<u8>,
}

impl Page {
    pub fn new(id: PageId, payload: Vec<u8>) -> Result<Self> {
        if payload.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "page payload cannot be empty",
            ));
        }

        Ok(Self { id, payload })
    }

    pub fn id(&self) -> PageId {
        self.id
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
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
    pages: Arc<RwLock<BTreeMap<PageId, Page>>>,
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
}

impl StorageBackend for MemoryBackend {
    fn read_page(&self, id: PageId) -> Result<Option<Page>> {
        let pages = self.pages.read().map_err(|_| {
            RnovError::new(ErrorKind::Internal, "memory backend page map lock poisoned")
        })?;
        Ok(pages.get(&id).cloned())
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

        let mut pages = self.pages.write().map_err(|_| {
            RnovError::new(ErrorKind::Internal, "memory backend page map lock poisoned")
        })?;
        pages.insert(page.id(), page);
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
