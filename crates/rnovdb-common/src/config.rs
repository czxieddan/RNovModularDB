#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeMode {
    MemoryOnly,
    DiskOnly,
    Hybrid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncryptionMode {
    Required,
    DisabledForDevelopment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageSize(usize);

impl PageSize {
    pub const DEFAULT_BYTES: usize = 4096;

    pub const fn new(bytes: usize) -> Self {
        Self(bytes)
    }

    pub const fn bytes(self) -> usize {
        self.0
    }
}

impl Default for PageSize {
    fn default() -> Self {
        Self(Self::DEFAULT_BYTES)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineConfig {
    runtime_mode: RuntimeMode,
    page_size: PageSize,
    disk_writes_allowed: bool,
    encryption_mode: EncryptionMode,
    worker_threads: usize,
}

impl EngineConfig {
    pub fn memory_only() -> Self {
        Self {
            runtime_mode: RuntimeMode::MemoryOnly,
            page_size: PageSize::default(),
            disk_writes_allowed: false,
            encryption_mode: EncryptionMode::Required,
            worker_threads: 1,
        }
    }

    pub fn runtime_mode(&self) -> RuntimeMode {
        self.runtime_mode
    }

    pub fn page_size(&self) -> PageSize {
        self.page_size
    }

    pub fn disk_writes_allowed(&self) -> bool {
        self.disk_writes_allowed
    }

    pub fn encryption_mode(&self) -> EncryptionMode {
        self.encryption_mode
    }

    pub fn worker_threads(&self) -> usize {
        self.worker_threads
    }
}
