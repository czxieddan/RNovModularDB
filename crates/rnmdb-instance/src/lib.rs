use std::{collections::BTreeMap, time::Duration};

use rnmdb_common::{
    ErrorKind, Result, RnovError,
    ids::{DatabaseId, InstanceId},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    max_memory_bytes: usize,
    max_worker_threads: usize,
    max_temp_bytes: usize,
    statement_timeout: Duration,
}

impl ResourceLimits {
    pub fn new(
        max_memory_bytes: usize,
        max_worker_threads: usize,
        max_temp_bytes: usize,
        statement_timeout: Duration,
    ) -> Result<Self> {
        if max_memory_bytes == 0 {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "instance memory limit must be greater than zero",
            ));
        }
        if max_worker_threads == 0 {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "instance worker limit must be greater than zero",
            ));
        }
        if statement_timeout.is_zero() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "statement timeout must be greater than zero",
            ));
        }

        Ok(Self {
            max_memory_bytes,
            max_worker_threads,
            max_temp_bytes,
            statement_timeout,
        })
    }

    pub fn max_memory_bytes(&self) -> usize {
        self.max_memory_bytes
    }

    pub fn max_worker_threads(&self) -> usize {
        self.max_worker_threads
    }

    pub fn max_temp_bytes(&self) -> usize {
        self.max_temp_bytes
    }

    pub fn statement_timeout(&self) -> Duration {
        self.statement_timeout
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024,
            max_worker_threads: 1,
            max_temp_bytes: 0,
            statement_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResourceUsage {
    memory_bytes: usize,
    temp_bytes: usize,
    worker_threads: usize,
}

impl ResourceUsage {
    pub fn new(memory_bytes: usize, temp_bytes: usize, worker_threads: usize) -> Self {
        Self {
            memory_bytes,
            temp_bytes,
            worker_threads,
        }
    }

    pub fn memory_bytes(&self) -> usize {
        self.memory_bytes
    }

    pub fn temp_bytes(&self) -> usize {
        self.temp_bytes
    }

    pub fn worker_threads(&self) -> usize {
        self.worker_threads
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceConfig {
    instance_id: InstanceId,
    database_id: DatabaseId,
    limits: ResourceLimits,
    isolation: InstanceIsolation,
}

impl InstanceConfig {
    pub fn isolated(
        instance_id: InstanceId,
        database_id: DatabaseId,
        limits: ResourceLimits,
    ) -> Self {
        Self {
            instance_id,
            database_id,
            limits,
            isolation: InstanceIsolation::for_instance(instance_id),
        }
    }

    pub fn instance_id(&self) -> InstanceId {
        self.instance_id
    }

    pub fn database_id(&self) -> DatabaseId {
        self.database_id
    }

    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    pub fn isolation(&self) -> &InstanceIsolation {
        &self.isolation
    }

    pub fn check_resource_usage(&self, usage: &ResourceUsage) -> Result<()> {
        if usage.memory_bytes() > self.limits.max_memory_bytes() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "instance memory request exceeds limit: requested {} bytes, limit {} bytes",
                    usage.memory_bytes(),
                    self.limits.max_memory_bytes()
                ),
            ));
        }
        if usage.temp_bytes() > self.limits.max_temp_bytes() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "instance temp request exceeds limit: requested {} bytes, limit {} bytes",
                    usage.temp_bytes(),
                    self.limits.max_temp_bytes()
                ),
            ));
        }
        if usage.worker_threads() > self.limits.max_worker_threads() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "instance worker request exceeds limit: requested {}, limit {}",
                    usage.worker_threads(),
                    self.limits.max_worker_threads()
                ),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceIsolation {
    catalog_namespace: String,
    key_namespace: String,
    temp_namespace: String,
    audit_namespace: String,
    background_worker_group: String,
}

impl InstanceIsolation {
    pub fn for_instance(instance_id: InstanceId) -> Self {
        let suffix = instance_id.get();
        Self {
            catalog_namespace: format!("catalog:{suffix}"),
            key_namespace: format!("keys:{suffix}"),
            temp_namespace: format!("temp:{suffix}"),
            audit_namespace: format!("audit:{suffix}"),
            background_worker_group: format!("workers:{suffix}"),
        }
    }

    pub fn catalog_namespace(&self) -> &str {
        &self.catalog_namespace
    }

    pub fn key_namespace(&self) -> &str {
        &self.key_namespace
    }

    pub fn temp_namespace(&self) -> &str {
        &self.temp_namespace
    }

    pub fn audit_namespace(&self) -> &str {
        &self.audit_namespace
    }

    pub fn background_worker_group(&self) -> &str {
        &self.background_worker_group
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstanceSyncState {
    MemoryOnly,
    DiskOnly,
    HybridSyncing,
    HybridReady,
    Switching,
    Faulted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstanceSyncTarget {
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
pub struct InstanceSyncStatus {
    state: InstanceSyncState,
    active_target: InstanceSyncTarget,
    memory_lsn: u64,
    disk_lsn: u64,
    dirty_bytes: usize,
    estimated_flush_bytes: usize,
}

impl InstanceSyncStatus {
    pub fn new(
        state: InstanceSyncState,
        active_target: InstanceSyncTarget,
        memory_lsn: u64,
        disk_lsn: u64,
        dirty_bytes: usize,
        estimated_flush_bytes: usize,
    ) -> Result<Self> {
        if estimated_flush_bytes < dirty_bytes {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "estimated flush bytes cannot be lower than dirty bytes",
            ));
        }
        if matches!(state, InstanceSyncState::HybridReady)
            && (dirty_bytes != 0 || memory_lsn != disk_lsn)
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "hybrid ready status requires equal LSNs and zero dirty bytes",
            ));
        }
        if matches!(state, InstanceSyncState::MemoryOnly)
            && !matches!(active_target, InstanceSyncTarget::Memory)
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "memory-only status must target memory",
            ));
        }
        if matches!(state, InstanceSyncState::DiskOnly)
            && !matches!(active_target, InstanceSyncTarget::Disk)
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "disk-only status must target disk",
            ));
        }

        Ok(Self {
            state,
            active_target,
            memory_lsn,
            disk_lsn,
            dirty_bytes,
            estimated_flush_bytes,
        })
    }

    pub fn state(self) -> InstanceSyncState {
        self.state
    }

    pub fn active_target(self) -> InstanceSyncTarget {
        self.active_target
    }

    pub fn memory_lsn(self) -> u64 {
        self.memory_lsn
    }

    pub fn disk_lsn(self) -> u64 {
        self.disk_lsn
    }

    pub fn dirty_bytes(self) -> usize {
        self.dirty_bytes
    }

    pub fn estimated_flush_bytes(self) -> usize {
        self.estimated_flush_bytes
    }

    pub fn switch_data_movement(self, target: InstanceSyncTarget) -> SwitchDataMovement {
        if target == self.active_target {
            return SwitchDataMovement::MetadataOnly;
        }
        if self.is_pre_synchronized() {
            return SwitchDataMovement::PreSynchronized;
        }
        SwitchDataMovement::FullDataMovement
    }

    pub fn can_switch_in_millis(self, target: InstanceSyncTarget) -> bool {
        !matches!(
            self.switch_data_movement(target),
            SwitchDataMovement::FullDataMovement
        )
    }

    pub fn require_millisecond_switch(
        self,
        target: InstanceSyncTarget,
    ) -> Result<SwitchDataMovement> {
        let movement = self.switch_data_movement(target);
        if matches!(movement, SwitchDataMovement::FullDataMovement) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "instance switch to {target:?} requires full data movement: dirty {} bytes, estimated flush {} bytes, memory LSN {}, disk LSN {}",
                    self.dirty_bytes, self.estimated_flush_bytes, self.memory_lsn, self.disk_lsn
                ),
            ));
        }
        Ok(movement)
    }

    fn is_pre_synchronized(self) -> bool {
        matches!(self.state, InstanceSyncState::HybridReady)
            && self.dirty_bytes == 0
            && self.memory_lsn == self.disk_lsn
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstanceSwitchPolicy {
    millisecond_switch_required: bool,
    full_data_movement_allowed: bool,
}

impl InstanceSwitchPolicy {
    pub fn millisecond_only() -> Self {
        Self {
            millisecond_switch_required: true,
            full_data_movement_allowed: false,
        }
    }

    pub fn allow_full_data_movement() -> Self {
        Self {
            millisecond_switch_required: false,
            full_data_movement_allowed: true,
        }
    }

    pub fn millisecond_switch_required(self) -> bool {
        self.millisecond_switch_required
    }

    pub fn full_data_movement_allowed(self) -> bool {
        self.full_data_movement_allowed
    }

    pub fn validate_switch(
        self,
        status: InstanceSyncStatus,
        target: InstanceSyncTarget,
    ) -> Result<SwitchDataMovement> {
        let movement = status.switch_data_movement(target);
        if matches!(movement, SwitchDataMovement::FullDataMovement)
            && (self.millisecond_switch_required || !self.full_data_movement_allowed)
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "instance switch policy rejects full data movement",
            ));
        }
        Ok(movement)
    }
}

impl Default for InstanceSwitchPolicy {
    fn default() -> Self {
        Self::millisecond_only()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceSyncChannel {
    source_instance: InstanceId,
    target_instance: InstanceId,
    switch_policy: InstanceSwitchPolicy,
}

impl InstanceSyncChannel {
    pub fn new(
        source_instance: InstanceId,
        target_instance: InstanceId,
        switch_policy: InstanceSwitchPolicy,
    ) -> Result<Self> {
        if source_instance == target_instance {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "instance sync channel requires distinct source and target instances",
            ));
        }
        Ok(Self {
            source_instance,
            target_instance,
            switch_policy,
        })
    }

    pub fn source_instance(&self) -> InstanceId {
        self.source_instance
    }

    pub fn target_instance(&self) -> InstanceId {
        self.target_instance
    }

    pub fn switch_policy(&self) -> InstanceSwitchPolicy {
        self.switch_policy
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InstanceManager {
    instances: BTreeMap<InstanceId, InstanceConfig>,
    sync_channels: BTreeMap<(InstanceId, InstanceId), InstanceSyncChannel>,
}

impl InstanceManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, config: InstanceConfig) -> Result<()> {
        let instance_id = config.instance_id();
        if self.instances.contains_key(&instance_id) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("instance already exists: {instance_id}"),
            ));
        }
        self.instances.insert(instance_id, config);
        Ok(())
    }

    pub fn get(&self, instance_id: InstanceId) -> Option<&InstanceConfig> {
        self.instances.get(&instance_id)
    }

    pub fn remove(&mut self, instance_id: InstanceId) -> Option<InstanceConfig> {
        self.sync_channels
            .retain(|(source, target), _| *source != instance_id && *target != instance_id);
        self.instances.remove(&instance_id)
    }

    pub fn register_sync_channel(&mut self, channel: InstanceSyncChannel) -> Result<()> {
        let source = channel.source_instance();
        let target = channel.target_instance();
        if !self.instances.contains_key(&source) {
            return Err(RnovError::new(
                ErrorKind::NotFound,
                format!("sync channel source instance not registered: {source}"),
            ));
        }
        if !self.instances.contains_key(&target) {
            return Err(RnovError::new(
                ErrorKind::NotFound,
                format!("sync channel target instance not registered: {target}"),
            ));
        }
        if self.sync_channels.contains_key(&(source, target)) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("instance sync channel already exists: {source} -> {target}"),
            ));
        }
        self.sync_channels.insert((source, target), channel);
        Ok(())
    }

    pub fn sync_channel(
        &self,
        source: InstanceId,
        target: InstanceId,
    ) -> Option<&InstanceSyncChannel> {
        self.sync_channels.get(&(source, target))
    }

    pub fn remove_sync_channel(
        &mut self,
        source: InstanceId,
        target: InstanceId,
    ) -> Option<InstanceSyncChannel> {
        self.sync_channels.remove(&(source, target))
    }

    pub fn sync_channels(&self) -> Vec<&InstanceSyncChannel> {
        self.sync_channels.values().collect()
    }

    pub fn instance_ids(&self) -> Vec<InstanceId> {
        self.instances.keys().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.instances.len()
    }

    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }
}
