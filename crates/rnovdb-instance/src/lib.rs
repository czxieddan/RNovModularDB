use std::{collections::BTreeMap, time::Duration};

use rnovdb_common::{
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InstanceManager {
    instances: BTreeMap<InstanceId, InstanceConfig>,
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
        self.instances.remove(&instance_id)
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
