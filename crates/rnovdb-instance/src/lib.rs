use std::time::Duration;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceConfig {
    instance_id: InstanceId,
    database_id: DatabaseId,
    limits: ResourceLimits,
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
}
