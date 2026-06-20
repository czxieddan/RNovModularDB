use rnovdb_cli::LocalSession;
use rnovdb_common::ids::{DatabaseId, InstanceId};
use rnovdb_common::{ErrorKind, Result, RnovError};
use rnovdb_instance::{InstanceConfig, ResourceLimits};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmbeddedRuntimeConfig {
    instance: InstanceConfig,
    memory_only: bool,
}

impl EmbeddedRuntimeConfig {
    pub fn temporary_memory(instance_id: InstanceId, database_id: DatabaseId) -> Self {
        Self {
            instance: InstanceConfig::isolated(instance_id, database_id, ResourceLimits::default()),
            memory_only: true,
        }
    }

    pub fn instance(&self) -> &InstanceConfig {
        &self.instance
    }

    pub fn is_memory_only(&self) -> bool {
        self.memory_only
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmbeddedRuntime {
    config: EmbeddedRuntimeConfig,
}

impl EmbeddedRuntime {
    pub fn temporary_memory(instance_id: InstanceId, database_id: DatabaseId) -> Self {
        Self {
            config: EmbeddedRuntimeConfig::temporary_memory(instance_id, database_id),
        }
    }

    pub fn config(&self) -> &EmbeddedRuntimeConfig {
        &self.config
    }

    pub fn open_session(&self) -> Result<LocalSession> {
        if !self.config.is_memory_only() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "embedded runtime only supports memory sessions",
            ));
        }
        LocalSession::memory()
    }
}
