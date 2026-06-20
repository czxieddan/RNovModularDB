use rnovdb_common::ids::{DatabaseId, InstanceId};
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
