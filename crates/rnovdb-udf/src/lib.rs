use std::time::Duration;

use rnovdb_common::{ErrorKind, Result, RnovError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdfBudget {
    max_memory_bytes: usize,
    max_instructions: u64,
    timeout: Duration,
}

impl UdfBudget {
    pub fn new(max_memory_bytes: usize, max_instructions: u64, timeout: Duration) -> Result<Self> {
        if max_memory_bytes == 0 {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "udf memory budget must be greater than zero",
            ));
        }
        if max_instructions == 0 {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "udf instruction budget must be greater than zero",
            ));
        }
        if timeout.is_zero() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "udf timeout must be greater than zero",
            ));
        }

        Ok(Self {
            max_memory_bytes,
            max_instructions,
            timeout,
        })
    }

    pub fn max_memory_bytes(self) -> usize {
        self.max_memory_bytes
    }

    pub fn max_instructions(self) -> u64 {
        self.max_instructions
    }

    pub fn timeout(self) -> Duration {
        self.timeout
    }
}

impl Default for UdfBudget {
    fn default() -> Self {
        Self {
            max_memory_bytes: 16 * 1024 * 1024,
            max_instructions: 1_000_000,
            timeout: Duration::from_millis(100),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdfSandboxPolicy {
    filesystem_allowed: bool,
    network_allowed: bool,
    deterministic_host_calls: bool,
    budget: UdfBudget,
}

impl UdfSandboxPolicy {
    pub fn locked_down(budget: UdfBudget) -> Self {
        Self {
            filesystem_allowed: false,
            network_allowed: false,
            deterministic_host_calls: true,
            budget,
        }
    }

    pub fn filesystem_allowed(&self) -> bool {
        self.filesystem_allowed
    }

    pub fn network_allowed(&self) -> bool {
        self.network_allowed
    }

    pub fn deterministic_host_calls(&self) -> bool {
        self.deterministic_host_calls
    }

    pub fn budget(&self) -> UdfBudget {
        self.budget
    }
}

impl Default for UdfSandboxPolicy {
    fn default() -> Self {
        Self::locked_down(UdfBudget::default())
    }
}
