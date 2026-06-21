use std::time::Duration;

use rnmdb_common::{ErrorKind, Result, RnovError, ids::FunctionId};
use rnmdb_types::SqlType;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FunctionKind {
    TrustedRust,
    WasmSandbox,
    SqlProcedure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdfDefinition {
    function_id: FunctionId,
    name: String,
    argument_types: Vec<SqlType>,
    return_type: SqlType,
    kind: FunctionKind,
    sandbox_policy: UdfSandboxPolicy,
}

impl UdfDefinition {
    pub fn new(
        name: impl Into<String>,
        argument_types: Vec<SqlType>,
        return_type: SqlType,
        kind: FunctionKind,
        sandbox_policy: UdfSandboxPolicy,
    ) -> Result<Self> {
        let name = name.into();
        if name.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "function name cannot be empty",
            ));
        }

        Ok(Self {
            function_id: FunctionId::new(0),
            name,
            argument_types,
            return_type,
            kind,
            sandbox_policy,
        })
    }

    pub fn function_id(&self) -> FunctionId {
        self.function_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn argument_types(&self) -> &[SqlType] {
        &self.argument_types
    }

    pub fn return_type(&self) -> &SqlType {
        &self.return_type
    }

    pub fn kind(&self) -> FunctionKind {
        self.kind
    }

    pub fn sandbox_policy(&self) -> &UdfSandboxPolicy {
        &self.sandbox_policy
    }

    fn with_function_id(mut self, function_id: FunctionId) -> Self {
        self.function_id = function_id;
        self
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UdfRegistry {
    next_function_id: u64,
    functions: Vec<UdfDefinition>,
}

impl UdfRegistry {
    pub fn new() -> Self {
        Self {
            next_function_id: 1,
            functions: Vec::new(),
        }
    }

    pub fn register(&mut self, definition: UdfDefinition) -> Result<FunctionId> {
        if self.functions.iter().any(|function| {
            function.name == definition.name && function.argument_types == definition.argument_types
        }) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("function already exists: {}", definition.name),
            ));
        }

        let function_id = FunctionId::new(self.next_function_id);
        self.next_function_id += 1;
        self.functions
            .push(definition.with_function_id(function_id));
        Ok(function_id)
    }

    pub fn resolve(&self, name: &str, argument_types: &[SqlType]) -> Option<&UdfDefinition> {
        self.functions
            .iter()
            .find(|function| function.name == name && function.argument_types == argument_types)
    }

    pub fn functions(&self) -> &[UdfDefinition] {
        &self.functions
    }

    pub fn len(&self) -> usize {
        self.functions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }
}
