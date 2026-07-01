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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WasmImportCapability {
    DeterministicHostCall,
    NondeterministicHostCall,
    Filesystem,
    Network,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmModuleDefinition {
    module_bytes: Vec<u8>,
    initial_memory_bytes: usize,
    imports: Vec<WasmImportCapability>,
}

impl WasmModuleDefinition {
    pub fn new(
        module_bytes: Vec<u8>,
        initial_memory_bytes: usize,
        imports: Vec<WasmImportCapability>,
    ) -> Result<Self> {
        if module_bytes.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "wasm module cannot be empty",
            ));
        }
        if initial_memory_bytes == 0 {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "wasm module initial memory must be greater than zero",
            ));
        }

        Ok(Self {
            module_bytes,
            initial_memory_bytes,
            imports,
        })
    }

    pub fn module_bytes(&self) -> &[u8] {
        &self.module_bytes
    }

    pub fn initial_memory_bytes(&self) -> usize {
        self.initial_memory_bytes
    }

    pub fn imports(&self) -> &[WasmImportCapability] {
        &self.imports
    }

    pub fn validate(&self, policy: &UdfSandboxPolicy) -> Result<()> {
        let budget = policy.budget();
        if self.initial_memory_bytes > budget.max_memory_bytes() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "wasm module initial memory exceeds udf memory budget",
            ));
        }

        for capability in &self.imports {
            match capability {
                WasmImportCapability::Filesystem if !policy.filesystem_allowed() => {
                    return Err(RnovError::new(
                        ErrorKind::Security,
                        "wasm module filesystem imports are not allowed",
                    ));
                }
                WasmImportCapability::Network if !policy.network_allowed() => {
                    return Err(RnovError::new(
                        ErrorKind::Security,
                        "wasm module network imports are not allowed",
                    ));
                }
                WasmImportCapability::NondeterministicHostCall
                    if policy.deterministic_host_calls() =>
                {
                    return Err(RnovError::new(
                        ErrorKind::Security,
                        "wasm module imports must be deterministic under this policy",
                    ));
                }
                _ => {}
            }
        }

        Ok(())
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FunctionClass {
    Scalar,
    Aggregate,
    TableValued,
    Window,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TableFunctionColumn {
    name: String,
    data_type: SqlType,
    nullable: bool,
}

impl TableFunctionColumn {
    pub fn new(name: impl Into<String>, data_type: SqlType, nullable: bool) -> Result<Self> {
        let name = name.into();
        if name.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "table function column name cannot be empty",
            ));
        }

        Ok(Self {
            name,
            data_type,
            nullable,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn data_type(&self) -> &SqlType {
        &self.data_type
    }

    pub fn nullable(&self) -> bool {
        self.nullable
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UdfOutput {
    Scalar(SqlType),
    Aggregate(SqlType),
    Table(Vec<TableFunctionColumn>),
    Window(SqlType),
}

impl UdfOutput {
    pub fn class(&self) -> FunctionClass {
        match self {
            Self::Scalar(_) => FunctionClass::Scalar,
            Self::Aggregate(_) => FunctionClass::Aggregate,
            Self::Table(_) => FunctionClass::TableValued,
            Self::Window(_) => FunctionClass::Window,
        }
    }

    pub fn return_type(&self) -> Option<&SqlType> {
        match self {
            Self::Scalar(return_type)
            | Self::Aggregate(return_type)
            | Self::Window(return_type) => Some(return_type),
            Self::Table(_) => None,
        }
    }

    pub fn table_columns(&self) -> &[TableFunctionColumn] {
        match self {
            Self::Table(columns) => columns,
            _ => &[],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdfDefinition {
    function_id: FunctionId,
    name: String,
    argument_types: Vec<SqlType>,
    output: UdfOutput,
    kind: FunctionKind,
    sandbox_policy: UdfSandboxPolicy,
    wasm_module: Option<WasmModuleDefinition>,
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
            output: UdfOutput::Scalar(return_type),
            kind,
            sandbox_policy,
            wasm_module: None,
        })
    }

    pub fn new_aggregate(
        name: impl Into<String>,
        argument_types: Vec<SqlType>,
        return_type: SqlType,
        kind: FunctionKind,
        sandbox_policy: UdfSandboxPolicy,
    ) -> Result<Self> {
        Self::new_with_output(
            name,
            argument_types,
            UdfOutput::Aggregate(return_type),
            kind,
            sandbox_policy,
        )
    }

    pub fn new_table(
        name: impl Into<String>,
        argument_types: Vec<SqlType>,
        columns: Vec<TableFunctionColumn>,
        kind: FunctionKind,
        sandbox_policy: UdfSandboxPolicy,
    ) -> Result<Self> {
        if columns.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "table-valued function must expose at least one column",
            ));
        }

        Self::new_with_output(
            name,
            argument_types,
            UdfOutput::Table(columns),
            kind,
            sandbox_policy,
        )
    }

    pub fn new_window(
        name: impl Into<String>,
        argument_types: Vec<SqlType>,
        return_type: SqlType,
        kind: FunctionKind,
        sandbox_policy: UdfSandboxPolicy,
    ) -> Result<Self> {
        Self::new_with_output(
            name,
            argument_types,
            UdfOutput::Window(return_type),
            kind,
            sandbox_policy,
        )
    }

    pub fn new_wasm(
        name: impl Into<String>,
        argument_types: Vec<SqlType>,
        return_type: SqlType,
        wasm_module: WasmModuleDefinition,
        sandbox_policy: UdfSandboxPolicy,
    ) -> Result<Self> {
        wasm_module.validate(&sandbox_policy)?;
        let mut definition = Self::new(
            name,
            argument_types,
            return_type,
            FunctionKind::WasmSandbox,
            sandbox_policy,
        )?;
        definition.wasm_module = Some(wasm_module);
        Ok(definition)
    }

    fn new_with_output(
        name: impl Into<String>,
        argument_types: Vec<SqlType>,
        output: UdfOutput,
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
            output,
            kind,
            sandbox_policy,
            wasm_module: None,
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

    pub fn return_type(&self) -> Option<&SqlType> {
        self.output.return_type()
    }

    pub fn class(&self) -> FunctionClass {
        self.output.class()
    }

    pub fn output(&self) -> &UdfOutput {
        &self.output
    }

    pub fn table_columns(&self) -> &[TableFunctionColumn] {
        self.output.table_columns()
    }

    pub fn kind(&self) -> FunctionKind {
        self.kind
    }

    pub fn sandbox_policy(&self) -> &UdfSandboxPolicy {
        &self.sandbox_policy
    }

    pub fn wasm_module(&self) -> Option<&WasmModuleDefinition> {
        self.wasm_module.as_ref()
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

    pub fn resolve_class(
        &self,
        name: &str,
        argument_types: &[SqlType],
        class: FunctionClass,
    ) -> Option<&UdfDefinition> {
        self.functions.iter().find(|function| {
            function.name == name
                && function.argument_types == argument_types
                && function.class() == class
        })
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
