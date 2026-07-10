use std::{
    collections::VecDeque,
    fmt::Display,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use rnmdb_common::{ErrorKind, Result, RnovError, ids::FunctionId};
use rnmdb_types::{SqlType, SqlValue};

const WASM_SCALAR_ENTRYPOINT: &str = "run";
const EPOCH_TICK_INTERVAL: Duration = Duration::from_millis(5);
const MAX_CACHED_WASM_MODULES: usize = 32;

/// Maximum accepted module size; accepted modules are lazily compiled and cached by exact bytes.
pub const MAX_WASM_MODULE_BYTES: usize = 1024 * 1024;

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
        if module_bytes.len() > MAX_WASM_MODULE_BYTES {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "wasm module exceeds the {MAX_WASM_MODULE_BYTES}-byte compilation input limit; runtime compilation is cached by exact module bytes"
                ),
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdfRegistry {
    next_function_id: Option<u64>,
    functions: Vec<UdfDefinition>,
}

impl Default for UdfRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl UdfRegistry {
    pub fn new() -> Self {
        Self {
            next_function_id: Some(1),
            functions: Vec::new(),
        }
    }

    pub fn register(&mut self, definition: UdfDefinition) -> Result<FunctionId> {
        let function_id = self.next_function_id.map(FunctionId::new).ok_or_else(|| {
            RnovError::new(ErrorKind::InvalidInput, "function id space is exhausted")
        })?;
        self.register_with_id(function_id, definition)
    }

    pub fn register_with_id(
        &mut self,
        function_id: FunctionId,
        definition: UdfDefinition,
    ) -> Result<FunctionId> {
        self.validate_registration(function_id, &definition)?;
        self.advance_next_function_id(function_id);
        self.functions
            .push(definition.with_function_id(function_id));
        Ok(function_id)
    }

    fn validate_registration(
        &self,
        function_id: FunctionId,
        definition: &UdfDefinition,
    ) -> Result<()> {
        if function_id.get() == 0 {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "function id must be greater than zero",
            ));
        }
        if self
            .functions
            .iter()
            .any(|function| function.function_id == function_id)
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("function id already exists: {}", function_id.get()),
            ));
        }
        if self.functions.iter().any(|function| {
            function.name == definition.name && function.argument_types == definition.argument_types
        }) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("function already exists: {}", definition.name),
            ));
        }
        Ok(())
    }

    fn advance_next_function_id(&mut self, function_id: FunctionId) {
        let Some(next_function_id) = self.next_function_id else {
            return;
        };
        if function_id.get() >= next_function_id {
            self.next_function_id = function_id.get().checked_add(1);
        }
    }

    pub fn resolve_by_id(&self, function_id: FunctionId) -> Option<&UdfDefinition> {
        self.functions
            .iter()
            .find(|function| function.function_id == function_id)
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

#[derive(Clone)]
pub struct WasmScalarRuntime {
    inner: Arc<WasmRuntimeInner>,
}

struct WasmRuntimeInner {
    engine: wasmtime::Engine,
    compiled_modules: Mutex<CompiledModuleCache>,
    _epoch_ticker: EpochTicker,
}

#[derive(Default)]
struct CompiledModuleCache {
    entries: VecDeque<(Vec<u8>, wasmtime::Module)>,
}

struct WasmStoreState {
    limits: wasmtime::StoreLimits,
}

struct InvocationDeadline {
    timed_out: Arc<AtomicBool>,
}

struct EpochTicker {
    shutdown: mpsc::Sender<()>,
    worker: Option<JoinHandle<()>>,
}

impl WasmScalarRuntime {
    pub fn new() -> Result<Self> {
        let engine = create_wasm_engine()?;
        let epoch_ticker = EpochTicker::start(engine.clone())?;
        Ok(Self {
            inner: Arc::new(WasmRuntimeInner {
                engine,
                compiled_modules: Mutex::new(CompiledModuleCache::default()),
                _epoch_ticker: epoch_ticker,
            }),
        })
    }

    pub fn execute_scalar(
        &self,
        definition: &UdfDefinition,
        arguments: &[SqlValue],
    ) -> Result<SqlValue> {
        let module = wasm_module_for_scalar(definition)?;
        let argument = i64_unary_argument(definition, arguments)?;
        let result = self.execute_i64_unary(module, definition.sandbox_policy(), argument)?;
        Ok(SqlValue::Int64(result))
    }

    fn execute_i64_unary(
        &self,
        module: &WasmModuleDefinition,
        policy: &UdfSandboxPolicy,
        argument: i64,
    ) -> Result<i64> {
        let wasm_module = self.compile_module(module)?;
        ensure_no_compiled_imports(&wasm_module)?;
        let mut store = self.create_store(policy)?;
        let timeout = policy.budget().timeout();
        let deadline = configure_epoch_deadline(&mut store, timeout);
        let instance = instantiate_module(&mut store, &wasm_module, &deadline, timeout)?;
        let function = instance
            .get_typed_func::<i64, i64>(&mut store, WASM_SCALAR_ENTRYPOINT)
            .map_err(|err| {
                wasm_invalid_guest_error("failed to resolve wasm scalar entrypoint", err)
            })?;
        call_i64_with_deadline(&mut store, function, argument, &deadline, timeout)
    }

    fn compile_module(&self, module: &WasmModuleDefinition) -> Result<wasmtime::Module> {
        let bytes = module.module_bytes();
        let mut cache = self.inner.compiled_modules.lock().map_err(|_| {
            RnovError::new(
                ErrorKind::Internal,
                "wasm compiled-module cache lock was poisoned",
            )
        })?;
        if let Some(compiled) = cache.get(bytes) {
            return Ok(compiled);
        }
        let compiled = wasmtime::Module::from_binary(&self.inner.engine, bytes)
            .map_err(|err| wasm_invalid_guest_error("failed to compile wasm module", err))?;
        cache.insert(bytes.to_vec(), compiled.clone());
        Ok(compiled)
    }

    fn create_store(&self, policy: &UdfSandboxPolicy) -> Result<wasmtime::Store<WasmStoreState>> {
        let limits = wasmtime::StoreLimitsBuilder::new()
            .memory_size(policy.budget().max_memory_bytes())
            .table_elements(0)
            .instances(1)
            .tables(0)
            .memories(1)
            .build();
        let mut store = wasmtime::Store::new(&self.inner.engine, WasmStoreState { limits });
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(policy.budget().max_instructions())
            .map_err(|err| wasm_internal_error("failed to set wasm fuel budget", err))?;
        Ok(store)
    }
}

impl CompiledModuleCache {
    fn get(&self, bytes: &[u8]) -> Option<wasmtime::Module> {
        self.entries
            .iter()
            .find(|(cached_bytes, _)| cached_bytes == bytes)
            .map(|(_, module)| module.clone())
    }

    fn insert(&mut self, bytes: Vec<u8>, module: wasmtime::Module) {
        if self.entries.len() >= MAX_CACHED_WASM_MODULES {
            self.entries.pop_front();
        }
        self.entries.push_back((bytes, module));
    }
}

impl EpochTicker {
    fn start(engine: wasmtime::Engine) -> Result<Self> {
        let (shutdown, receiver) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("rnmdb-wasm-epoch".to_owned())
            .spawn(move || run_epoch_ticker(engine, receiver))
            .map_err(|err| wasm_internal_error("failed to start wasm epoch ticker", err))?;
        Ok(Self {
            shutdown,
            worker: Some(worker),
        })
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        let _ = self.shutdown.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn create_wasm_engine() -> Result<wasmtime::Engine> {
    let mut config = wasmtime::Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    wasmtime::Engine::new(&config)
        .map_err(|err| wasm_internal_error("failed to create wasm engine", err))
}

fn run_epoch_ticker(engine: wasmtime::Engine, shutdown: mpsc::Receiver<()>) {
    loop {
        match shutdown.recv_timeout(EPOCH_TICK_INTERVAL) {
            Err(RecvTimeoutError::Timeout) => engine.increment_epoch(),
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn configure_epoch_deadline(
    store: &mut wasmtime::Store<WasmStoreState>,
    timeout: Duration,
) -> InvocationDeadline {
    let started = Instant::now();
    let timed_out = Arc::new(AtomicBool::new(false));
    let callback_timed_out = Arc::clone(&timed_out);
    store.set_epoch_deadline(epoch_ticks(timeout));
    store.epoch_deadline_callback(move |_| {
        if started.elapsed() < timeout {
            return Ok(wasmtime::UpdateDeadline::Continue(1));
        }
        callback_timed_out.store(true, Ordering::Release);
        Ok(wasmtime::UpdateDeadline::Interrupt)
    });
    InvocationDeadline { timed_out }
}

fn epoch_ticks(timeout: Duration) -> u64 {
    let ticks = timeout.as_nanos().div_ceil(EPOCH_TICK_INTERVAL.as_nanos());
    u64::try_from(ticks).unwrap_or(u64::MAX).max(1)
}

fn instantiate_module(
    store: &mut wasmtime::Store<WasmStoreState>,
    module: &wasmtime::Module,
    deadline: &InvocationDeadline,
    timeout: Duration,
) -> Result<wasmtime::Instance> {
    wasmtime::Instance::new(store, module, &[]).map_err(|err| {
        wasm_execution_error("failed to instantiate wasm module", err, deadline, timeout)
    })
}

fn call_i64_with_deadline(
    store: &mut wasmtime::Store<WasmStoreState>,
    function: wasmtime::TypedFunc<i64, i64>,
    argument: i64,
    deadline: &InvocationDeadline,
    timeout: Duration,
) -> Result<i64> {
    function
        .call(store, argument)
        .map_err(|err| wasm_execution_error("wasm scalar execution failed", err, deadline, timeout))
}

fn wasm_execution_error(
    context: &str,
    err: wasmtime::Error,
    deadline: &InvocationDeadline,
    timeout: Duration,
) -> RnovError {
    if deadline.timed_out.load(Ordering::Acquire) || is_interrupt_trap(&err) {
        return wasm_timeout_error(timeout);
    }
    if is_out_of_fuel_trap(&err) {
        return RnovError::new(ErrorKind::Canceled, "wasm instruction budget was exhausted");
    }
    wasm_invalid_guest_error(context, err)
}

fn is_interrupt_trap(err: &wasmtime::Error) -> bool {
    matches!(
        err.downcast_ref::<wasmtime::Trap>(),
        Some(&wasmtime::Trap::Interrupt)
    )
}

fn is_out_of_fuel_trap(err: &wasmtime::Error) -> bool {
    matches!(
        err.downcast_ref::<wasmtime::Trap>(),
        Some(&wasmtime::Trap::OutOfFuel)
    )
}

fn ensure_no_compiled_imports(module: &wasmtime::Module) -> Result<()> {
    let Some(import) = module.imports().next() else {
        return Ok(());
    };
    Err(RnovError::new(
        ErrorKind::Security,
        format!(
            "compiled wasm module import {}.{} is not allowed under locked-down policy",
            import.module(),
            import.name()
        ),
    ))
}

fn wasm_module_for_scalar(definition: &UdfDefinition) -> Result<&WasmModuleDefinition> {
    if definition.kind() != FunctionKind::WasmSandbox || definition.class() != FunctionClass::Scalar
    {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "wasm scalar runtime requires a scalar wasm function",
        ));
    }
    definition.wasm_module().ok_or_else(|| {
        RnovError::new(
            ErrorKind::InvalidInput,
            "wasm scalar runtime requires an attached wasm module",
        )
    })
}

fn i64_unary_argument(definition: &UdfDefinition, arguments: &[SqlValue]) -> Result<i64> {
    ensure_i64_unary_signature(definition)?;
    let [SqlValue::Int64(argument)] = arguments else {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "wasm scalar runtime currently supports one i64 argument",
        ));
    };
    Ok(*argument)
}

fn ensure_i64_unary_signature(definition: &UdfDefinition) -> Result<()> {
    if definition.argument_types() != [SqlType::Int64]
        || definition.return_type() != Some(&SqlType::Int64)
    {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "wasm scalar runtime currently supports run(i64) -> i64",
        ));
    }
    Ok(())
}

fn wasm_invalid_guest_error(context: &str, err: impl Display) -> RnovError {
    RnovError::new(ErrorKind::InvalidInput, format!("{context}: {err}"))
}

fn wasm_internal_error(context: &str, err: impl Display) -> RnovError {
    RnovError::new(ErrorKind::Internal, format!("{context}: {err}"))
}

fn wasm_timeout_error(timeout: Duration) -> RnovError {
    RnovError::new(
        ErrorKind::Canceled,
        format!("wasm scalar execution timed out after {timeout:?}"),
    )
}
