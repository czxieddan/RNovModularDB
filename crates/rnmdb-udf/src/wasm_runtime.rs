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

use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_types::{SqlType, SqlValue};

use super::{
    FunctionClass, FunctionKind, UdfBudget, UdfDefinition, UdfSandboxPolicy, WasmModuleDefinition,
};

const WASM_SCALAR_ENTRYPOINT: &str = "run";
const WASM_PAGE_BYTES: u64 = 64 * 1024;
const EPOCH_TICK_INTERVAL: Duration = Duration::from_millis(5);
const MAX_CACHED_WASM_MODULES: usize = 32;

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

struct PreparedInvocation {
    store: wasmtime::Store<WasmStoreState>,
    function: wasmtime::TypedFunc<i64, i64>,
    deadline: InvocationDeadline,
    timeout: Duration,
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

    pub fn prepare_i64_unary(
        &self,
        name: impl Into<String>,
        module_bytes: Vec<u8>,
        sandbox_policy: UdfSandboxPolicy,
    ) -> Result<UdfDefinition> {
        let provisional = WasmModuleDefinition::new(module_bytes, 0, Vec::new())?;
        let compiled = self.compile_module(&provisional)?;
        ensure_no_compiled_imports(&compiled)?;
        let initial_memory_bytes = ensure_compiled_resources(&compiled, sandbox_policy.budget())?;
        let module =
            WasmModuleDefinition::new(provisional.module_bytes, initial_memory_bytes, Vec::new())?;
        let definition = UdfDefinition::new_wasm(
            name,
            vec![SqlType::Int64],
            SqlType::Int64,
            module,
            sandbox_policy,
        )?;
        self.validate_scalar(&definition)?;
        Ok(definition)
    }

    pub fn validate_scalar(&self, definition: &UdfDefinition) -> Result<()> {
        let module = wasm_module_for_scalar(definition)?;
        ensure_i64_unary_signature(definition)?;
        let _ = self.prepare_invocation(module, definition.sandbox_policy())?;
        Ok(())
    }

    fn execute_i64_unary(
        &self,
        module: &WasmModuleDefinition,
        policy: &UdfSandboxPolicy,
        argument: i64,
    ) -> Result<i64> {
        let mut invocation = self.prepare_invocation(module, policy)?;
        call_i64_with_deadline(
            &mut invocation.store,
            invocation.function,
            argument,
            &invocation.deadline,
            invocation.timeout,
        )
    }

    fn prepare_invocation(
        &self,
        module: &WasmModuleDefinition,
        policy: &UdfSandboxPolicy,
    ) -> Result<PreparedInvocation> {
        let wasm_module = self.compile_module(module)?;
        ensure_no_compiled_imports(&wasm_module)?;
        let _ = ensure_compiled_resources(&wasm_module, policy.budget())?;
        let mut store = self.create_store(policy)?;
        let timeout = policy.budget().timeout();
        let deadline = configure_epoch_deadline(&mut store, timeout);
        let instance = instantiate_module(&mut store, &wasm_module, &deadline, timeout)?;
        let function = instance
            .get_typed_func::<i64, i64>(&mut store, WASM_SCALAR_ENTRYPOINT)
            .map_err(|err| {
                wasm_invalid_guest_error("failed to resolve wasm scalar entrypoint", err)
            })?;
        Ok(PreparedInvocation {
            store,
            function,
            deadline,
            timeout,
        })
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

fn ensure_compiled_resources(module: &wasmtime::Module, budget: UdfBudget) -> Result<usize> {
    let resources = module.resources_required();
    if resources.num_memories > 1 {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "wasm scalar modules may define at most one linear memory",
        ));
    }
    if resources.num_tables > 0 {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "wasm scalar modules may not define tables",
        ));
    }
    let initial_memory_bytes = compiled_initial_memory_bytes(&resources)?;
    if initial_memory_bytes > budget.max_memory_bytes() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "wasm module initial memory exceeds udf memory budget",
        ));
    }
    Ok(initial_memory_bytes)
}

fn compiled_initial_memory_bytes(resources: &wasmtime::ResourcesRequired) -> Result<usize> {
    let pages = resources.max_initial_memory_size.unwrap_or(0);
    let bytes = pages.checked_mul(WASM_PAGE_BYTES).ok_or_else(|| {
        RnovError::new(
            ErrorKind::InvalidInput,
            "wasm module initial memory size overflows u64",
        )
    })?;
    usize::try_from(bytes).map_err(|_| {
        RnovError::new(
            ErrorKind::InvalidInput,
            "wasm module initial memory does not fit this platform",
        )
    })
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
