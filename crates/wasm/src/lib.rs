//! [`WasmRunner`] runs an untrusted WebAssembly component under Wasmtime: bytes in, bytes out,
//! one fresh store and instance per call, inside the memory, time and output limits of the call.
//! This is wall 1 of `docs/WALLS.md`.
//!
//! The component is a `wasi:cli/command`. The input is its stdin, the output is what it writes to
//! stdout, and only a clean exit (status 0) counts as an answer. The runner knows nothing about
//! what the bytes mean; callers parse and validate the output as untrusted.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

use bytes::Bytes;
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, ResourceLimiter, Store, Trap};
use wasmtime_wasi::p2::bindings::sync::CommandPre;
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::{HostMonotonicClock, HostWallClock, I32Exit, WasiCtx, WasiCtxView, WasiView};

const TICK: Duration = Duration::from_millis(5);
const MAX_TABLE_ELEMENTS: usize = 100_000;

/// How Wasmtime executes the component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Cranelift compiles the component to machine code for this CPU (needs executable memory
    /// while compiling).
    Native,
    /// Cranelift compiles to Pulley bytecode, run by Wasmtime's interpreter: no executable memory,
    /// for platforms that forbid JIT (iOS). Slower than [`Backend::Native`].
    Pulley,
}

impl Default for Backend {
    /// [`Backend::Pulley`] with the `pulley` feature, [`Backend::Native`] without.
    fn default() -> Self {
        if cfg!(feature = "pulley") {
            Self::Pulley
        } else {
            Self::Native
        }
    }
}

/// The limits of one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Most bytes all linear memories of the instance may hold together.
    pub memory_bytes: u64,
    /// How long the call may run before it is interrupted.
    pub time_budget: Duration,
    /// Most bytes the component may write to stdout.
    pub max_output_bytes: u64,
}

impl Default for Limits {
    /// 256 MiB of memory, 2 s, 64 MiB of output.
    fn default() -> Self {
        Self {
            memory_bytes: 256 << 20,
            time_budget: Duration::from_secs(2),
            max_output_bytes: 64 << 20,
        }
    }
}

/// Why a call produced no output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WasmError {
    /// The component does not compile or link against WASI 0.2, or Wasmtime cannot run here.
    #[error("the WebAssembly runtime or component is unavailable")]
    Unavailable,
    /// The call ran past its time budget.
    #[error("the component ran out of time")]
    Timeout,
    /// The component tried to grow its memory past the limit.
    #[error("the component exceeded its memory limit")]
    MemoryExceeded,
    /// The component wrote more than the output limit.
    #[error("the component exceeded its output limit")]
    OutputTooLarge,
    /// The component trapped, panicked or exited with a non-zero status.
    #[error("the component crashed")]
    Crashed,
}

/// A compiled component, ready to run in fresh instances.
///
/// Every call gets a new store and instance (nothing survives from one call to the next), a WASI
/// context with no files, environment, arguments, network or clock (stdin and stdout are
/// in-memory pipes, stderr is discarded), a memory cap of [`Limits::memory_bytes`] across all
/// linear memories, an epoch deadline of [`Limits::time_budget`], and an output pipe that keeps
/// at most [`Limits::max_output_bytes`] plus one byte.
///
/// Cheap to clone; clones share the compiled component and one epoch ticker thread, which stops
/// when the last clone is dropped.
#[derive(Clone)]
pub struct WasmRunner {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for WasmRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmRunner")
            .field("backend", &self.inner.backend)
            .finish_non_exhaustive()
    }
}

struct Inner {
    engine: Engine,
    pre: CommandPre<State>,
    backend: Backend,
    ticker: Arc<AtomicBool>,
    blocking: OnceLock<Option<tokio::runtime::Runtime>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.ticker.store(true, Ordering::Relaxed);
    }
}

impl WasmRunner {
    /// Compiles a component from its bytes, which takes a moment: build one value and keep it.
    /// Fails with [`WasmError::Unavailable`] when the bytes are not a `wasi:cli/command`
    /// component linking against WASI 0.2, or Wasmtime cannot run on this platform.
    pub fn new(component: &[u8], backend: Backend) -> Result<Self, WasmError> {
        let mut config = Config::new();
        config.epoch_interruption(true);
        if backend == Backend::Pulley {
            config
                .target("pulley64")
                .map_err(|_| WasmError::Unavailable)?;
        }
        let engine = Engine::new(&config).map_err(|_| WasmError::Unavailable)?;
        let component = Component::new(&engine, component).map_err(|_| WasmError::Unavailable)?;
        let mut linker = Linker::<State>::new(&engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker).map_err(|_| WasmError::Unavailable)?;
        let pre = linker
            .instantiate_pre(&component)
            .and_then(CommandPre::new)
            .map_err(|_| WasmError::Unavailable)?;
        let ticker = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&ticker);
        let ticking = engine.clone();
        thread::Builder::new()
            .name("rinse-wasm-epoch".into())
            .spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    thread::sleep(TICK);
                    ticking.increment_epoch();
                }
            })
            .map_err(|_| WasmError::Unavailable)?;
        Ok(Self {
            inner: Arc::new(Inner {
                engine,
                pre,
                backend,
                ticker,
                blocking: OnceLock::new(),
            }),
        })
    }

    /// The backend this value runs the component on.
    pub fn backend(&self) -> Backend {
        self.inner.backend
    }

    /// Runs the component once on the calling thread with `input` on stdin and returns its
    /// stdout. Outside a Tokio runtime it enters a current-thread runtime owned by this value, so
    /// after the first call a call starts no thread and opens no descriptor, which a locked-down
    /// worker process relies on.
    ///
    /// A refused memory growth is [`WasmError::MemoryExceeded`], a passed deadline
    /// [`WasmError::Timeout`], more output than allowed [`WasmError::OutputTooLarge`], and any
    /// other trap or a non-zero exit [`WasmError::Crashed`], checked in that order.
    pub fn run_blocking(&self, input: Vec<u8>, limits: &Limits) -> Result<Bytes, WasmError> {
        let _context = self.inner.enter_blocking();
        self.inner.run(input, limits)
    }

    /// [`WasmRunner::run_blocking`] on Tokio's blocking pool.
    pub async fn run(&self, input: Vec<u8>, limits: Limits) -> Result<Bytes, WasmError> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.run_blocking(input, &limits))
            .await
            .unwrap_or(Err(WasmError::Crashed))
    }
}

impl Inner {
    fn enter_blocking(&self) -> Option<tokio::runtime::EnterGuard<'_>> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return None;
        }
        self.blocking
            .get_or_init(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                    .ok()
            })
            .as_ref()
            .map(tokio::runtime::Runtime::enter)
    }

    fn run(&self, input: Vec<u8>, limits: &Limits) -> Result<Bytes, WasmError> {
        let max_output = usize::try_from(limits.max_output_bytes).unwrap_or(usize::MAX);
        let stdout = MemoryOutputPipe::new(max_output.saturating_add(1));
        let wasi = WasiCtx::builder()
            .stdin(MemoryInputPipe::new(input))
            .stdout(stdout.clone())
            .wall_clock(Frozen)
            .monotonic_clock(Frozen)
            .allow_tcp(false)
            .allow_udp(false)
            .allow_ip_name_lookup(false)
            .build();
        let mut store = Store::new(
            &self.engine,
            State {
                wasi,
                table: ResourceTable::new(),
                limiter: Limiter {
                    memory_bytes: usize::try_from(limits.memory_bytes).unwrap_or(usize::MAX),
                    granted: 0,
                    denied: false,
                },
            },
        );
        store.limiter(|s| &mut s.limiter);
        let millis = u64::try_from(limits.time_budget.as_millis()).unwrap_or(u64::MAX);
        let ticks = millis
            .max(1)
            .div_ceil(TICK.as_millis() as u64)
            .saturating_add(1);
        store.set_epoch_deadline(ticks);

        let outcome = self
            .pre
            .instantiate(&mut store)
            .and_then(|command| command.wasi_cli_run().call_run(&mut store));
        let denied = store.data().limiter.denied;
        drop(store);
        let output = stdout.contents();

        if denied {
            return Err(WasmError::MemoryExceeded);
        }
        let exited_cleanly = match &outcome {
            Ok(Ok(())) => true,
            Ok(Err(())) => false,
            Err(e) => {
                if e.downcast_ref::<Trap>() == Some(&Trap::Interrupt) {
                    return Err(WasmError::Timeout);
                }
                e.downcast_ref::<I32Exit>().is_some_and(|code| code.0 == 0)
            }
        };
        if output.len() > max_output {
            return Err(WasmError::OutputTooLarge);
        }
        if !exited_cleanly {
            return Err(WasmError::Crashed);
        }
        Ok(output)
    }
}

struct State {
    wasi: WasiCtx,
    table: ResourceTable,
    limiter: Limiter,
}

impl WasiView for State {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

struct Limiter {
    memory_bytes: usize,
    granted: usize,
    denied: bool,
}

impl ResourceLimiter for Limiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let total = self.granted.saturating_sub(current).saturating_add(desired);
        if total > self.memory_bytes {
            self.denied = true;
            return Ok(false);
        }
        self.granted = total;
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= MAX_TABLE_ELEMENTS)
    }
}

/// A clock that always reads zero, so the component can measure nothing.
struct Frozen;

impl HostWallClock for Frozen {
    fn resolution(&self) -> Duration {
        Duration::from_secs(1)
    }
    fn now(&self) -> Duration {
        Duration::ZERO
    }
}

impl HostMonotonicClock for Frozen {
    fn resolution(&self) -> u64 {
        1_000_000_000
    }
    fn now(&self) -> u64 {
        0
    }
}

#[cfg(test)]
mod tests;
