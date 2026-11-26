//! [`ProcessRunner`] sends every request to a fresh worker process started through a
//! [`rinse_sandbox::Launcher`]: one process per request, locked down before it reads anything,
//! killed when it overruns its time budget, its response size-capped. This is wall 2 of
//! `docs/WALLS.md`. The runner moves opaque frames; what they mean is up to the caller, who
//! treats every response as untrusted.
//!
//! The worker side is [`worker::worker_main`].

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use rinse_sandbox::{
    Exit, KillReason, Launcher, Policy, SandboxError, WorkerCommand, WorkerProcess,
};
use tokio::time::Instant;

pub mod worker;

/// Largest request frame a worker reads.
pub const MAX_REQUEST_BYTES: usize = 512 << 20;
const REAP: Duration = Duration::from_secs(2);
const STARTUP: Duration = Duration::from_secs(30);

/// How [`ProcessRunner`] starts workers.
#[derive(Debug, Clone)]
pub struct ProcessConfig {
    /// The worker executable and its arguments.
    pub worker: WorkerCommand,
    /// The policy of every worker. Its `wall_time` bounds how long a warm worker may wait for a
    /// request plus the request itself; a request whose budget does not fit gets a fresh worker
    /// with a longer wall time.
    pub policy: Policy,
    /// Workers kept started, locked down and idle so a request does not wait for one to start.
    /// Each is used for one request only. 0 starts a worker per request on demand.
    pub warm_workers: usize,
    /// Added to a request's time budget before the worker is killed, so a worker's own deadline
    /// (which can answer cleanly) runs out first.
    pub grace: Duration,
}

impl ProcessConfig {
    /// The default policy, one warm worker, 500 ms of grace.
    pub fn new(worker: WorkerCommand) -> Self {
        Self {
            worker,
            policy: Policy::default(),
            warm_workers: 1,
            grace: Duration::from_millis(500),
        }
    }
}

/// Why a request got no response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProcessError {
    /// No worker could be started, or its lockdown report lacked a required restriction.
    #[error("the sandboxed worker is unavailable")]
    Unavailable,
    /// The request is larger than a worker reads ([`MAX_REQUEST_BYTES`]).
    #[error("the request is too large")]
    RequestTooLarge,
    /// No response within the budget plus grace, or the launcher killed the worker for CPU or
    /// wall time.
    #[error("the worker ran out of time")]
    Timeout,
    /// The launcher killed the worker for memory.
    #[error("the worker exceeded its memory limit")]
    MemoryExceeded,
    /// The response frame is larger than allowed; it was never read.
    #[error("the worker's response is too large")]
    ResponseTooLarge,
    /// The worker ended without a response for any other reason.
    #[error("the worker crashed")]
    Crashed,
}

/// Sandboxed worker processes, one per request.
///
/// Per call: the request goes to a worker that has never served another request (a warm one if
/// it still has enough wall time left, otherwise a new one); the response is read with a cap and
/// nothing beyond it is read ([`ProcessError::ResponseTooLarge`]); after the budget plus
/// [`ProcessConfig::grace`] the worker is killed ([`ProcessError::Timeout`]). A worker that ends
/// without a response maps to [`ProcessError::MemoryExceeded`] when the launcher killed it for
/// memory, [`ProcessError::Timeout`] for CPU or wall time, and [`ProcessError::Crashed`]
/// otherwise; a launch that fails is [`ProcessError::Unavailable`].
///
/// Needs a Tokio runtime (with the time driver) for its calls; cheap to clone.
#[derive(Clone)]
pub struct ProcessRunner {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for ProcessRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessRunner")
            .field("launcher", &self.inner.launcher.name())
            .finish_non_exhaustive()
    }
}

struct Idle {
    worker: Box<dyn WorkerProcess>,
    launched: Instant,
}

struct Inner {
    launcher: Arc<dyn Launcher>,
    config: ProcessConfig,
    idle: Mutex<VecDeque<Idle>>,
    starting: AtomicUsize,
}

impl ProcessRunner {
    /// A runner that starts workers with `launcher`. Starts nothing until the first call or
    /// [`ProcessRunner::warm_up`].
    pub fn new(launcher: Arc<dyn Launcher>, config: ProcessConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                launcher,
                config,
                idle: Mutex::new(VecDeque::new()),
                starting: AtomicUsize::new(0),
            }),
        }
    }

    /// Starts the warm workers now, in the background. Needs a Tokio runtime.
    pub fn warm_up(&self) {
        Inner::refill(&self.inner);
    }

    /// Starts one worker and waits for its lockdown report, to check at startup that the
    /// sandbox works on this system. Fails with [`ProcessError::Unavailable`] when it does not.
    pub async fn probe(&self) -> Result<(), ProcessError> {
        let mut worker = self.inner.launch(&self.inner.config.policy).await?;
        worker.kill().await;
        let _ = worker.wait().await;
        Ok(())
    }

    /// The name of the launcher (`"linux"`, `"macos"`, `"none"`).
    pub fn launcher_name(&self) -> &'static str {
        self.inner.launcher.name()
    }

    /// Whether the launcher sandboxes its workers.
    pub fn is_wall(&self) -> bool {
        self.inner.launcher.is_wall()
    }

    /// The configuration this runner was built with.
    pub fn config(&self) -> &ProcessConfig {
        &self.inner.config
    }

    /// Sends `request` as one frame to a fresh worker and returns its one response frame of at
    /// most `max_response` bytes, waiting at most `budget` plus [`ProcessConfig::grace`].
    pub async fn call(
        &self,
        request: Vec<u8>,
        budget: Duration,
        max_response: usize,
    ) -> Result<Vec<u8>, ProcessError> {
        if request.len() > MAX_REQUEST_BYTES {
            return Err(ProcessError::RequestTooLarge);
        }
        let budget = budget.saturating_add(self.inner.config.grace);
        let mut worker = self.inner.take(budget).await?;
        Inner::refill(&self.inner);
        if let Err(e) = worker.send(&request).await {
            drop(request);
            return Err(ended(worker, e).await);
        }
        drop(request);
        match tokio::time::timeout(budget, worker.receive(max_response)).await {
            Err(_) => {
                worker.kill().await;
                reap(worker);
                Err(ProcessError::Timeout)
            }
            Ok(Ok(response)) => {
                reap(worker);
                Ok(response)
            }
            Ok(Err(SandboxError::FrameTooLarge)) => {
                reap(worker);
                Err(ProcessError::ResponseTooLarge)
            }
            Ok(Err(e)) => Err(ended(worker, e).await),
        }
    }
}

fn reap(mut worker: Box<dyn WorkerProcess>) {
    tokio::spawn(async move {
        if tokio::time::timeout(REAP, worker.wait()).await.is_err() {
            worker.kill().await;
            let _ = worker.wait().await;
        }
    });
}

async fn ended(mut worker: Box<dyn WorkerProcess>, error: SandboxError) -> ProcessError {
    if error == SandboxError::WallTime {
        reap(worker);
        return ProcessError::Timeout;
    }
    let exit = match tokio::time::timeout(REAP, worker.wait()).await {
        Ok(Ok(exit)) => exit,
        _ => {
            worker.kill().await;
            reap(worker);
            return ProcessError::Crashed;
        }
    };
    match exit {
        Exit::Killed(KillReason::Memory) => ProcessError::MemoryExceeded,
        Exit::Killed(KillReason::Cpu | KillReason::WallTime) => ProcessError::Timeout,
        _ => ProcessError::Crashed,
    }
}

impl Inner {
    async fn launch(&self, policy: &Policy) -> Result<Box<dyn WorkerProcess>, ProcessError> {
        self.launcher
            .launch(&self.config.worker, policy)
            .await
            .map_err(|_| ProcessError::Unavailable)
    }

    async fn take(&self, budget: Duration) -> Result<Box<dyn WorkerProcess>, ProcessError> {
        let policy = self.config.policy;
        let needed = budget.saturating_add(REAP);
        loop {
            let idle = self.idle.lock().map_or(None, |mut q| q.pop_front());
            match idle {
                Some(idle) if idle.launched.elapsed() + needed < policy.wall_time => {
                    return Ok(idle.worker);
                }
                Some(_) => continue,
                None => break,
            }
        }
        let wall_time = policy.wall_time.max(needed.saturating_add(STARTUP));
        self.launch(&Policy {
            wall_time,
            ..policy
        })
        .await
    }

    fn refill(this: &Arc<Self>) {
        let idle = this.idle.lock().map_or(0, |q| q.len());
        let starting = this.starting.load(Ordering::Acquire);
        let wanted = this.config.warm_workers.saturating_sub(idle + starting);
        for _ in 0..wanted {
            this.starting.fetch_add(1, Ordering::AcqRel);
            let weak: Weak<Self> = Arc::downgrade(this);
            tokio::spawn(async move {
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                let launched = Instant::now();
                let started = inner.launch(&inner.config.policy).await;
                inner.starting.fetch_sub(1, Ordering::AcqRel);
                if let (Ok(worker), Ok(mut idle)) = (started, inner.idle.lock()) {
                    idle.push_back(Idle { worker, launched });
                }
            });
        }
    }
}
