//! `ProcessRunner` against this platform's sandbox. The binary is also the worker: with
//! `--worker=serve` it runs `worker_main` under the real lockdown, with `--worker=<fault>` it
//! locks down and then misbehaves in one way.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rinse_process::worker::{Serve, worker_main};
use rinse_process::{MAX_REQUEST_BYTES, ProcessConfig, ProcessError, ProcessRunner};
use rinse_sandbox::{Launcher, Lockdown, Policy, WorkerCommand, announce, read_frame, write_frame};

#[cfg(target_os = "macos")]
fn platform() -> (Arc<dyn Launcher>, Box<dyn Lockdown>) {
    (
        Arc::new(rinse_sandbox_macos::MacosLauncher),
        Box::new(rinse_sandbox_macos::SeatbeltLockdown),
    )
}

#[cfg(target_os = "linux")]
fn platform() -> (Arc<dyn Launcher>, Box<dyn Lockdown>) {
    (
        Arc::new(rinse_sandbox_linux::LinuxLauncher::new()),
        Box::new(rinse_sandbox_linux::LinuxLockdown::default()),
    )
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn platform() -> (Arc<dyn Launcher>, Box<dyn Lockdown>) {
    (
        Arc::new(rinse_sandbox_none::NoneLauncher),
        Box::new(rinse_sandbox_none::NoLockdown),
    )
}

struct Echo {
    warm: bool,
}

impl Serve for Echo {
    fn warm_up(&self) -> bool {
        self.warm
    }

    fn serve(&self, request: &[u8]) -> Option<Vec<u8>> {
        match request {
            b"pid" => Some(std::process::id().to_string().into_bytes()),
            [b'b', b'a', b'd', ..] => None,
            [b's', b'l', b'e', b'e', b'p', b':', ms @ ..] => {
                let ms = std::str::from_utf8(ms).ok()?.parse().ok()?;
                std::thread::sleep(Duration::from_millis(ms));
                Some(b"slept".to_vec())
            }
            _ => Some(request.to_vec()),
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if let Some(mode) = args.iter().find_map(|a| a.strip_prefix("--worker=")) {
        let (_, lockdown) = platform();
        return match mode {
            "serve" => worker_main(lockdown.as_ref(), |_| Some(Echo { warm: true })),
            "cold" => worker_main(lockdown.as_ref(), |_| Some(Echo { warm: false })),
            "unloadable" => worker_main(lockdown.as_ref(), |_| None::<Echo>),
            _ => fault(lockdown.as_ref(), mode),
        };
    }
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        serves().await;
        faults().await;
    });
    println!("rinse-process: ok");
    ExitCode::SUCCESS
}

fn fault(lockdown: &dyn Lockdown, mode: &str) -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let policy = Policy::from_args(&args).expect("policy");
    let report = lockdown
        .prepare(&policy)
        .and_then(|p| lockdown.lock_down(&policy, p))
        .expect("lockdown");
    let mut stdout = std::io::stdout().lock();
    announce(&mut stdout, &report).expect("announce");
    let _request = read_frame(&mut std::io::stdin().lock(), 64 << 20).expect("request");
    match mode {
        "spin" => {
            let mut x = 0u64;
            loop {
                x = std::hint::black_box(x.wrapping_add(1));
            }
        }
        "abort" => std::process::abort(),
        "exit" => {}
        "huge" => write_frame(&mut stdout, &vec![0u8; 2 << 20]).expect("write"),
        "memory" => {
            let v = vec![1u8; 4 << 30];
            std::hint::black_box(&v);
        }
        _ => return ExitCode::from(99),
    }
    ExitCode::SUCCESS
}

fn runner(mode: &str, warm_workers: usize, policy: Policy) -> ProcessRunner {
    let (launcher, _) = platform();
    let mut config = ProcessConfig::new(WorkerCommand {
        program: std::env::current_exe().expect("test binary path"),
        args: vec![format!("--worker={mode}")],
    });
    config.warm_workers = warm_workers;
    config.policy = policy;
    ProcessRunner::new(launcher, config)
}

const BUDGET: Duration = Duration::from_secs(10);

async fn call_err(mode: &str, max_response: usize, policy: Policy) -> ProcessError {
    runner(mode, 0, policy)
        .call(
            b"request".to_vec(),
            Duration::from_millis(300),
            max_response,
        )
        .await
        .expect_err(mode)
}

async fn serves() {
    let echo = runner("serve", 2, Policy::default());
    echo.probe().await.expect("the sandboxed worker starts");
    echo.warm_up();
    println!(
        "launcher: {} (wall: {})",
        echo.launcher_name(),
        echo.is_wall()
    );
    assert_eq!(
        echo.call(b"hello".to_vec(), BUDGET, 5).await,
        Ok(b"hello".to_vec())
    );
    assert_eq!(echo.call(Vec::new(), BUDGET, 0).await, Ok(Vec::new()));

    let mut pids = Vec::new();
    for _ in 0..4 {
        let pid = echo.call(b"pid".to_vec(), BUDGET, 32).await.expect("pid");
        assert!(!pids.contains(&pid), "a worker served twice");
        pids.push(pid);
    }

    let calls = (0..6u8).map(|i| {
        let echo = echo.clone();
        tokio::spawn(async move { echo.call(vec![b'a' + i; 100_000], BUDGET, 100_000).await })
    });
    for (i, call) in calls.collect::<Vec<_>>().into_iter().enumerate() {
        assert_eq!(call.await.expect("task"), Ok(vec![b'a' + i as u8; 100_000]));
    }

    let short_lived = Policy {
        wall_time: Duration::from_secs(3),
        ..Policy::default()
    };
    let stale = runner("serve", 1, short_lived);
    stale.warm_up();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        stale
            .call(b"sleep:3000".to_vec(), Duration::from_secs(4), 5)
            .await,
        Ok(b"slept".to_vec()),
        "a warm worker without enough wall time left is replaced by a fresh one"
    );
    println!("serving: ok");
}

async fn faults() {
    let policy = Policy::default();

    let started = Instant::now();
    assert_eq!(call_err("spin", 1024, policy).await, ProcessError::Timeout);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );

    for mode in ["abort", "exit"] {
        assert_eq!(
            call_err(mode, 1024, policy).await,
            ProcessError::Crashed,
            "{mode}"
        );
    }
    assert_eq!(
        runner("serve", 0, policy)
            .call(b"bad request".to_vec(), BUDGET, 1024)
            .await,
        Err(ProcessError::Crashed)
    );
    assert_eq!(
        runner("serve", 0, policy)
            .call(b"123456".to_vec(), BUDGET, 5)
            .await,
        Err(ProcessError::ResponseTooLarge)
    );
    assert_eq!(
        call_err("huge", 1 << 20, policy).await,
        ProcessError::ResponseTooLarge
    );

    let small_memory = Policy {
        memory_bytes: 256 << 20,
        ..policy
    };
    let memory = call_err("memory", 1024, small_memory).await;
    println!("over the memory limit: {memory:?}");
    if cfg!(target_os = "macos") {
        assert_eq!(memory, ProcessError::MemoryExceeded);
    } else {
        assert!(matches!(
            memory,
            ProcessError::Crashed | ProcessError::MemoryExceeded
        ));
    }

    for mode in ["cold", "unloadable"] {
        let failing = runner(mode, 0, policy);
        assert_eq!(
            failing.probe().await,
            Err(ProcessError::Unavailable),
            "{mode}"
        );
        assert_eq!(
            failing.call(b"x".to_vec(), BUDGET, 16).await,
            Err(ProcessError::Unavailable),
            "{mode}"
        );
    }

    let (launcher, _) = platform();
    let missing = ProcessRunner::new(
        launcher,
        ProcessConfig::new(WorkerCommand {
            program: std::env::temp_dir().join("rinse-no-such-worker"),
            args: Vec::new(),
        }),
    );
    assert_eq!(
        missing
            .call(vec![0; MAX_REQUEST_BYTES + 1], BUDGET, 16)
            .await,
        Err(ProcessError::RequestTooLarge)
    );
    assert_eq!(
        missing.call(b"x".to_vec(), BUDGET, 16).await,
        Err(ProcessError::Unavailable)
    );
    assert_eq!(missing.probe().await, Err(ProcessError::Unavailable));
    println!("fault cases: ok");
}
