//! `ProcessContent` against this platform's sandbox. The binary is also the worker: with
//! `--worker=wasm` it is a `rinse_host::run` worker with the real WebAssembly pipeline, with
//! `--worker=<fault>` it locks down and then misbehaves in one way.
//!
//! Unoptimized builds run the fault cases and one real render; the full `rinse-mail`
//! conformance suite (a fresh worker per call, each compiling the component) runs with
//! `cargo test --release -p rinse-mail-process`.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rinse_mail::testing::fixture;
use rinse_mail::{
    Content, ContentError, ContentLimits, DecodedPart, LimitKind, PartRequest, RenderOptions,
    RenderRequest, Rendered,
};
use rinse_mail_process::worker::{BlockingContent, ContentHandler};
use rinse_mail_process::{ProcessConfig, ProcessContent};
use rinse_mail_wasm::{EMBEDDED_WORKER, WasmContent};
use rinse_sandbox::{Launcher, Lockdown, Policy, WorkerCommand, announce, read_frame, write_frame};

#[cfg(target_os = "macos")]
fn launcher() -> Arc<dyn Launcher> {
    Arc::new(rinse_sandbox_macos::MacosLauncher)
}

#[cfg(target_os = "linux")]
fn launcher() -> Arc<dyn Launcher> {
    Arc::new(rinse_sandbox_linux::LinuxLauncher::new())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn launcher() -> Arc<dyn Launcher> {
    Arc::new(rinse_sandbox_none::NoneLauncher)
}

struct Wasm(WasmContent);

impl BlockingContent for Wasm {
    fn render(&self, request: RenderRequest) -> Result<Rendered, ContentError> {
        self.0.render_blocking(request)
    }

    fn decode_part(&self, request: PartRequest) -> Result<DecodedPart, ContentError> {
        self.0.decode_part_blocking(request)
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if let Some(mode) = args.iter().find_map(|a| a.strip_prefix("--worker=")) {
        return if mode == "wasm" {
            rinse_host::run(EMBEDDED_WORKER, |runner| {
                Some(ContentHandler::new(Wasm(WasmContent::from_runner(runner))))
            })
        } else {
            fault(&rinse_host::lockdown(), mode)
        };
    }
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        faults().await;
        real().await;
    });
    println!("mail-process: ok");
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
        "garbage" => write_frame(&mut stdout, &[0xff; 16]).expect("write"),
        "huge" => write_frame(&mut stdout, &vec![0u8; 2 << 20]).expect("write"),
        "error" => write_frame(
            &mut stdout,
            &postcard::to_stdvec(&Err::<(), _>(ContentError::PartNotFound)).expect("encode"),
        )
        .expect("write"),
        "memory" => {
            let v = vec![1u8; 4 << 30];
            std::hint::black_box(&v);
        }
        _ => return ExitCode::from(99),
    }
    ExitCode::SUCCESS
}

fn content(mode: &str, warm_workers: usize, policy: Policy) -> ProcessContent {
    let launcher = launcher();
    let mut config = ProcessConfig::new(WorkerCommand {
        program: std::env::current_exe().expect("test binary path"),
        args: vec![format!("--worker={mode}")],
    });
    config.warm_workers = warm_workers;
    config.policy = policy;
    ProcessContent::new(launcher, config)
}

fn request(name: &str, limits: ContentLimits) -> RenderRequest {
    RenderRequest {
        raw: Bytes::from_static(fixture(name)),
        options: RenderOptions::default(),
        limits,
    }
}

async fn render_err(mode: &str, limits: ContentLimits, policy: Policy) -> ContentError {
    content(mode, 0, policy)
        .render(request("text-only.eml", limits))
        .await
        .expect_err(mode)
}

async fn faults() {
    let policy = Policy::default();
    let quick = ContentLimits {
        time_budget_ms: 300,
        ..ContentLimits::default()
    };

    let started = Instant::now();
    assert_eq!(
        render_err("spin", quick, policy).await,
        ContentError::Timeout
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );

    for mode in ["abort", "exit", "garbage"] {
        assert_eq!(
            render_err(mode, ContentLimits::default(), policy).await,
            ContentError::Crashed,
            "{mode}"
        );
    }

    let small_output = ContentLimits {
        max_output_bytes: 1 << 20,
        ..ContentLimits::default()
    };
    assert_eq!(
        render_err("huge", small_output, policy).await,
        ContentError::LimitExceeded(LimitKind::Output)
    );

    let small_memory = Policy {
        memory_bytes: 256 << 20,
        ..policy
    };
    let memory = render_err("memory", ContentLimits::default(), small_memory).await;
    println!("over the memory limit: {memory:?}");
    if cfg!(target_os = "macos") {
        assert_eq!(memory, ContentError::LimitExceeded(LimitKind::Memory));
    } else {
        assert!(matches!(
            memory,
            ContentError::Crashed | ContentError::LimitExceeded(LimitKind::Memory)
        ));
    }

    let part = PartRequest {
        raw: Bytes::from_static(fixture("text-only.eml")),
        part: 1,
        limits: ContentLimits::default(),
    };
    assert_eq!(
        content("error", 0, policy)
            .decode_part(part)
            .await
            .unwrap_err(),
        ContentError::PartNotFound
    );

    let tiny_input = ContentLimits {
        max_input_bytes: 1,
        ..ContentLimits::default()
    };
    let launcher = launcher();
    let missing = ProcessContent::new(
        launcher,
        ProcessConfig::new(WorkerCommand {
            program: std::env::temp_dir().join("rinse-mail-no-such-worker"),
            args: Vec::new(),
        }),
    );
    assert_eq!(
        missing
            .render(request("text-only.eml", tiny_input))
            .await
            .unwrap_err(),
        ContentError::InputTooLarge
    );
    assert_eq!(
        missing
            .render(request("text-only.eml", ContentLimits::default()))
            .await
            .unwrap_err(),
        ContentError::Unavailable
    );
    assert_eq!(missing.probe().await, Err(ContentError::Unavailable));
    println!("fault cases: ok");
}

async fn real() {
    let wasm = content("wasm", 2, Policy::default());
    wasm.probe().await.expect("the sandboxed worker starts");
    wasm.warm_up();
    let started = Instant::now();
    let out = wasm
        .render(request("cid-image.eml", ContentLimits::default()))
        .await
        .expect("render in a sandboxed worker");
    assert_eq!(out.images.len(), 1);
    println!("first render: {:?}", started.elapsed());

    if cfg!(debug_assertions) {
        println!("skipping the conformance suite in an unoptimized build; run with --release");
        return;
    }
    let started = Instant::now();
    let renders = (0..4).map(|_| {
        let wasm = wasm.clone();
        async move {
            wasm.render(request("cid-image.eml", ContentLimits::default()))
                .await
                .map(|out| out.images.len())
        }
    });
    for result in futures_join(renders.collect()).await {
        assert_eq!(result, Ok(1));
    }
    println!("four concurrent renders: {:?}", started.elapsed());

    let started = Instant::now();
    rinse_mail::testing::run(Arc::new(wasm)).await;
    println!("conformance suite: {:?}", started.elapsed());
}

async fn futures_join<T: Send + 'static>(
    futures: Vec<impl Future<Output = T> + Send + 'static>,
) -> Vec<T> {
    let handles: Vec<_> = futures.into_iter().map(tokio::spawn).collect();
    let mut out = Vec::new();
    for handle in handles {
        out.push(handle.await.expect("task"));
    }
    out
}
