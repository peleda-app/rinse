//! A `rinse_host::run` executable (this test binary with `--serve-worker=<component>`), started
//! through this platform's launcher by `ProcessRunner`, runs the test component under the real
//! lockdown on both backends.

use std::process::ExitCode;
use std::time::Duration;

use rinse_process::worker::Serve;
use rinse_process::{ProcessConfig, ProcessError, ProcessRunner};
use rinse_sandbox::WorkerCommand;
use rinse_wasm::{Limits, WasmError, WasmRunner};

mod common;

const MODE: &str = "--serve-worker=";

struct Wasm(WasmRunner);

fn limits() -> Limits {
    Limits {
        time_budget: Duration::from_secs(3),
        max_output_bytes: 1 << 20,
        ..Limits::default()
    }
}

impl Serve for Wasm {
    fn warm_up(&self) -> bool {
        self.0.run_blocking(b"warm-up".to_vec(), &limits()).is_ok()
    }

    fn serve(&self, request: &[u8]) -> Option<Vec<u8>> {
        Some(match self.0.run_blocking(request.to_vec(), &limits()) {
            Ok(out) => [&[0u8][..], &out].concat(),
            Err(e) => vec![1, code(e)],
        })
    }
}

fn code(error: WasmError) -> u8 {
    match error {
        WasmError::Unavailable => 1,
        WasmError::Timeout => 2,
        WasmError::MemoryExceeded => 3,
        WasmError::OutputTooLarge => 4,
        WasmError::Crashed => 5,
    }
}

fn main() -> ExitCode {
    if let Some(component) = std::env::args().find_map(|a| a.strip_prefix(MODE).map(str::to_owned))
    {
        let bytes: &[u8] = if component == "test" {
            rinse_wasm_fixtures::TEST_WORKER
        } else {
            b"not a component"
        };
        return rinse_host::run(bytes, |runner| Some(Wasm(runner)));
    }
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        for args in [&[][..], &[rinse_host::PULLEY_ARG][..]] {
            let runner = runner("test", args);
            let call = |input: &'static [u8]| {
                let runner = runner.clone();
                async move {
                    runner
                        .call(input.to_vec(), Duration::from_secs(30), 2 << 20)
                        .await
                        .unwrap_or_else(|e| panic!("{args:?}: {e}"))
                }
            };
            assert_eq!(call(b"hello").await, b"\0hello");
            assert_eq!(
                String::from_utf8(call(b"probe").await).unwrap(),
                "\0env=0 args=0 root=denied cwd=denied tmp=denied tcp=denied wall=0"
            );
            assert_eq!(call(b"count").await, b"\x001");
            assert_eq!(
                call(b"spin").await,
                [1, code(WasmError::Timeout)],
                "{args:?}"
            );
            assert_eq!(call(b"hog").await, [1, code(WasmError::MemoryExceeded)]);
            assert_eq!(call(b"huge").await, [1, code(WasmError::OutputTooLarge)]);
            assert_eq!(call(b"panic").await, [1, code(WasmError::Crashed)]);
            println!("rinse-host {args:?}: ok ({})", runner.launcher_name());
        }
        let broken = runner("broken", &[]);
        assert_eq!(broken.probe().await, Err(ProcessError::Unavailable));
    });
    ExitCode::SUCCESS
}

fn runner(component: &str, args: &[&str]) -> ProcessRunner {
    let mut worker_args = vec![format!("{MODE}{component}")];
    worker_args.extend(args.iter().map(|a| (*a).to_owned()));
    let mut config = ProcessConfig::new(WorkerCommand {
        program: std::env::current_exe().expect("test binary path"),
        args: worker_args,
    });
    config.warm_workers = 0;
    ProcessRunner::new(common::launcher(), config)
}
