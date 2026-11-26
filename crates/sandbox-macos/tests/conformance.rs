//! The sandbox conformance suite with Seatbelt; this binary is also its own probe.

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    use std::sync::Arc;

    use rinse_sandbox::WorkerCommand;
    use rinse_sandbox::testing::{self, PROBE_ARG};
    use rinse_sandbox_macos::{MacosLauncher, SeatbeltLockdown};

    if testing::is_probe() {
        return testing::probe_main(&SeatbeltLockdown);
    }
    let probe = WorkerCommand {
        program: std::env::current_exe().expect("test binary path"),
        args: vec![PROBE_ARG.to_owned()],
    };
    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(testing::run(Arc::new(MacosLauncher), probe));
    println!("sandbox-macos conformance: ok");
    std::process::ExitCode::SUCCESS
}

#[cfg(not(target_os = "macos"))]
fn main() {}
