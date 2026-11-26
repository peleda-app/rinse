//! The sandbox conformance suite on Linux, plus checks of single layers; this binary is also its
//! own probe.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use std::sync::Arc;

    use rinse_sandbox::testing::{self, Outcome, PROBE_ARG};
    use rinse_sandbox::{Launcher, Policy, Restriction, WorkerCommand};
    use rinse_sandbox_linux::{LinuxLauncher, LinuxLockdown};

    const WITHOUT_SECCOMP: &str = "--without-seccomp";

    if testing::is_probe() {
        let seccomp = !std::env::args().any(|a| a == WITHOUT_SECCOMP);
        return testing::probe_main(&LinuxLockdown::default().with_seccomp(seccomp));
    }
    let program = std::env::current_exe().expect("test binary path");
    let probe = WorkerCommand {
        program: program.clone(),
        args: vec![PROBE_ARG.to_owned()],
    };
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let full: Arc<dyn Launcher> = Arc::new(LinuxLauncher::new());
        let report = {
            let worker = full
                .launch(&probe, &Policy::default())
                .await
                .expect("launch");
            worker.report().clone()
        };
        println!("lockdown report: {report:?}");

        let layered: Arc<dyn Launcher> = Arc::new(LinuxLauncher::new().requiring(&[]));
        let without_seccomp = WorkerCommand {
            program: program.clone(),
            args: vec![PROBE_ARG.to_owned(), WITHOUT_SECCOMP.to_owned()],
        };
        if report.has(Restriction::Landlock) {
            for request in [
                "read:/etc/passwd",
                "list:/",
                "write:/tmp/rinse-landlock-probe",
            ] {
                let outcome =
                    testing::outcome(&layered, &without_seccomp, &Policy::default(), request).await;
                println!("landlock only, {request}: {outcome:?}");
                assert_eq!(outcome, Outcome::Denied, "Landlock let {request} through");
            }
        }
        if report.has(Restriction::NetworkNamespace) || report.has(Restriction::Landlock) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("listener");
            let request = format!("connect:{}", listener.local_addr().expect("address"));
            let outcome =
                testing::outcome(&layered, &without_seccomp, &Policy::default(), &request).await;
            println!("without seccomp, {request}: {outcome:?}");
            assert_eq!(outcome, Outcome::Denied);
        }

        testing::run(full, probe).await;
    });
    println!("sandbox-linux conformance: ok");
    std::process::ExitCode::SUCCESS
}

#[cfg(not(target_os = "linux"))]
fn main() {}
