//! The child side of a sandboxed WebAssembly worker, for a worker executable's `main`.
//!
//! [`run`] picks this platform's [`Lockdown`] (Seatbelt on macOS, namespaces, Landlock and
//! seccomp on Linux, none elsewhere), compiles the component while the process may still allocate
//! executable memory and start threads, warms up, locks down, announces the lockdown, serves
//! exactly one request through [`rinse_process::worker::worker_main`] and returns the exit code.
//!
//! Arguments it understands: `--backend=pulley` runs the component on Wasmtime's interpreter
//! instead of native code; with the `probe` feature (tests only) `--rinse-sandbox-probe` turns
//! the executable into the probe of the `rinse-sandbox` conformance suite under the same
//! lockdown.

#[cfg(all(feature = "probe", not(debug_assertions)))]
compile_error!("the `probe` feature is for tests only and must never reach a release build");

use std::process::ExitCode;

use rinse_process::worker::{Serve, worker_main};
use rinse_sandbox::Lockdown;
use rinse_wasm::{Backend, WasmRunner};

/// The argument that selects [`Backend::Pulley`].
pub const PULLEY_ARG: &str = "--backend=pulley";

/// This platform's lockdown: what a worker applies to itself before it reads input.
#[cfg(target_os = "macos")]
pub fn lockdown() -> impl Lockdown {
    rinse_sandbox_macos::SeatbeltLockdown
}

/// This platform's lockdown: what a worker applies to itself before it reads input.
#[cfg(target_os = "linux")]
pub fn lockdown() -> impl Lockdown {
    rinse_sandbox_linux::LinuxLockdown::default()
}

/// This platform's lockdown: none (not a wall), until a Windows sandbox exists.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn lockdown() -> impl Lockdown {
    rinse_sandbox_none::NoLockdown
}

/// [`Backend::Pulley`] when `args` hold [`PULLEY_ARG`], [`Backend::Native`] otherwise.
pub fn backend_from_args<I, S>(args: I) -> Backend
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    if args.into_iter().any(|a| a.as_ref() == PULLEY_ARG) {
        Backend::Pulley
    } else {
        Backend::Native
    }
}

/// Runs this process as a worker: `component` is compiled with the backend chosen by the
/// arguments, `make` turns the compiled runner into the server of the one request, and the rest
/// is [`worker_main`] with this platform's [`lockdown`] (see its exit codes; a component that does
/// not compile or a `make` that returns `None` exit with 4 before the lockdown).
pub fn run<S: Serve>(component: &[u8], make: impl FnOnce(WasmRunner) -> Option<S>) -> ExitCode {
    let lockdown = lockdown();
    #[cfg(feature = "probe")]
    if rinse_sandbox::testing::is_probe() {
        return rinse_sandbox::testing::probe_main(&lockdown);
    }
    let backend = backend_from_args(std::env::args());
    worker_main(&lockdown, |_| {
        WasmRunner::new(component, backend).ok().and_then(make)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_the_backend_from_the_arguments() {
        assert_eq!(backend_from_args(["worker"]), Backend::Native);
        assert_eq!(backend_from_args(["worker", PULLEY_ARG]), Backend::Pulley);
        assert_eq!(
            backend_from_args(["worker", "--backend=pulley2"]),
            Backend::Native
        );
        assert_eq!(backend_from_args(Vec::<String>::new()), Backend::Native);
    }
}
