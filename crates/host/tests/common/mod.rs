use std::sync::Arc;

use rinse_sandbox::Launcher;

#[cfg(target_os = "macos")]
pub fn launcher() -> Arc<dyn Launcher> {
    Arc::new(rinse_sandbox_macos::MacosLauncher)
}

#[cfg(target_os = "linux")]
pub fn launcher() -> Arc<dyn Launcher> {
    Arc::new(rinse_sandbox_linux::LinuxLauncher::new())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn launcher() -> Arc<dyn Launcher> {
    Arc::new(rinse_sandbox_none::NoneLauncher)
}
