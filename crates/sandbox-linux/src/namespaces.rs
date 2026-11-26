#![allow(unsafe_code)]
//! `unshare(2)`, which rustix exposes only as an unsafe function because some flags (`FILES`)
//! can break file descriptor ownership between threads.

use rustix::thread::{UnshareFlags, unshare_unsafe};

/// Moves the process into new user, network, IPC and mount namespaces. The kernel refuses it in
/// a process with more than one thread, so it must run first in `main`.
pub(crate) fn unshare_namespaces() -> rustix::io::Result<()> {
    let flags =
        UnshareFlags::NEWUSER | UnshareFlags::NEWNET | UnshareFlags::NEWIPC | UnshareFlags::NEWNS;
    // SAFETY: the flags create new namespaces only; none of them (FILES, FS, SYSVSEM) changes
    // which file descriptors or file system state other threads of the process observe, and the
    // kernel rejects NEWUSER outright while more than one thread exists.
    unsafe { unshare_unsafe(flags) }
}
