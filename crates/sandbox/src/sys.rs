#![allow(unsafe_code)]
//! Raw descriptor and memory calls without a safe binding: closing descriptors a worker inherited
//! by number, and the probe operations of the conformance suite that act on a raw descriptor
//! number or shared memory.

#[cfg(unix)]
fn open_descriptors() -> std::io::Result<Vec<i32>> {
    let dir = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    let mut fds = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        if let Some(fd) = entry?.file_name().to_str().and_then(|n| n.parse().ok()) {
            fds.push(fd);
        }
    }
    Ok(fds)
}

/// Closes every descriptor above stderr. Runs while the process has a single thread, so no
/// descriptor number it closes can belong to another thread.
#[cfg(unix)]
pub(crate) fn close_inherited_descriptors() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: close_range takes three integers and touches no memory of this process; the
        // descriptors it closes are owned by no Rust value this early in `main`.
        let status = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3 as libc::c_uint,
                libc::c_uint::MAX,
                0 as libc::c_uint,
            )
        };
        if status == 0 {
            return Ok(());
        }
    }
    let fds = match open_descriptors() {
        Ok(fds) => fds,
        Err(_) => {
            let limit = rustix::process::getrlimit(rustix::process::Resource::Nofile)
                .current
                .unwrap_or(1 << 16)
                .min(1 << 20);
            (3..i32::try_from(limit).unwrap_or(1 << 20)).collect()
        }
    };
    for fd in fds.into_iter().filter(|&fd| fd > 2) {
        // SAFETY: closing a number that is not open fails with EBADF and nothing else; the open
        // ones were inherited and are owned by no Rust value this early in `main`.
        unsafe { libc::close(fd) };
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn close_inherited_descriptors() -> std::io::Result<()> {
    Ok(())
}

/// Writes `bytes` to descriptor number `fd`; whether the write succeeded.
#[cfg(all(unix, feature = "testing"))]
pub(crate) fn write_descriptor(fd: i32, bytes: &[u8]) -> bool {
    // SAFETY: `bytes` is a readable buffer of `bytes.len()` bytes for the whole call; a number
    // that is not open fails with EBADF.
    unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) > 0 }
}

/// Asks the kernel to signal `pid` (with `signal` where the platform can choose it) whenever
/// stdout becomes writable; whether every step succeeded.
#[cfg(all(unix, feature = "testing"))]
pub(crate) fn request_signals(pid: i32, signal: i32) -> bool {
    let _ = signal;
    // SAFETY: fcntl with F_SETOWN takes an integer argument and touches no memory.
    if unsafe { libc::fcntl(1, libc::F_SETOWN, pid) } != 0 {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        const F_SETSIG: libc::c_int = 10;
        // SAFETY: fcntl with F_SETSIG takes an integer argument and touches no memory.
        if unsafe { libc::fcntl(1, F_SETSIG, signal) } != 0 {
            return false;
        }
    }
    // SAFETY: fcntl with F_GETFL takes no argument and touches no memory.
    let flags = unsafe { libc::fcntl(1, libc::F_GETFL) };
    // SAFETY: fcntl with F_SETFL takes an integer argument and touches no memory.
    flags >= 0 && unsafe { libc::fcntl(1, libc::F_SETFL, flags | libc::O_ASYNC) } == 0
}

/// Maps `bytes` of shared anonymous memory and writes to every page; whether that worked.
#[cfg(all(unix, feature = "testing"))]
pub(crate) fn touch_shared_memory(bytes: usize) -> bool {
    if bytes == 0 {
        return false;
    }
    // SAFETY: a fresh anonymous mapping at an address the kernel chooses overlaps no existing
    // memory; the result is checked before use.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return false;
    }
    let base = ptr.cast::<u8>();
    for offset in (0..bytes).step_by(4096) {
        // SAFETY: `offset < bytes`, so the byte lies inside the readable and writable mapping.
        unsafe { base.add(offset).write_volatile(1) };
    }
    // SAFETY: `ptr` and `bytes` describe exactly the mapping created above, used nowhere else.
    unsafe { libc::munmap(ptr, bytes) };
    true
}
