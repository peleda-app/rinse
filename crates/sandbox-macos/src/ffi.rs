#![allow(unsafe_code)]
//! The two macOS calls without a safe binding: `sandbox_init` (Seatbelt) and `proc_pid_rusage`
//! (the memory footprint of a child).

use std::ffi::{CStr, CString, c_char, c_int};

unsafe extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// Applies an SBPL profile to the calling process. `Err` holds Seatbelt's message, which names
/// the faulty part of the profile and nothing else.
pub(crate) fn apply_profile(profile: &str) -> Result<(), String> {
    let profile = CString::new(profile).map_err(|_| "profile holds a NUL byte".to_owned())?;
    let mut error: *mut c_char = std::ptr::null_mut();
    // SAFETY: `profile` is a NUL-terminated string that outlives the call; flags 0 means the
    // string is SBPL source; `error` is a valid out-pointer that Seatbelt sets to NULL or to a
    // string it allocated.
    let status = unsafe { sandbox_init(profile.as_ptr(), 0, &mut error) };
    if status == 0 {
        return Ok(());
    }
    if error.is_null() {
        return Err(format!("sandbox_init failed with {status}"));
    }
    // SAFETY: Seatbelt set `error` to a NUL-terminated string it allocated; it is read once here.
    let message = unsafe { CStr::from_ptr(error) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: `error` came from `sandbox_init` and is freed exactly once with its own deallocator.
    unsafe { sandbox_free_error(error) };
    Err(message)
}

/// The physical footprint of process `pid` in bytes, as Activity Monitor's "Memory" column
/// shows it; `None` when the process is gone or not visible.
pub(crate) fn footprint(pid: u32) -> Option<u64> {
    let pid = c_int::try_from(pid).ok()?;
    let mut info = std::mem::MaybeUninit::<libc::rusage_info_v2>::zeroed();
    // SAFETY: `info` is a writable buffer of the size the RUSAGE_INFO_V2 flavor fills; the pid is
    // only read by the kernel.
    let status =
        unsafe { libc::proc_pid_rusage(pid, libc::RUSAGE_INFO_V2, info.as_mut_ptr().cast()) };
    if status != 0 {
        return None;
    }
    // SAFETY: the call succeeded, so the kernel filled the whole structure (it was also zeroed).
    Some(unsafe { info.assume_init() }.ri_phys_footprint)
}
