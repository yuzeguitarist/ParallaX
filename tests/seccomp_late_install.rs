//! Dedicated-process integration test for the late seccomp memory-scrape denylist
//! (#195).
//!
//! # Why its own test binary
//!
//! `install_late_seccomp_filter` installs a process-wide (TSYNC) seccomp filter
//! plus `PR_SET_NO_NEW_PRIVS`. Both are irreversible for the life of the process
//! and apply to every thread, so running this inside the shared `cargo test`
//! harness would constrain every parallel test thread. The unit tests in
//! `src/process_hardening.rs` therefore cover the Linux behavior piecewise with a
//! *thread-local* `apply_filter`; this file covers the real, shipped,
//! all-threads entry point, and deliberately contains exactly ONE test so the
//! filter dies with this process.
//!
//! Non-Linux targets compile this to an empty test binary: the installer is a
//! logged no-op there.

#![cfg(target_os = "linux")]

use std::io;

/// Attempt to read this process's own memory via `process_vm_readv`.
///
/// Returns `Ok(())` when the read succeeded and `Err(errno)` otherwise. Reading
/// one's own address space is ordinarily permitted, so this is a clean probe for
/// whether the syscall itself has been trapped.
fn try_process_vm_readv_self() -> Result<(), i32> {
    let source = [0x41_u8; 8];
    let mut sink = [0_u8; 8];

    let local = libc::iovec {
        iov_base: sink.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: sink.len(),
    };
    let remote = libc::iovec {
        iov_base: source.as_ptr() as *mut libc::c_void,
        iov_len: source.len(),
    };

    // SAFETY: both iovecs point at live, correctly sized local buffers that
    // outlive the call, and the target pid is this process.
    let read = unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };

    if read < 0 {
        return Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO));
    }
    assert_eq!(
        sink, source,
        "process_vm_readv reported success but did not copy the bytes"
    );
    Ok(())
}

/// The denylist must actually take effect on the shipped, process-wide install
/// path: `process_vm_readv` succeeds before it and returns `EPERM` after.
///
/// Asserting the *before* state is what makes this a test of the filter rather
/// than of the environment — a sandbox that already blocks the syscall would
/// otherwise let a completely unwired installer pass.
#[test]
fn late_filter_eperms_memory_scrape_syscalls() {
    match try_process_vm_readv_self() {
        Ok(()) => {}
        Err(errno) => {
            // Some sandboxes (a hardened container's default seccomp profile,
            // a restrictive LSM) deny this before we install anything. There is
            // nothing left to prove here, and failing would report an
            // environment property as a ParallaX regression.
            eprintln!(
                "skipping: process_vm_readv is already denied in this environment \
                 (errno {errno}), so the pre/post comparison is not meaningful"
            );
            return;
        }
    }

    parallax::process_hardening::install_late_seccomp_filter();

    let errno = try_process_vm_readv_self()
        .expect_err("process_vm_readv must be trapped once the late filter is installed");
    assert_eq!(
        errno,
        libc::EPERM,
        "denied scrape syscalls must fail with EPERM (fail-closed to the caller, \
         process survives), not some other errno"
    );

    // The filter must trap the denylist WITHOUT breaking ordinary serving work:
    // the production call site sits directly in front of the accept() loop, so a
    // filter that killed or blocked normal syscalls would take the server down.
    let pid = unsafe { libc::getpid() };
    assert!(pid > 0, "getpid must still work behind the filter");
    std::fs::metadata(file!()).expect("filesystem syscalls must still work behind the filter");
}
