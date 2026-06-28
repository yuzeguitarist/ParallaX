use std::{io, sync::OnceLock};

const HARDEN_TRANSIENT_ENV: &str = "PARALLAX_HARDEN_TRANSIENT_PLAINTEXT";
const DISABLE_ANTI_DEBUG_ENV: &str = "PARALLAX_DISABLE_ANTI_DEBUG";

/// Apply process-local hardening for long-running ParallaX runtimes.
///
/// These settings are best-effort and intentionally do not fail startup: a
/// deployment with a tight `RLIMIT_MEMLOCK`, older kernel, or non-Linux target
/// should keep serving traffic rather than break the protocol path.
///
/// Platform coverage: core dumps are disabled on every unix
/// (`setrlimit(RLIMIT_CORE, 0)`); debugger-attach resistance uses
/// `PR_SET_DUMPABLE` on Linux, `ptrace(PT_DENY_ATTACH)` on macOS, and
/// `procctl(PROC_TRACE_CTL)` on FreeBSD.
///
/// Anti-debug is on by default but honors `PARALLAX_DISABLE_ANTI_DEBUG`: on
/// macOS `ptrace(PT_DENY_ATTACH)` *terminates the process if it is already being
/// traced*, so an operator who must run under a debugger or an attaching crash
/// reporter can set that variable to skip the step and let startup proceed.
pub fn harden_current_process() {
    if let Err(err) = disable_core_dumps() {
        tracing::warn!(error = %err, "failed to disable core dumps for this process");
    }
    // Gated so a deployment that needs a debugger / crash reporter can opt out
    // rather than have macOS PT_DENY_ATTACH abort startup under a pre-existing
    // tracer (the syscall exits the process when it is already traced).
    if anti_debug_enabled() {
        if let Err(err) = disable_ptrace_dumpability() {
            tracing::warn!(error = %err, "failed to mark this process non-dumpable");
        }
    }
}

/// Anti-debug hardening is on unless `PARALLAX_DISABLE_ANTI_DEBUG` is truthy.
fn anti_debug_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED
        .get_or_init(|| !std::env::var(DISABLE_ANTI_DEBUG_ENV).is_ok_and(|v| env_flag_truthy(&v)))
}

/// Mark key material as excluded from core dumps and try to pin its pages.
///
/// `mlock` runs on every unix target (macOS and the BSDs included, not just
/// Linux), so the highest-value long-lived keys are kept out of swap there too.
/// If the kernel refuses the lock because the process has a small
/// `RLIMIT_MEMLOCK`, the secret still benefits from the process-level dump
/// controls and, where the platform offers per-VMA exclusion, `MADV_DONTDUMP`
/// (Linux) / `MADV_NOCORE` (FreeBSD). macOS has no per-VMA dump exclusion, so
/// there swap protection rests on `mlock` with `RLIMIT_CORE = 0` covering core
/// dumps.
///
/// Acts at page granularity, so apply only to secrets held at a stable, owned
/// address for their lifetime. The lock is process-lifetime best-effort: the
/// kernel releases it at exit. We intentionally do NOT `munlock` per-secret on
/// drop, because a sub-page secret can share its page with other still-live
/// secrets the allocator packed alongside it, and `munlock`/`MADV_DODUMP` act on
/// the whole page — a per-secret release would un-pin a live neighbor.
///
/// Because nothing is released until exit, the locked-page set grows with the
/// high-water mark of pages that have ever held a protected secret (not the
/// instantaneous live set). The long-lived crown-jewel secrets (PSK, static
/// identity / ML-KEM private keys) are locked once at startup, before any
/// connection, so they stay pinned; per-connection session keys are locked
/// afterwards and, on a host with a small `RLIMIT_MEMLOCK` under heavy churn,
/// may exhaust the budget and fall back to core-dump exclusion only. Raise
/// `RLIMIT_MEMLOCK` if per-session swap-pinning must hold past warmup.
pub fn protect_secret_bytes(label: &'static str, bytes: &[u8]) {
    exclude_from_core_dump(label, bytes);
    if let Err(err) = lock_memory(bytes) {
        warn_mlock_failed_once(label, &err);
    }
}

/// Warn at most once that swap-pinning is degraded. `protect_secret_bytes` runs
/// per connection, so an exhausted `RLIMIT_MEMLOCK` would otherwise log on every
/// session; a single actionable warning is enough.
fn warn_mlock_failed_once(label: &'static str, err: &io::Error) {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(
            label,
            error = %err,
            "failed to mlock sensitive memory; swap-pinning degraded for this and \
             subsequent secrets (raise RLIMIT_MEMLOCK to restore). This warning is one-shot."
        );
    }
}

/// Exclude transient plaintext buffers from Linux core dumps without pinning
/// them in RAM.
pub fn exclude_from_core_dump(label: &'static str, bytes: &[u8]) {
    if let Err(err) = dontdump_memory(bytes) {
        tracing::warn!(
            label,
            error = %err,
            "failed to exclude sensitive memory from core dumps"
        );
    }
}

/// Exclude hot-path transient plaintext only when explicitly requested.
///
/// Long-lived secrets are always protected through [`protect_secret_bytes`].
/// Per-record relay plaintext would otherwise issue a Linux `madvise` syscall
/// for every sealed/opened record, which dominates high-throughput data-plane
/// traffic. Operators that prefer this extra transient-buffer hardening can set
/// `PARALLAX_HARDEN_TRANSIENT_PLAINTEXT=1`.
pub fn exclude_transient_from_core_dump(label: &'static str, bytes: &[u8]) {
    if transient_plaintext_hardening_enabled() {
        exclude_from_core_dump(label, bytes);
    }
}

fn transient_plaintext_hardening_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED
        .get_or_init(|| transient_plaintext_setting_from_env(std::env::var(HARDEN_TRANSIENT_ENV)))
}

/// Pure decision for the transient-hardening toggle: an absent var is off, a
/// present var is truthy per [`transient_plaintext_setting_enabled`]. Extracted
/// so it can be tested with synthesized inputs (no ambient env / global state).
fn transient_plaintext_setting_from_env(value: Result<String, std::env::VarError>) -> bool {
    value.is_ok_and(|value| transient_plaintext_setting_enabled(&value))
}

fn transient_plaintext_setting_enabled(value: &str) -> bool {
    env_flag_truthy(value)
}

/// Whether an environment-variable value reads as a truthy boolean flag. Shared by
/// every `PARALLAX_*` on/off toggle so they accept the same spellings; named
/// neutrally (not after any one toggle) since it backs more than the transient
/// plaintext setting.
fn env_flag_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}
#[cfg(unix)]
fn disable_core_dumps() -> io::Result<()> {
    use rustix::process::{setrlimit, Resource, Rlimit};

    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(Into::into)
}

#[cfg(not(unix))]
fn disable_core_dumps() -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn disable_ptrace_dumpability() -> io::Result<()> {
    use rustix::process::{set_dumpable_behavior, DumpableBehavior};

    // `prctl(PR_SET_DUMPABLE, 0)`: clears the dumpable flag so a non-root process
    // can no longer be ptrace-attached / core-dumped.
    set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(Into::into)
}

#[cfg(target_os = "macos")]
fn disable_ptrace_dumpability() -> io::Result<()> {
    // SAFETY: `ptrace(PT_DENY_ATTACH)` passes a null `addr` and `0` data, takes
    // no user pointer we must keep valid, and only sets the current process'
    // deny-attach flag (resisting a later debugger attach / `task_for_pid`).
    if unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "freebsd")]
fn disable_ptrace_dumpability() -> io::Result<()> {
    let mut ctl: libc::c_int = libc::PROC_TRACE_CTL_DISABLE;
    // SAFETY: `procctl(PROC_TRACE_CTL)` reads one `c_int` through `data` for the
    // current process (`P_PID` + own pid); `&mut ctl` is a live stack int for
    // the duration of the call.
    if unsafe {
        libc::procctl(
            libc::P_PID,
            libc::getpid() as libc::id_t,
            libc::PROC_TRACE_CTL,
            &mut ctl as *mut libc::c_int as *mut libc::c_void,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
fn disable_ptrace_dumpability() -> io::Result<()> {
    Ok(())
}

/// Apply a `madvise` core-dump-exclusion advice to the page-aligned range
/// spanning `bytes` (Linux `MADV_DONTDUMP` / FreeBSD `MADV_NOCORE`).
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn madvise_range(bytes: &[u8], advice: libc::c_int) -> io::Result<()> {
    let Some((addr, len)) = page_aligned_range(bytes.as_ptr() as usize, bytes.len()) else {
        return Ok(());
    };
    // Miri cannot execute the `madvise` foreign function. It only adjusts VMA
    // core-dump metadata (no effect observable from program logic), so under Miri
    // treat it as a successful no-op; this keeps the pure-logic codec tests in the
    // Miri lane runnable. `cfg(miri)` is set only by the Miri interpreter, never
    // in a real build, so production behavior is unchanged.
    #[cfg(miri)]
    {
        let _ = (addr, len, advice);
        return Ok(());
    }
    #[cfg(not(miri))]
    {
        // SAFETY: the address/length pair is page-aligned and covers live memory
        // belonging to this process. `madvise` changes VMA dump metadata only.
        if unsafe { libc::madvise(addr as *mut libc::c_void, len, advice) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(target_os = "linux")]
fn dontdump_memory(bytes: &[u8]) -> io::Result<()> {
    madvise_range(bytes, libc::MADV_DONTDUMP)
}

#[cfg(target_os = "freebsd")]
fn dontdump_memory(bytes: &[u8]) -> io::Result<()> {
    madvise_range(bytes, libc::MADV_NOCORE)
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn dontdump_memory(_bytes: &[u8]) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn lock_memory(bytes: &[u8]) -> io::Result<()> {
    let Some((addr, len)) = page_aligned_range(bytes.as_ptr() as usize, bytes.len()) else {
        return Ok(());
    };
    // SAFETY: the address/length pair is page-aligned and covers live memory
    // belonging to this process. The lock is intentionally process-lifetime
    // best-effort; the kernel releases it on exit (see `protect_secret_bytes` for
    // why we do not `munlock` per-secret).
    if unsafe { libc::mlock(addr as *const libc::c_void, len) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn lock_memory(_bytes: &[u8]) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn page_aligned_range(addr: usize, len: usize) -> Option<(usize, usize)> {
    page_aligned_range_with_size(addr, len, page_size())
}

#[cfg(unix)]
fn page_size() -> usize {
    static PAGE_SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *PAGE_SIZE.get_or_init(query_page_size)
}

#[cfg(unix)]
fn query_page_size() -> usize {
    rustix::param::page_size()
}

#[cfg(any(unix, test))]
fn page_aligned_range_with_size(
    addr: usize,
    len: usize,
    page_size: usize,
) -> Option<(usize, usize)> {
    if len == 0 || page_size == 0 {
        return None;
    }
    let end = addr.checked_add(len)?;
    let start_page = addr / page_size * page_size;
    let end_page = end.checked_add(page_size - 1)? / page_size * page_size;
    Some((start_page, end_page.checked_sub(start_page)?))
}

#[cfg(test)]
mod tests {
    use super::{
        page_aligned_range_with_size, transient_plaintext_setting_enabled,
        transient_plaintext_setting_from_env,
    };

    #[test]
    fn page_range_covers_unaligned_buffer() {
        assert_eq!(
            page_aligned_range_with_size(0x1003, 16, 4096),
            Some((0x1000, 4096))
        );
    }

    #[test]
    fn page_range_spans_multiple_pages() {
        assert_eq!(
            page_aligned_range_with_size(0x1ff0, 64, 4096),
            Some((0x1000, 8192))
        );
    }

    #[test]
    fn empty_range_needs_no_syscall() {
        assert_eq!(page_aligned_range_with_size(0x1000, 0, 4096), None);
    }

    #[test]
    fn transient_plaintext_setting_requires_explicit_enable() {
        for enabled in ["1", "true", "TRUE", "yes", "on", " on "] {
            assert!(transient_plaintext_setting_enabled(enabled));
        }
        for disabled in ["", "0", "false", "off", "no", "random"] {
            assert!(!transient_plaintext_setting_enabled(disabled));
        }
    }

    #[test]
    fn transient_plaintext_setting_defaults_off() {
        // Absent var (the real default) is off regardless of any ambient value; a
        // present-but-empty var is off too. Pure inputs, no process-global state.
        assert!(!transient_plaintext_setting_from_env(Err(
            std::env::VarError::NotPresent
        )));
        assert!(!transient_plaintext_setting_from_env(Ok(String::new())));
    }

    // On unix, protecting a stable heap buffer exercises the real mlock (+ madvise
    // on Linux/FreeBSD) path and must never panic. Locking may fail under a tight
    // RLIMIT_MEMLOCK; protect_secret_bytes swallows that error, so the contract
    // under test is "never panics" rather than "always locks".
    #[cfg(unix)]
    #[test]
    fn protect_secret_bytes_does_not_panic() {
        let secret = vec![0x5a_u8; 64];
        super::protect_secret_bytes("test.secret", &secret);
    }
}
