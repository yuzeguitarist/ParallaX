use std::{io, sync::OnceLock};

const HARDEN_TRANSIENT_ENV: &str = "PARALLAX_HARDEN_TRANSIENT_PLAINTEXT";

/// Apply process-local hardening for long-running ParallaX runtimes.
///
/// These settings are best-effort and intentionally do not fail startup: a
/// deployment with a tight `RLIMIT_MEMLOCK`, older kernel, or non-Linux target
/// should keep serving traffic rather than break the protocol path.
pub fn harden_current_process() {
    if let Err(err) = disable_core_dumps() {
        tracing::warn!(error = %err, "failed to disable core dumps for this process");
    }
    if let Err(err) = disable_ptrace_dumpability() {
        tracing::warn!(error = %err, "failed to mark this process non-dumpable");
    }
}

/// Mark key material as excluded from core dumps and try to pin its pages.
///
/// Locking is deliberately scoped to small, long-lived secret buffers. If the
/// kernel refuses the lock because the process has a small memlock limit, the
/// memory remains protected by the process-level dump controls and
/// `MADV_DONTDUMP` where available.
pub fn protect_secret_bytes(label: &'static str, bytes: &[u8]) {
    exclude_from_core_dump(label, bytes);
    if let Err(err) = lock_memory(bytes) {
        tracing::warn!(
            label,
            error = %err,
            "failed to mlock sensitive memory; continuing without swap pinning"
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
    *ENABLED.get_or_init(|| {
        std::env::var(HARDEN_TRANSIENT_ENV)
            .is_ok_and(|value| transient_plaintext_setting_enabled(&value))
    })
}

fn transient_plaintext_setting_enabled(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}
#[cfg(unix)]
fn disable_core_dumps() -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `setrlimit` only receives a pointer to a stack-allocated
    // immutable `rlimit` and affects the current process.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn disable_core_dumps() -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn disable_ptrace_dumpability() -> io::Result<()> {
    // SAFETY: `prctl(PR_SET_DUMPABLE, 0)` changes only the current process'
    // dumpable flag and does not dereference any user-provided pointer.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn disable_ptrace_dumpability() -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn dontdump_memory(bytes: &[u8]) -> io::Result<()> {
    let Some((addr, len)) = page_aligned_range(bytes.as_ptr() as usize, bytes.len()) else {
        return Ok(());
    };
    // SAFETY: the address/length pair is page-aligned and covers live memory
    // belonging to this process. `MADV_DONTDUMP` changes VMA dump metadata only.
    if unsafe { libc::madvise(addr as *mut libc::c_void, len, libc::MADV_DONTDUMP) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn dontdump_memory(_bytes: &[u8]) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn lock_memory(bytes: &[u8]) -> io::Result<()> {
    let Some((addr, len)) = page_aligned_range(bytes.as_ptr() as usize, bytes.len()) else {
        return Ok(());
    };
    // SAFETY: the address/length pair is page-aligned and covers live memory
    // belonging to this process. The lock is intentionally process-lifetime
    // best-effort; the kernel releases it on exit.
    if unsafe { libc::mlock(addr as *const libc::c_void, len) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn lock_memory(_bytes: &[u8]) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn page_aligned_range(addr: usize, len: usize) -> Option<(usize, usize)> {
    page_aligned_range_with_size(addr, len, page_size())
}

#[cfg(target_os = "linux")]
fn page_size() -> usize {
    static PAGE_SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *PAGE_SIZE.get_or_init(query_page_size)
}

#[cfg(target_os = "linux")]
fn query_page_size() -> usize {
    // SAFETY: `sysconf(_SC_PAGESIZE)` has no pointer arguments and no memory
    // safety requirements.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 {
        size as usize
    } else {
        4096
    }
}

#[cfg(any(target_os = "linux", test))]
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
        page_aligned_range_with_size, transient_plaintext_hardening_enabled,
        transient_plaintext_setting_enabled,
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
        assert!(!transient_plaintext_hardening_enabled());
    }
}
