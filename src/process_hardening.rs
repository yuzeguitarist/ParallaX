use std::{io, sync::OnceLock};

use rand::{rngs::OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

const HARDEN_TRANSIENT_ENV: &str = "PARALLAX_HARDEN_TRANSIENT_PLAINTEXT";
const DISABLE_ANTI_DEBUG_ENV: &str = "PARALLAX_DISABLE_ANTI_DEBUG";

/// A long-lived secret kept XOR-masked in memory while idle (#3, obfuscated
/// residency).
///
/// The secret bytes are stored as `masked = plaintext XOR mask`, where `mask` is
/// a process-random one-time pad generated at construction. The plaintext only
/// materializes inside [`MaskedSecret::with_plaintext`], in a short-lived
/// `Zeroizing` scratch that is wiped the instant the closure returns.
///
/// ## What this does and does NOT buy
///
/// A ring-0 / malicious-OS attacker can dump both `masked` and `mask` from this
/// process and recombine them — this is NOT a defense against a kernel compromise,
/// and nothing user-space can be. What it raises is the cost of an *opportunistic*
/// memory scrape: the secret is not sitting in RAM as a contiguous high-entropy
/// blob a `memmem` sweep can lift; an attacker must grab two regions and know to
/// XOR them, and a snapshot taken outside the (rare, brief) sign window contains
/// no recoverable plaintext at all. Use it only for LOW-FREQUENCY secrets (e.g.
/// the once-per-connection identity signing key) — the unmask cost is paid on
/// every access, so it is wrong for hot-path keys.
///
/// `mask` and `masked` are both `mlock`'d (locked once at construction, stable
/// addresses) and zeroized on drop. The transient unmasked scratch in
/// [`MaskedSecret::with_plaintext`] is `Zeroizing` (wiped on return) and is
/// core-dump-excluded (`MADV_DONTDUMP` per call, plus the process-wide
/// `RLIMIT_CORE=0` and non-dumpable flag), but is deliberately NOT
/// `mlock`'d per-use — see that method for why locking a per-call allocation would
/// regress the long-lived keys' pinning. So the resident halves are swap-pinned;
/// the brief plaintext-at-use is not, and could touch swap in its short window.
pub struct MaskedSecret {
    masked: Vec<u8>,
    mask: Vec<u8>,
}

impl MaskedSecret {
    /// Mask `secret` under a fresh process-random pad. The caller's plaintext copy
    /// should be dropped/zeroized after handing it in (callers pass a `Zeroizing`).
    pub fn new(secret: &[u8]) -> Self {
        let mut mask = vec![0_u8; secret.len()];
        OsRng.fill_bytes(&mut mask);
        let mut masked = vec![0_u8; secret.len()];
        for ((m, k), s) in masked.iter_mut().zip(mask.iter()).zip(secret.iter()) {
            *m = s ^ k;
        }
        // Keep both halves out of swap and core dumps, like any other resident key.
        protect_secret_bytes("masked_secret.masked", &masked);
        protect_secret_bytes("masked_secret.mask", &mask);
        Self { masked, mask }
    }

    /// Length of the underlying secret.
    pub fn len(&self) -> usize {
        self.masked.len()
    }

    pub fn is_empty(&self) -> bool {
        self.masked.is_empty()
    }

    /// Unmask into a transient `Zeroizing` scratch, run `f` against the plaintext,
    /// and wipe the scratch on return. The plaintext never outlives the closure.
    ///
    /// The scratch is deliberately NOT `mlock`'d. `protect_secret_bytes` never
    /// `munlock`s (it is built for lifetime-stable secrets on shared pages), so
    /// locking a fresh per-call allocation would pin a new page on every connection
    /// and never release it — growing the locked-page high-water mark until it
    /// exhausts `RLIMIT_MEMLOCK` and starves the genuine long-lived keys (PSK,
    /// X25519/ML-KEM static) of their pinning. That regression is worse than the
    /// exposure it would close, so the brief unmask window relies instead on
    /// core-dump exclusion (per-page `MADV_DONTDUMP` applied before unmasking,
    /// on top of the process-wide `RLIMIT_CORE=0` + non-dumpable flag) plus
    /// immediate `Zeroizing` wipe. The masked/mask halves remain mlock'd
    /// (stable, locked once). This is a low-frequency path (once-per-connection
    /// signing), so the per-call `madvise` cost is irrelevant.
    pub fn with_plaintext<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        let mut plaintext = Zeroizing::new(vec![0_u8; self.masked.len()]);
        exclude_from_core_dump("masked_secret.plaintext", &plaintext);
        for ((p, m), k) in plaintext
            .iter_mut()
            .zip(self.masked.iter())
            .zip(self.mask.iter())
        {
            *p = m ^ k;
        }
        f(&plaintext)
    }
}

impl Drop for MaskedSecret {
    fn drop(&mut self) {
        self.masked.zeroize();
        self.mask.zeroize();
    }
}

/// Apply process-local hardening for long-running ParallaX runtimes.
///
/// These settings are best-effort and intentionally do not fail startup: a
/// deployment with a tight `RLIMIT_MEMLOCK`, older kernel, or non-Linux target
/// should keep serving traffic rather than break the protocol path.
///
/// Platform coverage: core dumps are disabled on every unix
/// (`setrlimit(RLIMIT_CORE, 0)`); dumpability / debugger-attach resistance uses
/// `PR_SET_DUMPABLE` on Linux, `ptrace(PT_DENY_ATTACH)` on macOS, and
/// `procctl(PROC_TRACE_CTL)` on FreeBSD. On Linux and FreeBSD the dumpability
/// disable runs unconditionally (#247): `RLIMIT_CORE = 0` alone does not stop a
/// piped `core_pattern` handler from capturing memory, so the dumpable flag is
/// the exclusion that actually holds there.
///
/// Anti-debug is on by default but honors `PARALLAX_DISABLE_ANTI_DEBUG`: on
/// macOS `ptrace(PT_DENY_ATTACH)` *terminates the process if it is already being
/// traced*, so an operator who must run under a debugger or an attaching crash
/// reporter can set that variable to skip the step and let startup proceed.
pub fn harden_current_process() {
    if let Err(err) = disable_core_dumps() {
        tracing::warn!(error = %err, "failed to disable core dumps for this process");
    }
    // #247: `RLIMIT_CORE = 0` does not stop a piped `core_pattern` handler
    // (e.g. systemd-coredump) from capturing process memory; clearing the
    // dumpable flag is the reliable core-dump exclusion, so it must apply even
    // when anti-debug is opted out. Only macOS keeps it behind the gate:
    // `ptrace(PT_DENY_ATTACH)` *terminates the process if it is already being
    // traced*, which is exactly what the opt-out exists to avoid.
    if should_disable_dumpability(anti_debug_enabled()) {
        if let Err(err) = disable_ptrace_dumpability() {
            tracing::warn!(error = %err, "failed to mark this process non-dumpable");
        }
    }
    if anti_debug_enabled() {
        warn_if_already_traced();
    }
}

/// Install a **best-effort seccomp-BPF denylist** that returns `EPERM` for the
/// cheapest live-memory-scrape / anti-forensics syscalls, after first setting
/// `PR_SET_NO_NEW_PRIVS`. Linux-only; a no-op on every other target.
///
/// # What it denies (everything else is ALLOWED)
///
/// This is a **denylist**, not an allowlist: the default action is
/// `SeccompAction::Allow`, and only these syscalls are trapped to `EPERM`:
///
/// - `ptrace` — attach / peek / poke another task's memory & registers.
/// - `process_vm_readv` / `process_vm_writev` — direct cross-process RAM copy.
/// - `process_madvise` — remote `madvise` (can force pages out / probe layout).
/// - `kcmp` — compares two processes' kernel objects (ASLR / handle oracles).
/// - `pidfd_open` + `pidfd_getfd` — obtain a pidfd and steal another process's
///   file descriptors (a modern, ptrace-free scrape / pivot primitive).
///
/// A denylist is used **deliberately** so the filter cannot break normal proxy
/// operation: the tokio multi-thread runtime, `epoll`/`io_uring`, `futex`,
/// `mmap`, socket and timer syscalls all fall through to `Allow`. A strict
/// allowlist that forgot one of those would kill the runtime, which is exactly
/// what the CRITICAL-SAFETY constraint forbids here. `EPERM` (not kill) is used
/// for the denied set so that even if some future in-tree code path legitimately
/// issued one of them, the daemon degrades with an error return rather than dying.
///
/// # Threat model — what this does and does NOT buy
///
/// seccomp constrains the syscalls issued **by this process and its threads**,
/// not what other processes may do *to* it. So this does **NOT** stop a full
/// ring-0 / root / malicious-kernel attacker — they can read `/proc/<pid>/mem`,
/// attach from an unconstrained process, or disable the filter outright, and
/// nothing in user space can prevent that. What it raises is the bar against an
/// **unprivileged same-host foothold that ends up executing inside this address
/// space** (an exploited worker thread, an injected `.so`, a malicious in-proc
/// plugin): such code can no longer reach for `process_vm_readv`/`pidfd_getfd`/
/// `ptrace` to scrape *other* processes' secrets or use `kcmp`/`process_madvise`
/// for anti-forensics — those return `EPERM` instead. It is defense-in-depth,
/// not a guarantee.
///
/// # Best-effort / fail-open
///
/// Every failure path (old kernel without `seccomp(2)`, a container that blocks
/// the syscall, `PR_SET_NO_NEW_PRIVS` denied, an unsupported target arch) logs a
/// **warning and returns** — it never panics and never fails the process. It also
/// never falsely claims success: the confirming `INFO` log is emitted only after
/// the kernel actually accepts the filter.
///
/// # Why "late"
///
/// It must be installed **after** startup work that legitimately touches the
/// filesystem/keys and after listeners are bound, so none of those startup
/// syscalls are affected — the filter only governs the steady-state serving loop.
/// The denied set is never used on the normal serving path, so installing it late
/// is transparent to traffic.
///
/// The BPF is compiled for `std::env::consts::ARCH` (the running binary's arch)
/// by the vetted, pure-Rust `seccompiler` crate (from the Firecracker project),
/// whose generated program kills the process on a *foreign-arch* syscall — an
/// inherent, standard property of seccomp arch validation that native same-arch
/// operation never triggers.
///
/// # Recommended call site (not wired here)
///
/// This module intentionally does **not** call this function; `src/cli.rs` /
/// `src/main.rs` are owned elsewhere. The recommended placement is inside the
/// long-running server path in `src/handshake/server.rs::run`, immediately after
/// `let listener = TcpListener::bind(server.listen).await?;` (and after the
/// optional UDP carrier bind), i.e. once keys are loaded and every listener is
/// bound but before the `accept()` loop. It could also be gated behind a
/// `PARALLAX_DISABLE_SECCOMP` env toggle by the owner of that call site, mirroring
/// the existing `PARALLAX_DISABLE_ANTI_DEBUG` pattern, for operators who must run
/// under unusual tracing tools.
pub fn install_late_seccomp_filter() {
    #[cfg(target_os = "linux")]
    install_late_seccomp_filter_linux();

    #[cfg(not(target_os = "linux"))]
    tracing::debug!(
        "late seccomp filter is Linux-only; skipping the memory-scrape denylist on this target"
    );
}

/// The memory-scrape / anti-forensics syscalls the late filter traps to `EPERM`.
/// Names are carried alongside the numbers purely for the confirmation log.
#[cfg(target_os = "linux")]
const SCRAPE_DENYLIST: &[(&str, libc::c_long)] = &[
    ("ptrace", libc::SYS_ptrace),
    ("process_vm_readv", libc::SYS_process_vm_readv),
    ("process_vm_writev", libc::SYS_process_vm_writev),
    ("process_madvise", libc::SYS_process_madvise),
    ("kcmp", libc::SYS_kcmp),
    ("pidfd_getfd", libc::SYS_pidfd_getfd),
    ("pidfd_open", libc::SYS_pidfd_open),
];

#[cfg(target_os = "linux")]
fn install_late_seccomp_filter_linux() {
    // Required for an unprivileged process to load a seccomp filter; harmless if
    // already privileged and idempotent if a prior call set it. seccompiler also
    // sets this internally during apply, but doing it explicitly first both
    // matches the documented ordering and lets us fail open with a clear reason.
    if let Err(err) = rustix::thread::set_no_new_privs(true) {
        tracing::warn!(
            error = %err,
            "PR_SET_NO_NEW_PRIVS failed; skipping best-effort seccomp filter (continuing)"
        );
        return;
    }

    let program = match build_scrape_denylist_filter() {
        Ok(program) => program,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "could not compile seccomp memory-scrape denylist (unsupported arch?); \
                 continuing without it (best-effort)"
            );
            return;
        }
    };

    // TSYNC applies the filter to EVERY thread in the process, not just the
    // caller — essential under the tokio multi-thread runtime, whose worker
    // threads already exist by the late install point.
    match seccompiler::apply_filter_all_threads(&program) {
        Ok(()) => {
            let denied: Vec<&str> = SCRAPE_DENYLIST.iter().map(|(name, _)| *name).collect();
            tracing::info!(
                ?denied,
                "installed best-effort seccomp denylist \
                 (memory-scrape/anti-forensics syscalls -> EPERM; all others allowed). \
                 Note: does not stop a root/ring-0 attacker; raises the bar against an \
                 unprivileged in-process foothold only."
            );
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                "failed to install seccomp filter (old kernel or blocked syscall?); \
                 continuing without it (best-effort)"
            );
        }
    }
}

/// Compile the denylist into a BPF program for the running architecture.
///
/// Default action = `Allow` (fall-through for all unlisted syscalls); matched
/// (denied) syscalls => `EPERM`. Empty rule vecs mean "match this syscall number
/// unconditionally", so the deny is not argument-dependent. Kept separate from
/// installation so it is unit-testable without touching process state.
#[cfg(target_os = "linux")]
fn build_scrape_denylist_filter() -> Result<seccompiler::BpfProgram, seccompiler::BackendError> {
    use seccompiler::{SeccompAction, SeccompFilter, TargetArch};
    use std::collections::BTreeMap;
    use std::convert::TryInto;

    let target_arch: TargetArch = std::env::consts::ARCH.try_into()?;

    // `c_long` is `i64` on the 64-bit targets seccompiler supports but `i32` on
    // 32-bit Linux, so the widening cast to the filter's `i64` key is required for
    // portability even though it is a no-op on x86_64/aarch64/riscv64.
    #[allow(clippy::unnecessary_cast)]
    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = SCRAPE_DENYLIST
        .iter()
        .map(|(_, nr)| (*nr as i64, Vec::new()))
        .collect();

    let filter = SeccompFilter::new(
        rules,
        // Default (mismatch) action for everything NOT in the denylist: allow.
        SeccompAction::Allow,
        // Action for the denied syscalls: return EPERM without executing them.
        SeccompAction::Errno(libc::EPERM as u32),
        target_arch,
    )?;

    filter.try_into()
}

/// Whether [`disable_ptrace_dumpability`] runs for a given anti-debug setting.
/// Unconditional everywhere the syscall cannot abort startup, because it is the
/// core-dump exclusion that actually holds against a piped `core_pattern` — not
/// merely an anti-debug measure. macOS is the exception: there the syscall is
/// `PT_DENY_ATTACH`, which kills an already-traced process, so it stays behind
/// the anti-debug opt-out. Pure so the gating is unit-testable.
const fn should_disable_dumpability(anti_debug: bool) -> bool {
    !cfg!(target_os = "macos") || anti_debug
}

/// One-shot startup check: if a debugger / tracer is already attached at launch,
/// emit a single warning. Deliberately a WARN only — never auto-wipe or exit:
///
/// - On a server (out of GFW's reach, no on-host agent watching syscalls) this is
///   the realistic "someone attached to my live process" signal, but an operator
///   legitimately attaching gdb to debug a hang must not have the service killed
///   under them, and on a multi-user proxy an auto-action on a false positive
///   would take down every user's session at once.
/// - Against a ring-0 / malicious-OS attacker the `TracerPid` field is whatever
///   the kernel chooses to report, so escalating beyond a warning buys nothing.
///
/// Gated by [`anti_debug_enabled`]. Linux-only (reads `/proc/self/status`); a
/// no-op elsewhere.
#[cfg(target_os = "linux")]
fn warn_if_already_traced() {
    match std::fs::read_to_string("/proc/self/status") {
        Ok(status) => {
            if let Some(tracer_pid) = parse_tracer_pid(&status) {
                if tracer_pid != 0 {
                    tracing::warn!(
                        tracer_pid,
                        "this process is already being traced at startup (a debugger / \
                         tracer is attached). Taking no action; if unexpected, \
                         investigate the host."
                    );
                }
            }
        }
        Err(err) => {
            tracing::debug!(error = %err, "could not read /proc/self/status for tracer check");
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn warn_if_already_traced() {}

/// Parse the `TracerPid:` field out of the Linux `/proc/<pid>/status` text.
/// Returns the tracer's PID (0 = not traced), or `None` if the field is absent /
/// unparseable. Pure so it is unit-testable without `/proc`.
#[cfg(any(target_os = "linux", test))]
fn parse_tracer_pid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("TracerPid:"))
        .and_then(|value| value.trim().parse::<u32>().ok())
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
    fn masked_secret_round_trips_and_hides_plaintext() {
        let secret = b"ML-DSA-87 identity signing key bytes (stand-in)".to_vec();
        let masked = super::MaskedSecret::new(&secret);

        // Unmask reproduces the exact plaintext.
        masked.with_plaintext(|pt| assert_eq!(pt, secret.as_slice()));
        // ...and does so repeatedly (the mask is not consumed).
        masked.with_plaintext(|pt| assert_eq!(pt, secret.as_slice()));

        assert_eq!(masked.len(), secret.len());
        assert!(!masked.is_empty());

        // The stored masked bytes must NOT equal the plaintext (it is XORed under a
        // random pad), or the masking bought nothing. A random all-zero pad is
        // astronomically unlikely; assert they differ.
        assert_ne!(
            masked.masked, secret,
            "masked residency must not store the raw plaintext"
        );
    }

    #[test]
    fn masked_secret_handles_empty() {
        let masked = super::MaskedSecret::new(&[]);
        assert!(masked.is_empty());
        masked.with_plaintext(|pt| assert!(pt.is_empty()));
    }

    // #247: the dumpable-flag disable is the core-dump exclusion that actually
    // holds against a piped `core_pattern` handler (RLIMIT_CORE=0 does not), so
    // the harden path must invoke it even when anti-debug is opted out. Only
    // macOS may gate it (PT_DENY_ATTACH kills an already-traced process there).
    #[test]
    fn dumpability_disable_ignores_anti_debug_opt_out() {
        if cfg!(target_os = "macos") {
            assert!(super::should_disable_dumpability(true));
            assert!(!super::should_disable_dumpability(false));
        } else {
            assert!(super::should_disable_dumpability(true));
            assert!(super::should_disable_dumpability(false));
        }
    }

    #[test]
    fn parse_tracer_pid_reads_field() {
        // Untraced: TracerPid is 0.
        let untraced = "Name:\tplx\nState:\tS (sleeping)\nTracerPid:\t0\nUid:\t1000\n";
        assert_eq!(super::parse_tracer_pid(untraced), Some(0));
        // Traced: a real tracer PID.
        let traced = "Name:\tplx\nTracerPid:\t4242\nUid:\t1000\n";
        assert_eq!(super::parse_tracer_pid(traced), Some(4242));
        // Absent field -> None (don't fabricate a "not traced" answer).
        let absent = "Name:\tplx\nState:\tS (sleeping)\n";
        assert_eq!(super::parse_tracer_pid(absent), None);
        // Garbage value -> None rather than a wrong number.
        let garbage = "TracerPid:\tnope\n";
        assert_eq!(super::parse_tracer_pid(garbage), None);
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

    // The public entry point is a no-op-safe, fail-open function on every target;
    // calling it twice must never panic (idempotent, best-effort). On Linux this
    // actually installs the process-wide filter, so it runs last-ish; the deny
    // set is EPERM-only (never kill), so it cannot take the test process down.
    #[test]
    fn install_late_seccomp_filter_is_safe_to_call() {
        super::install_late_seccomp_filter();
        super::install_late_seccomp_filter();
    }

    // The denylist must compile to a non-empty BPF program on the supported
    // architectures (x86_64/aarch64/riscv64 — what CI runs). On an unsupported
    // arch `build` returns Err and the installer fails open, which is the
    // documented behavior, so we only assert the shape when compilation succeeds.
    #[cfg(target_os = "linux")]
    #[test]
    fn scrape_denylist_compiles_to_bpf() {
        match super::build_scrape_denylist_filter() {
            Ok(program) => {
                // Arch-validation preamble + one chain per denied syscall + the
                // trailing default action => comfortably more than the raw count.
                assert!(
                    program.len() > super::SCRAPE_DENYLIST.len(),
                    "BPF program should include the arch preamble and per-syscall chains"
                );
            }
            Err(err) => {
                // Only tolerated on an arch seccompiler cannot target.
                eprintln!("seccomp denylist not compiled on this arch (tolerated): {err}");
            }
        }
    }

    // CRITICAL-SAFETY test: prove the *shipped* BPF program does not kill the
    // process for normal work and that a denied syscall returns EPERM.
    //
    // Isolation: we install the program with the thread-local `apply_filter`
    // (NOT the process-wide TSYNC variant used in production) inside a dedicated
    // worker thread. A non-TSYNC seccomp filter binds to the calling thread only,
    // so sibling test threads and the rest of the harness are unaffected, and the
    // thread simply exits when done (seccomp filters are irremovable, but this one
    // dies with its thread). This exercises the exact BpfProgram we ship; only the
    // apply flag differs. Denied syscalls use EPERM (never kill), and the program
    // is compiled for the running arch, so the only seccomp kill path — a
    // foreign-arch syscall — is never hit by this thread's native syscalls.
    #[cfg(target_os = "linux")]
    #[test]
    fn filter_allows_normal_ops_and_eperms_scrape() {
        use std::convert::TryInto;

        // If seccompiler cannot target this arch, the installer fails open; there
        // is nothing to assert about the kernel behavior, so skip.
        let arch: Result<seccompiler::TargetArch, _> = std::env::consts::ARCH.try_into();
        if arch.is_err() {
            eprintln!("skipping: seccomp unsupported on this arch");
            return;
        }
        let program = super::build_scrape_denylist_filter().expect("denylist compiles");

        let handle = std::thread::spawn(move || {
            // Bind the filter to THIS thread only (no TSYNC).
            rustix::thread::set_no_new_privs(true).expect("PR_SET_NO_NEW_PRIVS");
            // If the kernel lacks seccomp entirely, fail open like production.
            if seccompiler::apply_filter(&program).is_err() {
                eprintln!("skipping kernel assertions: seccomp(2) unavailable");
                return;
            }

            // --- Normal syscalls: must all be ALLOWED (thread stays alive). ---
            // Heap allocation (brk/mmap).
            let mut scratch = vec![0_u8; 64 * 1024];
            scratch[0] = 1;
            assert_eq!(scratch[0], 1);
            // File open + read (openat/read).
            let devnull = std::fs::File::open("/dev/null").expect("open /dev/null allowed");
            drop(devnull);
            // Socket create + bind (socket/bind).
            let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("socket/bind allowed");
            assert!(sock.local_addr().is_ok());
            // Timer sleep (clock_nanosleep/nanosleep).
            std::thread::sleep(std::time::Duration::from_millis(1));
            // Thread create + join (clone/clone3 + futex), all fall through to Allow.
            let inner = std::thread::spawn(|| 40 + 2);
            assert_eq!(inner.join().expect("inner thread joins under filter"), 42);

            // --- Denied syscalls: must return EPERM (intercepted, not executed). ---
            // process_vm_readv with count=0 would normally succeed (return 0); under
            // the filter it is trapped to EPERM before the kernel runs it, so a
            // non-zero errno here proves the denial path fired.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_process_vm_readv,
                    libc::getpid(),
                    std::ptr::null::<libc::iovec>(),
                    0_u64,
                    std::ptr::null::<libc::iovec>(),
                    0_u64,
                    0_u64,
                )
            };
            let errno = std::io::Error::last_os_error().raw_os_error();
            assert_eq!(rc, -1, "process_vm_readv must be blocked, not executed");
            assert_eq!(errno, Some(libc::EPERM), "process_vm_readv must EPERM");

            // ptrace(PTRACE_TRACEME) would normally succeed; must also EPERM.
            let rc = unsafe { libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0) };
            let errno = std::io::Error::last_os_error().raw_os_error();
            assert_eq!(rc, -1, "ptrace must be blocked, not executed");
            assert_eq!(errno, Some(libc::EPERM), "ptrace must EPERM");
        });

        // If the thread had been killed by seccomp, the whole process would have
        // died; reaching here with a clean join proves normal ops survived.
        handle
            .join()
            .expect("filtered worker thread completed without being killed");
    }
}
