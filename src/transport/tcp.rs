#[cfg(target_os = "linux")]
use std::time::Duration;
use std::{
    future::{poll_fn, Future},
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        OnceLock,
    },
    task::Poll,
};

use tokio::{
    net::{lookup_host, tcp::OwnedReadHalf, TcpSocket, TcpStream},
    time::{timeout_at, Instant},
};

const RESERVED_PROCESS_FDS: usize = 64;
const FDS_PER_RELAY_CONNECTION: usize = 2;
pub(crate) const MAX_CONCURRENT_CAP_SHED_FALLBACKS: usize = 64;
// The server may hold the 64 cap-shed client/origin pairs plus one accepted
// socket waiting for a slot. Cap-shed always uses userspace (no splice clones or
// pipes). Keep this separate from the client's fd budget.
const RESERVED_CAP_SHED_FDS: usize =
    MAX_CONCURRENT_CAP_SHED_FALLBACKS * FDS_PER_RELAY_CONNECTION + 1;
const MAX_RELAY_CONNECTION_LIMIT: usize = 16_384;
const MAX_PARALLEL_CONNECT_ATTEMPTS: usize = 4;
/// Aggregate cap on the *extra* (beyond the first) parallel connect sockets held
/// across all in-flight multi-address races. The per-relay fd budget counts a
/// settled relay's single outbound socket, not the connect-race fan-out, so a
/// burst of multi-address fallback dials could transiently over-commit fds. This
/// bounds that fan-out process-wide: the always-allowed first attempt preserves
/// connectivity, extra racers degrade gracefully under pressure rather than
/// exhausting RLIMIT_NOFILE.
const MAX_INFLIGHT_EXTRA_CONNECT_ATTEMPTS: usize = 256;
static INFLIGHT_EXTRA_CONNECTS: AtomicUsize = AtomicUsize::new(0);
// Optional connect racers and Linux splice descriptors share headroom reserved
// before the relay admission limit is calculated. Until startup configures it,
// optional work stays disabled and connections use their base socket budget.
static EXTRA_FD_BUDGET: OnceLock<ExtraFdBudget> = OnceLock::new();

struct ExtraFdBudget {
    limit: usize,
    used: AtomicUsize,
}

impl ExtraFdBudget {
    const fn new(limit: usize) -> Self {
        Self {
            limit,
            used: AtomicUsize::new(0),
        }
    }

    fn try_reserve(&self, count: usize) -> Option<ExtraFdReservation<'_>> {
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let next = used.checked_add(count).filter(|next| *next <= self.limit)?;
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(actual) => used = actual,
            }
        }
        Some(ExtraFdReservation {
            budget: self,
            count,
        })
    }
}

struct ExtraFdReservation<'a> {
    budget: &'a ExtraFdBudget,
    count: usize,
}

impl Drop for ExtraFdReservation<'_> {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.count, Ordering::AcqRel);
    }
}

/// RAII reservation for one extra (non-first) parallel connect attempt. Held for
/// the attempt and its completed socket until losing attempts have closed.
struct ExtraConnectGuard {
    _fds: ExtraFdReservation<'static>,
}

impl ExtraConnectGuard {
    fn try_acquire(budget: &'static ExtraFdBudget) -> Option<Self> {
        let fds = budget.try_reserve(1)?;
        let prev = INFLIGHT_EXTRA_CONNECTS.fetch_add(1, Ordering::AcqRel);
        if prev >= MAX_INFLIGHT_EXTRA_CONNECT_ATTEMPTS {
            INFLIGHT_EXTRA_CONNECTS.fetch_sub(1, Ordering::AcqRel);
            None
        } else {
            Some(Self { _fds: fds })
        }
    }
}

impl Drop for ExtraConnectGuard {
    fn drop(&mut self) {
        INFLIGHT_EXTRA_CONNECTS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Bounds concurrent Linux kernel-splice fallback relays. Each splice relay holds
/// ~8 fds (2 sockets + 2 clones + 2 pipes) and 2 native OS threads, far more than
/// the 2 fds the admission semaphore budgets per connection. Reserve all 8 from
/// the shared budget too: cancelling the async caller releases admission while
/// its blocking splice workers can still hold both original sockets.
/// Beyond either cap, callers use the userspace async relay (2 fds, no native
/// threads).
const MAX_CONCURRENT_KERNEL_SPLICE_RELAYS: usize = 256;
#[cfg(target_os = "linux")]
static ACTIVE_KERNEL_SPLICE_RELAYS: AtomicUsize = AtomicUsize::new(0);
const RESERVED_FDS_PER_KERNEL_SPLICE: usize = 8;

/// Path-attribution counters for ordinary fallback relays: how often the
/// zero-copy kernel splice path was taken vs forced to userspace, and why.
/// Observability only -- no behavior change. Read via [`splice_path_stats`]; the relay decision in
/// `handshake::server::relay_fallback_with_idle_timeout` records into them.
/// Cap-shed relays always use userspace and bypass that kernel selector.
static SPLICE_KERNEL_TAKEN: AtomicU64 = AtomicU64::new(0);
static SPLICE_USERSPACE_CAP_HIT: AtomicU64 = AtomicU64::new(0);
static SPLICE_USERSPACE_NON_LINUX: AtomicU64 = AtomicU64::new(0);

/// Records that a fallback relay took the zero-copy kernel splice(2) path.
pub fn record_kernel_splice_relay() {
    SPLICE_KERNEL_TAKEN.fetch_add(1, Ordering::Relaxed);
}

/// Records that a fallback relay was forced to userspace because the kernel
/// splice cap or shared fd budget was reached.
pub fn record_userspace_cap_hit_relay() {
    SPLICE_USERSPACE_CAP_HIT.fetch_add(1, Ordering::Relaxed);
}

/// Records that a fallback relay used userspace because the platform has no
/// kernel splice (non-Linux).
pub fn record_userspace_non_linux_relay() {
    SPLICE_USERSPACE_NON_LINUX.fetch_add(1, Ordering::Relaxed);
}

/// `(kernel_splice_taken, userspace_cap_hit, userspace_non_linux)` since start.
pub fn splice_path_stats() -> (u64, u64, u64) {
    (
        SPLICE_KERNEL_TAKEN.load(Ordering::Relaxed),
        SPLICE_USERSPACE_CAP_HIT.load(Ordering::Relaxed),
        SPLICE_USERSPACE_NON_LINUX.load(Ordering::Relaxed),
    )
}

/// RAII slot for a kernel-splice relay; releases the slot on drop.
#[cfg(target_os = "linux")]
pub struct KernelSpliceSlot {
    _fds: ExtraFdReservation<'static>,
}

#[cfg(target_os = "linux")]
impl Drop for KernelSpliceSlot {
    fn drop(&mut self) {
        ACTIVE_KERNEL_SPLICE_RELAYS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Reserves a kernel-splice relay slot and all its fds, or returns `None` when
/// either budget is full (signalling the caller to use the userspace relay).
#[cfg(target_os = "linux")]
pub fn try_enter_kernel_splice_relay() -> Option<KernelSpliceSlot> {
    try_enter_kernel_splice_relay_with_budget(EXTRA_FD_BUDGET.get()?)
}

#[cfg(target_os = "linux")]
fn try_enter_kernel_splice_relay_with_budget(
    budget: &'static ExtraFdBudget,
) -> Option<KernelSpliceSlot> {
    let fds = budget.try_reserve(RESERVED_FDS_PER_KERNEL_SPLICE)?;
    let prev = ACTIVE_KERNEL_SPLICE_RELAYS.fetch_add(1, Ordering::AcqRel);
    if prev >= MAX_CONCURRENT_KERNEL_SPLICE_RELAYS {
        ACTIVE_KERNEL_SPLICE_RELAYS.fetch_sub(1, Ordering::AcqRel);
        None
    } else {
        Some(KernelSpliceSlot { _fds: fds })
    }
}
#[cfg(target_os = "linux")]
const TCP_NOTSENT_LOWAT_BYTES: libc::c_uint = 256 * 1024;
#[cfg(target_os = "linux")]
const SOCKET_BUSY_POLL_MICROS: libc::c_int = 50;

pub async fn connect_tuned_tcp_host(addr: &str, deadline: Instant) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = timeout_at(deadline, lookup_host(addr))
        .await
        .map_err(|_| connect_timeout_error())??
        .collect();
    connect_tuned_tcp_any(&addrs, deadline).await
}

pub async fn connect_tuned_tcp_any(
    addrs: &[SocketAddr],
    deadline: Instant,
) -> io::Result<TcpStream> {
    if !addrs.is_empty() && Instant::now() >= deadline {
        return Err(connect_timeout_error());
    }
    match addrs {
        [] => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no socket addresses resolved",
        )),
        [addr] => timeout_at(deadline, connect_tuned_tcp_addr(*addr))
            .await
            .map_err(|_| connect_timeout_error())?,
        _ => connect_tuned_tcp_race(addrs, Some(connect_fd_budget()?), deadline).await,
    }
}

async fn connect_tuned_tcp_race(
    addrs: &[SocketAddr],
    extra_fd_budget: Option<&'static ExtraFdBudget>,
    deadline: Instant,
) -> io::Result<TcpStream> {
    connect_tuned_tcp_race_with(addrs, extra_fd_budget, deadline, connect_tuned_tcp_addr).await
}

async fn connect_tuned_tcp_race_with<F, Fut, S>(
    addrs: &[SocketAddr],
    extra_fd_budget: Option<&'static ExtraFdBudget>,
    deadline: Instant,
    mut connect: F,
) -> io::Result<S>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<S>>,
{
    let mut attempts = Vec::new();
    let mut addr_iter = addrs.iter().copied();

    // Keep the bounded races in this future: cancelling it closes every socket
    // before the caller releases its relay permit. Reservations travel with a
    // completed socket until losing attempts are dropped, not just until connect
    // returns (several connects may complete before their results are polled).
    while addr_iter.len() > 0 && attempts.len() < MAX_PARALLEL_CONNECT_ATTEMPTS {
        let guard = if attempts.is_empty() {
            None // The first outbound socket is covered by relay admission.
        } else {
            let Some(guard) = extra_fd_budget.and_then(ExtraConnectGuard::try_acquire) else {
                break;
            };
            Some(guard)
        };
        let addr = addr_iter.next().expect("remaining connect address");
        let connect = connect(addr);
        attempts.push(Box::pin(async move { (connect.await, guard) }));
    }

    let mut last_err = None;
    // Pending parallel candidates share time with every unstarted address.
    // Recompute after immediate failures so a black hole cannot retain the
    // failed candidates' shares and starve a later reachable address.
    while !attempts.is_empty() {
        let now = Instant::now();
        let pending = attempts.len();
        let batch_deadline = now
            + deadline.saturating_duration_since(now) * pending as u32
                / (pending + addr_iter.len()) as u32;
        let ready = poll_fn(|cx| {
            for (index, attempt) in attempts.iter_mut().enumerate() {
                if let Poll::Ready(result) = attempt.as_mut().poll(cx) {
                    return Poll::Ready((index, result));
                }
            }
            Poll::Pending
        });
        let Ok((index, result)) = timeout_at(batch_deadline, ready).await else {
            last_err = Some(connect_timeout_error());
            break;
        };
        drop(attempts.swap_remove(index));
        match result {
            (Ok(stream), guard) => {
                drop(attempts);
                drop(guard);
                return Ok(stream);
            }
            (Err(err), _) => last_err = Some(err),
        }
    }
    // Cancel and close every timed-out socket before opening another one.
    drop(attempts);
    while let Some(addr) = addr_iter.next() {
        let now = Instant::now();
        if now >= deadline {
            return Err(connect_timeout_error());
        }
        let attempt_deadline =
            now + deadline.saturating_duration_since(now) / (addr_iter.len() + 1) as u32;
        match timeout_at(attempt_deadline, connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => last_err = Some(err),
            Err(_) => last_err = Some(connect_timeout_error()),
        }
    }

    Err(last_err
        .unwrap_or_else(|| io::Error::other("all parallel TCP connect attempts were cancelled")))
}

fn connect_timeout_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "TCP connect timed out")
}

pub async fn connect_tuned_tcp_addr(addr: SocketAddr) -> io::Result<TcpStream> {
    let socket = tuned_tcp_socket(addr)?;
    socket.connect(addr).await
}

fn tuned_tcp_socket(addr: SocketAddr) -> io::Result<TcpSocket> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_nodelay(true)?;
    socket.set_keepalive(true)?;
    // NB: socket buffers are deliberately NOT set here (pre-connect). On Linux the
    // SYN's TCP window-scale shift count is derived from SO_RCVBUF at connect time,
    // so an explicit recv buffer on this camouflage dial would shift the window
    // scale away from Safari/macOS autotuning — an observable, ClientHello-adjacent
    // fingerprint on the SYN. Buffers are applied post-connect via tune_tcp_stream.
    tune_tcp_socket_before_connect(&socket);
    Ok(socket)
}

pub fn tune_tcp_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    set_low_latency_congestion(stream);
    set_socket_buffers(stream);
    set_notsent_lowat(stream);
    set_busy_poll(stream);
    set_incoming_cpu(stream);
    set_quick_ack(stream);
    Ok(())
}

pub fn drain_ready_tcp_read(
    reader: &OwnedReadHalf,
    buf: &mut [u8],
    mut filled: usize,
) -> io::Result<usize> {
    while filled < buf.len() {
        match reader.try_read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

pub fn kernel_splice_available() -> bool {
    cfg!(target_os = "linux")
}

#[cfg(target_os = "linux")]
pub async fn relay_kernel_splice_bidirectional_with_idle_timeout(
    left: TcpStream,
    right: TcpStream,
    idle_timeout: Duration,
    splice_slot: KernelSpliceSlot,
) -> io::Result<()> {
    let left = left.into_std()?;
    let right = right.into_std()?;
    tokio::task::spawn_blocking(move || {
        // Blocking splice threads survive cancellation of the async caller.
        // Keep their fd/thread reservation until both directions have joined.
        let _splice_slot = splice_slot;
        kernel_splice::splice_bidirectional_with_idle_timeout(left, right, idle_timeout)
    })
    .await
    .map_err(|err| io::Error::other(err.to_string()))?
}

#[cfg(unix)]
pub fn bump_nofile_soft_limit() {
    use rustix::process::{getrlimit, setrlimit, Resource};

    let mut limit = getrlimit(Resource::Nofile);
    // rustix uses `None` for RLIM_INFINITY; fold it to u64::MAX so the
    // "already at the hard limit?" check matches the old raw-value comparison.
    let old_soft = limit.current.unwrap_or(u64::MAX);
    let hard = limit.maximum.unwrap_or(u64::MAX);
    if old_soft >= hard {
        return;
    }

    limit.current = limit.maximum; // raise the soft limit up to the hard limit
    match setrlimit(Resource::Nofile, limit) {
        Ok(()) => tracing::debug!(
            old_soft_limit = old_soft,
            new_soft_limit = hard,
            "raised RLIMIT_NOFILE soft limit"
        ),
        Err(err) => tracing::debug!(
            error = %io::Error::from(err),
            old_soft_limit = old_soft,
            hard_limit = hard,
            "failed to raise RLIMIT_NOFILE soft limit"
        ),
    }
}

#[cfg(not(unix))]
pub fn bump_nofile_soft_limit() {}

pub fn is_fd_exhaustion_error(err: &io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(err.raw_os_error(), Some(libc::EMFILE) | Some(libc::ENFILE))
    }

    #[cfg(not(unix))]
    {
        let _ = err;
        false
    }
}

/// Whether an `accept()` error is a transient, per-connection condition that the
/// accept loop must survive rather than treat as fatal.
///
/// These errors describe the *incoming* connection (a peer that reset between SYN
/// and accept, a signal interrupting the syscall, a transient network/protocol
/// hiccup), not the listening socket, so the loop should drop the would-be
/// connection and keep serving. Returning `Err` on any of these would let a remote
/// peer shut the listener down by, e.g., RST-ing after SYN to induce
/// `ECONNABORTED`. Fd exhaustion is handled separately (it warrants a backoff).
pub fn is_transient_accept_error(err: &io::Error) -> bool {
    if err.kind() == io::ErrorKind::Interrupted {
        return true;
    }

    #[cfg(unix)]
    {
        // ENONET is Linux-only (absent from macOS/BSD libc), so handle it separately.
        #[cfg(target_os = "linux")]
        if err.raw_os_error() == Some(libc::ENONET) {
            return true;
        }

        matches!(
            err.raw_os_error(),
            Some(libc::ECONNABORTED)
                | Some(libc::EINTR)
                | Some(libc::EPROTO)
                | Some(libc::ENETDOWN)
                | Some(libc::ENETUNREACH)
                | Some(libc::EHOSTDOWN)
                | Some(libc::EHOSTUNREACH)
        )
    }

    #[cfg(not(unix))]
    {
        err.kind() == io::ErrorKind::ConnectionAborted
    }
}

pub fn relay_connection_limit(udp_enabled: bool) -> io::Result<usize> {
    configure_relay_fd_budget(
        nofile_soft_limit()?,
        client_fds_per_relay(udp_enabled),
        RESERVED_PROCESS_FDS,
    )
    .ok_or_else(|| {
        io::Error::other(format!(
            "RLIMIT_NOFILE soft limit is too low; need more than \
                 {RESERVED_PROCESS_FDS} file descriptors"
        ))
    })
}

pub(crate) fn server_relay_connection_limit(
    udp_enabled: bool,
    max_streams: usize,
) -> io::Result<usize> {
    configure_relay_fd_budget(
        nofile_soft_limit()?,
        server_fds_per_relay(udp_enabled, max_streams),
        RESERVED_PROCESS_FDS + RESERVED_CAP_SHED_FDS,
    )
    .ok_or_else(|| {
        io::Error::other(format!(
            "RLIMIT_NOFILE soft limit is too low; need more than {} file descriptors",
            RESERVED_PROCESS_FDS + RESERVED_CAP_SHED_FDS,
        ))
    })
}

#[cfg(test)]
fn server_relay_connection_limit_from_nofile(
    nofile_soft_limit: usize,
    udp_enabled: bool,
    max_streams: usize,
) -> Option<usize> {
    relay_fd_budget_from_nofile(
        nofile_soft_limit,
        server_fds_per_relay(udp_enabled, max_streams),
        RESERVED_PROCESS_FDS + RESERVED_CAP_SHED_FDS,
    )
    .map(|budget| budget.relay_limit)
}

pub fn relay_connection_limit_from_nofile(
    nofile_soft_limit: usize,
    udp_enabled: bool,
) -> Option<usize> {
    relay_fd_budget_from_nofile(
        nofile_soft_limit,
        client_fds_per_relay(udp_enabled),
        RESERVED_PROCESS_FDS,
    )
    .map(|budget| budget.relay_limit)
}

fn client_fds_per_relay(udp_enabled: bool) -> usize {
    FDS_PER_RELAY_CONNECTION + usize::from(udp_enabled)
}

fn server_fds_per_relay(udp_enabled: bool, max_streams: usize) -> usize {
    // One incoming control socket, every live target socket, and a speculative
    // origin socket draining concurrently with an authenticated session.
    // Non-mux handshakes/fallbacks need one origin socket even if mux is disabled.
    2 + max_streams.max(1) + usize::from(udp_enabled)
}

fn connect_fd_budget() -> io::Result<&'static ExtraFdBudget> {
    if let Some(budget) = EXTRA_FD_BUDGET.get() {
        return Ok(budget);
    }
    let nofile = nofile_soft_limit()?;
    let extra_fds =
        relay_fd_budget_from_nofile(nofile, FDS_PER_RELAY_CONNECTION, RESERVED_PROCESS_FDS)
            .map_or(0, |budget| budget.extra_fds);
    Ok(EXTRA_FD_BUDGET.get_or_init(|| ExtraFdBudget::new(extra_fds)))
}

struct RelayFdBudget {
    relay_limit: usize,
    extra_fds: usize,
}

fn configure_relay_fd_budget(
    nofile: usize,
    fds_per_relay: usize,
    reserved_fds: usize,
) -> Option<usize> {
    let budget = relay_fd_budget_from_nofile(nofile, fds_per_relay, reserved_fds)?;
    let shared = EXTRA_FD_BUDGET.get_or_init(|| ExtraFdBudget::new(budget.extra_fds));
    // The process normally starts either a client or a server once. If reused,
    // admission must still reserve the already configured optional fd pool.
    relay_limit_with_extra_fds(nofile, fds_per_relay, reserved_fds, shared.limit)
}

fn relay_fd_budget_from_nofile(
    nofile: usize,
    fds_per_relay: usize,
    reserved_fds: usize,
) -> Option<RelayFdBudget> {
    let available = nofile.checked_sub(reserved_fds)?;
    // Keep most capacity for ordinary relays. Low limits shrink this optional
    // pool to zero rather than requiring hundreds of spare fds to start.
    let max_extra_fds = MAX_INFLIGHT_EXTRA_CONNECT_ATTEMPTS
        + if cfg!(target_os = "linux") {
            MAX_CONCURRENT_KERNEL_SPLICE_RELAYS * RESERVED_FDS_PER_KERNEL_SPLICE
        } else {
            0
        };
    let extra_fds = (available / 4)
        .min(max_extra_fds)
        .min(available.checked_sub(fds_per_relay)?);
    Some(RelayFdBudget {
        relay_limit: relay_limit_with_extra_fds(nofile, fds_per_relay, reserved_fds, extra_fds)?,
        extra_fds,
    })
}

fn relay_limit_with_extra_fds(
    nofile: usize,
    fds_per_relay: usize,
    reserved_fds: usize,
    extra_fds: usize,
) -> Option<usize> {
    let available = nofile.checked_sub(reserved_fds)?.checked_sub(extra_fds)?;
    let limit = available / fds_per_relay;
    if limit == 0 {
        None
    } else {
        Some(limit.min(MAX_RELAY_CONNECTION_LIMIT))
    }
}

#[cfg(unix)]
fn nofile_soft_limit() -> io::Result<usize> {
    use rustix::process::{getrlimit, Resource};

    // None == RLIM_INFINITY; clamp to usize::MAX for the relay-budget math,
    // matching the old `rlim_cur as usize` behaviour on 64-bit.
    Ok(getrlimit(Resource::Nofile)
        .current
        .map_or(usize::MAX, |cur| cur as usize))
}

#[cfg(not(unix))]
fn nofile_soft_limit() -> io::Result<usize> {
    Ok(512)
}

/// Process-wide TCP congestion-control override, set once at startup.
static CONGESTION_OVERRIDE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

/// Sets the congestion-control algorithm requested on relay sockets, process
/// wide. Call once at startup before any socket is tuned. `None` (or a name
/// containing a NUL) keeps the built-in default ("bbr" on Linux).
pub fn configure_congestion_control(algorithm: Option<&str>) {
    // A name with an interior NUL can't be a valid sockopt value; treat it as
    // unset (matches the previous `CString::new(name).ok()` rejection).
    let value = algorithm
        .filter(|name| !name.contains('\0'))
        .map(str::to_owned);
    if CONGESTION_OVERRIDE.set(value).is_err() {
        tracing::debug!("congestion control override already set; keeping the first value");
    }
}

/// Process-wide explicit TCP socket buffer sizes, set once at startup. Either
/// field `None` keeps kernel autotuning for that direction (the safe default,
/// which preserves full Safari parity). An explicit SO_SNDBUF/SO_RCVBUF DISABLES
/// autotuning for the socket and is clamped by the OS maximum
/// (`net.core.{w,r}mem_max` on Linux, `kern.ipc.maxsockbuf` on macOS), so only set
/// these when that maximum has been raised.
///
/// Covertness note: SO_SNDBUF is wire-invisible (it does not affect the advertised
/// receive window). SO_RCVBUF is NOT fully invisible — on Linux it sets the SYN's
/// TCP window-scale shift and the advertised window. To keep the camouflage SYN
/// Safari-identical, buffers are applied ONLY post-connect/accept (via
/// `tune_tcp_stream`), never on the pre-connect dial (see `tuned_tcp_socket`); even
/// then, a fixed recv buffer flattens the advertised-window curve vs Safari's
/// autotuning, so the recv knob is for data-sink (server) tuning — opt-in, off by
/// default. A kernel-side throughput tuning for high-BDP links where autotuning
/// under-provisions the upload window.
static SOCKET_BUFFER_OVERRIDE: std::sync::OnceLock<SocketBuffers> = std::sync::OnceLock::new();

#[derive(Clone, Copy, Default)]
struct SocketBuffers {
    send: Option<u32>,
    recv: Option<u32>,
}

/// Sets the explicit SO_SNDBUF/SO_RCVBUF requested on relay sockets, process
/// wide. Call once at startup before any socket is tuned. A `Some(0)` is treated
/// as `None` (keep autotuning). First call wins.
pub fn configure_socket_buffers(send_bytes: Option<u32>, recv_bytes: Option<u32>) {
    let bufs = SocketBuffers {
        send: send_bytes.filter(|&b| b > 0),
        recv: recv_bytes.filter(|&b| b > 0),
    };
    if SOCKET_BUFFER_OVERRIDE.set(bufs).is_err() {
        tracing::debug!("socket buffer override already set; keeping the first value");
    }
}

#[cfg(unix)]
fn set_socket_buffers<S>(socket: &S)
where
    S: std::os::fd::AsFd,
{
    use socket2::SockRef;

    let Some(bufs) = SOCKET_BUFFER_OVERRIDE.get() else {
        return;
    };
    if bufs.send.is_none() && bufs.recv.is_none() {
        return;
    }
    let sock = SockRef::from(socket);
    // Best-effort, with a getsockopt read-back: the kernel silently clamps to the
    // OS max, and a clamp BELOW the request means autotuning would likely have done
    // better, so surface it (the same diagnostic shape as the congestion read-back).
    if let Some(send) = bufs.send {
        match sock.set_send_buffer_size(send as usize) {
            Ok(()) => {
                if let Ok(applied) = sock.send_buffer_size() {
                    if applied < send as usize {
                        tracing::warn!(
                            requested = send,
                            applied,
                            "kernel clamped SO_SNDBUF (raise net.core.wmem_max / kern.ipc.maxsockbuf)"
                        );
                    }
                }
            }
            Err(_) => tracing::trace!("SO_SNDBUF request failed; keeping kernel default"),
        }
    }
    if let Some(recv) = bufs.recv {
        match sock.set_recv_buffer_size(recv as usize) {
            Ok(()) => {
                if let Ok(applied) = sock.recv_buffer_size() {
                    if applied < recv as usize {
                        tracing::warn!(
                            requested = recv,
                            applied,
                            "kernel clamped SO_RCVBUF (raise net.core.rmem_max / kern.ipc.maxsockbuf)"
                        );
                    }
                }
            }
            Err(_) => tracing::trace!("SO_RCVBUF request failed; keeping kernel default"),
        }
    }
}

#[cfg(not(unix))]
fn set_socket_buffers<S>(_socket: &S) {}

#[cfg(target_os = "linux")]
fn set_low_latency_congestion(stream: &TcpStream) {
    use socket2::SockRef;

    let configured = CONGESTION_OVERRIDE.get().and_then(|opt| opt.clone());
    let algorithm = configured.unwrap_or_else(|| "bbr".to_owned());

    let sock = SockRef::from(stream);
    if sock.set_tcp_congestion(algorithm.as_bytes()).is_err() {
        tracing::trace!(
            algorithm = %algorithm,
            "TCP congestion control request failed; keeping kernel default"
        );
        return;
    }
    // Read back: the kernel silently ignores an unknown/unloaded algorithm, so a
    // successful set does not mean it was applied. Warn on mismatch so a
    // configured algorithm the kernel dropped does not silently lie. Use socket2's
    // getter, which returns raw bytes and never panics; rustix's tcp_congestion()
    // asserts + unwraps on a malformed reply, which this best-effort diagnostic
    // must not do.
    if let Ok(applied) = sock.tcp_congestion() {
        // Kernel returns the name NUL-padded; compare up to the first NUL.
        let applied = applied.split(|&b| b == 0).next().unwrap_or(&[]);
        if applied != algorithm.as_bytes() {
            tracing::warn!(
                requested = %algorithm,
                applied = %String::from_utf8_lossy(applied),
                "kernel did not apply the requested TCP congestion control (algorithm not loaded?)"
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn set_low_latency_congestion(_stream: &TcpStream) {}

#[cfg(target_os = "linux")]
fn tune_tcp_socket_before_connect(socket: &TcpSocket) {
    // NB: TCP Fast Open (TCP_FASTOPEN_CONNECT) is deliberately NOT enabled here.
    // It advertises a TFO option in the SYN (and can send data in the SYN on
    // cached-cookie paths), a stable TCP-layer distinguisher outside the TLS
    // ClientHello camouflage that modern desktop browsers do not exhibit.
    set_notsent_lowat(socket);
    set_busy_poll(socket);
    set_incoming_cpu(socket);
}

#[cfg(not(target_os = "linux"))]
fn tune_tcp_socket_before_connect(_socket: &TcpSocket) {}

#[cfg(target_os = "linux")]
fn set_notsent_lowat<S>(socket: &S)
where
    S: std::os::fd::AsFd,
{
    use socket2::SockRef;

    if SockRef::from(socket)
        .set_tcp_notsent_lowat(TCP_NOTSENT_LOWAT_BYTES)
        .is_err()
    {
        tracing::trace!("TCP_NOTSENT_LOWAT is unavailable; keeping kernel send queue defaults");
    }
}

#[cfg(not(target_os = "linux"))]
fn set_notsent_lowat<S>(_socket: &S) {}

#[cfg(target_os = "linux")]
fn set_busy_poll<S>(socket: &S)
where
    S: std::os::fd::AsFd,
{
    use socket2::SockRef;

    if SockRef::from(socket)
        .set_busy_poll(SOCKET_BUSY_POLL_MICROS as u32)
        .is_err()
    {
        tracing::trace!("SO_BUSY_POLL is unavailable; keeping kernel default");
    }
    // SO_PREFER_BUSY_POLL has no safe wrapper in rustix or socket2, so it stays on
    // libc — the only remaining FFI in the socket-tuning path.
    set_prefer_busy_poll(socket.as_fd());
}

#[cfg(not(target_os = "linux"))]
fn set_busy_poll<S>(_socket: &S) {}

#[cfg(target_os = "linux")]
fn set_prefer_busy_poll(fd: std::os::fd::BorrowedFd<'_>) {
    use std::os::fd::AsRawFd;

    let enabled: libc::c_int = 1;
    // SAFETY: setsockopt with a pointer to a stack-local c_int of matching length
    // on a valid borrowed fd; it only mutates this socket's option state.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PREFER_BUSY_POLL,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if rc != 0 {
        tracing::trace!("SO_PREFER_BUSY_POLL is unavailable; keeping kernel default");
    }
}

#[cfg(target_os = "linux")]
fn set_incoming_cpu<S>(socket: &S)
where
    S: std::os::fd::AsFd,
{
    // rustix sched_getcpu() returns usize (no error sentinel) and does not fail on
    // Linux; a bogus value would just make the setsockopt below a no-op.
    let cpu = rustix::thread::sched_getcpu();
    if rustix::net::sockopt::set_socket_incoming_cpu(socket, cpu as u32).is_err() {
        tracing::trace!("SO_INCOMING_CPU is unavailable; keeping kernel default");
    }
}

#[cfg(not(target_os = "linux"))]
fn set_incoming_cpu<S>(_socket: &S) {}

#[cfg(target_os = "linux")]
fn set_quick_ack(stream: &TcpStream) {
    if rustix::net::sockopt::set_tcp_quickack(stream, true).is_err() {
        tracing::trace!("TCP_QUICKACK is unavailable; keeping kernel delayed-ACK defaults");
    }
}

#[cfg(not(target_os = "linux"))]
fn set_quick_ack(_stream: &TcpStream) {}

#[cfg(target_os = "linux")]
mod kernel_splice {
    use std::{
        io,
        net::{Shutdown, TcpStream as StdTcpStream},
        os::fd::{AsFd, BorrowedFd, OwnedFd},
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    use rustix::event::PollFlags;

    const SPLICE_CHUNK: usize = 256 * 1024;
    type SpliceWorker = Box<dyn FnOnce() -> io::Result<()> + Send>;

    pub(super) fn splice_bidirectional_with_idle_timeout(
        left: StdTcpStream,
        right: StdTcpStream,
        idle_timeout: Duration,
    ) -> io::Result<()> {
        splice_bidirectional_with_spawner(left, right, idle_timeout, |worker| {
            thread::Builder::new().spawn(worker)
        })
    }

    pub(super) fn splice_bidirectional_with_spawner(
        left: StdTcpStream,
        right: StdTcpStream,
        idle_timeout: Duration,
        mut spawn: impl FnMut(SpliceWorker) -> io::Result<thread::JoinHandle<io::Result<()>>>,
    ) -> io::Result<()> {
        left.set_nonblocking(true)?;
        right.set_nonblocking(true)?;
        let left_to_right_read = left.try_clone()?;
        let left_to_right_write = right.try_clone()?;
        let right_to_left_read = right;
        let right_to_left_write = left;

        // Do not enter a long poll until both workers exist. A failed second
        // spawn closes this rendezvous, waking the first worker for FIN teardown
        // without another fd or an unbounded queue.
        let (start_tx, start_rx) = mpsc::sync_channel(0);
        let left_to_right = spawn(Box::new(move || {
            if start_rx.recv().is_err() {
                let _ = left_to_right_read.shutdown(Shutdown::Write);
                fin_write_then_drain_read(&left_to_right_read, &left_to_right_write);
                fin_write_then_drain_read(&left_to_right_write, &left_to_right_read);
                return Ok(());
            }
            splice_one_direction(left_to_right_read, left_to_right_write, idle_timeout)
        }))?;
        let right_to_left = match spawn(Box::new(move || {
            splice_one_direction(right_to_left_read, right_to_left_write, idle_timeout)
        })) {
            Ok(worker) => worker,
            Err(err) => {
                drop(start_tx);
                // The blocking caller still owns KernelSpliceSlot. Join before
                // returning so neither its fd budget nor its active slot can be
                // released while this worker survives the failed startup.
                let _ = join_splice_thread(left_to_right);
                return Err(err);
            }
        };
        let _ = start_tx.send(());

        // Always join BOTH threads before returning so neither relay thread (and
        // its socket/pipe fds) is detached when the sibling direction errors;
        // surface the first error via `and`.
        let left_result = join_splice_thread(left_to_right);
        let right_result = join_splice_thread(right_to_left);
        left_result.and(right_result)
    }

    fn join_splice_thread(handle: thread::JoinHandle<io::Result<()>>) -> io::Result<()> {
        handle
            .join()
            .map_err(|_| io::Error::other("kernel splice relay thread panicked"))?
    }

    fn splice_one_direction(
        read_stream: StdTcpStream,
        write_stream: StdTcpStream,
        idle_timeout: Duration,
    ) -> io::Result<()> {
        let result = splice_pump(&read_stream, &write_stream, idle_timeout);
        // Strict-FIN teardown on BOTH exits -- the clean path (read-side idle
        // timeout or EOF) AND the error/truncation path (e.g. a write-side idle
        // timeout with pipe-buffered bytes, or a splice/poll IO error). A wire RST
        // is a censor-observable confirmation signal that a real origin never emits
        // on close, so it is forbidden even on the error path: the fallback splice
        // is the origin-facing, censor-observable plane. In every case we FIN the
        // downstream and drain this direction's read socket toward EOF (bounded), so
        // no socket drops with queued bytes and RSTs. The clean-vs-truncated
        // distinction the relay relies on is surfaced to the caller through `result`
        // -- a truncation returns `Err` -- NEVER by resetting the peer on the wire.
        fin_write_then_drain_read(&read_stream, &write_stream);
        result
    }

    /// Pumps one direction (read -> pipe -> write) until idle timeout, EOF, or
    /// error. Never shuts the socket down itself; the caller tears down on exit.
    fn splice_pump(
        read_stream: &StdTcpStream,
        write_stream: &StdTcpStream,
        idle_timeout: Duration,
    ) -> io::Result<()> {
        let pipe = Pipe::new()?;
        // The idle clock is PER DIRECTION: it is bumped only by this direction's
        // own progress, so a busy sibling direction cannot keep a wedged direction
        // (and its OS thread + fds) alive indefinitely.
        let mut last_progress = Instant::now();
        loop {
            if !poll_fd_until_progress(
                read_stream.as_fd(),
                PollFlags::IN,
                idle_timeout,
                last_progress,
            )? {
                return Ok(()); // read-side idle timeout
            }
            let Some(moved) = splice_fd(read_stream.as_fd(), pipe.write_fd.as_fd(), SPLICE_CHUNK)?
            else {
                continue;
            };
            if moved == 0 {
                return Ok(()); // read EOF (peer half-closed)
            }
            last_progress = Instant::now();

            let mut remaining = moved;
            while remaining > 0 {
                if !poll_fd_until_progress(
                    write_stream.as_fd(),
                    PollFlags::OUT,
                    idle_timeout,
                    last_progress,
                )? {
                    // Write-side idle timeout with bytes still in the pipe: those
                    // bytes are dropped with the pipe, so reporting success would
                    // let the caller FIN and masquerade the truncated stream as a
                    // clean close. Fail so the teardown is abortive instead.
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "write-side idle timeout with buffered data",
                    ));
                }
                let Some(written) =
                    splice_fd(pipe.read_fd.as_fd(), write_stream.as_fd(), remaining)?
                else {
                    continue;
                };
                if written == 0 {
                    // A non-empty pipe yields bytes or EAGAIN, and a closed
                    // destination yields EPIPE, so no-progress-with-bytes-buffered
                    // is not expected to be reachable. If it ever is, those bytes go
                    // away with the pipe, so the direction WAS truncated and must not
                    // report success: `splice_one_direction` FINs either way (a wire
                    // RST is forbidden here), and `result` is the only channel that
                    // tells the relay a truncation happened.
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "write-side splice made no progress with buffered data",
                    ));
                }
                remaining -= written;
                last_progress = Instant::now();
            }
        }
    }

    /// Wall-clock budget for the FIN-first lingering drain of a splice direction's
    /// read socket. Bounded so a peer that keeps sending (or never closes) after
    /// our FIN cannot pin the blocking relay thread; matches the userspace relay's
    /// `graceful_fin_then_drain` budget (`handshake::server`). Hitting this cutoff
    /// with bytes still queued is the sole residual: an adversarial never-closing
    /// sender then still risks a RST at the final drop, which is indistinguishable
    /// from a real origin shedding a peer under memory pressure.
    const FIN_DRAIN_TIME_BUDGET: Duration = Duration::from_secs(2);

    /// Companion hard byte cap on the same drain: a fast, never-closing sender
    /// keeps the read socket endlessly readable, so bound the total bytes discarded
    /// per direction as well as the wall-clock time so it cannot pin the thread for
    /// the full budget. Same residual as the time cutoff; generous enough to fully
    /// drain a cooperating peer's in-flight backlog before it FINs.
    const FIN_DRAIN_BYTE_BUDGET: usize = 16 * 1024 * 1024;

    /// FIN-first graceful half-close of one splice direction -- the std/blocking
    /// analogue of `handshake::server::graceful_fin_then_drain`. `shutdown(Write)`
    /// the downstream FIRST (our FIN), THEN drain this direction's read socket
    /// toward the peer's EOF -- bounded by both [`FIN_DRAIN_TIME_BUDGET`] and
    /// [`FIN_DRAIN_BYTE_BUDGET`] -- so the read socket's final drop finds an empty
    /// receive queue and the kernel emits a FIN, not a RST.
    ///
    /// Ordering matters: only draining to EOF *after* our FIN empties the receive
    /// queue under a fast/late sender; the old drain-then-close (bounded at 256 KiB,
    /// breaking on the first WouldBlock) left queued or just-arrived bytes at the
    /// drop and the kernel RST'd -- the exact censor-observable tell a real origin
    /// never produces. `shutdown(Read)` is deliberately NOT used here: it neither
    /// flushes the receive queue nor suppresses the RST, and it cannot wake the
    /// sibling direction without RST risk under continued data, so the sibling
    /// instead tears down on its own per-direction idle timeout. `shutdown` (not a
    /// bare drop) is required because the sibling still holds the other clone of
    /// each socket. The stream is already nonblocking (set in
    /// `splice_bidirectional_with_idle_timeout`).
    fn fin_write_then_drain_read(read_stream: &StdTcpStream, write_stream: &StdTcpStream) {
        use std::io::Read;

        // FIN the downstream first, before draining, so the peer sees the graceful
        // close promptly regardless of how long the read-side drain lingers.
        let _ = write_stream.shutdown(Shutdown::Write);

        // Then drain the read socket toward EOF so its final drop carries no queued
        // bytes. Bounded by time AND bytes so a never-closing peer cannot pin us.
        let start = Instant::now();
        let mut drained = 0_usize;
        let mut scratch = [0_u8; 16 * 1024];
        let mut reader: &StdTcpStream = read_stream;
        while drained < FIN_DRAIN_BYTE_BUDGET {
            if start.elapsed() >= FIN_DRAIN_TIME_BUDGET {
                break; // time budget elapsed (residual)
            }
            match reader.read(&mut scratch) {
                Ok(0) => break, // peer EOF: receive queue drained, clean FIN at drop
                Ok(n) => drained = drained.saturating_add(n),
                Err(ref err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    // Momentarily empty: wait (bounded) for late bytes or the
                    // peer's FIN rather than stopping now, so a brief sender pause
                    // cannot leave bytes to arrive between here and the final drop.
                    match poll_fd_until_progress(
                        read_stream.as_fd(),
                        PollFlags::IN,
                        FIN_DRAIN_TIME_BUDGET,
                        start,
                    ) {
                        Ok(true) => {}      // readable (data or EOF): loop and read
                        Ok(false) => break, // time budget elapsed (residual)
                        Err(_) => break,    // poll error
                    }
                }
                Err(_) => break, // read error (e.g. the peer RST'd): nothing to drain
            }
        }
    }

    fn poll_fd_until_progress(
        fd: BorrowedFd<'_>,
        events: PollFlags,
        idle_timeout: Duration,
        last_progress: Instant,
    ) -> io::Result<bool> {
        use rustix::event::{poll, PollFd, Timespec};
        use rustix::io::Errno;

        loop {
            let remaining = idle_timeout.saturating_sub(last_progress.elapsed());
            if remaining.is_zero() {
                return Ok(false); // this direction's own idle deadline elapsed
            }
            let timeout = Timespec {
                tv_sec: remaining.as_secs() as i64,
                tv_nsec: remaining.subsec_nanos() as _,
            };
            let mut poll_fds = [PollFd::from_borrowed_fd(fd, events)];
            match poll(&mut poll_fds, Some(&timeout)) {
                Ok(ready) if ready > 0 => return Ok(true),
                // Poll ran the full remaining time and nothing can refresh this
                // direction's deadline while it waits (progress is per direction),
                // so the idle timeout has elapsed.
                Ok(_) => return Ok(false),
                Err(Errno::INTR) => continue,
                Err(err) => return Err(err.into()),
            }
        }
    }

    fn splice_fd(
        read_fd: BorrowedFd<'_>,
        write_fd: BorrowedFd<'_>,
        len: usize,
    ) -> io::Result<Option<usize>> {
        use rustix::io::Errno;
        use rustix::pipe::{splice, SpliceFlags};

        loop {
            match splice(
                read_fd,
                None,
                write_fd,
                None,
                len,
                SpliceFlags::MOVE | SpliceFlags::NONBLOCK,
            ) {
                Ok(moved) => return Ok(Some(moved)),
                Err(Errno::INTR) => continue,
                Err(Errno::AGAIN) => return Ok(None),
                Err(err) => return Err(err.into()),
            }
        }
    }

    struct Pipe {
        read_fd: OwnedFd,
        write_fd: OwnedFd,
    }

    impl Pipe {
        fn new() -> io::Result<Self> {
            use rustix::pipe::{pipe_with, PipeFlags};

            // OwnedFd closes each end on drop, so `Pipe` needs no manual `Drop`.
            let (read_fd, write_fd) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)?;
            Ok(Self { read_fd, write_fd })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc, time::Duration};

    #[test]
    fn splice_path_stats_counts_each_path() {
        let before = splice_path_stats();
        record_kernel_splice_relay();
        record_userspace_cap_hit_relay();
        record_userspace_non_linux_relay();
        let after = splice_path_stats();
        assert_eq!(after.0, before.0 + 1, "kernel-splice counter");
        assert_eq!(after.1, before.1 + 1, "userspace cap-hit counter");
        assert_eq!(after.2, before.2 + 1, "userspace non-linux counter");
    }

    #[test]
    fn relay_connection_limit_reserves_process_fds() {
        assert_eq!(relay_connection_limit_from_nofile(64, false), None);
        assert_eq!(relay_connection_limit_from_nofile(66, false), Some(1));
        assert_eq!(relay_connection_limit_from_nofile(256, false), Some(72));
        // With the UDP fast plane on, each relay also retains a QUIC endpoint fd,
        // so the per-connection budget is 3 and the limit drops accordingly.
        assert_eq!(relay_connection_limit_from_nofile(256, true), Some(48));
    }

    #[test]
    fn server_connection_limit_reserves_cap_shed_pairs_and_waiting_socket() {
        let reserved = RESERVED_PROCESS_FDS + MAX_CONCURRENT_CAP_SHED_FALLBACKS * 2 + 1;
        assert_eq!(
            server_relay_connection_limit_from_nofile(reserved, false, 1),
            None
        );
        assert_eq!(
            server_relay_connection_limit_from_nofile(reserved + 3, false, 1),
            Some(1)
        );
        assert_eq!(
            server_relay_connection_limit_from_nofile(256, false, 1),
            Some(16)
        );
        assert_eq!(
            server_relay_connection_limit_from_nofile(256, true, 1),
            Some(12)
        );
    }

    #[test]
    fn server_fd_budget_reserves_all_mux_targets_at_saturation() {
        let reserved = RESERVED_PROCESS_FDS + RESERVED_CAP_SHED_FDS;
        for max_streams in [1, 4, 255, 256] {
            for udp_enabled in [false, true] {
                let fds_per_relay = server_fds_per_relay(udp_enabled, max_streams);
                assert_eq!(
                    server_relay_connection_limit_from_nofile(
                        reserved + fds_per_relay - 1,
                        udp_enabled,
                        max_streams,
                    ),
                    None,
                );
                for nofile in [reserved + fds_per_relay, 1024, 4096, 65_536] {
                    let budget = relay_fd_budget_from_nofile(nofile, fds_per_relay, reserved)
                        .expect("enough fds for one fully populated mux carrier");
                    assert!(
                        reserved + budget.relay_limit * fds_per_relay + budget.extra_fds <= nofile
                    );
                    assert!(budget.relay_limit > 0);
                }
                let minimum =
                    relay_fd_budget_from_nofile(reserved + fds_per_relay, fds_per_relay, reserved)
                        .unwrap();
                assert_eq!(minimum.relay_limit, 1);
                assert_eq!(minimum.extra_fds, 0);
            }
        }
    }

    #[test]
    fn relay_fd_budget_covers_relays_cap_shed_racers_and_splice() {
        for reserved in [
            RESERVED_PROCESS_FDS,
            RESERVED_PROCESS_FDS + RESERVED_CAP_SHED_FDS,
        ] {
            for udp_enabled in [false, true] {
                let fds_per_relay = if udp_enabled { 3 } else { 2 };
                for nofile in [66, 67, 195, 196, 256, 1024, 4096, 65_536, usize::MAX] {
                    let Some(budget) = relay_fd_budget_from_nofile(nofile, fds_per_relay, reserved)
                    else {
                        assert!(nofile < reserved + fds_per_relay);
                        continue;
                    };
                    let relay_fds = budget.relay_limit * fds_per_relay;
                    assert!(reserved + relay_fds + budget.extra_fds <= nofile);
                    for splice_relays in 0..=MAX_CONCURRENT_KERNEL_SPLICE_RELAYS {
                        let splice_fds = splice_relays * RESERVED_FDS_PER_KERNEL_SPLICE;
                        if splice_fds > budget.extra_fds {
                            break;
                        }
                        let racers = (budget.extra_fds - splice_fds)
                            .min(MAX_INFLIGHT_EXTRA_CONNECT_ATTEMPTS);
                        assert!(reserved + relay_fds + splice_fds + racers <= nofile);
                    }
                }
                let minimum =
                    relay_fd_budget_from_nofile(reserved + fds_per_relay, fds_per_relay, reserved)
                        .unwrap();
                assert_eq!(minimum.relay_limit, 1);
                assert_eq!(minimum.extra_fds, 0);
            }
        }
    }

    #[test]
    fn optional_fd_budget_is_shared_and_released_on_drop() {
        let budget = ExtraFdBudget::new(RESERVED_FDS_PER_KERNEL_SPLICE);
        let racer = budget.try_reserve(1).unwrap();
        assert!(budget.try_reserve(RESERVED_FDS_PER_KERNEL_SPLICE).is_none());
        drop(racer);
        let splice = budget.try_reserve(RESERVED_FDS_PER_KERNEL_SPLICE).unwrap();
        assert!(budget.try_reserve(1).is_none());
        drop(splice);
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn optional_fd_budget_concurrent_reservations_do_not_oversubscribe() {
        let budget = ExtraFdBudget::new(8);
        let admitted_fds = AtomicUsize::new(0);
        let phase = std::sync::Barrier::new(9);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    phase.wait();
                    let reservation = budget.try_reserve(2);
                    if reservation.is_some() {
                        admitted_fds.fetch_add(2, Ordering::AcqRel);
                    }
                    phase.wait();
                    phase.wait();
                    drop(reservation);
                });
            }
            phase.wait();
            phase.wait();
            let admitted = admitted_fds.load(Ordering::Acquire);
            let held = budget.used.load(Ordering::Acquire);
            phase.wait();
            assert_eq!(admitted, 8);
            assert_eq!(held, 8);
        });
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn reused_process_reserves_the_already_configured_optional_pool() {
        let nofile = 1024;
        for first_reserved in [
            RESERVED_PROCESS_FDS,
            RESERVED_PROCESS_FDS + RESERVED_CAP_SHED_FDS,
        ] {
            let shared = relay_fd_budget_from_nofile(nofile, 2, first_reserved)
                .unwrap()
                .extra_fds;
            for reserved in [
                RESERVED_PROCESS_FDS,
                RESERVED_PROCESS_FDS + RESERVED_CAP_SHED_FDS,
            ] {
                for udp_enabled in [false, true] {
                    let fds_per_relay = client_fds_per_relay(udp_enabled);
                    let limit = relay_limit_with_extra_fds(nofile, fds_per_relay, reserved, shared)
                        .unwrap();
                    let relay_fds = limit * fds_per_relay;
                    assert!(reserved + relay_fds + shared <= nofile);
                    let server_fds = server_fds_per_relay(udp_enabled, 4);
                    let server_limit =
                        relay_limit_with_extra_fds(nofile, server_fds, reserved, shared).unwrap();
                    assert!(reserved + server_limit * server_fds + shared <= nofile);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_splice_requires_shared_fd_headroom() {
        static BUDGET: ExtraFdBudget = ExtraFdBudget::new(RESERVED_FDS_PER_KERNEL_SPLICE);
        let racer = BUDGET.try_reserve(1).unwrap();
        assert!(try_enter_kernel_splice_relay_with_budget(&BUDGET).is_none());
        drop(racer);
        let splice = try_enter_kernel_splice_relay_with_budget(&BUDGET).unwrap();
        assert!(BUDGET.try_reserve(1).is_none());
        drop(splice);
        assert_eq!(BUDGET.used.load(Ordering::Acquire), 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cancelling_splice_keeps_all_eight_fds_reserved_until_workers_finish() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        static BUDGET: ExtraFdBudget = ExtraFdBudget::new(RESERVED_FDS_PER_KERNEL_SPLICE);
        let left_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(left_listener.local_addr().unwrap())
            .await
            .unwrap();
        let (left, _) = left_listener.accept().await.unwrap();
        let right_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let right = TcpStream::connect(right_listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut origin, _) = right_listener.accept().await.unwrap();
        let slot = try_enter_kernel_splice_relay_with_budget(&BUDGET).unwrap();
        let relay = tokio::spawn(relay_kernel_splice_bidirectional_with_idle_timeout(
            left,
            right,
            Duration::from_secs(60),
            slot,
        ));

        // Receiving a relayed byte proves the blocking workers have started.
        client.write_all(b"x").await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), origin.read_exact(&mut [0_u8; 1]))
            .await
            .unwrap()
            .unwrap();
        relay.abort();
        assert!(relay.await.unwrap_err().is_cancelled());
        assert_eq!(
            BUDGET.used.load(Ordering::Acquire),
            RESERVED_FDS_PER_KERNEL_SPLICE
        );
        drop(client);
        drop(origin);
        tokio::time::timeout(Duration::from_secs(5), async {
            while BUDGET.used.load(Ordering::Acquire) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("finished splice workers release their fd reservation");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn failed_second_splice_spawn_joins_worker_before_releasing_fd_budget() {
        static BUDGET: ExtraFdBudget = ExtraFdBudget::new(RESERVED_FDS_PER_KERNEL_SPLICE);
        let left_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(left_listener.local_addr().unwrap())
            .await
            .unwrap();
        let (left, _) = left_listener.accept().await.unwrap();
        let right_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let right = TcpStream::connect(right_listener.local_addr().unwrap())
            .await
            .unwrap();
        let (origin, _) = right_listener.accept().await.unwrap();
        drop(client);
        drop(origin);
        let slot = try_enter_kernel_splice_relay_with_budget(&BUDGET).unwrap();
        let (paused_tx, paused_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let relay = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            let mut first = Some((paused_tx, release_rx));
            kernel_splice::splice_bidirectional_with_spawner(
                left.into_std().unwrap(),
                right.into_std().unwrap(),
                Duration::from_secs(600),
                |worker| {
                    let Some((paused_tx, release_rx)) = first.take() else {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "injected second worker spawn failure",
                        ));
                    };
                    std::thread::Builder::new().spawn(move || {
                        let result = worker();
                        // Pause just before thread exit: the failed startup
                        // must still be joining us with both budgets held.
                        let _ = paused_tx.send(());
                        let _ = release_rx.recv();
                        assert_eq!(
                            BUDGET.used.load(Ordering::Acquire),
                            RESERVED_FDS_PER_KERNEL_SPLICE
                        );
                        assert!(ACTIVE_KERNEL_SPLICE_RELAYS.load(Ordering::Acquire) > 0);
                        result
                    })
                },
            )
        });
        tokio::time::timeout(Duration::from_secs(5), paused_rx)
            .await
            .expect("failed startup wakes its worker instead of polling for 600s")
            .unwrap();
        assert!(!relay.is_finished(), "failed startup must join its worker");
        assert_eq!(
            BUDGET.used.load(Ordering::Acquire),
            RESERVED_FDS_PER_KERNEL_SPLICE
        );
        assert!(BUDGET.try_reserve(1).is_none());
        release_tx.send(()).unwrap();
        let err = relay.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(BUDGET.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn relay_connection_limit_is_capped() {
        assert_eq!(
            relay_connection_limit_from_nofile(usize::MAX, false),
            Some(MAX_RELAY_CONNECTION_LIMIT)
        );
    }

    #[tokio::test]
    async fn tuned_connect_rejects_empty_addr_list() {
        let err = connect_tuned_tcp_any(&[], Instant::now())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn tuned_connect_races_to_reachable_addr() {
        static BUDGET: ExtraFdBudget = ExtraFdBudget::new(3);
        let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let refused_addr = unused.local_addr().unwrap();
        drop(unused);

        let reachable = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reachable_addr = reachable.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let _ = reachable.accept().await.unwrap();
        });

        let stream = connect_tuned_tcp_race(
            &[refused_addr, reachable_addr],
            Some(&BUDGET),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), reachable_addr);
        assert_eq!(BUDGET.used.load(Ordering::Acquire), 0);
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn tuned_connect_without_extra_fd_headroom_tries_next_address() {
        let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let refused_addr = unused.local_addr().unwrap();
        drop(unused);
        let reachable = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reachable_addr = reachable.local_addr().unwrap();
        let stream = connect_tuned_tcp_race(
            &[refused_addr, reachable_addr],
            None,
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), reachable_addr);
        let _ = reachable.accept().await.unwrap();
    }

    #[derive(Default)]
    struct ConnectCounts {
        live: Cell<usize>,
        peak: Cell<usize>,
        started: Cell<usize>,
    }

    struct CountedSocket(Rc<ConnectCounts>);

    impl Drop for CountedSocket {
        fn drop(&mut self) {
            self.0.live.set(self.0.live.get() - 1);
        }
    }

    fn counted_connect_socket(counts: Rc<ConnectCounts>) -> io::Result<(TcpSocket, CountedSocket)> {
        let socket = TcpSocket::new_v4()?;
        counts.started.set(counts.started.get() + 1);
        counts.live.set(counts.live.get() + 1);
        counts.peak.set(counts.peak.get().max(counts.live.get()));
        // Tuple fields drop in order: close the real socket before decrementing
        // the live count, including when a pending connect is cancelled.
        Ok((socket, CountedSocket(counts)))
    }

    async fn injected_connect(
        addr: SocketAddr,
        counts: Rc<ConnectCounts>,
        all_pending: bool,
    ) -> io::Result<(TcpSocket, CountedSocket)> {
        assert_eq!(
            counts.live.get(),
            0,
            "the prior socket must close before the next dial"
        );
        let socket = counted_connect_socket(counts)?;
        if all_pending || addr.port() == 1 {
            std::future::pending::<()>().await;
        }
        Ok(socket)
    }

    #[tokio::test(start_paused = true)]
    async fn serial_connect_black_hole_leaves_time_for_reachable_candidate() {
        let addrs = [
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
        ];
        let counts = Rc::new(ConnectCounts::default());
        let started = Instant::now();
        let stream =
            connect_tuned_tcp_race_with(&addrs, None, started + Duration::from_secs(8), |addr| {
                injected_connect(addr, Rc::clone(&counts), false)
            })
            .await
            .unwrap();
        assert_eq!(started.elapsed(), Duration::from_secs(4));
        assert_eq!(counts.started.get(), 2);
        assert_eq!(counts.peak.get(), 1);
        assert_eq!(counts.live.get(), 1);
        drop(stream);
        assert_eq!(counts.live.get(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn serial_connect_all_black_holes_share_one_absolute_deadline() {
        let addrs = [1, 2, 3, 4, 5, 6, 7, 8].map(|port| SocketAddr::from(([127, 0, 0, 1], port)));
        let counts = Rc::new(ConnectCounts::default());
        let started = Instant::now();
        let err =
            connect_tuned_tcp_race_with(&addrs, None, started + Duration::from_secs(5), |addr| {
                injected_connect(addr, Rc::clone(&counts), true)
            })
            .await
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), Duration::from_secs(5));
        assert_eq!(counts.started.get(), 8);
        assert_eq!(counts.peak.get(), 1);
        assert_eq!(counts.live.get(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn connect_race_preserves_high_rtt_candidate() {
        static BUDGET: ExtraFdBudget = ExtraFdBudget::new(3);
        let addrs = [1, 2, 3, 4, 5, 6].map(|port| SocketAddr::from(([127, 0, 0, 1], port)));
        let counts = Rc::new(ConnectCounts::default());
        let started = Instant::now();
        let stream = connect_tuned_tcp_race_with(
            &addrs,
            Some(&BUDGET),
            started + Duration::from_secs(5),
            |addr| {
                let counts = Rc::clone(&counts);
                async move {
                    let socket = counted_connect_socket(counts)?;
                    if addr.port() == 1 {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                    Ok(socket)
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(started.elapsed(), Duration::from_secs(2));
        assert_eq!(counts.started.get(), 4);
        assert_eq!(counts.peak.get(), 4);
        assert_eq!(counts.live.get(), 1);
        assert_eq!(BUDGET.used.load(Ordering::Acquire), 0);
        drop(stream);
        assert_eq!(counts.live.get(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn connect_failing_prefix_preserves_last_candidate_budget() {
        static BUDGET: ExtraFdBudget = ExtraFdBudget::new(3);
        let addrs = [1, 2, 3, 4, 5].map(|port| SocketAddr::from(([127, 0, 0, 1], port)));
        for budget in [None, Some(&BUDGET)] {
            let counts = Rc::new(ConnectCounts::default());
            let started = Instant::now();
            let stream = connect_tuned_tcp_race_with(
                &addrs,
                budget,
                started + Duration::from_secs(5),
                |addr| {
                    let counts = Rc::clone(&counts);
                    async move {
                        if budget.is_none() {
                            assert_eq!(counts.live.get(), 0);
                        }
                        let socket = counted_connect_socket(counts)?;
                        match addr.port() {
                            1..=3 => return Err(io::Error::from(io::ErrorKind::ConnectionRefused)),
                            4 => std::future::pending::<()>().await,
                            _ => tokio::time::sleep(Duration::from_secs(2)).await,
                        }
                        Ok(socket)
                    }
                },
            )
            .await
            .unwrap();
            assert_eq!(started.elapsed(), Duration::from_millis(4500));
            assert_eq!(counts.started.get(), 5);
            assert!(counts.peak.get() <= if budget.is_some() { 4 } else { 1 });
            assert_eq!(counts.live.get(), 1);
            assert_eq!(BUDGET.used.load(Ordering::Acquire), 0);
            drop(stream);
            assert_eq!(counts.live.get(), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn connect_parallel_window_is_bounded_across_all_candidates() {
        static BUDGET: ExtraFdBudget = ExtraFdBudget::new(256);
        let addrs = [1, 2, 3, 4, 5, 6, 7, 8].map(|port| SocketAddr::from(([127, 0, 0, 1], port)));
        let counts = Rc::new(ConnectCounts::default());
        let started = Instant::now();
        let err = connect_tuned_tcp_race_with(
            &addrs,
            Some(&BUDGET),
            started + Duration::from_secs(5),
            |_| {
                let counts = Rc::clone(&counts);
                async move {
                    let socket = counted_connect_socket(counts)?;
                    std::future::pending::<()>().await;
                    Ok(socket)
                }
            },
        )
        .await
        .err()
        .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), Duration::from_secs(5));
        assert_eq!(counts.started.get(), 8);
        assert_eq!(counts.peak.get(), 4);
        assert_eq!(counts.live.get(), 0);
        assert_eq!(BUDGET.used.load(Ordering::Acquire), 0);
    }

    #[cfg(target_os = "linux")]
    fn test_kernel_splice_slot() -> KernelSpliceSlot {
        server_relay_connection_limit(false, 1).unwrap();
        try_enter_kernel_splice_relay().expect("test fd budget has splice headroom")
    }

    #[test]
    fn kernel_splice_availability_matches_target() {
        assert_eq!(kernel_splice_available(), cfg!(target_os = "linux"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn splice_relay_idle_timeout_closes_client_with_fin() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        // Origin accepts, reads whatever is relayed, then stays idle.
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut origin, _) = origin_listener.accept().await.unwrap();
            let mut buf = [0_u8; 64];
            let _ = origin.read(&mut buf).await; // forwarded client bytes
            let _ = origin.read(&mut buf).await; // blocks until the relay FINs
        });

        // The relay splices the client side to a freshly dialed origin side.
        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (client_side, _) = relay_listener.accept().await.unwrap();
            let origin_side = TcpStream::connect(origin_addr).await.unwrap();
            relay_kernel_splice_bidirectional_with_idle_timeout(
                client_side,
                origin_side,
                Duration::from_millis(50),
                test_kernel_splice_slot(),
            )
            .await
            .unwrap();
        });

        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        // Carry real bytes so the close is non-trivial, then go idle.
        client.write_all(b"hello-through-splice").await.unwrap();

        // After the idle timeout the relay tears down. The client MUST observe a
        // graceful FIN (read == Ok(0)); a RST would surface as a ConnectionReset
        // error and fail the inner expect.
        let mut buf = [0_u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("relay should close promptly after idle timeout")
            .expect("splice teardown must be a graceful FIN, not a RST");
        assert_eq!(n, 0, "client must see EOF (FIN) after splice idle teardown");

        relay_task.await.unwrap();
        origin_task.abort();
    }

    // Finding #21: a write-side idle timeout with bytes still buffered in the
    // splice pipe is a truncation, and must surface as an error (abortive
    // teardown), not as a clean FIN masquerading as success.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn splice_relay_write_side_wedge_with_buffered_data_is_an_error() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::{TcpListener, TcpStream};

        // Origin accepts but never reads, wedging the client->origin direction
        // once every socket buffer on the path fills up.
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (_origin, _) = origin_listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });

        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (client_side, _) = relay_listener.accept().await.unwrap();
            let origin_side = TcpStream::connect(origin_addr).await.unwrap();
            relay_kernel_splice_bidirectional_with_idle_timeout(
                client_side,
                origin_side,
                Duration::from_millis(100),
                test_kernel_splice_slot(),
            )
            .await
        });

        // Flood far past any plausible combined socket buffering so bytes are
        // guaranteed to be sitting in the relay pipe when the write side wedges.
        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        let flood = tokio::spawn(async move {
            let chunk = vec![0x42_u8; 1024 * 1024];
            for _ in 0..64 {
                if client.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });

        let err = tokio::time::timeout(Duration::from_secs(10), relay_task)
            .await
            .expect("relay must tear down once the write side wedges")
            .unwrap()
            .expect_err("write-side idle timeout with pipe-buffered bytes must fail the relay");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        flood.abort();
        origin_task.abort();
    }

    // Strict-FIN mandate: the ERROR/truncation teardown path (a write-side idle
    // timeout with pipe-buffered bytes) must still close the write-side (origin-
    // facing, censor-observable) peer with a graceful FIN -- the peer reads EOF --
    // never a wire RST (which would surface as ConnectionReset). The truncation is
    // surfaced to the CALLER via the relay's Err return, NOT by resetting the peer.
    // This is the regression guard for the old SO_LINGER(0) abortive close.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn splice_relay_error_path_closes_write_peer_with_fin_not_rst() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        // The origin stays idle past the idle timeout so the client->origin
        // direction wedges and hits its write-side idle timeout with bytes still
        // in the splice pipe -- the error/truncation teardown path. Only AFTER
        // that does the origin read, so its reads observe the teardown the relay
        // chose: a graceful FIN (Ok(0)) under the strict-FIN fix, or a RST
        // (ConnectionReset) under the old SO_LINGER(0) abortive close.
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut origin, _) = origin_listener.accept().await.unwrap();
            // Let the wedge form and the write-side idle timeout fire (idle
            // timeout is 100ms below) before reading anything.
            tokio::time::sleep(Duration::from_millis(500)).await;
            // Drain whatever was buffered before the wedge; the TERMINAL read must
            // be a graceful EOF (Ok(0)), never a ConnectionReset that a wire RST
            // would produce.
            let mut buf = [0_u8; 64 * 1024];
            loop {
                match tokio::time::timeout(Duration::from_secs(5), origin.read(&mut buf)).await {
                    Ok(Ok(0)) => break,    // FIN observed: graceful, censor-safe close
                    Ok(Ok(_)) => continue, // buffered pre-wedge bytes
                    Ok(Err(err)) => panic!(
                        "error-path teardown must FIN the write-side peer, got {:?}",
                        err.kind()
                    ),
                    Err(_) => panic!("relay did not close the wedged write-side peer"),
                }
            }
        });

        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (client_side, _) = relay_listener.accept().await.unwrap();
            let origin_side = TcpStream::connect(origin_addr).await.unwrap();
            relay_kernel_splice_bidirectional_with_idle_timeout(
                client_side,
                origin_side,
                Duration::from_millis(100),
                test_kernel_splice_slot(),
            )
            .await
        });

        // Flood so bytes are sitting in the relay pipe when the write side wedges,
        // and keep the client alive (write_all blocks once buffers fill) so its own
        // teardown does not race the assertion on the origin side.
        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        let flood = tokio::spawn(async move {
            let chunk = vec![0x42_u8; 1024 * 1024];
            for _ in 0..64 {
                if client.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });

        // The relay must fail (truncation surfaced to the caller as an error), which
        // proves the truncation signal is threaded via the return value rather than
        // via a wire RST.
        let err = tokio::time::timeout(Duration::from_secs(10), relay_task)
            .await
            .expect("relay must tear down once the write side wedges")
            .unwrap()
            .expect_err("write-side idle timeout with pipe-buffered bytes must fail the relay");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        // The crux: the write-side peer saw a FIN, not a RST (asserted in the task).
        tokio::time::timeout(Duration::from_secs(10), origin_task)
            .await
            .expect("origin must observe the teardown promptly")
            .unwrap();

        flood.abort();
    }

    // Finding #22: the idle clock is per direction, so a direction with no
    // traffic of its own must time out on its OWN inactivity even while the
    // sibling direction is actively pumping bytes.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn splice_relay_idle_direction_times_out_despite_busy_sibling() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();

        // Origin streams continuously (keeping origin->client busy) while
        // watching its inbound side for the relay's idle-timeout FIN.
        let origin_task = tokio::spawn(async move {
            let (origin, _) = origin_listener.accept().await.unwrap();
            let (mut origin_read, mut origin_write) = origin.into_split();
            let writer = tokio::spawn(async move {
                let chunk = [0x42_u8; 8 * 1024];
                loop {
                    if origin_write.write_all(&chunk).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            });
            // The client->origin direction is idle from the start, so the relay
            // must FIN this inbound side after that direction's own idle
            // timeout even though the other direction keeps making progress.
            let mut buf = [0_u8; 64];
            let n = tokio::time::timeout(Duration::from_secs(5), origin_read.read(&mut buf))
                .await
                .expect("idle direction must time out on its own inactivity")
                .expect("idle-direction teardown must be a graceful FIN, not a RST");
            assert_eq!(n, 0, "origin must see EOF while its stream is still busy");
            writer.abort();
        });

        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (client_side, _) = relay_listener.accept().await.unwrap();
            let origin_side = TcpStream::connect(origin_addr).await.unwrap();
            relay_kernel_splice_bidirectional_with_idle_timeout(
                client_side,
                origin_side,
                Duration::from_millis(100),
                test_kernel_splice_slot(),
            )
            .await
        });

        // The client never writes; it only drains the origin's stream so the
        // busy direction keeps bumping its own progress clock.
        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        let drain = tokio::spawn(async move {
            let mut sink = [0_u8; 16 * 1024];
            loop {
                match client.read(&mut sink).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });

        origin_task.await.unwrap();
        // Once the origin's writer stops, the busy direction EOFs/idles out and
        // the relay joins both threads and returns.
        tokio::time::timeout(Duration::from_secs(10), relay_task)
            .await
            .expect("relay must return once both directions are done")
            .unwrap()
            .unwrap();
        drain.await.unwrap();
    }
}
