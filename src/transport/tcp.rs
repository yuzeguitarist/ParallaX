#[cfg(target_os = "linux")]
use std::time::Duration;
use std::{
    io,
    net::SocketAddr,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

use tokio::{
    net::{lookup_host, tcp::OwnedReadHalf, TcpSocket, TcpStream},
    task::JoinSet,
};

const RESERVED_PROCESS_FDS: usize = 64;
const FDS_PER_RELAY_CONNECTION: usize = 2;
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

/// RAII reservation for one extra (non-first) parallel connect attempt. Held for
/// the lifetime of the connect task and released on completion or abort.
struct ExtraConnectGuard;

impl ExtraConnectGuard {
    fn try_acquire() -> Option<Self> {
        let prev = INFLIGHT_EXTRA_CONNECTS.fetch_add(1, Ordering::AcqRel);
        if prev >= MAX_INFLIGHT_EXTRA_CONNECT_ATTEMPTS {
            INFLIGHT_EXTRA_CONNECTS.fetch_sub(1, Ordering::AcqRel);
            None
        } else {
            Some(Self)
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
/// the 2 fds the admission semaphore budgets per connection, so unauthenticated
/// fallback traffic could drive fd/thread exhaustion before the connection limit
/// is reached. Beyond this cap, callers fall back to the userspace async relay
/// (2 fds, no native threads), which scales without per-relay threads.
#[cfg(target_os = "linux")]
const MAX_CONCURRENT_KERNEL_SPLICE_RELAYS: usize = 256;
#[cfg(target_os = "linux")]
static ACTIVE_KERNEL_SPLICE_RELAYS: AtomicUsize = AtomicUsize::new(0);

/// Path-attribution counters for fallback relays: how often the zero-copy kernel
/// splice path was taken vs forced to userspace, and why. Observability only --
/// no behavior change. Read via [`splice_path_stats`]; the relay decision in
/// `handshake::server::relay_fallback_with_idle_timeout` records into them.
static SPLICE_KERNEL_TAKEN: AtomicU64 = AtomicU64::new(0);
static SPLICE_USERSPACE_CAP_HIT: AtomicU64 = AtomicU64::new(0);
static SPLICE_USERSPACE_NON_LINUX: AtomicU64 = AtomicU64::new(0);

/// Records that a fallback relay took the zero-copy kernel splice(2) path.
pub fn record_kernel_splice_relay() {
    SPLICE_KERNEL_TAKEN.fetch_add(1, Ordering::Relaxed);
}

/// Records that a fallback relay was forced to userspace because the kernel
/// splice cap was reached.
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
pub struct KernelSpliceSlot(());

#[cfg(target_os = "linux")]
impl Drop for KernelSpliceSlot {
    fn drop(&mut self) {
        ACTIVE_KERNEL_SPLICE_RELAYS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Reserves a kernel-splice relay slot, or returns `None` when the cap is reached
/// (signalling the caller to use the userspace relay instead).
#[cfg(target_os = "linux")]
pub fn try_enter_kernel_splice_relay() -> Option<KernelSpliceSlot> {
    let prev = ACTIVE_KERNEL_SPLICE_RELAYS.fetch_add(1, Ordering::AcqRel);
    if prev >= MAX_CONCURRENT_KERNEL_SPLICE_RELAYS {
        ACTIVE_KERNEL_SPLICE_RELAYS.fetch_sub(1, Ordering::AcqRel);
        None
    } else {
        Some(KernelSpliceSlot(()))
    }
}
#[cfg(target_os = "linux")]
const TCP_NOTSENT_LOWAT_BYTES: libc::c_uint = 256 * 1024;
#[cfg(target_os = "linux")]
const SOCKET_BUSY_POLL_MICROS: libc::c_int = 50;

pub async fn connect_tuned_tcp_host(addr: &str) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = lookup_host(addr).await?.collect();
    connect_tuned_tcp_any(&addrs).await
}

pub async fn connect_tuned_tcp_any(addrs: &[SocketAddr]) -> io::Result<TcpStream> {
    match addrs {
        [] => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no socket addresses resolved",
        )),
        [addr] => connect_tuned_tcp_addr(*addr).await,
        _ => connect_tuned_tcp_race(addrs).await,
    }
}

async fn connect_tuned_tcp_race(addrs: &[SocketAddr]) -> io::Result<TcpStream> {
    let mut attempts = JoinSet::new();
    let mut addr_iter = addrs.iter().copied().take(MAX_PARALLEL_CONNECT_ATTEMPTS);

    // The first attempt is always raced: its outbound fd is covered by the
    // per-relay budget. Extra attempts only spawn while the process-wide
    // connect-race budget has room, so a burst of multi-address dials cannot
    // over-commit fds beyond what the connection limit assumes.
    if let Some(first) = addr_iter.next() {
        attempts.spawn(async move { connect_tuned_tcp_addr(first).await });
    }
    for addr in addr_iter {
        let Some(guard) = ExtraConnectGuard::try_acquire() else {
            break;
        };
        attempts.spawn(async move {
            let _guard = guard;
            connect_tuned_tcp_addr(addr).await
        });
    }

    let mut last_err = None;
    while let Some(result) = attempts.join_next().await {
        match result {
            Ok(Ok(stream)) => {
                attempts.abort_all();
                return Ok(stream);
            }
            Ok(Err(err)) => last_err = Some(err),
            Err(err) => last_err = Some(io::Error::other(err)),
        }
    }

    Err(last_err
        .unwrap_or_else(|| io::Error::other("all parallel TCP connect attempts were cancelled")))
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
    tune_tcp_socket_before_connect(&socket);
    Ok(socket)
}

pub fn tune_tcp_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    set_low_latency_congestion(stream);
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
) -> io::Result<()> {
    let left = left.into_std()?;
    let right = right.into_std()?;
    tokio::task::spawn_blocking(move || {
        kernel_splice::splice_bidirectional_with_idle_timeout(left, right, idle_timeout)
    })
    .await
    .map_err(|err| io::Error::other(err.to_string()))?
}

#[cfg(unix)]
pub fn bump_nofile_soft_limit() {
    use libc::{getrlimit, rlimit, setrlimit, RLIMIT_NOFILE};

    let mut limit = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { getrlimit(RLIMIT_NOFILE, &mut limit) };
    if rc != 0 || limit.rlim_cur >= limit.rlim_max {
        return;
    }

    let old_soft = limit.rlim_cur;
    limit.rlim_cur = limit.rlim_max;
    if unsafe { setrlimit(RLIMIT_NOFILE, &limit) } == 0 {
        tracing::debug!(
            old_soft_limit = old_soft,
            new_soft_limit = limit.rlim_cur,
            "raised RLIMIT_NOFILE soft limit"
        );
    } else {
        tracing::debug!(
            error = %io::Error::last_os_error(),
            old_soft_limit = old_soft,
            hard_limit = limit.rlim_max,
            "failed to raise RLIMIT_NOFILE soft limit"
        );
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

pub fn relay_connection_limit(udp_enabled: bool) -> io::Result<usize> {
    relay_connection_limit_from_nofile(nofile_soft_limit()?, udp_enabled).ok_or_else(|| {
        io::Error::other(format!(
            "RLIMIT_NOFILE soft limit is too low; need more than \
                 {RESERVED_PROCESS_FDS} file descriptors"
        ))
    })
}

pub fn relay_connection_limit_from_nofile(
    nofile_soft_limit: usize,
    udp_enabled: bool,
) -> Option<usize> {
    let available = nofile_soft_limit.checked_sub(RESERVED_PROCESS_FDS)?;
    // Each relay holds the TCP control pair (FDS_PER_RELAY_CONNECTION). With the
    // UDP fast plane enabled, a Verified probe also retains a quinn::Endpoint (its
    // own UDP-socket fd) for the relay's lifetime, so budget one extra fd per
    // connection or the process can approach EMFILE before the semaphore blocks.
    let fds_per_conn = if udp_enabled {
        FDS_PER_RELAY_CONNECTION + 1
    } else {
        FDS_PER_RELAY_CONNECTION
    };
    let limit = available / fds_per_conn;
    if limit == 0 {
        None
    } else {
        Some(limit.min(MAX_RELAY_CONNECTION_LIMIT))
    }
}

#[cfg(unix)]
fn nofile_soft_limit() -> io::Result<usize> {
    use libc::{getrlimit, rlimit, RLIMIT_NOFILE};

    let mut limit = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { getrlimit(RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(limit.rlim_cur as usize)
}

#[cfg(not(unix))]
fn nofile_soft_limit() -> io::Result<usize> {
    Ok(512)
}

/// Process-wide TCP congestion-control override, set once at startup.
static CONGESTION_OVERRIDE: std::sync::OnceLock<Option<std::ffi::CString>> =
    std::sync::OnceLock::new();

/// Sets the congestion-control algorithm requested on relay sockets, process
/// wide. Call once at startup before any socket is tuned. `None` (or a name
/// containing a NUL) keeps the built-in default ("bbr" on Linux).
pub fn configure_congestion_control(algorithm: Option<&str>) {
    let value = algorithm.and_then(|name| std::ffi::CString::new(name).ok());
    if CONGESTION_OVERRIDE.set(value).is_err() {
        tracing::debug!("congestion control override already set; keeping the first value");
    }
}

#[cfg(target_os = "linux")]
fn set_low_latency_congestion(stream: &TcpStream) {
    use std::{ffi::CString, os::fd::AsRawFd};

    let default = CString::new("bbr").ok();
    let configured = CONGESTION_OVERRIDE.get().and_then(|opt| opt.clone());
    let Some(algorithm) = configured.or(default) else {
        return;
    };
    let fd = stream.as_raw_fd();
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            algorithm.as_ptr().cast(),
            algorithm.as_bytes().len() as libc::socklen_t,
        )
    };
    if rc != 0 {
        tracing::trace!(
            algorithm = ?algorithm,
            "TCP congestion control request failed; keeping kernel default"
        );
        return;
    }
    // Read back: the kernel silently ignores an unknown/unloaded algorithm, so a
    // zero setsockopt return does not mean it was applied. Warn on mismatch so a
    // configured algorithm the kernel dropped does not silently lie.
    let mut current = [0_u8; 32];
    let mut len = current.len() as libc::socklen_t;
    let rrc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            current.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rrc != 0 {
        return;
    }
    // getsockopt(TCP_CONGESTION) returns min(buf, TCP_CA_NAME_MAX) bytes with the
    // name NUL-padded, so trim at the first NUL before comparing to the requested
    // name (which carries no NUL). Clamp len defensively against the buffer.
    let len = (len as usize).min(current.len());
    let applied = &current[..len];
    let applied = &applied[..applied
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(applied.len())];
    if applied != algorithm.as_bytes() {
        tracing::warn!(
            requested = ?algorithm,
            applied = %String::from_utf8_lossy(applied),
            "kernel did not apply the requested TCP congestion control (algorithm not loaded?)"
        );
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
    S: std::os::fd::AsRawFd,
{
    set_notsent_lowat_fd(socket.as_raw_fd());
}

#[cfg(target_os = "linux")]
fn set_notsent_lowat_fd(fd: std::os::fd::RawFd) {
    let lowat = TCP_NOTSENT_LOWAT_BYTES;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NOTSENT_LOWAT,
            (&lowat as *const libc::c_uint).cast(),
            std::mem::size_of_val(&lowat) as libc::socklen_t,
        )
    };
    if rc != 0 {
        tracing::trace!("TCP_NOTSENT_LOWAT is unavailable; keeping kernel send queue defaults");
    }
}

#[cfg(not(target_os = "linux"))]
fn set_notsent_lowat<S>(_socket: &S) {}

#[cfg(target_os = "linux")]
fn set_busy_poll<S>(socket: &S)
where
    S: std::os::fd::AsRawFd,
{
    set_busy_poll_fd(socket.as_raw_fd());
}

#[cfg(target_os = "linux")]
fn set_busy_poll_fd(fd: std::os::fd::RawFd) {
    set_socket_int_option_fd(
        fd,
        libc::SOL_SOCKET,
        libc::SO_BUSY_POLL,
        SOCKET_BUSY_POLL_MICROS,
    );
    set_socket_int_option_fd(fd, libc::SOL_SOCKET, libc::SO_PREFER_BUSY_POLL, 1);
}

#[cfg(not(target_os = "linux"))]
fn set_busy_poll<S>(_socket: &S) {}

#[cfg(target_os = "linux")]
fn set_incoming_cpu<S>(socket: &S)
where
    S: std::os::fd::AsRawFd,
{
    set_incoming_cpu_fd(socket.as_raw_fd());
}

#[cfg(target_os = "linux")]
fn set_incoming_cpu_fd(fd: std::os::fd::RawFd) {
    let cpu = unsafe { libc::sched_getcpu() };
    if cpu >= 0 {
        set_socket_int_option_fd(fd, libc::SOL_SOCKET, libc::SO_INCOMING_CPU, cpu);
    }
}

#[cfg(not(target_os = "linux"))]
fn set_incoming_cpu<S>(_socket: &S) {}

#[cfg(target_os = "linux")]
fn set_socket_int_option_fd(
    fd: std::os::fd::RawFd,
    level: libc::c_int,
    optname: libc::c_int,
    value: libc::c_int,
) {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc != 0 {
        tracing::trace!(
            error = %io::Error::last_os_error(),
            optname,
            "socket option unavailable; keeping kernel default"
        );
    }
}

#[cfg(target_os = "linux")]
fn set_quick_ack(stream: &TcpStream) {
    use std::os::fd::AsRawFd;

    let enabled: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_QUICKACK,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if rc != 0 {
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
        os::fd::{AsRawFd, RawFd},
        sync::{Arc, Mutex},
        thread,
        time::{Duration, Instant},
    };

    const SPLICE_CHUNK: usize = 256 * 1024;

    pub(super) fn splice_bidirectional_with_idle_timeout(
        left: StdTcpStream,
        right: StdTcpStream,
        idle_timeout: Duration,
    ) -> io::Result<()> {
        left.set_nonblocking(true)?;
        right.set_nonblocking(true)?;
        let left_to_right_read = left.try_clone()?;
        let left_to_right_write = right.try_clone()?;
        let right_to_left_read = right;
        let right_to_left_write = left;
        let last_progress = Arc::new(Mutex::new(Instant::now()));
        let left_progress = Arc::clone(&last_progress);
        let right_progress = Arc::clone(&last_progress);

        let left_to_right = thread::spawn(move || {
            splice_one_direction(
                left_to_right_read,
                left_to_right_write,
                idle_timeout,
                left_progress,
            )
        });
        let right_to_left = thread::spawn(move || {
            splice_one_direction(
                right_to_left_read,
                right_to_left_write,
                idle_timeout,
                right_progress,
            )
        });

        join_splice_thread(left_to_right)?;
        join_splice_thread(right_to_left)
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
        last_progress: Arc<Mutex<Instant>>,
    ) -> io::Result<()> {
        let result = splice_pump(&read_stream, &write_stream, idle_timeout, &last_progress);
        // FIN on EVERY exit (idle timeout, EOF, or any error): drain bytes still
        // queued on the read socket so its drop does not RST, then half-close the
        // write socket so the downstream peer sees a graceful FIN. shutdown (not a
        // bare drop) is required because the sibling direction still holds the
        // other clone of this socket. Mirrors the userspace graceful_close path.
        drain_std_recv(&read_stream);
        let _ = write_stream.shutdown(Shutdown::Write);
        result
    }

    /// Pumps one direction (read -> pipe -> write) until idle timeout, EOF, or
    /// error. Never shuts the socket down itself; the caller FINs on every exit.
    fn splice_pump(
        read_stream: &StdTcpStream,
        write_stream: &StdTcpStream,
        idle_timeout: Duration,
        last_progress: &Arc<Mutex<Instant>>,
    ) -> io::Result<()> {
        let pipe = Pipe::new()?;
        loop {
            if !poll_fd_until_progress(
                read_stream.as_raw_fd(),
                libc::POLLIN,
                idle_timeout,
                last_progress,
            )? {
                return Ok(()); // read-side idle timeout
            }
            let Some(moved) = splice_fd(read_stream.as_raw_fd(), pipe.write_fd, SPLICE_CHUNK)?
            else {
                continue;
            };
            if moved == 0 {
                return Ok(()); // read EOF (peer half-closed)
            }
            *last_progress
                .lock()
                .map_err(|_| io::Error::other("kernel splice progress lock poisoned"))? =
                Instant::now();

            let mut remaining = moved;
            while remaining > 0 {
                if !poll_fd_until_progress(
                    write_stream.as_raw_fd(),
                    libc::POLLOUT,
                    idle_timeout,
                    last_progress,
                )? {
                    return Ok(()); // write-side idle timeout
                }
                let Some(written) = splice_fd(pipe.read_fd, write_stream.as_raw_fd(), remaining)?
                else {
                    continue;
                };
                if written == 0 {
                    return Ok(());
                }
                remaining -= written;
                *last_progress
                    .lock()
                    .map_err(|_| io::Error::other("kernel splice progress lock poisoned"))? =
                    Instant::now();
            }
        }
    }

    /// Best-effort, bounded, non-blocking drain of a socket's receive buffer so
    /// that closing it emits a FIN rather than a RST. The stream is already
    /// nonblocking (set in `splice_bidirectional_with_idle_timeout`).
    fn drain_std_recv(stream: &StdTcpStream) {
        use std::io::Read;
        let mut reader: &StdTcpStream = stream;
        let mut scratch = [0_u8; 16 * 1024];
        for _ in 0..16 {
            match reader.read(&mut scratch) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }

    fn poll_fd_until_progress(
        fd: RawFd,
        events: libc::c_short,
        idle_timeout: Duration,
        last_progress: &Mutex<Instant>,
    ) -> io::Result<bool> {
        loop {
            let timeout = poll_timeout_ms(idle_timeout, last_progress)?;
            let mut poll_fd = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut poll_fd, 1, timeout) };
            if rc > 0 {
                return Ok(true);
            }
            if rc == 0 {
                // Poll timed out. The sibling direction shares last_progress and
                // may have bumped it while we waited, so only give up if the
                // shared idle deadline has truly elapsed; otherwise re-poll with
                // the refreshed remaining. This keeps the idle timer a single
                // shared deadline rather than letting a quiet direction tear down
                // a connection the other direction is actively pumping.
                if poll_timeout_ms(idle_timeout, last_progress)? == 0 {
                    return Ok(false);
                }
                continue;
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
    }

    fn poll_timeout_ms(
        idle_timeout: Duration,
        last_progress: &Mutex<Instant>,
    ) -> io::Result<libc::c_int> {
        let elapsed = last_progress
            .lock()
            .map_err(|_| io::Error::other("kernel splice progress lock poisoned"))?
            .elapsed();
        let remaining = idle_timeout.saturating_sub(elapsed);
        if remaining.is_zero() {
            Ok(0)
        } else {
            Ok(remaining.as_millis().min(libc::c_int::MAX as u128) as libc::c_int)
        }
    }

    fn splice_fd(read_fd: RawFd, write_fd: RawFd, len: usize) -> io::Result<Option<usize>> {
        loop {
            let moved = unsafe {
                libc::splice(
                    read_fd,
                    std::ptr::null_mut(),
                    write_fd,
                    std::ptr::null_mut(),
                    len,
                    libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                )
            };
            if moved >= 0 {
                return Ok(Some(moved as usize));
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => return Ok(None),
                _ => return Err(err),
            }
        }
    }

    struct Pipe {
        read_fd: RawFd,
        write_fd: RawFd,
    }

    impl Pipe {
        fn new() -> io::Result<Self> {
            let mut fds = [0; 2];
            let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                read_fd: fds[0],
                write_fd: fds[1],
            })
        }
    }

    impl Drop for Pipe {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.read_fd);
                libc::close(self.write_fd);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(relay_connection_limit_from_nofile(256, false), Some(96));
        // With the UDP fast plane on, each relay also retains a QUIC endpoint fd,
        // so the per-connection budget is 3 and the limit drops accordingly.
        assert_eq!(relay_connection_limit_from_nofile(256, true), Some(64));
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
        let err = connect_tuned_tcp_any(&[]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn tuned_connect_races_to_reachable_addr() {
        let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let refused_addr = unused.local_addr().unwrap();
        drop(unused);

        let reachable = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reachable_addr = reachable.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let _ = reachable.accept().await.unwrap();
        });

        let stream = connect_tuned_tcp_any(&[refused_addr, reachable_addr])
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), reachable_addr);
        accept.await.unwrap();
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
}
