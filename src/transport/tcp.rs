#[cfg(target_os = "linux")]
use std::time::Duration;
use std::{io, net::SocketAddr};

use tokio::net::{lookup_host, tcp::OwnedReadHalf, TcpSocket, TcpStream};

const RESERVED_PROCESS_FDS: usize = 64;
const FDS_PER_RELAY_CONNECTION: usize = 2;
const MAX_RELAY_CONNECTION_LIMIT: usize = 16_384;
#[cfg(target_os = "linux")]
const TCP_NOTSENT_LOWAT_BYTES: libc::c_uint = 256 * 1024;
#[cfg(target_os = "linux")]
const SOCKET_BUSY_POLL_MICROS: libc::c_int = 50;

pub async fn connect_tuned_tcp_host(addr: &str) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = lookup_host(addr).await?.collect();
    connect_tuned_tcp_any(&addrs).await
}

pub async fn connect_tuned_tcp_any(addrs: &[SocketAddr]) -> io::Result<TcpStream> {
    let mut last_err = None;
    for addr in addrs {
        match connect_tuned_tcp_addr(*addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "no socket addresses resolved")
    }))
}

pub async fn connect_tuned_tcp_addr(addr: SocketAddr) -> io::Result<TcpStream> {
    #[cfg(target_os = "linux")]
    match connect_mptcp_addr(addr).await {
        Ok(stream) => return Ok(stream),
        Err(err) => {
            tracing::trace!(error = %err, "MPTCP connect failed; falling back to TCP");
        }
    }

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

pub fn relay_connection_limit() -> io::Result<usize> {
    relay_connection_limit_from_nofile(nofile_soft_limit()?).ok_or_else(|| {
        io::Error::other(format!(
            "RLIMIT_NOFILE soft limit is too low; need more than \
                 {RESERVED_PROCESS_FDS} file descriptors"
        ))
    })
}

pub fn relay_connection_limit_from_nofile(nofile_soft_limit: usize) -> Option<usize> {
    let available = nofile_soft_limit.checked_sub(RESERVED_PROCESS_FDS)?;
    let limit = available / FDS_PER_RELAY_CONNECTION;
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

#[cfg(target_os = "linux")]
fn set_low_latency_congestion(stream: &TcpStream) {
    use std::{ffi::CString, os::fd::AsRawFd};

    let Ok(algorithm) = CString::new("bbr") else {
        return;
    };
    let rc = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            algorithm.as_ptr().cast(),
            algorithm.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if rc != 0 {
        tracing::trace!("TCP BBR congestion control is unavailable; keeping kernel default");
    }
}

#[cfg(not(target_os = "linux"))]
fn set_low_latency_congestion(_stream: &TcpStream) {}

#[cfg(target_os = "linux")]
fn tune_tcp_socket_before_connect(socket: &TcpSocket) {
    set_fastopen_connect(socket);
    set_notsent_lowat(socket);
    set_busy_poll(socket);
    set_incoming_cpu(socket);
}

#[cfg(not(target_os = "linux"))]
fn tune_tcp_socket_before_connect(_socket: &TcpSocket) {}

#[cfg(target_os = "linux")]
fn set_fastopen_connect(socket: &TcpSocket) {
    use std::os::fd::AsRawFd;

    set_fastopen_connect_fd(socket.as_raw_fd());
}

#[cfg(target_os = "linux")]
fn set_fastopen_connect_fd(fd: std::os::fd::RawFd) {
    let enabled: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN_CONNECT,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if rc != 0 {
        tracing::trace!("TCP_FASTOPEN_CONNECT is unavailable; using normal TCP connect");
    }
}

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
async fn connect_mptcp_addr(addr: SocketAddr) -> io::Result<TcpStream> {
    use std::os::fd::{FromRawFd, RawFd};

    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::IPPROTO_MPTCP,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    set_socket_int_option_fd(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1);
    set_socket_int_option_fd(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1);
    set_fastopen_connect_fd(fd);
    set_notsent_lowat_fd(fd);
    set_busy_poll_fd(fd);
    set_incoming_cpu_fd(fd);

    let (storage, len) = socket_addr_storage(addr);
    let rc = unsafe { libc::connect(fd, (&storage as *const libc::sockaddr_storage).cast(), len) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINPROGRESS) {
            close_raw_fd(fd);
            return Err(err);
        }
    }

    let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd as RawFd) };
    std_stream.set_nonblocking(true)?;
    let stream = TcpStream::from_std(std_stream)?;
    if rc != 0 {
        stream.writable().await?;
        if let Some(err) = stream.take_error()? {
            return Err(err);
        }
    }
    Ok(stream)
}

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
fn socket_addr_storage(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage = std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed();
    match addr {
        SocketAddr::V4(addr) => {
            let sockaddr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                storage
                    .as_mut_ptr()
                    .cast::<libc::sockaddr_in>()
                    .write(sockaddr);
            }
            (
                unsafe { storage.assume_init() },
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(addr) => {
            let sockaddr = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: addr.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: addr.scope_id(),
            };
            unsafe {
                storage
                    .as_mut_ptr()
                    .cast::<libc::sockaddr_in6>()
                    .write(sockaddr);
            }
            (
                unsafe { storage.assume_init() },
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

#[cfg(target_os = "linux")]
fn close_raw_fd(fd: std::os::fd::RawFd) {
    unsafe {
        libc::close(fd);
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
        let pipe = Pipe::new()?;
        loop {
            if !poll_fd_until_progress(
                read_stream.as_raw_fd(),
                libc::POLLIN,
                idle_timeout,
                &last_progress,
            )? {
                return Ok(());
            }
            let Some(moved) = splice_fd(read_stream.as_raw_fd(), pipe.write_fd, SPLICE_CHUNK)?
            else {
                continue;
            };
            if moved == 0 {
                let _ = write_stream.shutdown(Shutdown::Write);
                return Ok(());
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
                    &last_progress,
                )? {
                    return Ok(());
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
                return Ok(false);
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
    fn relay_connection_limit_reserves_process_fds() {
        assert_eq!(relay_connection_limit_from_nofile(64), None);
        assert_eq!(relay_connection_limit_from_nofile(66), Some(1));
        assert_eq!(relay_connection_limit_from_nofile(256), Some(96));
    }

    #[test]
    fn relay_connection_limit_is_capped() {
        assert_eq!(
            relay_connection_limit_from_nofile(usize::MAX),
            Some(MAX_RELAY_CONNECTION_LIMIT)
        );
    }

    #[tokio::test]
    async fn tuned_connect_rejects_empty_addr_list() {
        let err = connect_tuned_tcp_any(&[]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn kernel_splice_availability_matches_target() {
        assert_eq!(kernel_splice_available(), cfg!(target_os = "linux"));
    }
}
