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
}
