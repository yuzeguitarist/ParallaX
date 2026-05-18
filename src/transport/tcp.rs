use std::io;

use tokio::net::{tcp::OwnedReadHalf, TcpStream};

const RESERVED_PROCESS_FDS: usize = 64;
const FDS_PER_RELAY_CONNECTION: usize = 2;
const MAX_RELAY_CONNECTION_LIMIT: usize = 16_384;

pub fn tune_tcp_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    set_low_latency_congestion(stream);
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
        io::Error::other(
            format!(
                "RLIMIT_NOFILE soft limit is too low; need more than {RESERVED_PROCESS_FDS} file descriptors"
            ),
        )
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
}
