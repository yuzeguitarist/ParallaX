use std::io;

use tokio::net::TcpStream;

pub fn tune_tcp_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    set_low_latency_congestion(stream);
    Ok(())
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

#[cfg(target_os = "linux")]
fn set_low_latency_congestion(stream: &TcpStream) {
    use std::{
        ffi::CString,
        os::{
            fd::AsRawFd,
            raw::{c_int, c_void},
        },
    };

    const IPPROTO_TCP: c_int = 6;
    const TCP_CONGESTION: c_int = 13;

    unsafe extern "C" {
        fn setsockopt(
            socket: c_int,
            level: c_int,
            option_name: c_int,
            option_value: *const c_void,
            option_len: u32,
        ) -> c_int;
    }

    let Ok(algorithm) = CString::new("bbr") else {
        return;
    };
    let rc = unsafe {
        setsockopt(
            stream.as_raw_fd(),
            IPPROTO_TCP,
            TCP_CONGESTION,
            algorithm.as_ptr().cast(),
            algorithm.as_bytes_with_nul().len() as u32,
        )
    };
    if rc != 0 {
        tracing::trace!("TCP BBR congestion control is unavailable; keeping kernel default");
    }
}

#[cfg(not(target_os = "linux"))]
fn set_low_latency_congestion(_stream: &TcpStream) {}
