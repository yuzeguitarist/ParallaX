use std::io;

use tokio::net::TcpStream;

pub fn tune_tcp_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    set_low_latency_congestion(stream);
    Ok(())
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
