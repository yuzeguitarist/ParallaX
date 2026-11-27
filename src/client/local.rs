//! The application side of one proxied stream.
//!
//! The relay loops only need a byte stream to read the application's upload from
//! and a byte stream to write its download to. The CLI hands them the two halves
//! of an accepted SOCKS5 `TcpStream`; an embedder (for example a userspace
//! TCP/IP stack behind an iOS packet tunnel) hands them its own flow halves.
//! These traits carry the two socket-specific behaviors the relay relies on, so
//! both inputs run the exact same relay code.

use std::{io, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadHalf, WriteHalf},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
};

/// Read half of a proxied stream: the bytes the application uploads.
pub trait LocalReader: AsyncRead + Send + Unpin + 'static {
    /// Appends bytes that are readable right now, without waiting, to
    /// `buf[filled..]` and returns the new filled length (at most `buf.len()`).
    ///
    /// The relay calls this after every successful read so a burst that is
    /// already queued is sealed as one batch. That batching also drives the
    /// relay's read-ahead gate: read-ahead engages only while a drain fills the
    /// whole buffer. Returning `filled` unchanged (the default) is always correct;
    /// it only forgoes the batching.
    fn drain_ready(&mut self, buf: &mut [u8], filled: usize) -> io::Result<usize> {
        let _ = buf;
        Ok(filled)
    }
}

/// Write half of a proxied stream: the bytes the application downloads.
pub trait LocalWriter: AsyncWrite + Send + Unpin + 'static {
    /// Ends the stream abortively. The relay calls this instead of a graceful
    /// shutdown when the server reset the stream or the download failed, so the
    /// application sees a connection error rather than a clean, complete-looking
    /// end of a truncated response. The default drops the writer, which a plain
    /// byte stream reports as a graceful close; implementations with reset
    /// semantics (TCP RST) should override it.
    fn abort(self: Box<Self>) {}
}

impl LocalReader for OwnedReadHalf {
    fn drain_ready(&mut self, buf: &mut [u8], filled: usize) -> io::Result<usize> {
        crate::transport::tcp::drain_ready_tcp_read(self, buf, filled)
    }
}

impl LocalWriter for OwnedWriteHalf {
    fn abort(self: Box<Self>) {
        let local_write = *self;
        let _ = socket2::SockRef::from(local_write.as_ref()).set_linger(Some(Duration::ZERO));
        // OwnedWriteHalf's ordinary drop shuts down the write direction, emitting
        // FIN before the upload half closes. Leave it open for the abortive close.
        local_write.forget();
    }
}

impl<T> LocalReader for ReadHalf<T> where T: AsyncRead + Send + 'static {}

impl<T> LocalWriter for WriteHalf<T> where T: AsyncWrite + Send + 'static {}

impl LocalReader for DuplexStream {}

impl LocalWriter for DuplexStream {}
