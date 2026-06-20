//! HTTP/3 façade orchestration over the QUIC fast plane.
//!
//! After a Verified probe both ends retain the QUIC connection for the
//! single-Connect relay. Before any relay data flows, this module establishes the
//! HTTP/3 control-stream set a real Safari-26 H3 client/server would open, so the
//! post-handshake on-wire behaviour is RFC 9114-compliant H3 rather than a bare
//! QUIC byte stream:
//!
//!   * a unidirectional **control stream** (`stream type 0x00`) whose first frame
//!     is the Safari-26 SETTINGS frame ([`crate::fingerprint::http3::safari26_settings_frame`]);
//!   * a unidirectional **QPACK encoder stream** (`stream type 0x02`). ParallaX
//!     uses static-table-only QPACK (Required Insert Count = 0), so the encoder
//!     stream carries only its type prefix and then stays idle — a fully
//!     RFC-9204-legal empty encoder stream.
//!
//! Both control streams stay OPEN for the connection's life (RFC 9114 §6.2.1: the
//! control stream must not be closed): the returned [`H3ControlStreams`] holds the
//! send handles so they are not finished until the relay tears the connection
//! down.
//!
//! This is the H3 *control* layer only. Folding the reachability probe and the
//! relay payload into an H3 request bidi stream (HEADERS + DATA frames) is a
//! separate slice; the probe and relay byte carriers are unchanged here.
//!
//! TODO(qpack-dynamic-encoder): confirm whether real Safari 26 issues QPACK
//! dynamic-table inserts on its encoder stream for the first request. ParallaX is
//! static-only, so its encoder stream is legitimately empty; if parity demands
//! inserts this is where they would be written.

use std::io;

use crate::fingerprint::http3::{
    self, parse_settings_payload, safari26_settings_frame, Http3Setting, FRAME_TYPE_SETTINGS,
    STREAM_TYPE_CONTROL, STREAM_TYPE_QPACK_DECODER, STREAM_TYPE_QPACK_ENCODER,
};

/// Defensive cap on the SETTINGS frame this façade will read off the peer's
/// control stream. Safari's SETTINGS frame is a few bytes; a hostile peer must
/// not be able to make us buffer an unbounded "SETTINGS" length.
const MAX_PEER_SETTINGS_FRAME_LEN: usize = 256;

/// The send halves of the HTTP/3 control-stream set this endpoint opened. They
/// MUST be held for the connection's whole life: dropping (and thus, in quinn,
/// implicitly resetting) or finishing the control stream would violate RFC 9114
/// §6.2.1 (the control stream stays open) and is an observable divergence from a
/// real H3 endpoint. The relay holds this until it tears the connection down.
pub(crate) struct H3ControlStreams {
    /// The unidirectional control stream (type 0x00); its first frame is SETTINGS.
    _control_send: quinn::SendStream,
    /// The unidirectional QPACK encoder stream (type 0x02); static-only, so empty
    /// after its type prefix.
    _encoder_send: quinn::SendStream,
}

impl H3ControlStreams {
    /// Assemble the held control-stream set from its individually-opened halves.
    /// Used by callers that interleave the request bidi between the control and
    /// encoder opens to match Safari's control -> request -> encoder ordering.
    pub(crate) fn new(control_send: quinn::SendStream, encoder_send: quinn::SendStream) -> Self {
        Self {
            _control_send: control_send,
            _encoder_send: encoder_send,
        }
    }
}

/// Open this endpoint's HTTP/3 **control** uni stream and send the Safari-26
/// SETTINGS (writes `stream_type(0x00) ++ SETTINGS`). Returned send handle MUST
/// be held for the connection's life (RFC 9114 §6.2.1). Opened FIRST in the
/// Safari control -> request -> encoder stream order.
pub(crate) async fn open_h3_control_stream(
    conn: &quinn::Connection,
) -> Result<quinn::SendStream, io::Error> {
    let mut control_send = conn
        .open_uni()
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::ConnectionAborted, err.to_string()))?;
    let mut control_bytes = http3::encode_stream_type(STREAM_TYPE_CONTROL);
    let settings = safari26_settings_frame()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    control_bytes.extend_from_slice(&settings);
    control_send
        .write_all(&control_bytes)
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;
    Ok(control_send)
}

/// Open this endpoint's HTTP/3 **QPACK encoder** uni stream (writes
/// `stream_type(0x02)`; static-only, so nothing more). Opened LAST in the Safari
/// control -> request -> encoder stream order. The returned send handle is held
/// for the connection's life.
pub(crate) async fn open_h3_encoder_stream(
    conn: &quinn::Connection,
) -> Result<quinn::SendStream, io::Error> {
    let mut encoder_send = conn
        .open_uni()
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::ConnectionAborted, err.to_string()))?;
    let encoder_bytes = http3::encode_stream_type(STREAM_TYPE_QPACK_ENCODER);
    encoder_send
        .write_all(&encoder_bytes)
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;
    Ok(encoder_send)
}

/// Open this endpoint's full HTTP/3 control-stream set (control + SETTINGS, then
/// QPACK encoder) back to back. Used where there is no request bidi to interleave
/// (the loopback tests); production interleaves the request bidi between the two
/// opens to match Safari's control -> request -> encoder ordering.
#[cfg(test)]
pub(crate) async fn open_h3_control(
    conn: &quinn::Connection,
) -> Result<H3ControlStreams, io::Error> {
    let control_send = open_h3_control_stream(conn).await?;
    let encoder_send = open_h3_encoder_stream(conn).await?;
    Ok(H3ControlStreams::new(control_send, encoder_send))
}

/// Accept the peer's HTTP/3 control stream and read its SETTINGS frame.
///
/// Accepts incoming uni streams until it finds the control stream (type 0x00) —
/// the peer also opens a QPACK encoder stream (type 0x02), which may arrive first
/// and is skipped here (ParallaX is static-only, so it never needs encoder-stream
/// inserts). On the control stream it reads exactly the first frame and parses it
/// as SETTINGS, returning the peer's advertised settings. Fail-closed on an
/// unexpected non-control/non-encoder stream type, a non-SETTINGS first frame, an
/// oversize length, or truncation. Streams are left open (dropping a `RecvStream`
/// stops reading without resetting the peer's send side).
pub(crate) async fn read_peer_h3_settings(
    conn: &quinn::Connection,
) -> Result<Vec<Http3Setting>, io::Error> {
    let mut recv = loop {
        let mut recv = conn
            .accept_uni()
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::ConnectionAborted, err.to_string()))?;
        let stream_type = read_varint_from_stream(&mut recv).await?;
        if stream_type == STREAM_TYPE_CONTROL {
            break recv;
        }
        if stream_type == STREAM_TYPE_QPACK_ENCODER || stream_type == STREAM_TYPE_QPACK_DECODER {
            // A QPACK encoder/decoder stream the peer opened; ParallaX is
            // static-only, so skip it and keep looking for the control stream.
            continue;
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("peer uni stream has unexpected H3 stream type {stream_type:#x}"),
        ));
    };

    let frame_type = read_varint_from_stream(&mut recv).await?;
    if frame_type != FRAME_TYPE_SETTINGS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("peer control stream first frame is not SETTINGS (type {frame_type:#x})"),
        ));
    }
    let len = read_varint_from_stream(&mut recv).await?;
    if len > MAX_PEER_SETTINGS_FRAME_LEN as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("peer SETTINGS frame length {len} exceeds bound"),
        ));
    }
    let mut payload = vec![0u8; len as usize];
    recv.read_exact(&mut payload)
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::UnexpectedEof, err.to_string()))?;
    parse_settings_payload(&payload)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
}

/// Read one QUIC varint off a quinn `RecvStream`, byte by byte. The first byte's
/// two high bits give the total length (1/2/4/8 bytes); we then read the rest with
/// `read_exact`. Used for the control stream's small framing varints (stream type,
/// frame type, frame length), so the per-call cost is negligible.
async fn read_varint_from_stream(recv: &mut quinn::RecvStream) -> Result<u64, io::Error> {
    let mut first = [0u8; 1];
    recv.read_exact(&mut first)
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::UnexpectedEof, err.to_string()))?;
    let len = 1usize << (first[0] >> 6);
    let mut value = u64::from(first[0] & 0x3f);
    if len > 1 {
        let mut rest = vec![0u8; len - 1];
        recv.read_exact(&mut rest)
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::UnexpectedEof, err.to_string()))?;
        for b in rest {
            value = (value << 8) | u64::from(b);
        }
    }
    Ok(value)
}

/// Read exactly one complete HTTP/3 frame off a quinn `RecvStream`, returning its
/// `(frame_type, payload)`. The frame's length is read incrementally (type + length
/// varints, then the payload), so this works on a streaming bidi without
/// pre-buffering. `max_payload` bounds the payload allocation so a hostile peer
/// cannot make us buffer an unbounded frame.
pub(crate) async fn read_one_h3_frame(
    recv: &mut quinn::RecvStream,
    max_payload: usize,
) -> Result<(u64, Vec<u8>), io::Error> {
    let frame_type = read_varint_from_stream(recv).await?;
    let len = read_varint_from_stream(recv).await?;
    if len > max_payload as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("H3 frame payload length {len} exceeds bound {max_payload}"),
        ));
    }
    let mut payload = vec![0u8; len as usize];
    recv.read_exact(&mut payload)
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::UnexpectedEof, err.to_string()))?;
    Ok((frame_type, payload))
}

/// Decode a self-describing H3 frame already fully buffered (used by tests and by
/// the relay-bidi slice). Thin pass-through to the codec's [`decode_frame`] so
/// callers in this module need not import the codec directly.
#[cfg(test)]
pub(crate) fn decode_buffered_frame(
    input: &[u8],
) -> Result<(http3::Http3FrameHeader, &[u8], usize), http3::Http3Error> {
    http3::decode_frame(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::http3::safari26_settings;
    use crate::transport::udp::test_support::loopback_pair;

    /// Both ends open their H3 control set and each reads the OTHER's SETTINGS;
    /// the parsed settings must equal Safari-26's ground truth, and the connection
    /// must stay alive (control streams held open, not reset).
    #[tokio::test]
    async fn h3_control_settings_exchange_over_loopback() {
        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;

        // Drive both directions concurrently: each side opens its control set and
        // reads the peer's, mirroring the relay-phase ordering.
        let client = async {
            let held = open_h3_control(&client_conn).await.unwrap();
            let peer = read_peer_h3_settings(&client_conn).await.unwrap();
            (held, peer)
        };
        let server = async {
            let held = open_h3_control(&server_conn).await.unwrap();
            let peer = read_peer_h3_settings(&server_conn).await.unwrap();
            (held, peer)
        };
        let ((_c_held, server_settings), (_s_held, client_settings)) = tokio::join!(client, server);

        assert_eq!(server_settings, safari26_settings().to_vec());
        assert_eq!(client_settings, safari26_settings().to_vec());
        assert!(client_conn.close_reason().is_none());
        assert!(server_conn.close_reason().is_none());
    }

    /// A peer whose uni stream has an UNEXPECTED type (not control, encoder, or
    /// decoder) must be rejected fail-closed. (Encoder/decoder streams are
    /// legitimately skipped while searching for the control stream.)
    #[tokio::test]
    async fn read_peer_h3_settings_rejects_unexpected_stream_type() {
        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;

        let bad = async move {
            let mut s = client_conn.open_uni().await.unwrap();
            // Open a uni stream with a reserved/unexpected type (0x21), neither the
            // control (0x00) nor the QPACK encoder/decoder (0x02/0x03) streams.
            s.write_all(&http3::encode_stream_type(0x21)).await.unwrap();
            s.finish().unwrap();
            // Keep the connection alive until the reader has classified the stream.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            client_conn
        };
        let reader = async { read_peer_h3_settings(&server_conn).await };
        let (_keepalive, result) = tokio::join!(bad, reader);
        let err = result.expect_err("an unexpected-type uni stream must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn buffered_frame_decode_passthrough() {
        let frame = safari26_settings_frame().unwrap();
        let (hdr, _payload, total) = decode_buffered_frame(&frame).unwrap();
        assert_eq!(hdr.frame_type, FRAME_TYPE_SETTINGS);
        assert_eq!(total, frame.len());
    }
}
