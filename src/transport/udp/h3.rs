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
    STREAM_TYPE_CONTROL, STREAM_TYPE_QPACK_ENCODER,
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

/// Open this endpoint's HTTP/3 control-stream set and send the Safari-26 SETTINGS.
///
/// Opens the control uni stream (writes `stream_type(0x00) ++ SETTINGS`) and the
/// QPACK encoder uni stream (writes `stream_type(0x02)`; static-only, so nothing
/// more). Symmetric on client and server — both peers open their own control set
/// and emit their own SETTINGS, exactly as RFC 9114 requires of each H3 endpoint.
/// Returns the held send handles so the caller keeps the streams open for the
/// connection's life.
pub(crate) async fn open_h3_control(
    conn: &quinn::Connection,
) -> Result<H3ControlStreams, io::Error> {
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

    let mut encoder_send = conn
        .open_uni()
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::ConnectionAborted, err.to_string()))?;
    // Static-only QPACK encoder stream: just the type prefix, then idle.
    let encoder_bytes = http3::encode_stream_type(STREAM_TYPE_QPACK_ENCODER);
    encoder_send
        .write_all(&encoder_bytes)
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;

    Ok(H3ControlStreams {
        _control_send: control_send,
        _encoder_send: encoder_send,
    })
}

/// Accept the peer's HTTP/3 control stream and read its SETTINGS frame.
///
/// Accepts a single incoming uni stream, verifies its leading stream-type varint
/// is the control stream (0x00), then reads exactly the first frame and parses it
/// as SETTINGS. Returns the peer's advertised settings. Fail-closed on a wrong
/// stream type, a non-SETTINGS first frame, an oversize length, or truncation.
///
/// This reads ONLY the control stream's first frame; the stream is left open (the
/// returned `RecvStream` is dropped, which on a receive stream just stops reading
/// — it does not reset the peer's send side). The QPACK encoder/decoder streams
/// the peer may also open are not awaited here: ParallaX is static-only, so it
/// never needs to consume encoder-stream inserts.
pub(crate) async fn read_peer_h3_settings(
    conn: &quinn::Connection,
) -> Result<Vec<Http3Setting>, io::Error> {
    let mut recv = conn
        .accept_uni()
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::ConnectionAborted, err.to_string()))?;

    let stream_type = read_varint_from_stream(&mut recv).await?;
    if stream_type != STREAM_TYPE_CONTROL {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("peer first uni stream is not the H3 control stream (type {stream_type:#x})"),
        ));
    }

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

    /// A peer whose first uni stream is NOT the control stream (wrong type prefix)
    /// must be rejected fail-closed rather than silently parsed.
    #[tokio::test]
    async fn read_peer_h3_settings_rejects_wrong_stream_type() {
        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;

        let bad = async move {
            let mut s = client_conn.open_uni().await.unwrap();
            // Open a uni stream whose type is the encoder stream (0x02), not control.
            s.write_all(&http3::encode_stream_type(STREAM_TYPE_QPACK_ENCODER))
                .await
                .unwrap();
            s.finish().unwrap();
            // Keep the connection alive until the reader has classified the stream.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            client_conn
        };
        let reader = async { read_peer_h3_settings(&server_conn).await };
        let (_keepalive, result) = tokio::join!(bad, reader);
        let err = result.expect_err("a non-control first uni stream must be rejected");
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
