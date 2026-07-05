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
//! This module owns the H3 *control* layer (the uni streams above). The
//! reachability probe and the relay payload ride an H3 *request bidi* stream
//! (HEADERS + DATA frames); that carrier lives in [`crate::transport::udp::probe`]
//! and the client/server runtimes, which interleave the request bidi between the
//! control and encoder opens to match Safari's control -> request -> encoder
//! stream order.
//!
//! TODO(qpack-dynamic-encoder): confirm whether real Safari 26 issues QPACK
//! dynamic-table inserts on its encoder stream for the first request. ParallaX is
//! static-only, so its encoder stream is legitimately empty; if parity demands
//! inserts this is where they would be written.

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::fingerprint::http3::{
    self, parse_settings_payload, response_status_200_headers_frame, safari26_headers_frame,
    safari26_headers_frame_with_language, safari26_settings_frame, Http3Setting,
    FRAME_TYPE_HEADERS, FRAME_TYPE_SETTINGS, STREAM_TYPE_CONTROL, STREAM_TYPE_QPACK_DECODER,
    STREAM_TYPE_QPACK_ENCODER,
};
use crate::transport::udp::quic::endpoint::{Connection, RecvStream, SendStream};

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
    _control_send: SendStream,
    /// The unidirectional QPACK encoder stream (type 0x02); static-only, so empty
    /// after its type prefix.
    _encoder_send: SendStream,
}

impl H3ControlStreams {
    /// Assemble the held control-stream set from its individually-opened halves.
    /// Used by callers that interleave the request bidi between the control and
    /// encoder opens to match Safari's control -> request -> encoder ordering.
    pub(crate) fn new(control_send: SendStream, encoder_send: SendStream) -> Self {
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
pub(crate) async fn open_h3_control_stream(conn: &Connection) -> Result<SendStream, io::Error> {
    let mut control_send = conn.open_uni();
    let mut control_bytes = http3::encode_stream_type(STREAM_TYPE_CONTROL);
    // Safari draws a fresh GREASE SETTINGS (random id + value) on every H3
    // connection; generate ours from the system CSPRNG so it is not a fixed tell.
    let grease_seed = {
        use aws_lc_rs::rand::{SecureRandom, SystemRandom};
        let mut seed = [0u8; 8];
        SystemRandom::new()
            .fill(&mut seed)
            .expect("system CSPRNG must be available");
        seed
    };
    let settings = safari26_settings_frame(http3::grease_setting_from_seed(grease_seed))
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
pub(crate) async fn open_h3_encoder_stream(conn: &Connection) -> Result<SendStream, io::Error> {
    let mut encoder_send = conn.open_uni();
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
pub(crate) async fn open_h3_control(conn: &Connection) -> Result<H3ControlStreams, io::Error> {
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
/// oversize length, or truncation.
///
/// Fail-fast on a non-cooperative peer: each of the encoder (0x02) and decoder
/// (0x03) streams is legal exactly once before the control stream (RFC 9114
/// §6.2.1 / RFC 9204 §4.2), so a DUPLICATE encoder/decoder — or more than that
/// many non-control uni streams in total — is a protocol violation and is
/// rejected rather than skipped forever. (Without this, a peer that opens endless
/// encoder/decoder streams and never opens its control stream would keep this
/// loop spinning until the caller's outer timeout fired; rejecting here turns that
/// into a prompt, clean Unreachable.) Streams are left open (dropping a
/// `RecvStream` stops reading without resetting the peer's send side).
pub(crate) async fn read_peer_h3_settings(
    conn: &Connection,
) -> Result<Vec<Http3Setting>, io::Error> {
    // At most one encoder + one decoder stream may legitimately precede the
    // control stream; cap the non-control uni streams we will skip at that count
    // so a peer cannot stall us with a flood of (even distinct-looking) streams.
    const MAX_NON_CONTROL_UNI_STREAMS: usize = 2;
    let mut seen_encoder = false;
    let mut seen_decoder = false;
    let mut non_control_seen = 0usize;
    let mut recv = loop {
        let mut recv = conn.accept_uni().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection closed before the peer's H3 control stream",
            )
        })?;
        let stream_type = read_varint_from_stream(&mut recv).await?;
        if stream_type == STREAM_TYPE_CONTROL {
            break recv;
        }
        if stream_type == STREAM_TYPE_QPACK_ENCODER || stream_type == STREAM_TYPE_QPACK_DECODER {
            // A QPACK encoder/decoder stream the peer opened; ParallaX is
            // static-only, so skip it and keep looking for the control stream — but
            // each type is legal only once, and only so many total, so reject a
            // duplicate or an over-cap flood instead of skipping it forever.
            let duplicate = if stream_type == STREAM_TYPE_QPACK_ENCODER {
                std::mem::replace(&mut seen_encoder, true)
            } else {
                std::mem::replace(&mut seen_decoder, true)
            };
            non_control_seen += 1;
            if duplicate || non_control_seen > MAX_NON_CONTROL_UNI_STREAMS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "peer opened a duplicate/excess H3 uni stream (type {stream_type:#x}) before its control stream"
                    ),
                ));
            }
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
async fn read_varint_from_stream(recv: &mut RecvStream) -> Result<u64, io::Error> {
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
    recv: &mut RecvStream,
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

/// Defensive cap on a business-bidi request/response HEADERS frame. Safari's
/// request field section is a few hundred bytes and the `:status 200` response
/// section is two; this bounds a hostile peer's HEADERS allocation, mirroring the
/// probe path's `MAX_PROBE_H3_FRAME_LEN`.
const MAX_BUSINESS_HEADERS_FRAME_LEN: usize = 4096;

/// Write the Safari-26 request HEADERS frame (method GET, `:authority = authority`)
/// as the FIRST frame on a fresh mux-over-QUIC business bidi, so the bidi opens
/// with a browser-plausible HTTP/3 request lifecycle (HEADERS then DATA) instead of
/// starting directly with a DATA frame. The encrypted ParallaX records follow as
/// DATA frames (written by [`crate::transport::leg::H3DataFrameLegWriter`]). Mirrors
/// the request-bidi probe's opening HEADERS (see [`crate::transport::udp::probe`]),
/// so a business bidi is on-wire indistinguishable from the probe bidi: a normal H3
/// request stream.
pub(crate) async fn write_business_request_headers(
    send: &mut SendStream,
    authority: &str,
    accept_language: Option<&str>,
) -> Result<(), io::Error> {
    let headers = match accept_language {
        Some(al) => safari26_headers_frame_with_language(authority, al),
        None => safari26_headers_frame(authority),
    }
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    send.write_all(&headers)
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))
}

/// Read and validate the request HEADERS frame a business bidi opens with, before
/// its relay DATA frames. The field section is NOT interpreted (ParallaX derives
/// the target from the encrypted `ConnectRequest`, not the camouflage headers): this
/// only asserts the bidi follows the HEADERS-then-DATA request shape and consumes
/// the HEADERS frame so the caller can wrap the REMAINING stream in the DATA-frame
/// de-framer ([`crate::transport::leg::H3DataFrameLegReader`]). Fail-closed on a
/// non-HEADERS first frame, an over-cap length, or truncation.
pub(crate) async fn read_business_request_headers(recv: &mut RecvStream) -> Result<(), io::Error> {
    let (frame_type, _section) = read_one_h3_frame(recv, MAX_BUSINESS_HEADERS_FRAME_LEN).await?;
    if frame_type != FRAME_TYPE_HEADERS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("business bidi first frame is not HEADERS (type {frame_type:#x})"),
        ));
    }
    Ok(())
}

/// Write the `:status 200` response HEADERS frame as the FIRST frame the SERVER
/// sends back on a business bidi, before its download DATA frames — completing the
/// browser-plausible request/response lifecycle (the client opened with request
/// HEADERS). Mirrors the probe's response HEADERS.
pub(crate) async fn write_business_response_headers(
    send: &mut SendStream,
) -> Result<(), io::Error> {
    let headers = response_status_200_headers_frame()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    send.write_all(&headers)
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))
}

/// Read and validate the server's `:status 200` response HEADERS frame the CLIENT
/// sees on a business bidi before the download DATA frames. Like the request side,
/// the field section is not interpreted; this only consumes the HEADERS frame so
/// the remaining stream can be wrapped in the DATA-frame de-framer. Fail-closed on a
/// non-HEADERS first frame, an over-cap length, or truncation.
pub(crate) async fn read_business_response_headers(recv: &mut RecvStream) -> Result<(), io::Error> {
    let (frame_type, _section) = read_one_h3_frame(recv, MAX_BUSINESS_HEADERS_FRAME_LEN).await?;
    if frame_type != FRAME_TYPE_HEADERS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("business bidi first response frame is not HEADERS (type {frame_type:#x})"),
        ));
    }
    Ok(())
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
    use crate::fingerprint::http3::is_safari26_settings;
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

        assert!(is_safari26_settings(&server_settings));
        assert!(is_safari26_settings(&client_settings));
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
            let mut s = client_conn.open_uni();
            // Open a uni stream with a reserved/unexpected type (0x21), neither the
            // control (0x00) nor the QPACK encoder/decoder (0x02/0x03) streams.
            s.write_all(&http3::encode_stream_type(0x21)).await.unwrap();
            s.finish();
            // Keep the connection alive until the reader has classified the stream.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            client_conn
        };
        let reader = async { read_peer_h3_settings(&server_conn).await };
        let (_keepalive, result) = tokio::join!(bad, reader);
        let err = result.expect_err("an unexpected-type uni stream must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A peer that opens a DUPLICATE QPACK encoder stream (each is legal only once)
    /// without ever opening its control stream must be rejected fail-fast rather
    /// than skipped forever — so a non-cooperative peer cannot stall the SETTINGS
    /// read by flooding encoder/decoder streams.
    #[tokio::test]
    async fn read_peer_h3_settings_rejects_duplicate_encoder_stream() {
        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;

        let bad = async move {
            // Two encoder streams (type 0x02), no control stream: the first is
            // legitimately skipped, the duplicate must be rejected.
            for _ in 0..2 {
                let mut s = client_conn.open_uni();
                s.write_all(&http3::encode_stream_type(STREAM_TYPE_QPACK_ENCODER))
                    .await
                    .unwrap();
                s.finish();
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            client_conn
        };
        let reader = async { read_peer_h3_settings(&server_conn).await };
        let (_keepalive, result) = tokio::join!(bad, reader);
        let err = result.expect_err("a duplicate encoder uni stream must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn buffered_frame_decode_passthrough() {
        let frame = safari26_settings_frame(http3::grease_setting_from_seed([0; 8])).unwrap();
        let (hdr, _payload, total) = decode_buffered_frame(&frame).unwrap();
        assert_eq!(hdr.frame_type, FRAME_TYPE_SETTINGS);
        assert_eq!(total, frame.len());
    }

    /// A business bidi opens with the Safari request HEADERS frame and the server
    /// answers with `:status 200` HEADERS — both sides accept the other's HEADERS,
    /// so the per-bidi request/response lifecycle round-trips over a real QUIC bidi.
    #[tokio::test]
    async fn business_bidi_headers_round_trip_over_loopback() {
        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;

        let client = async move {
            let (mut send, mut recv) = client_conn.open_bi();
            write_business_request_headers(&mut send, "example.com", None)
                .await
                .unwrap();
            // A DATA frame would normally follow; here we only assert the HEADERS
            // handshake, so read the server's response HEADERS and finish.
            read_business_response_headers(&mut recv).await.unwrap();
            client_conn
        };
        let server = async {
            let (mut send, mut recv) = server_conn.accept_bi().await.expect("accept_bi");
            read_business_request_headers(&mut recv).await.unwrap();
            write_business_response_headers(&mut send).await.unwrap();
        };
        let (_keepalive, ()) = tokio::join!(client, server);
    }

    /// A business bidi that starts directly with a DATA frame (the pre-hardening
    /// shape) MUST be rejected by the server's HEADERS read: a fresh request bidi
    /// has to open with HEADERS, never DATA.
    #[tokio::test]
    async fn business_bidi_data_first_is_rejected() {
        use crate::fingerprint::http3::{encode_frame, FRAME_TYPE_DATA};

        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;

        let bad = async move {
            let (mut send, _recv) = client_conn.open_bi();
            let data = encode_frame(FRAME_TYPE_DATA, b"records-without-headers").unwrap();
            send.write_all(&data).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            client_conn
        };
        let reader = async {
            let (_send, mut recv) = server_conn.accept_bi().await.expect("accept_bi");
            read_business_request_headers(&mut recv).await
        };
        let (_keepalive, result) = tokio::join!(bad, reader);
        let err = result.expect_err("a DATA-first business bidi must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A peer that opens the bidi but never sends the response HEADERS must NOT pin
    /// the reader forever: `read_business_response_headers` blocks pending bytes, so
    /// the caller bounds it with a timeout (CLIENT_ESTABLISH_TIMEOUT in the client
    /// substream path). This asserts that contract — the bare read does not return on
    /// its own under a silent peer, and the wrapping timeout fires instead.
    #[tokio::test]
    async fn business_bidi_response_headers_read_is_bounded_by_timeout() {
        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;

        let silent_peer = async move {
            // Accept the bidi but send nothing: the client's response-HEADERS read
            // has no bytes to make progress on.
            let (_send, _recv) = server_conn.accept_bi().await.expect("accept_bi");
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            server_conn
        };
        let reader = async {
            let (mut _send, mut recv) = client_conn.open_bi();
            // Nudge the bidi open so the peer's accept_bi resolves.
            _send.write_all(b"\x00").await.ok();
            tokio::time::timeout(
                std::time::Duration::from_millis(150),
                read_business_response_headers(&mut recv),
            )
            .await
        };
        let (_keepalive, result) = tokio::join!(silent_peer, reader);
        assert!(
            result.is_err(),
            "an unbounded read against a silent peer must hit the wrapping timeout"
        );
    }
}
