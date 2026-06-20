//! UDP fast-plane reachability + authenticity probe (Happy-Eyeballs).
//!
//! After the server offers the UDP leg (`PX1O` over the TCP control plane) the
//! client opens the QUIC connection and runs this probe. A verified echo proves
//! two things at once: (1) the UDP path delivers a round-trip, and (2) the
//! responder holds the exporter-bound auth token — so a middlebox that replays
//! the QUIC Initial, which cannot complete the handshake to obtain the RFC 5705
//! exporter, cannot forge the response. QUIC/UDP blocking is silent (timeout, no
//! error), so detection is ACTIVE: no verified echo within the Happy-Eyeballs
//! window means treat the UDP leg as unreachable and stay on TCP.
//!
//! The PRODUCTION round-trip rides an HTTP/3 **request bidi** stream (RFC 9114):
//! the client writes a HEADERS frame (Safari-26 request fields, method GET)
//! followed by a DATA frame whose body is the `PXp1 + nonce` request; the server
//! replies with a `:status 200` HEADERS frame and a DATA frame whose body is the
//! `PXp2 + HMAC` response. The SAME bidi stream then carries the data relay (the
//! probe round-trip IS the fast-plane Verified determination). See
//! [`probe_client_over_bidi`] / [`serve_probe_over_bidi`].
//!
//! The bare-uni-stream round-trip ([`probe_client`] / [`serve_probe`]) is the
//! earlier carrier, now PRODUCTION-UNUSED: it is retained as a tested reference
//! for the exporter-token round-trip and the Unreachable-timeout coverage (see
//! the `#[cfg(test)]` cases below). Reliable delivery (bidi or uni) means a single
//! lost packet is retransmitted rather than silently dropping the probe.
//!
//! Wired into the client/server runtimes: a Verified probe causes both ends to
//! retain the QUIC connection and carry the single-Connect data relay over the
//! request bidi stream. The demote/promote scheduler (switching transports
//! mid-session) is a later slice; for now a Verified probe commits the relay to
//! QUIC, and a mid-relay failure is a clean connection reset.

use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::auth::{export_udp_auth_token, UdpAuthError, UDP_AUTH_TOKEN_LEN};

type HmacSha256 = Hmac<Sha256>;

const PROBE_REQUEST_MAGIC: &[u8; 4] = b"PXp1";
const PROBE_RESPONSE_MAGIC: &[u8; 4] = b"PXp2";
const PROBE_NONCE_LEN: usize = 16;
const PROBE_RESPONSE_LEN: usize = 32;
/// On-wire request length: magic + nonce.
const PROBE_REQUEST_WIRE_LEN: usize = 4 + PROBE_NONCE_LEN;
/// On-wire response length: magic + HMAC.
const PROBE_RESPONSE_WIRE_LEN: usize = 4 + PROBE_RESPONSE_LEN;

/// Result of a single UDP probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// A verified, authenticated round-trip succeeded.
    Verified { rtt: Duration },
    /// No response within the Happy-Eyeballs window, or the connection died
    /// (silent black-holing) — the UDP leg is unusable; stay on TCP.
    Unreachable,
    /// A response arrived but failed authentication (e.g. an on-path echo that
    /// does not hold the exporter-bound token).
    Failed,
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("UDP auth: {0}")]
    Auth(#[from] UdpAuthError),
    #[error("QUIC probe stream send failed: {0}")]
    Send(String),
    #[error("malformed probe message")]
    Malformed,
    #[error("connection lost during probe: {0}")]
    ConnectionLost(String),
}

/// Authentication response binding the probe `nonce` to the exporter-bound token.
fn probe_response(token: &[u8; UDP_AUTH_TOKEN_LEN], nonce: &[u8]) -> [u8; PROBE_RESPONSE_LEN] {
    let mut mac = HmacSha256::new_from_slice(token).expect("HMAC accepts any key length");
    mac.update(nonce);
    mac.finalize().into_bytes().into()
}

/// Client side: send an authenticated probe over the UDP leg and classify the
/// result against the Happy-Eyeballs `timeout`.
///
/// PRODUCTION-UNUSED: the production probe rides the request bidi
/// ([`probe_client_over_bidi`]); this bare-uni carrier is kept as a tested
/// reference for the exporter-token round-trip and the Unreachable-timeout
/// coverage (its `#[cfg(test)]` cases below). It shares the SAME token derivation
/// and `probe_response` HMAC as the bidi path.
pub async fn probe_client(
    connection: &quinn::Connection,
    psk: &[u8],
    context: &[u8],
    timeout: Duration,
) -> Result<ProbeOutcome, ProbeError> {
    let token = export_udp_auth_token(connection, psk, context)?;
    let nonce: [u8; PROBE_NONCE_LEN] = rand::random();

    let mut request = Vec::with_capacity(PROBE_REQUEST_WIRE_LEN);
    request.extend_from_slice(PROBE_REQUEST_MAGIC);
    request.extend_from_slice(&nonce);

    let expected = probe_response(&token, &nonce);
    let started = Instant::now();

    // The whole request-send + response-read round-trip rides the Happy-Eyeballs
    // window. A silent black-hole or a dead connection surfaces as a timeout or a
    // stream error -> Unreachable; a well-formed but unauthenticated reply ->
    // Failed.
    match tokio::time::timeout(timeout, probe_client_round_trip(connection, &request)).await {
        // Silent black-hole, or the connection died: the path is unusable.
        Err(_) => Ok(ProbeOutcome::Unreachable),
        Ok(Err(ProbeError::ConnectionLost(_))) => Ok(ProbeOutcome::Unreachable),
        Ok(Err(other)) => Err(other),
        Ok(Ok(reply)) => {
            let authentic = reply.len() == PROBE_RESPONSE_WIRE_LEN
                && &reply[..4] == PROBE_RESPONSE_MAGIC
                && bool::from(reply[4..].ct_eq(&expected[..]));
            if authentic {
                Ok(ProbeOutcome::Verified {
                    rtt: started.elapsed(),
                })
            } else {
                Ok(ProbeOutcome::Failed)
            }
        }
    }
}

/// Send the request on a client-initiated uni stream and read the server's reply
/// off a server-initiated uni stream. Returns the raw reply bytes (validated by
/// the caller). A lost/closed connection maps to `ConnectionLost` (-> Unreachable).
///
/// PRODUCTION-UNUSED helper of [`probe_client`]; see that fn's note.
async fn probe_client_round_trip(
    connection: &quinn::Connection,
    request: &[u8],
) -> Result<Vec<u8>, ProbeError> {
    let mut send = connection
        .open_uni()
        .await
        .map_err(|err| ProbeError::ConnectionLost(err.to_string()))?;
    send.write_all(request)
        .await
        .map_err(|err| ProbeError::Send(err.to_string()))?;
    send.finish()
        .map_err(|err| ProbeError::Send(err.to_string()))?;

    let mut recv = connection
        .accept_uni()
        .await
        .map_err(|err| ProbeError::ConnectionLost(err.to_string()))?;
    recv.read_to_end(PROBE_RESPONSE_WIRE_LEN)
        .await
        .map_err(|err| ProbeError::ConnectionLost(err.to_string()))
}

/// Server side: answer one probe request with an authenticated response derived
/// from the same exporter-bound token.
///
/// PRODUCTION-UNUSED: the production server serves the probe over the request bidi
/// ([`serve_probe_over_bidi`]); this bare-uni responder is the peer of
/// [`probe_client`] and is kept as a tested reference (see that fn's note).
pub async fn serve_probe(
    connection: &quinn::Connection,
    psk: &[u8],
    context: &[u8],
) -> Result<(), ProbeError> {
    let token = export_udp_auth_token(connection, psk, context)?;
    let mut recv = connection
        .accept_uni()
        .await
        .map_err(|err| ProbeError::ConnectionLost(err.to_string()))?;
    let request = recv
        .read_to_end(PROBE_REQUEST_WIRE_LEN)
        .await
        .map_err(|err| ProbeError::ConnectionLost(err.to_string()))?;
    if request.len() != PROBE_REQUEST_WIRE_LEN || &request[..4] != PROBE_REQUEST_MAGIC {
        return Err(ProbeError::Malformed);
    }
    let response = probe_response(&token, &request[4..]);
    let mut reply = Vec::with_capacity(PROBE_RESPONSE_WIRE_LEN);
    reply.extend_from_slice(PROBE_RESPONSE_MAGIC);
    reply.extend_from_slice(&response);

    let mut send = connection
        .open_uni()
        .await
        .map_err(|err| ProbeError::ConnectionLost(err.to_string()))?;
    send.write_all(&reply)
        .await
        .map_err(|err| ProbeError::Send(err.to_string()))?;
    send.finish()
        .map_err(|err| ProbeError::Send(err.to_string()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP/3 request-bidi probe carrier.
//
// Same exporter-bound auth as the uni probe above (token derivation +
// `probe_response` HMAC are UNCHANGED): only the carrier moves from a bare uni
// round-trip to an HTTP/3 request bidi stream. The client writes a HEADERS frame
// (Safari-26 request fields for `authority`, method GET) followed by a DATA frame
// whose body is the SAME `PXp1 + nonce` request bytes; the server replies with a
// `:status 200` HEADERS frame and a DATA frame whose body is the SAME
// `PXp2 + HMAC` response bytes. After a Verified exchange the SAME bidi stream
// carries the relay (DATA-framed sealed records), so the probe round-trip IS the
// fast-plane Verified determination.
// ---------------------------------------------------------------------------

/// Defensive cap on a probe-carrying H3 frame payload read off the bidi. The
/// probe request/response bodies are tiny (<=36 bytes) and the HEADERS field
/// section is small; this bounds a hostile peer's frame allocation.
const MAX_PROBE_H3_FRAME_LEN: usize = 4096;

/// Client side of the request-bidi probe. Writes HEADERS + DATA(request) on
/// `send`, reads the server's HEADERS + DATA(response) on `recv`, and classifies
/// the result against `timeout`. The bidi streams are caller-owned (opened by the
/// relay so the SAME stream continues into the data relay); a lost/closed
/// connection maps to Unreachable, a malformed-but-present reply to Failed.
pub async fn probe_client_over_bidi(
    connection: &quinn::Connection,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    authority: &str,
    psk: &[u8],
    context: &[u8],
    timeout: Duration,
) -> Result<ProbeOutcome, ProbeError> {
    let token = export_udp_auth_token(connection, psk, context)?;
    let nonce: [u8; PROBE_NONCE_LEN] = rand::random();

    let mut request = Vec::with_capacity(PROBE_REQUEST_WIRE_LEN);
    request.extend_from_slice(PROBE_REQUEST_MAGIC);
    request.extend_from_slice(&nonce);

    let expected = probe_response(&token, &nonce);
    let started = Instant::now();

    match tokio::time::timeout(
        timeout,
        probe_client_bidi_round_trip(send, recv, authority, &request),
    )
    .await
    {
        Err(_) => Ok(ProbeOutcome::Unreachable),
        Ok(Err(ProbeError::ConnectionLost(_))) => Ok(ProbeOutcome::Unreachable),
        Ok(Err(other)) => Err(other),
        Ok(Ok(reply)) => {
            let authentic = reply.len() == PROBE_RESPONSE_WIRE_LEN
                && &reply[..4] == PROBE_RESPONSE_MAGIC
                && bool::from(reply[4..].ct_eq(&expected[..]));
            if authentic {
                Ok(ProbeOutcome::Verified {
                    rtt: started.elapsed(),
                })
            } else {
                Ok(ProbeOutcome::Failed)
            }
        }
    }
}

/// Write the H3 request (HEADERS + DATA(request)) on the bidi send half and read
/// the server's H3 response (HEADERS + DATA), returning the response DATA body.
async fn probe_client_bidi_round_trip(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    authority: &str,
    request: &[u8],
) -> Result<Vec<u8>, ProbeError> {
    use crate::fingerprint::http3::{encode_frame, safari26_headers_frame, FRAME_TYPE_DATA};

    // TODO(h3-request-semantics): the HEADERS use method GET (Safari's opening
    // request shape), but we then send a client->server DATA frame (the probe
    // request, and subsequently the relay payload). A real browser GET carries NO
    // request body, so a GET followed by request-body DATA is non-typical H3
    // request semantics. This is sub-wire: it lives inside the 1-RTT-encrypted
    // request stream, so it is observable only to an adversary with MITM + the PSK
    // (who can decrypt the stream). It is the residual of the method choice in the
    // request-bidi threat model; a fully browser-faithful shape would use a method
    // that legitimately carries an upload body (or a request/response pattern with
    // no client body). Gated behind the same QUIC enable decision.
    let headers =
        safari26_headers_frame(authority).map_err(|err| ProbeError::Send(err.to_string()))?;
    let data =
        encode_frame(FRAME_TYPE_DATA, request).map_err(|err| ProbeError::Send(err.to_string()))?;
    let mut out = headers;
    out.extend_from_slice(&data);
    send.write_all(&out)
        .await
        .map_err(|err| ProbeError::Send(err.to_string()))?;

    read_probe_data_after_headers(recv).await
}

/// Server side of the request-bidi probe. Reads the client's HEADERS + DATA on
/// `recv`, verifies the exporter-bound token over the request nonce, and writes a
/// `:status 200` HEADERS + DATA(response) on `send`. Auth is identical to the uni
/// `serve_probe`; only the carrier differs. The caller keeps the bidi open for the
/// relay that follows on the SAME stream.
pub async fn serve_probe_over_bidi(
    connection: &quinn::Connection,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    psk: &[u8],
    context: &[u8],
) -> Result<(), ProbeError> {
    use crate::fingerprint::http3::{
        encode_frame, response_status_200_headers_frame, FRAME_TYPE_DATA,
    };

    let token = export_udp_auth_token(connection, psk, context)?;
    let request = read_probe_data_after_headers(recv).await?;
    if request.len() != PROBE_REQUEST_WIRE_LEN || &request[..4] != PROBE_REQUEST_MAGIC {
        return Err(ProbeError::Malformed);
    }
    let response = probe_response(&token, &request[4..]);
    let mut reply = Vec::with_capacity(PROBE_RESPONSE_WIRE_LEN);
    reply.extend_from_slice(PROBE_RESPONSE_MAGIC);
    reply.extend_from_slice(&response);

    let headers =
        response_status_200_headers_frame().map_err(|err| ProbeError::Send(err.to_string()))?;
    let data =
        encode_frame(FRAME_TYPE_DATA, &reply).map_err(|err| ProbeError::Send(err.to_string()))?;
    let mut out = headers;
    out.extend_from_slice(&data);
    send.write_all(&out)
        .await
        .map_err(|err| ProbeError::Send(err.to_string()))?;
    Ok(())
}

/// Read the peer's HEADERS frame (skipped — its field section is not interpreted
/// by the probe) and then the first DATA frame, returning the DATA body. Any
/// non-HEADERS-then-DATA shape, or a lost connection, is surfaced as an error.
async fn read_probe_data_after_headers(
    recv: &mut quinn::RecvStream,
) -> Result<Vec<u8>, ProbeError> {
    use crate::fingerprint::http3::{FRAME_TYPE_DATA, FRAME_TYPE_HEADERS};

    let (first_type, _first_payload) = super::h3::read_one_h3_frame(recv, MAX_PROBE_H3_FRAME_LEN)
        .await
        .map_err(|err| ProbeError::ConnectionLost(err.to_string()))?;
    if first_type != FRAME_TYPE_HEADERS {
        return Err(ProbeError::Malformed);
    }
    let (second_type, data) = super::h3::read_one_h3_frame(recv, MAX_PROBE_H3_FRAME_LEN)
        .await
        .map_err(|err| ProbeError::ConnectionLost(err.to_string()))?;
    if second_type != FRAME_TYPE_DATA {
        return Err(ProbeError::Malformed);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::udp::test_support::loopback_pair;

    const PSK: &[u8] = b"parallax-tudp-probe-test-psk-0123";
    const CTX: &[u8] = b"probe-offer-context";

    #[test]
    fn probe_response_is_deterministic_and_bound_to_token_and_nonce() {
        let token_a = [3_u8; UDP_AUTH_TOKEN_LEN];
        let token_b = [4_u8; UDP_AUTH_TOKEN_LEN];
        let nonce = [9_u8; PROBE_NONCE_LEN];
        assert_eq!(
            probe_response(&token_a, &nonce),
            probe_response(&token_a, &nonce)
        );
        assert_ne!(
            probe_response(&token_a, &nonce),
            probe_response(&token_b, &nonce),
            "response must depend on the token"
        );
        assert_ne!(
            probe_response(&token_a, &nonce),
            probe_response(&token_a, &[1_u8; PROBE_NONCE_LEN]),
            "response must depend on the nonce"
        );
    }

    #[tokio::test]
    async fn probe_verifies_over_loopback() {
        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;
        // Drive both sides with join! (not spawn): serve_probe only *queues* its
        // reply, so server_conn must stay alive until the client has read it.
        let server = serve_probe(&server_conn, PSK, CTX);
        let client = probe_client(&client_conn, PSK, CTX, Duration::from_secs(5));
        let (server_res, client_res) = tokio::join!(server, client);
        server_res.expect("server serve_probe");
        let outcome = client_res.expect("client probe");
        assert!(
            matches!(outcome, ProbeOutcome::Verified { .. }),
            "expected Verified, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn probe_unanswered_times_out_to_unreachable() {
        // The server connection stays alive but never serves a probe, so the
        // client must hit the Happy-Eyeballs timeout and report Unreachable.
        let (_server_endpoint, _client_endpoint, client_conn, _server_conn) = loopback_pair().await;
        let outcome = probe_client(&client_conn, PSK, CTX, Duration::from_millis(300))
            .await
            .unwrap();
        assert_eq!(outcome, ProbeOutcome::Unreachable);
    }

    #[tokio::test]
    async fn probe_with_wrong_token_is_failed_not_verified() {
        // An on-path echo / replayed Initial can return a well-FORMED response
        // (correct magic + length) but cannot hold the exporter-bound token, so
        // its HMAC over the nonce will not match. Model that by serving the probe
        // with a DIFFERENT PSK than the client uses: both derive a token from the
        // same live exporter, but the differing PSK yields differing tokens, so
        // the server's response MAC fails the client's constant-time compare. The
        // client must classify this as `Failed` (authentication rejected), NOT
        // `Verified` -- this is the captured-Initial-replay / on-path-echo defense
        // and guards against a regression that makes the HMAC compare always-
        // accept.
        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;
        const WRONG_PSK: &[u8] = b"a-completely-different-psk-value!";
        // Drive both sides with join!: serve_probe only QUEUES its reply, so
        // server_conn must stay alive until the client has read it.
        let server = serve_probe(&server_conn, WRONG_PSK, CTX);
        let client = probe_client(&client_conn, PSK, CTX, Duration::from_secs(5));
        let (server_res, client_res) = tokio::join!(server, client);
        // The server happily answers (it cannot tell its token is "wrong"); the
        // mismatch is detected only on the client's authenticated compare.
        server_res.expect("server serve_probe");
        let outcome = client_res.expect("client probe");
        assert_eq!(
            outcome,
            ProbeOutcome::Failed,
            "a response that fails the exporter-bound HMAC must be Failed, not Verified"
        );
    }

    const AUTHORITY: &str = "example.com";

    #[tokio::test]
    async fn bidi_probe_verifies_over_loopback() {
        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;

        let server = async {
            let (mut send, mut recv) = server_conn.accept_bi().await.expect("accept_bi");
            serve_probe_over_bidi(&server_conn, &mut send, &mut recv, PSK, CTX)
                .await
                .expect("server serve_probe_over_bidi");
            // Keep the streams alive until the client has read the reply.
            (send, recv)
        };
        let client = async {
            let (mut send, mut recv) = client_conn.open_bi().await.expect("open_bi");
            probe_client_over_bidi(
                &client_conn,
                &mut send,
                &mut recv,
                AUTHORITY,
                PSK,
                CTX,
                Duration::from_secs(5),
            )
            .await
            .expect("client probe_client_over_bidi")
        };
        let (_server_streams, outcome) = tokio::join!(server, client);
        assert!(
            matches!(outcome, ProbeOutcome::Verified { .. }),
            "expected Verified over the request bidi, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn bidi_probe_with_wrong_token_is_failed_not_verified() {
        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;
        const WRONG_PSK: &[u8] = b"a-completely-different-psk-value!";

        let server = async {
            let (mut send, mut recv) = server_conn.accept_bi().await.expect("accept_bi");
            serve_probe_over_bidi(&server_conn, &mut send, &mut recv, WRONG_PSK, CTX)
                .await
                .expect("server serve_probe_over_bidi");
            (send, recv)
        };
        let client = async {
            let (mut send, mut recv) = client_conn.open_bi().await.expect("open_bi");
            probe_client_over_bidi(
                &client_conn,
                &mut send,
                &mut recv,
                AUTHORITY,
                PSK,
                CTX,
                Duration::from_secs(5),
            )
            .await
            .expect("client probe_client_over_bidi")
        };
        let (_server_streams, outcome) = tokio::join!(server, client);
        assert_eq!(
            outcome,
            ProbeOutcome::Failed,
            "a bidi response that fails the exporter-bound HMAC must be Failed, not Verified"
        );
    }

    /// Wire-structure oracle (application layer): the client's probe request on the
    /// H3 request bidi must be a HEADERS frame whose QPACK field section decodes to
    /// EXACTLY Safari-26's request fields (method GET, `:authority` = the camouflage
    /// SNI), followed by a DATA frame carrying the `PXp1` probe request. The
    /// server's reply must be a `:status 200` HEADERS frame + a DATA frame. This
    /// asserts the H3 framing the censor would observe matches Safari ground truth.
    ///
    /// TODO(wire-1rtt): this validates the H3 frames at the application layer (the
    /// bytes handed to/from quinn streams). A byte-level 1-RTT wire assertion (the
    /// encrypted QUIC packets a censor sees) requires in-process 1-RTT decryption
    /// and is deferred to a dedicated parity slice.
    #[tokio::test]
    async fn bidi_probe_headers_match_safari26_ground_truth() {
        use crate::fingerprint::http3::{
            decode_field_section, safari26_request_fields, FRAME_TYPE_DATA, FRAME_TYPE_HEADERS,
        };

        let (_server_endpoint, _client_endpoint, client_conn, server_conn) = loopback_pair().await;

        // Server: read the raw H3 frames the client wrote (HEADERS + DATA), assert
        // their structure, then reply with a serve_probe_over_bidi-shaped response
        // so the client's round-trip completes.
        let server = async {
            let (mut send, mut recv) = server_conn.accept_bi().await.expect("accept_bi");
            // First frame: HEADERS decoding to Safari-26 request fields.
            let (htype, hpayload) = super::super::h3::read_one_h3_frame(&mut recv, 4096)
                .await
                .expect("read client HEADERS");
            assert_eq!(
                htype, FRAME_TYPE_HEADERS,
                "client first frame must be HEADERS"
            );
            let fields = decode_field_section(&hpayload).expect("decode client HEADERS");
            assert_eq!(
                fields,
                safari26_request_fields(AUTHORITY),
                "client probe HEADERS must equal Safari-26 request fields",
            );
            // Second frame: DATA carrying the PXp1 probe request.
            let (dtype, dpayload) = super::super::h3::read_one_h3_frame(&mut recv, 4096)
                .await
                .expect("read client DATA");
            assert_eq!(dtype, FRAME_TYPE_DATA, "client second frame must be DATA");
            assert_eq!(
                &dpayload[..4],
                PROBE_REQUEST_MAGIC,
                "DATA carries PXp1 request"
            );

            // Reply with the real server response so the client classifies Verified.
            serve_probe_response_for_test(&server_conn, &mut send, &dpayload).await;
            (send, recv)
        };
        let client = async {
            let (mut send, mut recv) = client_conn.open_bi().await.expect("open_bi");
            let outcome = probe_client_over_bidi(
                &client_conn,
                &mut send,
                &mut recv,
                AUTHORITY,
                PSK,
                CTX,
                Duration::from_secs(5),
            )
            .await
            .expect("client probe_client_over_bidi");
            (outcome, send, recv)
        };
        let (_server_streams, (outcome, _c_send, _c_recv)) = tokio::join!(server, client);
        assert!(
            matches!(outcome, ProbeOutcome::Verified { .. }),
            "round-trip with structurally-asserted HEADERS must Verify, got {outcome:?}"
        );
    }

    /// Test helper: build the server's `:status 200` HEADERS + DATA(PXp2 response)
    /// for a given client request body, mirroring `serve_probe_over_bidi`'s reply
    /// (used by the wire-structure oracle which reads the request frames manually).
    async fn serve_probe_response_for_test(
        conn: &quinn::Connection,
        send: &mut quinn::SendStream,
        request: &[u8],
    ) {
        use crate::fingerprint::http3::{
            encode_frame, response_status_200_headers_frame, FRAME_TYPE_DATA,
        };
        let token = export_udp_auth_token(conn, PSK, CTX).expect("export token");
        let response = probe_response(&token, &request[4..]);
        let mut reply = Vec::new();
        reply.extend_from_slice(PROBE_RESPONSE_MAGIC);
        reply.extend_from_slice(&response);
        let headers = response_status_200_headers_frame().expect("status headers");
        let data = encode_frame(FRAME_TYPE_DATA, &reply).expect("data frame");
        let mut out = headers;
        out.extend_from_slice(&data);
        send.write_all(&out).await.expect("write response");
    }
}
