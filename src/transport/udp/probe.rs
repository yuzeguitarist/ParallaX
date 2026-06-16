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
//! Wired into the client/server runtimes: a Verified probe causes both ends to
//! retain the QUIC connection and carry the single-Connect data relay over a
//! reliable bidi stream. The demote/promote scheduler (switching transports
//! mid-session) is a later slice; for now a Verified probe commits the relay to
//! QUIC, and a mid-relay failure is a clean connection reset.

use std::time::{Duration, Instant};

use bytes::Bytes;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::auth::{export_udp_auth_token, UdpAuthError, UDP_AUTH_TOKEN_LEN};

type HmacSha256 = Hmac<Sha256>;

const PROBE_REQUEST_MAGIC: &[u8; 4] = b"PXp1";
const PROBE_RESPONSE_MAGIC: &[u8; 4] = b"PXp2";
const PROBE_NONCE_LEN: usize = 16;
const PROBE_RESPONSE_LEN: usize = 32;

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
    #[error("QUIC datagram send failed: {0}")]
    Send(String),
    #[error("malformed probe datagram")]
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
pub async fn probe_client(
    connection: &quinn::Connection,
    psk: &[u8],
    context: &[u8],
    timeout: Duration,
) -> Result<ProbeOutcome, ProbeError> {
    let token = export_udp_auth_token(connection, psk, context)?;
    let nonce: [u8; PROBE_NONCE_LEN] = rand::random();

    let mut request = Vec::with_capacity(4 + PROBE_NONCE_LEN);
    request.extend_from_slice(PROBE_REQUEST_MAGIC);
    request.extend_from_slice(&nonce);

    let started = Instant::now();
    connection
        .send_datagram(Bytes::from(request))
        .map_err(|err| ProbeError::Send(err.to_string()))?;

    let expected = probe_response(&token, &nonce);
    match tokio::time::timeout(timeout, connection.read_datagram()).await {
        // Silent black-hole, or the connection died: the path is unusable.
        Err(_) => Ok(ProbeOutcome::Unreachable),
        Ok(Err(_)) => Ok(ProbeOutcome::Unreachable),
        Ok(Ok(datagram)) => {
            let authentic = datagram.len() == 4 + PROBE_RESPONSE_LEN
                && &datagram[..4] == PROBE_RESPONSE_MAGIC
                && bool::from(datagram[4..].ct_eq(&expected[..]));
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

/// Server side: answer one probe request with an authenticated response derived
/// from the same exporter-bound token.
pub async fn serve_probe(
    connection: &quinn::Connection,
    psk: &[u8],
    context: &[u8],
) -> Result<(), ProbeError> {
    let token = export_udp_auth_token(connection, psk, context)?;
    let datagram = connection
        .read_datagram()
        .await
        .map_err(|err| ProbeError::ConnectionLost(err.to_string()))?;
    if datagram.len() != 4 + PROBE_NONCE_LEN || &datagram[..4] != PROBE_REQUEST_MAGIC {
        return Err(ProbeError::Malformed);
    }
    let response = probe_response(&token, &datagram[4..]);
    let mut reply = Vec::with_capacity(4 + PROBE_RESPONSE_LEN);
    reply.extend_from_slice(PROBE_RESPONSE_MAGIC);
    reply.extend_from_slice(&response);
    connection
        .send_datagram(Bytes::from(reply))
        .map_err(|err| ProbeError::Send(err.to_string()))?;
    Ok(())
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
}
