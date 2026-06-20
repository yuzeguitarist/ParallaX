//! Exporter-bound authentication for the UDP fast plane (TUDP).
//!
//! The UDP leg's auth token is derived from BOTH the pre-shared key AND the live
//! QUIC/TLS session's RFC 5705 exporter secret (`export_keying_material`). The
//! exporter secret is bound to the live TLS 1.3 handshake transcript and the
//! ephemeral (EC)DHE key exchange, so it is unique per session. A censor that
//! captures and replays a QUIC Initial cannot reproduce the token: a replayed
//! Initial onto a fresh handshake yields a different exporter, hence a different
//! token. (Authenticity rests on the PSK plus the per-session exporter, not on
//! validating the server certificate, which this leg treats as camouflage.) This
//! closes the captured-Initial-replay endpoint-confirmation hole the GFW's
//! residual QUIC blocking relies on.
//!
//! The derivation is split so the crypto is unit-testable without a live QUIC
//! connection: [`derive_udp_auth_token`] is pure (exporter secret + PSK), and
//! [`export_udp_auth_token`] is the thin quinn adapter that obtains the exporter
//! secret bound to a caller-supplied context. These ARE called at runtime by the
//! reachability probe ([`crate::transport::udp::probe`]): when `[udp].enabled` is
//! set on both ends, the client and server each derive this exporter-bound token
//! over the live QUIC connection to authenticate the fast-plane probe before the
//! single-Connect data relay is committed to QUIC.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// RFC 5705 exporter label for the UDP auth binding.
pub const UDP_AUTH_EXPORTER_LABEL: &[u8] = b"ParallaX v1 TUDP auth exporter binding";
/// HKDF info label that derives the token from the PSK (salt) + exporter (IKM).
const UDP_AUTH_KEY_LABEL: &[u8] = b"ParallaX v1 TUDP auth key";
/// Domain-separation label for the hashed exporter context.
const UDP_AUTH_CONTEXT_LABEL: &[u8] = b"ParallaX v1 TUDP auth context";
/// Length of the RFC 5705 exporter secret requested from the QUIC/TLS session.
pub const UDP_AUTH_EXPORTER_LEN: usize = 32;
/// Length of the derived auth token.
pub const UDP_AUTH_TOKEN_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum UdpAuthError {
    #[error("PSK must not be empty")]
    EmptyPsk,
    #[error("QUIC TLS keying-material export failed")]
    Exporter,
    #[error("auth token derivation failed")]
    Derive,
}

/// Fold a caller-supplied context into a fixed-size, unambiguous exporter context
/// (domain-separated + length-prefixed so distinct inputs cannot collide).
fn exporter_context(context: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(UDP_AUTH_CONTEXT_LABEL);
    hasher.update((context.len() as u64).to_be_bytes());
    hasher.update(context);
    hasher.finalize().into()
}

/// Derive the UDP auth token from an RFC 5705 exporter secret and the PSK.
///
/// Pure and deterministic: the same `(exporter_secret, psk)` always yields the
/// same token, while a different exporter secret (i.e. a different TLS session)
/// or a different PSK yields a different token. This is what makes a token
/// captured on one session useless on any other.
pub fn derive_udp_auth_token(
    exporter_secret: &[u8; UDP_AUTH_EXPORTER_LEN],
    psk: &[u8],
) -> Result<Zeroizing<[u8; UDP_AUTH_TOKEN_LEN]>, UdpAuthError> {
    if psk.is_empty() {
        return Err(UdpAuthError::EmptyPsk);
    }
    // PSK in the salt position, exporter secret as IKM: the token requires BOTH
    // the shared secret and the live TLS session (mirrors the prior QUIC runtime
    // and crypto/auth's "need both" posture).
    let hk = Hkdf::<Sha256>::new(Some(psk), exporter_secret);
    // Wipe the derived token's stack slot on return (it is the HMAC key gating the
    // probe), matching the Zeroizing discipline in crypto/session.rs.
    let mut token = Zeroizing::new([0_u8; UDP_AUTH_TOKEN_LEN]);
    hk.expand(UDP_AUTH_KEY_LABEL, token.as_mut())
        .map_err(|_| UdpAuthError::Derive)?;
    Ok(token)
}

/// Export the RFC 5705 secret bound to `context` from a live QUIC connection and
/// derive the exporter-bound UDP auth token. Both peers calling this over the
/// same connection with the same PSK and context obtain the same token.
pub fn export_udp_auth_token(
    connection: &quinn::Connection,
    psk: &[u8],
    context: &[u8],
) -> Result<Zeroizing<[u8; UDP_AUTH_TOKEN_LEN]>, UdpAuthError> {
    if psk.is_empty() {
        return Err(UdpAuthError::EmptyPsk);
    }
    let ctx = exporter_context(context);
    // The live RFC 5705 exporter secret is wiped on return (including the
    // export-error path) rather than left in the stack frame, matching
    // crypto/session.rs.
    let mut exporter_secret = Zeroizing::new([0_u8; UDP_AUTH_EXPORTER_LEN]);
    connection
        .export_keying_material(exporter_secret.as_mut(), UDP_AUTH_EXPORTER_LABEL, &ctx)
        .map_err(|_| UdpAuthError::Exporter)?;
    derive_udp_auth_token(&exporter_secret, psk)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSK: &[u8] = b"parallax-tudp-test-psk-0123456789";

    #[test]
    fn token_is_deterministic_for_same_inputs() {
        let exporter = [7_u8; 32];
        let a = derive_udp_auth_token(&exporter, PSK).unwrap();
        let b = derive_udp_auth_token(&exporter, PSK).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_session_exporter_yields_different_token() {
        let token_a = derive_udp_auth_token(&[1_u8; 32], PSK).unwrap();
        let token_b = derive_udp_auth_token(&[2_u8; 32], PSK).unwrap();
        assert_ne!(
            token_a, token_b,
            "a token captured on one session must not transfer to another"
        );
    }

    #[test]
    fn different_psk_yields_different_token() {
        let exporter = [9_u8; 32];
        let a = derive_udp_auth_token(&exporter, PSK).unwrap();
        let b = derive_udp_auth_token(&exporter, b"a-completely-different-psk-value!").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn empty_psk_is_rejected() {
        assert!(matches!(
            derive_udp_auth_token(&[0_u8; 32], b""),
            Err(UdpAuthError::EmptyPsk)
        ));
    }

    /// M-15: guard against the stale "nothing calls these at runtime yet" doc
    /// claim returning — it misled reviewers into under-estimating the live QUIC
    /// attack surface (these helpers ARE driven by the runtime probe).
    #[test]
    fn module_doc_does_not_claim_helpers_are_unused_at_runtime() {
        let src = include_str!("auth.rs");
        // Build the phrases from fragments so THIS test's own source does not
        // contain them verbatim (include_str! pulls in this file too).
        let stale = format!("{} {}", "Nothing calls these", "at runtime yet");
        assert!(
            !src.contains(&stale),
            "the stale 'unused at runtime' doc claim must not return",
        );
        let sentinel = format!("{} {}", "These ARE", "called at runtime");
        assert!(
            src.contains(&sentinel),
            "the corrected runtime-usage doc sentinel must be present",
        );
    }
}
