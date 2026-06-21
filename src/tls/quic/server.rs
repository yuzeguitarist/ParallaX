//! Server-side QUIC TLS 1.3 handshake (RFC 9001 + RFC 8446), clean-room.
//!
//! The mirror of [`super::handshake::ClientHandshake`]: it ingests the client's
//! ClientHello, runs the X25519MLKEM768 hybrid key exchange, and (across later
//! slices) emits the ServerHello / EncryptedExtensions / Certificate /
//! CertificateVerify / Finished flight, reusing the shared key schedule
//! ([`super::schedule`]) and packet/header protection ([`super::keys`]). Trust is
//! REALITY-style — the server signs a CertificateVerify the client need not
//! validate — but the server Finished MAC and the RFC 5705 exporter are real and
//! MUST match the client byte-for-byte.
//!
//! The server engine is built incrementally; items are wired into the
//! `ServerHandshake` state machine as the slices land, so unused-until-wired
//! pieces are tolerated here.
#![allow(dead_code)]

use aws_lc_rs::kem::{EncapsulationKey, ML_KEM_768};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{QuicTlsError, ALERT_ILLEGAL_PARAMETER};
use crate::crypto::session::{x25519_shared_secret, X25519KeyPair};

/// X25519MLKEM768 wire sizes (the IETF hybrid): the client offers the ML-KEM-768
/// encapsulation key ‖ X25519 public; the server replies with the ML-KEM-768
/// ciphertext ‖ X25519 public.
const MLKEM768_PUBLIC_KEY_LEN: usize = 1184;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
const X25519_LEN: usize = 32;

/// The combined hybrid shared-secret length (ML-KEM 32 ‖ X25519 32).
const HYBRID_SHARED_LEN: usize = 64;

/// Server half of the X25519MLKEM768 key exchange.
///
/// `client_share` is the client's key_share entry for group 0x11ec (the ML-KEM-768
/// encapsulation key ‖ the X25519 public). Returns the server's key_share entry
/// (ML-KEM-768 ciphertext ‖ the server's X25519 public) and the combined shared
/// secret using the IETF combiner — ML-KEM secret first, then X25519 — exactly as
/// [`super::handshake`]'s client-side combiner, so both ends agree.
fn server_hybrid_kex(client_share: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), QuicTlsError> {
    if client_share.len() != MLKEM768_PUBLIC_KEY_LEN + X25519_LEN {
        return Err(QuicTlsError::alert(
            ALERT_ILLEGAL_PARAMETER,
            "invalid X25519MLKEM768 client key_share length",
        ));
    }
    let (client_mlkem_pub, client_x25519) = client_share.split_at(MLKEM768_PUBLIC_KEY_LEN);

    let ek = EncapsulationKey::new(&ML_KEM_768, client_mlkem_pub)
        .map_err(|_| QuicTlsError::Crypto("ML-KEM-768 encapsulation key".into()))?;
    let (ciphertext, mlkem_ss) = ek
        .encapsulate()
        .map_err(|_| QuicTlsError::Crypto("ML-KEM-768 encapsulation".into()))?;
    let mlkem_shared = Zeroizing::new(mlkem_ss.as_ref().to_vec());

    let server_x25519 = X25519KeyPair::generate();
    let mut client_pub = [0u8; X25519_LEN];
    client_pub.copy_from_slice(client_x25519);
    let x25519_shared = Zeroizing::new(x25519_shared_secret(&server_x25519.private, &client_pub));
    // Reject a degenerate (all-zero) X25519 shared secret from a low-order client
    // share, mirroring the client engine's guard.
    if bool::from(x25519_shared.ct_eq(&[0u8; X25519_LEN])) {
        return Err(QuicTlsError::alert(
            ALERT_ILLEGAL_PARAMETER,
            "degenerate X25519 client key_share",
        ));
    }

    let mut combined = Zeroizing::new(Vec::with_capacity(HYBRID_SHARED_LEN));
    combined.extend_from_slice(&mlkem_shared);
    combined.extend_from_slice(&x25519_shared[..]);

    let mut server_share = Vec::with_capacity(MLKEM768_CIPHERTEXT_LEN + X25519_LEN);
    server_share.extend_from_slice(ciphertext.as_ref());
    server_share.extend_from_slice(&server_x25519.public);

    Ok((server_share, combined))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::kem::{Ciphertext, DecapsulationKey};

    #[test]
    fn hybrid_kex_client_and_server_derive_the_same_secret() {
        // Client side: build the key_share the server ingests (ML-KEM pub ‖ X25519).
        let client_x = X25519KeyPair::generate();
        let dk = DecapsulationKey::generate(&ML_KEM_768).unwrap();
        let mut client_share = dk
            .encapsulation_key()
            .and_then(|ek| ek.key_bytes())
            .unwrap()
            .as_ref()
            .to_vec();
        assert_eq!(client_share.len(), MLKEM768_PUBLIC_KEY_LEN);
        client_share.extend_from_slice(&client_x.public);

        // Server encapsulates against the client's ML-KEM key and ECDHs.
        let (server_share, server_secret) = server_hybrid_kex(&client_share).unwrap();
        assert_eq!(server_share.len(), MLKEM768_CIPHERTEXT_LEN + X25519_LEN);
        assert_eq!(server_secret.len(), HYBRID_SHARED_LEN);

        // Client recombines from the server's key_share and must match.
        let (ct, server_x25519) = server_share.split_at(MLKEM768_CIPHERTEXT_LEN);
        let mlkem_shared = dk
            .decapsulate(Ciphertext::from(ct))
            .unwrap()
            .as_ref()
            .to_vec();
        let mut sx = [0u8; X25519_LEN];
        sx.copy_from_slice(server_x25519);
        let x_shared = x25519_shared_secret(&client_x.private, &sx);
        let mut client_secret = Vec::with_capacity(HYBRID_SHARED_LEN);
        client_secret.extend_from_slice(&mlkem_shared);
        client_secret.extend_from_slice(&x_shared);

        assert_eq!(
            &server_secret[..],
            &client_secret[..],
            "client and server derive the identical hybrid shared secret"
        );
    }

    #[test]
    fn rejects_wrong_length_client_share() {
        assert!(server_hybrid_kex(&[0u8; 100]).is_err());
    }
}
