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

use super::{
    QuicTlsError, ALERT_DECODE_ERROR, ALERT_HANDSHAKE_FAILURE, ALERT_ILLEGAL_PARAMETER,
    ALERT_MISSING_EXTENSION,
};
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

// --- ClientHello ingest (RFC 8446 §4.1.2) --------------------------------------

/// TLS extension codepoints the server reads off the ClientHello.
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;
/// Named-group codepoint for the X25519MLKEM768 hybrid (the only group the engine
/// completes; the GREASE entry and the standalone X25519 share are ignored).
const GROUP_X25519MLKEM768: u16 = 0x11ec;
/// The QUIC v1 Initial / pinned suite (RFC 9001).
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
/// TLS 1.3 wire version (in `supported_versions`).
const TLS13_VERSION: u16 = 0x0304;

/// The fields the server needs from a parsed ClientHello.
struct ClientHelloSummary {
    /// Echoed verbatim into the ServerHello (empty for the QUIC client).
    legacy_session_id: Vec<u8>,
    /// The client's X25519MLKEM768 key_share (ML-KEM-768 encapsulation key ‖
    /// X25519 public).
    hybrid_key_share: Vec<u8>,
    /// The peer's raw `quic_transport_parameters` (0x39) blob, for the TP reader.
    transport_params: Vec<u8>,
}

/// Parse a ClientHello body (the handshake-message payload, i.e. WITHOUT the
/// 4-byte handshake type+length header) far enough to drive the server handshake:
/// it must offer TLS 1.3 + `TLS_AES_128_GCM_SHA256`, an X25519MLKEM768 key_share,
/// and `quic_transport_parameters`.
fn parse_client_hello(body: &[u8]) -> Result<ClientHelloSummary, QuicTlsError> {
    let mut r = Reader::new(body);
    let _legacy_version = r.u16()?;
    r.take(32)?; // random
    let legacy_session_id = r.vec_u8()?.to_vec();
    let cipher_suites = r.vec_u16()?;
    if !cipher_suites
        .chunks_exact(2)
        .any(|c| u16::from_be_bytes([c[0], c[1]]) == TLS_AES_128_GCM_SHA256)
    {
        return Err(QuicTlsError::alert(
            ALERT_HANDSHAKE_FAILURE,
            "client did not offer TLS_AES_128_GCM_SHA256",
        ));
    }
    let _compression = r.vec_u8()?;

    let mut er = Reader::new(r.vec_u16()?);
    let mut hybrid_key_share = None;
    let mut transport_params = None;
    let mut offers_tls13 = false;
    while er.remaining() > 0 {
        let ext_type = er.u16()?;
        let ext_data = er.vec_u16()?;
        match ext_type {
            EXT_KEY_SHARE => {
                let mut kr = Reader::new(ext_data);
                let mut sr = Reader::new(kr.vec_u16()?);
                while sr.remaining() > 0 {
                    let group = sr.u16()?;
                    let key_exchange = sr.vec_u16()?;
                    if group == GROUP_X25519MLKEM768 {
                        hybrid_key_share = Some(key_exchange.to_vec());
                    }
                }
            }
            EXT_SUPPORTED_VERSIONS => {
                let mut vr = Reader::new(ext_data);
                if vr
                    .vec_u8()?
                    .chunks_exact(2)
                    .any(|c| u16::from_be_bytes([c[0], c[1]]) == TLS13_VERSION)
                {
                    offers_tls13 = true;
                }
            }
            EXT_QUIC_TRANSPORT_PARAMETERS => transport_params = Some(ext_data.to_vec()),
            _ => {}
        }
    }

    if !offers_tls13 {
        return Err(QuicTlsError::alert(
            ALERT_MISSING_EXTENSION,
            "client did not offer TLS 1.3",
        ));
    }
    Ok(ClientHelloSummary {
        legacy_session_id,
        hybrid_key_share: hybrid_key_share.ok_or_else(|| {
            QuicTlsError::alert(ALERT_MISSING_EXTENSION, "no X25519MLKEM768 key_share")
        })?,
        transport_params: transport_params.ok_or_else(|| {
            QuicTlsError::alert(ALERT_MISSING_EXTENSION, "no quic_transport_parameters")
        })?,
    })
}

/// A minimal big-endian, length-prefix-aware reader over a TLS structure.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], QuicTlsError> {
        let s = self
            .buf
            .get(self.pos..self.pos + n)
            .ok_or_else(|| QuicTlsError::alert(ALERT_DECODE_ERROR, "truncated ClientHello"))?;
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, QuicTlsError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, QuicTlsError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    /// A `u8`-length-prefixed byte string.
    fn vec_u8(&mut self) -> Result<&'a [u8], QuicTlsError> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    /// A `u16`-length-prefixed byte string.
    fn vec_u16(&mut self) -> Result<&'a [u8], QuicTlsError> {
        let n = self.u16()? as usize;
        self.take(n)
    }
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

    #[test]
    fn parses_a_real_client_hello_and_ingests_its_key_share() {
        use crate::tls::quic::{
            AcceptAnyServerCert, ClientConfig, ClientHandshake, QUIC_VERSION_V1,
        };
        use std::sync::Arc;

        let config = Arc::new(ClientConfig::new(
            Arc::new(AcceptAnyServerCert),
            vec![b"h3".to_vec()],
        ));
        let tp_blob = vec![0xde, 0xad, 0xbe, 0xef];
        let mut engine =
            ClientHandshake::new(config, QUIC_VERSION_V1, "example.com", tp_blob.clone()).unwrap();

        // Pull the real ClientHello handshake message and strip its 4-byte header.
        let mut msg = Vec::new();
        let _ = engine.write_handshake(&mut msg);
        assert_eq!(msg[0], 0x01, "handshake message is a ClientHello");
        let summary = parse_client_hello(&msg[4..]).unwrap();

        assert!(
            summary.legacy_session_id.is_empty(),
            "QUIC ClientHello carries an empty legacy_session_id"
        );
        assert_eq!(
            summary.hybrid_key_share.len(),
            MLKEM768_PUBLIC_KEY_LEN + X25519_LEN,
            "extracted the X25519MLKEM768 client share"
        );
        assert_eq!(summary.transport_params, tp_blob, "recovered the 0x39 blob");

        // The server can immediately ingest that share into the hybrid KEX.
        let (server_share, secret) = server_hybrid_kex(&summary.hybrid_key_share).unwrap();
        assert_eq!(server_share.len(), MLKEM768_CIPHERTEXT_LEN + X25519_LEN);
        assert_eq!(secret.len(), HYBRID_SHARED_LEN);
    }
}
