//! Rustls-free server-certificate trust policy for the hand-written QUIC TLS
//! client.
//!
//! The engine calls a [`ServerCertVerifier`] at the two TLS-1.3 authentication
//! points: the certificate chain (after Certificate) and the handshake signature
//! (CertificateVerify). Production injects [`AcceptAnyServerCert`] because the
//! QUIC leg's trust is the exporter-bound auth token, not the certificate
//! (REALITY-style; see [`crate::transport::udp::auth`]). A real
//! `rustls-webpki`-backed verifier can be supplied through the same trait without
//! pulling rustls into the engine.

use thiserror::Error;

/// Reason a certificate or handshake signature was rejected.
#[derive(Debug, Error)]
pub enum CertVerifyError {
    /// The certificate chain did not validate (untrusted, expired, wrong name…).
    #[error("invalid certificate chain: {0}")]
    Chain(String),
    /// The CertificateVerify signature did not validate.
    #[error("invalid handshake signature: {0}")]
    Signature(String),
    /// The offered signature scheme is not supported.
    #[error("unsupported signature scheme {0:#06x}")]
    UnsupportedScheme(u16),
}

/// Pluggable server-certificate trust policy.
///
/// Both methods are called by [`super::ClientHandshake`] during the server
/// flight. Implementations MUST be constant-time where they compare secrets, but
/// certificate validation here is not secret-dependent.
pub trait ServerCertVerifier: Send + Sync + std::fmt::Debug {
    /// Verify the end-entity certificate plus `intermediates` chains to a trusted
    /// root and is valid for `server_name` at `now_unix_secs`.
    ///
    /// `end_entity` and each `intermediates` entry are DER-encoded certificates.
    fn verify_cert(
        &self,
        end_entity: &[u8],
        intermediates: &[&[u8]],
        server_name: &str,
        now_unix_secs: u64,
    ) -> Result<(), CertVerifyError>;

    /// Verify the TLS 1.3 server CertificateVerify `signature` over `message`
    /// (the 64-space + context + transcript-hash construction) using the public
    /// key in `end_entity` and the wire `scheme` (a TLS `SignatureScheme`).
    fn verify_signature(
        &self,
        message: &[u8],
        end_entity: &[u8],
        scheme: u16,
        signature: &[u8],
    ) -> Result<(), CertVerifyError>;
}

/// Accept any server certificate and any handshake signature.
///
/// FOOTGUN — this disables TLS authentication entirely. It is sound ONLY on the
/// ParallaX UDP leg, whose authenticity derives from the exporter-bound auth
/// token (not the certificate), exactly like the TCP leg's REALITY-style splice.
/// Never wire it into a path whose security depends on certificate validation.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_cert(
        &self,
        _end_entity: &[u8],
        _intermediates: &[&[u8]],
        _server_name: &str,
        _now_unix_secs: u64,
    ) -> Result<(), CertVerifyError> {
        Ok(())
    }

    fn verify_signature(
        &self,
        _message: &[u8],
        _end_entity: &[u8],
        _scheme: u16,
        _signature: &[u8],
    ) -> Result<(), CertVerifyError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `AcceptAnyServerCert` deliberately trusts everything on the auth-token-bound
    // UDP leg. These tests pin that documented FOOTGUN contract so an accidental
    // future edit that starts *rejecting* inputs (which would silently break the
    // QUIC leg's handshake) fails loudly here.

    #[test]
    fn accept_any_verifies_a_typical_cert_and_signature() {
        let v = AcceptAnyServerCert;
        assert!(v
            .verify_cert(b"end-entity-der", &[b"intermediate-der"], "example.com", 1)
            .is_ok());
        assert!(v
            .verify_signature(b"transcript", b"end-entity-der", 0x0807, b"sig")
            .is_ok());
    }

    #[test]
    fn accept_any_verifies_empty_and_garbage_inputs() {
        // Empty cert, no intermediates, empty server name, epoch 0 and u64::MAX
        // clocks, empty signature, arbitrary scheme — all still accepted, because
        // this verifier makes NO decision based on its inputs.
        let v = AcceptAnyServerCert;
        assert!(v.verify_cert(b"", &[], "", 0).is_ok());
        assert!(v
            .verify_cert(&[0xFF; 8], &[b"", b"\x00\x01"], "\u{0}", u64::MAX)
            .is_ok());
        assert!(v.verify_signature(b"", b"", 0x0000, b"").is_ok());
        assert!(v
            .verify_signature(&[0xAA; 64], &[0xBB; 4], u16::MAX, &[0xCC; 3])
            .is_ok());
    }

    #[test]
    fn accept_any_is_object_safe_behind_a_trait_object() {
        // Production injects the verifier as `dyn ServerCertVerifier` into the
        // handshake, so the trait must stay object-safe and dispatch correctly.
        let v: Box<dyn ServerCertVerifier> = Box::new(AcceptAnyServerCert);
        assert!(v.verify_cert(b"c", &[], "h", 42).is_ok());
        assert!(v.verify_signature(b"m", b"c", 0x0403, b"s").is_ok());
    }

    #[test]
    fn cert_verify_error_display_is_stable() {
        // The Display strings are the diagnostic surface a real (rejecting)
        // verifier reports through; keep them stable and distinguishable.
        assert_eq!(
            CertVerifyError::Chain("expired".into()).to_string(),
            "invalid certificate chain: expired"
        );
        assert_eq!(
            CertVerifyError::Signature("bad".into()).to_string(),
            "invalid handshake signature: bad"
        );
        assert_eq!(
            CertVerifyError::UnsupportedScheme(0x0201).to_string(),
            "unsupported signature scheme 0x0201"
        );
    }
}
