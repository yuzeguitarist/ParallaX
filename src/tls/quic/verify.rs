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
