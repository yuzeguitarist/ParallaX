//! Server-side TLS certificate inspection.
//!
//! An inspector that decrypts (or, for TLS 1.2, observes in the clear) the
//! server's Certificate handshake message can fingerprint the destination from
//! the certificate chain: the leaf subject CN, its SubjectAltName DNS list, the
//! issuer, and the validity window. This module reconstructs the certificate
//! chain from a `Certificate` handshake message and applies the heuristics a
//! censor uses to flag camouflage TLS endpoints whose certificate does not
//! match the SNI it presented.
//!
//! The certificate bodies themselves (DER) are summarised into
//! [`CertificateMetadata`] by the scenario; this module models the chain
//! framing and the policy heuristics, which is where the detection decision is
//! made.

/// Handshake type for a TLS `Certificate` message.
pub const HANDSHAKE_CERTIFICATE: u8 = 0x0b;

/// Maximum number of certificates accepted from a single chain.
pub const MAX_CHAIN_LEN: usize = 8;

/// Summary of one X.509 certificate, as the inspector would extract it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateMetadata {
    /// Leaf subject common name.
    pub subject_cn: String,
    /// SubjectAltName DNS entries.
    pub san_dns: Vec<String>,
    /// Issuer common name.
    pub issuer_cn: String,
    /// True when subject == issuer (self-signed).
    pub self_signed: bool,
    /// Validity window length in days.
    pub validity_days: u32,
}

/// Position of a certificate within the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainPosition {
    /// The only certificate in the chain.
    Individual,
    /// The leaf (end-entity) certificate in a multi-cert chain.
    Leaf,
    /// An intermediate CA certificate.
    Intermediate,
    /// The root CA certificate.
    Root,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CertificateParseError {
    #[error("buffer shorter than a Certificate handshake header")]
    Truncated,
    #[error("not a Certificate handshake message (type {0:#x})")]
    NotCertificate(u8),
    #[error("malformed certificate length field")]
    MalformedLength,
    #[error("certificate chain exceeds the {MAX_CHAIN_LEN}-entry limit")]
    ChainTooLong,
}

/// A parsed Certificate handshake message: the raw DER blobs of each cert in
/// chain order (leaf first) with their assigned [`ChainPosition`].
#[derive(Debug, Clone)]
pub struct CertificateChain {
    pub certs: Vec<(ChainPosition, Vec<u8>)>,
}

/// Parse a TLS `Certificate` handshake message (TLS 1.2 framing: 3-byte total
/// length followed by 3-byte-length-prefixed DER blobs). Returns the chain with
/// each entry tagged by its position.
pub fn parse_certificate_message(bytes: &[u8]) -> Result<CertificateChain, CertificateParseError> {
    if bytes.len() < 4 {
        return Err(CertificateParseError::Truncated);
    }
    if bytes[0] != HANDSHAKE_CERTIFICATE {
        return Err(CertificateParseError::NotCertificate(bytes[0]));
    }
    let hs_len = u24(&bytes[1..4]);
    let hs_end = 4 + hs_len;
    if hs_end > bytes.len() {
        return Err(CertificateParseError::MalformedLength);
    }
    if hs_end < 7 {
        return Err(CertificateParseError::MalformedLength);
    }
    // 3-byte certificate_list length.
    let list_len = u24(&bytes[4..7]);
    let list_start = 7;
    let list_end = list_start + list_len;
    if list_end > hs_end {
        return Err(CertificateParseError::MalformedLength);
    }

    let mut raw = Vec::new();
    let mut cur = list_start;
    while cur < list_end {
        if cur + 3 > list_end {
            return Err(CertificateParseError::MalformedLength);
        }
        let cert_len = u24(&bytes[cur..cur + 3]);
        cur += 3;
        if cur + cert_len > list_end {
            return Err(CertificateParseError::MalformedLength);
        }
        if raw.len() == MAX_CHAIN_LEN {
            return Err(CertificateParseError::ChainTooLong);
        }
        raw.push(bytes[cur..cur + cert_len].to_vec());
        cur += cert_len;
    }

    let n = raw.len();
    let certs = raw
        .into_iter()
        .enumerate()
        .map(|(i, der)| (chain_position(i, n), der))
        .collect();
    Ok(CertificateChain { certs })
}

fn chain_position(index: usize, total: usize) -> ChainPosition {
    match total {
        0 | 1 => ChainPosition::Individual,
        _ if index == 0 => ChainPosition::Leaf,
        _ if index == total - 1 => ChainPosition::Root,
        _ => ChainPosition::Intermediate,
    }
}

fn u24(b: &[u8]) -> usize {
    (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2])
}

// ---------------------- Heuristics ----------------------

/// A reason the certificate looks inconsistent with the presented SNI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertTell {
    /// Neither the CN nor any SAN entry covers the SNI.
    SniNotCovered,
    /// The leaf certificate is self-signed.
    SelfSigned,
    /// The validity window is implausibly short for a public CA cert.
    ShortValidity { days: u32 },
}

/// Verdict for a server certificate against the SNI the client presented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateVerdict {
    /// Certificate is consistent with the SNI and shows no tells.
    Consistent,
    /// One or more tells fired; a censor would flag the endpoint.
    Suspicious { tells: Vec<CertTell> },
}

/// Validity windows below this many days are treated as implausibly short for
/// a public-CA-issued certificate fronting a real site.
pub const MIN_PLAUSIBLE_VALIDITY_DAYS: u32 = 7;

/// Assess a leaf certificate against the SNI presented in the ClientHello.
pub fn assess_certificate(sni: &str, meta: &CertificateMetadata) -> CertificateVerdict {
    let mut tells = Vec::new();

    if !name_covers(&meta.subject_cn, sni) && !meta.san_dns.iter().any(|n| name_covers(n, sni)) {
        tells.push(CertTell::SniNotCovered);
    }
    if meta.self_signed {
        tells.push(CertTell::SelfSigned);
    }
    if meta.validity_days < MIN_PLAUSIBLE_VALIDITY_DAYS {
        tells.push(CertTell::ShortValidity {
            days: meta.validity_days,
        });
    }

    if tells.is_empty() {
        CertificateVerdict::Consistent
    } else {
        CertificateVerdict::Suspicious { tells }
    }
}

/// Returns true if a certificate name (`pattern`, possibly a `*.` wildcard)
/// covers the SNI, matching only at label boundaries.
fn name_covers(pattern: &str, sni: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let sni = sni.trim().trim_end_matches('.').to_ascii_lowercase();
    if pattern.is_empty() || sni.is_empty() {
        return false;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // A wildcard covers exactly one extra label.
        return sni
            .strip_suffix(suffix)
            .map(|head| head.ends_with('.') && head[..head.len() - 1].split('.').count() == 1)
            .unwrap_or(false);
    }
    pattern == sni
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_certificate_message(certs: &[&[u8]]) -> Vec<u8> {
        let mut list = Vec::new();
        for cert in certs {
            let len = cert.len();
            list.push((len >> 16) as u8);
            list.push((len >> 8) as u8);
            list.push(len as u8);
            list.extend_from_slice(cert);
        }
        let mut body = Vec::new();
        let list_len = list.len();
        body.push((list_len >> 16) as u8);
        body.push((list_len >> 8) as u8);
        body.push(list_len as u8);
        body.extend_from_slice(&list);

        let mut msg = Vec::new();
        msg.push(HANDSHAKE_CERTIFICATE);
        let hs_len = body.len();
        msg.push((hs_len >> 16) as u8);
        msg.push((hs_len >> 8) as u8);
        msg.push(hs_len as u8);
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn parses_single_cert_chain() {
        let msg = build_certificate_message(&[b"leaf-der-bytes"]);
        let chain = parse_certificate_message(&msg).unwrap();
        assert_eq!(chain.certs.len(), 1);
        assert_eq!(chain.certs[0].0, ChainPosition::Individual);
        assert_eq!(chain.certs[0].1, b"leaf-der-bytes");
    }

    #[test]
    fn tags_chain_positions() {
        let msg = build_certificate_message(&[b"leaf", b"intermediate", b"root"]);
        let chain = parse_certificate_message(&msg).unwrap();
        let positions: Vec<_> = chain.certs.iter().map(|(p, _)| *p).collect();
        assert_eq!(
            positions,
            vec![
                ChainPosition::Leaf,
                ChainPosition::Intermediate,
                ChainPosition::Root
            ]
        );
    }

    #[test]
    fn rejects_non_certificate_message() {
        let mut msg = build_certificate_message(&[b"x"]);
        msg[0] = 0x02; // ServerHello type
        assert!(matches!(
            parse_certificate_message(&msg),
            Err(CertificateParseError::NotCertificate(0x02))
        ));
    }

    #[test]
    fn consistent_certificate_passes() {
        let meta = CertificateMetadata {
            subject_cn: "cloudflare.com".into(),
            san_dns: vec!["*.cloudflare.com".into(), "cloudflare.com".into()],
            issuer_cn: "DigiCert TLS".into(),
            self_signed: false,
            validity_days: 90,
        };
        assert_eq!(
            assess_certificate("www.cloudflare.com", &meta),
            CertificateVerdict::Consistent
        );
    }

    #[test]
    fn self_signed_short_validity_and_sni_mismatch_are_flagged() {
        let meta = CertificateMetadata {
            subject_cn: "internal.local".into(),
            san_dns: vec!["internal.local".into()],
            issuer_cn: "internal.local".into(),
            self_signed: true,
            validity_days: 1,
        };
        match assess_certificate("cloudflare.com", &meta) {
            CertificateVerdict::Suspicious { tells } => {
                assert!(tells.contains(&CertTell::SniNotCovered));
                assert!(tells.contains(&CertTell::SelfSigned));
                assert!(tells
                    .iter()
                    .any(|t| matches!(t, CertTell::ShortValidity { .. })));
            }
            other => panic!("expected Suspicious, got {other:?}"),
        }
    }

    #[test]
    fn wildcard_covers_single_label_only() {
        let meta = CertificateMetadata {
            subject_cn: "*.example.com".into(),
            san_dns: vec!["*.example.com".into()],
            issuer_cn: "Public CA".into(),
            self_signed: false,
            validity_days: 365,
        };
        // One extra label: covered.
        assert_eq!(
            assess_certificate("a.example.com", &meta),
            CertificateVerdict::Consistent
        );
        // Two extra labels: a wildcard does not cover this.
        match assess_certificate("a.b.example.com", &meta) {
            CertificateVerdict::Suspicious { tells } => {
                assert!(tells.contains(&CertTell::SniNotCovered))
            }
            other => panic!("expected Suspicious, got {other:?}"),
        }
    }
}
