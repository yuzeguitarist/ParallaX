//! Lightweight protocol fingerprint signatures used to satisfy the USENIX'23 Ex5
//! exemption rule ("first bytes match a well-known protocol fingerprint").
//!
//! The original GFW heuristic ships a fingerprint table for at least TLS, HTTP/1.x,
//! SSH, BitTorrent and a handful of other clear-text wire formats. We replicate that
//! pattern at low fidelity: each fingerprint is a `(name, predicate)` pair; the
//! predicate runs over the first packet bytes and returns true on a match.
//!
//! These predicates intentionally look at the *first packet* only because the
//! USENIX'23 paper measured exemption behavior on the first TCP payload. They are
//! cheap and pure functions, suitable to be called millions of times per second by
//! a line-rate DPI engine.

/// A named first-packet fingerprint. `priority` lets us pick the most specific
/// match when multiple fingerprints fire on the same input (lower is more specific).
pub struct ProtocolFingerprint {
    pub name: &'static str,
    pub priority: u8,
    pub matches: fn(&[u8]) -> bool,
}

/// The canonical fingerprint table. Add new entries here when adding new
/// exemption-eligible protocols.
pub const PROTOCOL_FINGERPRINTS: &[ProtocolFingerprint] = &[
    ProtocolFingerprint {
        name: "TLS",
        priority: 0,
        matches: is_tls_record,
    },
    ProtocolFingerprint {
        name: "QUIC-long-header",
        priority: 0,
        matches: is_quic_long_header,
    },
    ProtocolFingerprint {
        name: "HTTP/1",
        priority: 1,
        matches: is_http1_request,
    },
    ProtocolFingerprint {
        name: "HTTP/2-preface",
        priority: 1,
        matches: is_http2_preface,
    },
    ProtocolFingerprint {
        name: "SSH",
        priority: 1,
        matches: is_ssh_banner,
    },
    ProtocolFingerprint {
        name: "SMTP",
        priority: 2,
        matches: is_smtp_greeting,
    },
    ProtocolFingerprint {
        name: "FTP",
        priority: 2,
        matches: is_ftp_response,
    },
    ProtocolFingerprint {
        name: "BitTorrent",
        priority: 2,
        matches: is_bittorrent_handshake,
    },
];

/// Looks for the most specific (lowest priority) fingerprint that matches the
/// first packet bytes. Returns `None` if nothing matches.
pub fn classify_first_packet(bytes: &[u8]) -> Option<&'static str> {
    PROTOCOL_FINGERPRINTS
        .iter()
        .filter(|fp| (fp.matches)(bytes))
        .min_by_key(|fp| fp.priority)
        .map(|fp| fp.name)
}

/// TLS record: `content_type` (1 byte) `legacy_version` (2 bytes) `length` (2 bytes) + body.
///
/// The first record on a TLS connection is always a Handshake (0x16). The legacy
/// version is either 0x0301 (TLS 1.0), 0x0302 (TLS 1.1), 0x0303 (TLS 1.2/1.3) or
/// 0x0300 (SSL 3). The handshake type for ClientHello is 0x01.
pub fn is_tls_record(bytes: &[u8]) -> bool {
    if bytes.len() < 6 {
        return false;
    }
    let content_type = bytes[0];
    let major = bytes[1];
    let minor = bytes[2];
    let handshake_type = bytes[5];
    let valid_version = major == 0x03 && (0x00..=0x04).contains(&minor);
    let valid_content_type = matches!(content_type, 0x14..=0x17);
    let valid_handshake_for_clienthello = content_type != 0x16 || handshake_type == 0x01;
    valid_version && valid_content_type && valid_handshake_for_clienthello
}

/// QUIC long-header packet: first byte has the high bit set; second-highest bit is 1
/// (long-header form); the four version bytes that follow are non-zero and reflect a
/// known QUIC version. Bytes 1..=4 carry the QUIC version number in big-endian.
///
/// Note: For QUIC Initial packets (the only kind GFW can decrypt), the four-bit
/// packet type encoded in bits 4-5 of byte 0 is `00`. We don't enforce that here
/// because the simulator only uses this predicate for Ex5 exemption (any QUIC
/// long header is benign-looking enough to skip the heuristic).
pub fn is_quic_long_header(bytes: &[u8]) -> bool {
    if bytes.len() < 5 {
        return false;
    }
    let first = bytes[0];
    let is_long = (first & 0x80) != 0;
    let fixed_bit = (first & 0x40) != 0;
    if !is_long || !fixed_bit {
        return false;
    }
    let version = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    matches!(
        version,
        0x0000_0001 // QUIC v1 (RFC 9000)
            | 0x6b33_43cf // QUIC v2 draft (RFC 9369)
            | 0xff00_001d // draft-29
            | 0xff00_0020 // draft-32
            | 0xff00_0021 // draft-33
            | 0xff00_0022 // draft-34
    )
}

/// HTTP/1.x request line: any of the standard verbs followed by a space.
pub fn is_http1_request(bytes: &[u8]) -> bool {
    const VERBS: &[&[u8]] = &[
        b"GET ",
        b"HEAD ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
    ];
    VERBS.iter().any(|verb| bytes.starts_with(verb))
}

/// HTTP/2 preface (RFC 7540 §3.5): `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` (24 bytes).
pub fn is_http2_preface(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
}

/// SSH banner per RFC 4253: `SSH-` followed by version digits.
pub fn is_ssh_banner(bytes: &[u8]) -> bool {
    bytes.starts_with(b"SSH-")
}

/// SMTP server greeting: `220 ` (or `220-` for multi-line).
pub fn is_smtp_greeting(bytes: &[u8]) -> bool {
    bytes.starts_with(b"220 ") || bytes.starts_with(b"220-")
}

/// FTP server greeting: `220 ` or `220-` followed by a banner.
///
/// Same wire-level prefix as SMTP - this is intentional. The GFW does not need
/// to disambiguate FTP vs SMTP at exemption time; both are exempt.
pub fn is_ftp_response(bytes: &[u8]) -> bool {
    is_smtp_greeting(bytes)
}

/// BitTorrent handshake: 0x13 length byte followed by "BitTorrent protocol".
pub fn is_bittorrent_handshake(bytes: &[u8]) -> bool {
    if bytes.len() < 20 {
        return false;
    }
    bytes[0] == 0x13 && &bytes[1..20] == b"BitTorrent protocol"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_real_tls_clienthello_prefix() {
        // Real Chrome TLS 1.3 ClientHello prefix.
        let bytes = [0x16, 0x03, 0x01, 0x06, 0xd2, 0x01];
        assert!(is_tls_record(&bytes));
        assert_eq!(classify_first_packet(&bytes), Some("TLS"));
    }

    #[test]
    fn rejects_random_first_packet() {
        let bytes: [u8; 16] = [0xab; 16];
        assert!(!is_tls_record(&bytes));
        assert!(!is_quic_long_header(&bytes));
        assert!(classify_first_packet(&bytes).is_none());
    }

    #[test]
    fn detects_quic_v1_long_header() {
        let mut bytes = [0_u8; 1200];
        bytes[0] = 0xc0; // long header, fixed bit set, Initial packet type
        bytes[1..5].copy_from_slice(&0x0000_0001_u32.to_be_bytes());
        assert!(is_quic_long_header(&bytes));
    }

    #[test]
    fn detects_http1_request() {
        assert!(is_http1_request(b"GET /index HTTP/1.1\r\n"));
        assert!(is_http1_request(b"POST /api HTTP/1.1\r\n"));
        assert!(is_http1_request(b"OPTIONS / HTTP/1.1\r\n"));
        assert!(!is_http1_request(b"NOTAVERB / HTTP/1.1\r\n"));
    }

    #[test]
    fn detects_ssh_banner() {
        assert!(is_ssh_banner(b"SSH-2.0-OpenSSH_9.6"));
        assert!(!is_ssh_banner(b"SOMETHING-ELSE"));
    }

    #[test]
    fn priority_picks_most_specific_match() {
        // Build a packet that satisfies both HTTP1 verb check (priority 1) and
        // is technically printable ASCII (no other priority-0 match). Should
        // classify as HTTP/1.
        let bytes = b"GET / HTTP/1.1\r\n";
        assert_eq!(classify_first_packet(bytes), Some("HTTP/1"));
    }
}
