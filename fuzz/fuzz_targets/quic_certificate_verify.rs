#![no_main]
use libfuzzer_sys::fuzz_target;

// Client-side, PRE-AUTH. The hand-written QUIC TLS 1.3 client parses the server's
// CertificateVerify body (RFC 8446 §4.4.3) BEFORE validating the signature: a u16
// SignatureScheme followed by the u16-length signature. A MITM upstream fully
// controls these bytes. Input is the handshake-message BODY (no 4-byte
// type+length header). Hunting: panics, slice OOB, unbounded allocations.
fuzz_target!(|data: &[u8]| {
    let _ = parallax::tls::quic::fuzz::parse_certificate_verify(data);
});
