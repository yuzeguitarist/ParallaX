#![no_main]
use libfuzzer_sys::fuzz_target;

// Client-side, PRE-CERTIFICATE-VERIFY. The hand-written QUIC TLS 1.3 client parses
// the server's Certificate body (RFC 8446 §4.4.2) into the DER chain BEFORE the
// verifier runs: a u8 request_context, then the u24 CertificateEntry list (each a
// u24-length cert_data ‖ u16-length extensions). The QUIC-plane twin of the plain
// certificate parse in `tls_compressed_cert`. A MITM upstream fully controls these
// bytes. Input is the handshake-message BODY (no 4-byte type+length header).
// Hunting: panics, slice OOB, unbounded allocations.
fuzz_target!(|data: &[u8]| {
    let _ = parallax::tls::quic::fuzz::parse_certificate_body(data);
});
