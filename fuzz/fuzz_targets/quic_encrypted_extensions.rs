#![no_main]
use libfuzzer_sys::fuzz_target;

// Client-side, PRE-AUTH. The hand-written QUIC TLS 1.3 client parses the server's
// EncryptedExtensions body (RFC 8446 §4.3.1) BEFORE the certificate is verified:
// the extension walk selects ALPN (RFC 7301), captures the opaque
// quic_transport_parameters blob (RFC 9001 §8.2), and detects the empty
// early_data acceptance, rejecting duplicates / trailing bytes. A MITM upstream
// fully controls these bytes. Input is the handshake-message BODY (no 4-byte
// type+length header). Hunting: panics, slice OOB, unbounded allocations.
fuzz_target!(|data: &[u8]| {
    let _ = parallax::tls::quic::fuzz::parse_encrypted_extensions(data);
});
