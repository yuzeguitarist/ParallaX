#![no_main]
use libfuzzer_sys::fuzz_target;

// Client-side, PRE-AUTH. The hand-written QUIC TLS 1.3 client parses an
// impersonating/MITM upstream's ServerHello body (RFC 8446 §4.1.3) BEFORE any
// certificate is verified: legacy_version, HRR sentinel, session-id echo, cipher
// suite, and the extension walk (supported_versions, key_share, pre_shared_key).
// The QUIC-plane twin of `tls_server_hello`; a network peer fully controls these
// bytes. Input is the handshake-message BODY (no 4-byte type+length header).
// Hunting: panics, slice OOB, unbounded allocations.
fuzz_target!(|data: &[u8]| {
    let _ = parallax::tls::quic::fuzz::parse_server_hello(data);
});
