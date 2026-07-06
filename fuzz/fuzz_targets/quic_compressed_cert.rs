#![no_main]
use libfuzzer_sys::fuzz_target;

// Client-side, PRE-CERTIFICATE-VERIFY. The QUIC-plane twin of `tls_compressed_cert`.
// parse_compressed_certificate_body reads an attacker-controlled u24
// `uncompressed_length`, then zlib-inflates the u24-length compressed body (RFC
// 8879) before parsing it as a Certificate. Both the declared and the actual
// inflation are capped (MAX_DECOMPRESSED_CERT_CHAIN) to defend against a malicious
// (pre-authentication) cover origin's zlib bomb; this exercises that decompression
// bound plus the certificate parse. Input is the CompressedCertificate
// handshake-message BODY (no 4-byte type+length header).
//
// Run with an RSS cap so any OOM is reported as a crash instead of killing the
// host, e.g.  cargo +nightly fuzz run quic_compressed_cert -- -rss_limit_mb=2048
fuzz_target!(|data: &[u8]| {
    let _ = parallax::tls::quic::fuzz::parse_compressed_certificate_body(data);
});
