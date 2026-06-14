#![no_main]
use libfuzzer_sys::fuzz_target;

// SECURITY_REVIEW finding H1: zlib decompression bomb reachable
// PRE-CERTIFICATE-VERIFY. parse_compressed_certificate_body reads an
// attacker-controlled u24 `uncompressed_len`, does Vec::with_capacity(that),
// then ZlibDecoder::read_to_end with no output cap (~1032:1 inflation), and
// only checks the length AFTER inflating. The plain certificate parser shares
// the same flight, so we exercise both.
//
// Run with an RSS cap so the OOM is reported as a crash instead of killing the
// host, e.g.  cargo +nightly fuzz run tls_compressed_cert -- -rss_limit_mb=2048
fuzz_target!(|data: &[u8]| {
    let _ = parallax::tls::safari26::fuzz::parse_compressed_certificate_body(data);
    let _ = parallax::tls::safari26::fuzz::parse_certificate_body(data);
});
