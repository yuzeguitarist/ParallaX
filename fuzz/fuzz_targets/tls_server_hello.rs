#![no_main]
use libfuzzer_sys::fuzz_target;

// Client-side, PRE-AUTH. Parses a ServerHello record supplied by an
// impersonating/MITM upstream before the certificate is verified.
// Hunting: panics, slice OOB, unbounded allocations.
fuzz_target!(|data: &[u8]| {
    let _ = parallax::tls::server_hello::parse_server_hello(data);
});
