#![no_main]
use libfuzzer_sys::fuzz_target;

// Server-side, PRE-AUTH. Parses an attacker-supplied ClientHello record:
// UTF-8 SNI decode + nested extension/length walks (client_hello.rs). A
// network peer fully controls these bytes before any authentication.
// Hunting: panics, slice OOB, unbounded allocations.
fuzz_target!(|data: &[u8]| {
    let _ = parallax::tls::client_hello::parse_client_hello(data);
});
