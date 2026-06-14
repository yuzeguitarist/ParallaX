#![no_main]
use libfuzzer_sys::fuzz_target;

// Server-side PRE-AUTH classification entry point (server.rs:442-606). The
// attacker fully controls `first_client_record`; psk / authorized_sni /
// server_private are fixed dummies because we are hunting parser and
// classification panics here, not modelling an auth bypass.
fuzz_target!(|data: &[u8]| {
    let psk = [0u8; 32];
    let server_private = [0u8; 32];
    let authorized_sni: &[String] = &[];
    let _ = parallax::handshake::server::decide_inbound(data, &psk, authorized_sni, &server_private);
});
