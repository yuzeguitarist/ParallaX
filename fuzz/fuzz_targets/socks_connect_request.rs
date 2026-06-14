#![no_main]
use libfuzzer_sys::fuzz_target;

// LOCAL/trusted SOCKS5 CONNECT request parser (client-side). Not censor-facing,
// but a malformed local request must reject cleanly, never panic.
// read_connect_request is private + async; the crate exposes a sync cfg(fuzzing)
// driver that runs it over an in-memory &[u8] on a current-thread runtime.
fuzz_target!(|data: &[u8]| {
    let _ = parallax::client::socks::fuzz::read_connect_request_sync(data);
});
