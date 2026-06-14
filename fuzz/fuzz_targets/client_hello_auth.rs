#![no_main]
use libfuzzer_sys::fuzz_target;

// PRE-AUTH. Full ClientHello authentication path (parse_client_hello + HMAC
// verification) under a fixed dummy auth key. Exercises the verify logic
// beyond plain parsing; the HMAC will essentially always fail, so this hunts
// for panics on the way to that rejection, not auth success.
fuzz_target!(|data: &[u8]| {
    let _ = parallax::crypto::auth::verify_client_hello_auth(data, &[0u8; 32]);
});
