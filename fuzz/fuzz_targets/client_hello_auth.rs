#![no_main]
use libfuzzer_sys::fuzz_target;

// PRE-AUTH. Drives the masked-stateful recovery path (parse_client_hello +
// carrier-mask decode) over arbitrary bytes under a fixed dummy psk + mask_ecdh.
// Recovery essentially always fails or yields garbage material; this hunts for
// panics on the parse+decode path, not auth success.
fuzz_target!(|data: &[u8]| {
    let _ = parallax::crypto::auth::recover_stateful_auth_material(data, &[0u8; 32], &[0u8; 32]);
});
