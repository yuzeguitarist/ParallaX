#![no_main]
use libfuzzer_sys::fuzz_target;

// TransportParameters::read parses the peer's QUIC transport-parameters TLS
// extension. On the server this is attacker-controlled, pre-authentication input
// (the client's transport params arrive inside the first Initial's ClientHello),
// so the decoder must never panic — no arithmetic overflow on the running offset,
// no out-of-bounds slice, no unbounded allocation — regardless of the bytes.
//
// The parser sat at 0% fuzz coverage: alongside the packet/frame decoders it is a
// pre-auth QUIC parse path that no target reached, because
// `transport::udp::quic::transport_params` is `pub(crate)`. `quic_fuzz` surfaces a
// fuzzing-only shim. `TransportParameters` and its encoders stay crate-private, so
// this target asserts the "never panics on any input" contract; the value-stable
// encode/decode round-trip is already covered by the in-module unit tests.
fuzz_target!(|data: &[u8]| {
    let _ = parallax::quic_fuzz::transport_params::read(data);
});
