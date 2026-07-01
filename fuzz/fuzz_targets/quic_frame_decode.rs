#![no_main]
use libfuzzer_sys::fuzz_target;
use parallax::transport::udp::quic_frame_fuzz::decode_all_roundtrip;

// The QUIC frame codec (src/transport/udp/quic/frame.rs) decodes attacker-
// controlled QUIC packet payloads off the wire — the receive path in
// `Connection::process_packet` feeds it every 1-RTT/handshake packet body from a
// terminated ParallaX<->ParallaX tunnel. It is the one directly network-facing
// frame parser in the tree that previously had no fuzz target; the mux, HTTP/2,
// and HTTP/3 frame parsers all do.
//
// The driver walks the whole payload with the real `Iter` decoder. For every
// frame that decodes it asserts the encode->decode->encode roundtrip is
// byte-stable (our encoder emits canonical, self-delimiting framing, so this must
// be exact — the same invariant the `mux_frame` target enforces). A decode error
// on arbitrary bytes is expected and stops the walk; the property under test is
// simply that no input — however malformed, truncated, or adversarial (huge
// varint lengths, underflowing ACK ranges, out-of-range connection-id lengths) —
// can panic, over-allocate, or read out of bounds.
fuzz_target!(|data: &[u8]| {
    let _ = decode_all_roundtrip(data);
});
