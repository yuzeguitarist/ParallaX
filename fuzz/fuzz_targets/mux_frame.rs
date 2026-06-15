#![no_main]
use libfuzzer_sys::fuzz_target;
use parallax::protocol::command::MuxFrame;

// Decode an attacker-supplied mux frame (related to #37: length-before-alloc).
// Beyond "does not panic", this asserts a ROUNDTRIP PROPERTY: if a frame
// decodes, it must re-encode, and that encoding must decode again to bytes
// identical to the first encoding. A decoder that accepts input the encoder
// would reject (or that is not idempotent) is itself a bug.
fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = MuxFrame::decode(data) {
        let b1 = frame.encode().expect("a freshly decoded MuxFrame must re-encode");
        let frame2 = MuxFrame::decode(&b1).expect("our own MuxFrame encoding must decode");
        let b2 = frame2.encode().expect("re-encode of a decoded frame must succeed");
        assert_eq!(b1, b2, "MuxFrame encode/decode is not idempotent");
    }
});
