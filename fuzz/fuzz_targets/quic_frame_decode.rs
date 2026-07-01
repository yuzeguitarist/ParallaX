#![no_main]
use libfuzzer_sys::fuzz_target;
use parallax::transport::udp::quic::frame::{Frame, Iter};

// `Iter` walks the frame sequence of a QUIC packet payload (RFC 9000 §19). On the
// server this is attacker-controlled: it is the decrypted payload of a
// ParallaX<->ParallaX tunnel packet, decoded before any of its contents are
// trusted. Beyond "never panics on arbitrary bytes", this asserts the decoder's
// structural contract AND a re-encode round-trip property.
//
// The `Iter` contract (frame.rs): each `next()` yields `Ok(Frame)` until the
// first `Err`, after which iteration stops. So we take frames only up to the
// first error, and for each decoded frame assert:
//
//   * it re-encodes, and
//   * re-decoding that encoding yields exactly the same `Frame` and consumes
//     exactly its own bytes (a canonical single-frame round-trip).
//
// A frame the decoder accepts but the encoder cannot reproduce, or a decode that
// is not idempotent, is itself a bug — the same property the `mux_frame` /
// `h3_frame_decode` targets pin for their codecs.
fuzz_target!(|data: &[u8]| {
    // Walk to the first error (mirrors how `Connection::process_packet` consumes
    // the payload) and collect the frames that decoded cleanly. `Frame` borrows
    // from `data`, so re-encode each into an owned buffer as we go.
    let mut encodings: Vec<Vec<u8>> = Vec::new();
    for item in Iter::new(data) {
        match item {
            Ok(frame) => {
                let mut buf = Vec::new();
                frame.encode(&mut buf);
                encodings.push(buf);
            }
            Err(_) => break,
        }
    }

    // Each cleanly decoded frame must survive a canonical single-frame round-trip.
    for buf in &encodings {
        let mut iter = Iter::new(buf);
        let redecoded = iter
            .next()
            .expect("a freshly encoded frame must decode")
            .expect("our own frame encoding must decode without error");

        let mut buf2 = Vec::new();
        redecoded.encode(&mut buf2);
        assert_eq!(
            *buf, buf2,
            "frame encode/decode is not idempotent (re-encode differs)"
        );

        // PADDING coalesces a run of zero bytes into one `Frame::Padding(n)`, so a
        // buffer of N zero bytes is a single frame that consumes all N bytes; every
        // other frame kind likewise consumes exactly its own encoding. In all cases
        // the encoding of one decoded frame must contain exactly one frame.
        assert!(
            matches!(iter.next(), None),
            "a single frame's encoding must decode to exactly one frame"
        );
    }

    // Type-tag sanity: a coalesced PADDING run reports a positive count (never a
    // zero-length padding frame), guarding the `n` accounting in `parse_one`.
    for item in Iter::new(data).flatten() {
        if let Frame::Padding(n) = item {
            assert!(n >= 1, "coalesced PADDING must cover at least one byte");
        }
    }
});
