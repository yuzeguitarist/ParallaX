#![no_main]
use libfuzzer_sys::fuzz_target;
use parallax::fingerprint::http3::{
    decode_frame, encode_frame, read_stream_type, Http3FrameHeader, MAX_PAYLOAD_LEN,
};

// decode_frame parses attacker-controlled HTTP/3 framing on the QUIC fast-plane
// H3 façade (RFC 9114 §7.1: varint(type) varint(len) payload). Beyond "does not
// panic", this checks the structural invariants the decoder promises AND a
// value-stable decode->encode->decode round-trip: a canonical re-encode of a
// decoded frame must decode back to the same type+payload (the encoding may use
// non-minimal varints, so we assert value equality, not byte identity). The
// leading uni-stream type varint (read_stream_type) is exercised too.
fuzz_target!(|data: &[u8]| {
    // Uni-stream prefix varint: must never claim more than the buffer holds.
    if let Some((_st, used)) = read_stream_type(data) {
        assert!(
            (1..=8).contains(&used),
            "stream-type varint length out of range"
        );
        assert!(used <= data.len(), "stream-type varint consumed past input");
    }

    if let Ok((h, payload, total)) = decode_frame(data) {
        // Structural invariants of a single decoded frame.
        assert!(total <= data.len(), "decode_frame claimed more than input");
        assert_eq!(
            payload.len(),
            h.len,
            "payload slice disagrees with header len"
        );
        assert!(h.len <= MAX_PAYLOAD_LEN, "len exceeds MAX_PAYLOAD_LEN");
        // The payload must be exactly the trailing bytes of the consumed region.
        let header_len = total - h.len;
        assert_eq!(
            &data[header_len..total],
            payload,
            "payload is not data[header..total]"
        );

        // Value-stable round-trip: a canonical re-encode decodes back identically
        // and consumes exactly its own bytes (canonical = minimal varints).
        let reenc = encode_frame(h.frame_type, payload)
            .expect("re-encoding a decoded frame must succeed (len already <= MAX)");
        let (h2, payload2, total2) =
            decode_frame(&reenc).expect("a canonically encoded frame must decode");
        assert_eq!(
            h2,
            Http3FrameHeader {
                frame_type: h.frame_type,
                len: h.len
            }
        );
        assert_eq!(payload2, payload, "round-trip payload mismatch");
        assert_eq!(
            total2,
            reenc.len(),
            "canonical frame must consume all its bytes"
        );
    }

    // Walk consecutive frames to exercise advancing offsets (mirrors the H2
    // target): decode, advance by total, stop on no-progress or overrun.
    let mut off = 0usize;
    while let Ok((_, _, t)) = decode_frame(&data[off..]) {
        off = match off.checked_add(t) {
            Some(v) if v <= data.len() => v,
            _ => break,
        };
        if t == 0 {
            break;
        }
    }
});
