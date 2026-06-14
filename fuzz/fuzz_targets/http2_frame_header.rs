#![no_main]
use libfuzzer_sys::fuzz_target;
use parallax::fingerprint::http2::Http2FrameHeader;

// parse_complete walks attacker-influenced HTTP/2 framing during the camouflage
// H2 exchange. Beyond "does not panic", this recomputes the header fields
// INDEPENDENTLY from the raw bytes and asserts the parser agrees — a real
// property check that a parser regression would trip, not a restatement of the
// parser's own arithmetic.
fuzz_target!(|data: &[u8]| {
    if let Some((h, total)) = Http2FrameHeader::parse_complete(data) {
        // parse_complete returns Some only when data.len() >= total >= SIZE(9),
        // so the 9-byte header is guaranteed in bounds here.
        let want_len = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | data[2] as usize;
        let want_stream = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) & 0x7fff_ffff;
        assert_eq!(h.len, want_len, "parsed len disagrees with raw u24 length");
        assert_eq!(h.frame_type, data[3], "parsed frame_type disagrees with raw byte");
        assert_eq!(h.flags, data[4], "parsed flags disagrees with raw byte");
        assert_eq!(h.stream_id, want_stream, "parsed stream_id disagrees with raw masked bytes");
        assert_eq!(total, Http2FrameHeader::SIZE + want_len, "total must equal header + payload");
        assert!(total <= data.len(), "parse_complete must not claim more than input");

        // Walk consecutive frames to exercise advancing offsets.
        let mut off = 0usize;
        while let Some((_, t)) = Http2FrameHeader::parse_complete(&data[off..]) {
            off = match off.checked_add(t) {
                Some(v) if v <= data.len() => v,
                _ => break,
            };
            if t == 0 {
                break;
            }
        }
    }
});
