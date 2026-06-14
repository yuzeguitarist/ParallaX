#![no_main]
use libfuzzer_sys::fuzz_target;
use parallax::fingerprint::http2::Http2FrameHeader;

// parse_complete walks attacker-influenced HTTP/2 framing during the camouflage
// H2 exchange. Pure 9-byte header read. Hunting panics + the length-claim
// invariant: the returned `total` must never exceed the consumed input, must
// equal SIZE + len, and stream_id's reserved high bit must be cleared.
fuzz_target!(|data: &[u8]| {
    if let Some((h, total)) = Http2FrameHeader::parse_complete(data) {
        assert!(total <= data.len(), "parse_complete claimed more bytes than input");
        assert_eq!(total, Http2FrameHeader::SIZE + h.len, "total != SIZE + len");
        assert_eq!(h.stream_id & 0x8000_0000, 0, "stream_id high bit must be cleared");
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
