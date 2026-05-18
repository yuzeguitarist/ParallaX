//! Regression baseline that locks the Safari 17 HTTP/2 fingerprint against a
//! real Safari 26.4 (macOS Tahoe) capture of the connection preface.
//!
//! The fixture under `tests/fixtures/safari26_h2_preface_localhost.bin` was
//! captured by terminating a TLS connection from Safari 26.4 with ALPN `h2`
//! and dumping the first 4 KiB of plaintext. Two independent fresh-tab
//! captures produced byte-identical bytes, so we commit one fixture and rely
//! on Safari's deterministic preface for the parity check.
//!
//! The bytes we lock down are:
//!
//! * the 24-byte HTTP/2 connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`)
//! * the SETTINGS frame: `ENABLE_PUSH=0`, `INITIAL_WINDOW_SIZE=4_194_304`,
//!   `MAX_CONCURRENT_STREAMS=100`, `NO_RFC7540_PRIORITIES=1` in that order
//! * the connection-level WINDOW_UPDATE increment of 10_485_760 (10 MiB)
//! * the opening HEADERS frame on stream 1 with
//!   `flags = END_STREAM | END_HEADERS` and pseudo-header order
//!   `:method, :scheme, :path, :authority`

use parallax::fingerprint::http2::{Http2Fingerprint, Http2PeerProfile};

const SAFARI_H2_FIXTURE: &[u8] = include_bytes!("fixtures/safari26_h2_preface_localhost.bin");

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_SETTINGS: u8 = 0x4;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FRAME_HEADERS: u8 = 0x1;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;

/// Authority used by both the fixture (Safari hit `https://localhost:8443/`)
/// and the parallax-emitted comparison frame.
const FIXTURE_AUTHORITY: &str = "localhost:8443";

#[derive(Debug)]
struct H2Frame {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

fn parse_frames(mut input: &[u8]) -> Vec<H2Frame> {
    let mut out = Vec::new();
    while input.len() >= 9 {
        let len = ((input[0] as usize) << 16) | ((input[1] as usize) << 8) | input[2] as usize;
        let frame_type = input[3];
        let flags = input[4];
        let stream_id = u32::from_be_bytes([input[5], input[6], input[7], input[8]]) & 0x7fff_ffff;
        let total = 9 + len;
        if input.len() < total {
            break;
        }
        out.push(H2Frame {
            frame_type,
            flags,
            stream_id,
            payload: input[9..total].to_vec(),
        });
        input = &input[total..];
    }
    out
}

fn parse_settings(payload: &[u8]) -> Vec<(u16, u32)> {
    assert!(
        payload.len() % 6 == 0,
        "SETTINGS payload must be a multiple of 6 bytes, got {}",
        payload.len()
    );
    payload
        .chunks_exact(6)
        .map(|chunk| {
            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
            let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
            (id, value)
        })
        .collect()
}

fn fixture_after_preface() -> &'static [u8] {
    assert!(
        SAFARI_H2_FIXTURE.starts_with(H2_PREFACE),
        "Safari H2 fixture lost its connection preface"
    );
    &SAFARI_H2_FIXTURE[H2_PREFACE.len()..]
}

#[test]
fn safari_h2_fixture_starts_with_connection_preface() {
    assert!(
        SAFARI_H2_FIXTURE.starts_with(H2_PREFACE),
        "fixture must begin with the HTTP/2 connection preface"
    );
}

#[test]
fn safari_h2_fixture_settings_match_known_shape() {
    let frames = parse_frames(fixture_after_preface());
    let settings_frame = frames
        .iter()
        .find(|f| f.frame_type == FRAME_SETTINGS && (f.flags & 0x1) == 0 && f.stream_id == 0)
        .expect("Safari fixture must contain a non-ACK SETTINGS frame on stream 0");

    let entries = parse_settings(&settings_frame.payload);
    assert_eq!(
        entries,
        vec![
            (0x2, 0),         // ENABLE_PUSH
            (0x4, 4_194_304), // INITIAL_WINDOW_SIZE = 4 MiB
            (0x3, 100),       // MAX_CONCURRENT_STREAMS
            (0x9, 1),         // NO_RFC7540_PRIORITIES
        ],
        "Safari 26.4 SETTINGS list or order drifted from the captured baseline",
    );
}

#[test]
fn safari_h2_fixture_window_update_matches_known_increment() {
    let frames = parse_frames(fixture_after_preface());
    let wu = frames
        .iter()
        .find(|f| f.frame_type == FRAME_WINDOW_UPDATE && f.stream_id == 0)
        .expect("Safari fixture must contain a connection-level WINDOW_UPDATE");

    assert_eq!(wu.payload.len(), 4, "WINDOW_UPDATE payload is 4 bytes");
    let increment =
        u32::from_be_bytes([wu.payload[0], wu.payload[1], wu.payload[2], wu.payload[3]])
            & 0x7fff_ffff;
    assert_eq!(
        increment, 10_485_760,
        "Safari 26.4 connection-level WINDOW_UPDATE increment drifted"
    );
}

#[test]
fn safari_h2_fixture_opening_headers_match_known_shape() {
    let frames = parse_frames(fixture_after_preface());
    let headers = frames
        .iter()
        .find(|f| f.frame_type == FRAME_HEADERS && f.stream_id == 1)
        .expect("Safari fixture must contain an opening HEADERS frame on stream 1");

    assert_eq!(
        headers.flags,
        FLAG_END_STREAM | FLAG_END_HEADERS,
        "Safari sets END_STREAM | END_HEADERS on its initial GET / (no body)"
    );

    // Pseudo-header section: indexed `:method GET` (#2), `:scheme https` (#7),
    // `:path /` (#4), then literal-with-indexed-name `:authority` (#1).
    // Safari huffman-encodes the authority value, but the leading 4 HPACK
    // bytes are independent of the value encoding.
    assert_eq!(
        &headers.payload[..4],
        &[0x82, 0x87, 0x84, 0x41],
        "Safari pseudo-header order changed (expected :method, :scheme, :path, :authority)"
    );
}

#[test]
fn parallax_safari_h2_preface_matches_fixture_byte_for_byte() {
    let fp = Http2Fingerprint::for_profile(Http2PeerProfile::Safari17);

    let preface = fp.connection_preface().expect("build ParallaX preface");
    let safari_frames = parse_frames(fixture_after_preface());
    let parallax_frames = parse_frames(&preface[H2_PREFACE.len()..]);

    let safari_settings = safari_frames
        .iter()
        .find(|f| f.frame_type == FRAME_SETTINGS && (f.flags & 0x1) == 0)
        .expect("Safari SETTINGS frame");
    let parallax_settings = parallax_frames
        .iter()
        .find(|f| f.frame_type == FRAME_SETTINGS && (f.flags & 0x1) == 0)
        .expect("ParallaX SETTINGS frame");
    assert_eq!(
        parallax_settings.payload, safari_settings.payload,
        "ParallaX Safari17 SETTINGS payload must match Safari 26.4 byte-for-byte"
    );
    assert_eq!(
        parallax_settings.flags, safari_settings.flags,
        "ParallaX Safari17 SETTINGS flags must match (no ACK on outbound)"
    );

    let safari_wu = safari_frames
        .iter()
        .find(|f| f.frame_type == FRAME_WINDOW_UPDATE && f.stream_id == 0)
        .expect("Safari WINDOW_UPDATE");
    let parallax_wu = parallax_frames
        .iter()
        .find(|f| f.frame_type == FRAME_WINDOW_UPDATE && f.stream_id == 0)
        .expect("ParallaX WINDOW_UPDATE");
    assert_eq!(
        parallax_wu.payload, safari_wu.payload,
        "ParallaX Safari17 WINDOW_UPDATE increment must match Safari 26.4 byte-for-byte"
    );
}

#[test]
fn parallax_safari_opening_headers_match_fixture_pseudo_header_section() {
    let fp = Http2Fingerprint::for_profile(Http2PeerProfile::Safari17);
    let parallax_headers_frame = fp
        .headers_frame(FIXTURE_AUTHORITY)
        .expect("build ParallaX Safari HEADERS");
    let parallax_frames = parse_frames(&parallax_headers_frame);
    let parallax_headers = parallax_frames
        .first()
        .expect("ParallaX must emit a single HEADERS frame");

    let safari_frames = parse_frames(fixture_after_preface());
    let safari_headers = safari_frames
        .iter()
        .find(|f| f.frame_type == FRAME_HEADERS && f.stream_id == 1)
        .expect("Safari fixture HEADERS frame");

    assert_eq!(
        parallax_headers.frame_type, FRAME_HEADERS,
        "ParallaX must emit a HEADERS frame type"
    );
    assert_eq!(
        parallax_headers.stream_id, 1,
        "ParallaX must open stream 1 on the first HEADERS"
    );
    assert_eq!(
        parallax_headers.flags, safari_headers.flags,
        "ParallaX Safari17 HEADERS flags must match Safari (END_STREAM | END_HEADERS)"
    );
    assert_eq!(
        parallax_headers.flags,
        FLAG_END_STREAM | FLAG_END_HEADERS,
        "ParallaX must set END_STREAM | END_HEADERS on its initial GET /"
    );
    // Pseudo-header section is the only HPACK prefix we can lock to Safari
    // without huffman-encoding the authority value. Both Safari and ParallaX
    // emit `82 87 84 41 <authority-literal>` in this order.
    assert_eq!(
        &parallax_headers.payload[..4],
        &safari_headers.payload[..4],
        "ParallaX Safari17 pseudo-header section diverged from Safari 26.4"
    );
    assert_eq!(
        &parallax_headers.payload[..4],
        &[0x82, 0x87, 0x84, 0x41],
        "ParallaX pseudo-header order must be :method, :scheme, :path, :authority"
    );

    // The :authority literal that follows is encoded as plain (non-huffman)
    // because the current `push_hpack_string` helper does not implement HPACK
    // huffman coding. This is a known wire-level delta from Safari, which
    // huffman-encodes the value. Document it as a positive assertion so a
    // future huffman-aware implementation will trip this test and remind us
    // to retire this carve-out.
    let authority_len_byte = parallax_headers.payload[4];
    assert_eq!(
        authority_len_byte & 0x80,
        0,
        "ParallaX currently emits a plain (non-huffman) :authority value; \
         Safari uses huffman. If this assertion fails, the huffman path was \
         added and the test needs to be reworked."
    );
    assert_eq!(
        authority_len_byte as usize,
        FIXTURE_AUTHORITY.len(),
        "ParallaX :authority length prefix must encode the literal length"
    );
    assert_eq!(
        &parallax_headers.payload[5..5 + FIXTURE_AUTHORITY.len()],
        FIXTURE_AUTHORITY.as_bytes(),
        "ParallaX :authority literal must match the fixture's host"
    );
}
