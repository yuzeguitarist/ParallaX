//! Regression baseline that locks the Safari 26 HTTP/2 fingerprint against a
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
//!   `flags = END_STREAM | END_HEADERS`, pseudo-header order
//!   `:method, :scheme, :path, :authority`, browser metadata headers, and
//!   HPACK-Huffman-encoded values where Safari uses Huffman.

use parallax::fingerprint::http2::{Http2Fingerprint, SAFARI26_ACCEPT_LANGUAGE};

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
    // `:path /` (#4), then literal-with-indexed-name `:authority` (#1) whose
    // value is HPACK-Huffman-encoded (high bit of the length prefix set).
    // The remaining byte ranges lock Safari's request metadata shape:
    // `accept`, `user-agent`, `priority`, `accept-language`, and
    // `accept-encoding` in that order.
    assert_eq!(
        &headers.payload[..4],
        &[0x82, 0x87, 0x84, 0x41],
        "Safari pseudo-header order changed (expected :method, :scheme, :path, :authority)"
    );
    assert_eq!(
        &headers.payload[4..15],
        &[0x8a, 0xa0, 0xe4, 0x1d, 0x13, 0x9d, 0x09, 0xb8, 0xf3, 0x4d, 0x33],
        "Safari 26.4 :authority huffman bytes for `localhost:8443` drifted"
    );
    assert_eq!(&headers.payload[15..20], &[0x53, 0x03, b'*', b'/', b'*']);
    assert_eq!(
        &headers.payload[110..122],
        &[0x40, 0x86, 0xae, 0xc3, 0x1e, 0xc3, 0x27, 0xd7, 0x03, b'u', b'=', b'3'],
        "Safari 26.4 priority header shape drifted"
    );
    assert_eq!(
        &headers.payload[122..140],
        &hex(b"5190f73ad7b4fd7b9d6c63a91f7da002efff"),
        "Safari 26.4 captured accept-language bytes drifted"
    );
    assert_eq!(
        &headers.payload[140..],
        &hex(b"508d9bd9abfa5242cb40d25fa523b3"),
        "Safari 26.4 accept-encoding bytes drifted"
    );
}

#[test]
fn parallax_safari_h2_preface_matches_fixture_byte_for_byte() {
    let fp = Http2Fingerprint::safari26();

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
        "ParallaX Safari26 SETTINGS payload must match Safari 26.4 byte-for-byte"
    );
    assert_eq!(
        parallax_settings.flags, safari_settings.flags,
        "ParallaX Safari26 SETTINGS flags must match (no ACK on outbound)"
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
        "ParallaX Safari26 WINDOW_UPDATE increment must match Safari 26.4 byte-for-byte"
    );
}

#[test]
fn parallax_safari_opening_headers_match_fixture_metadata_except_language() {
    let fp = Http2Fingerprint::safari26();
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
        "ParallaX Safari26 HEADERS flags must match Safari (END_STREAM | END_HEADERS)"
    );
    assert_eq!(
        parallax_headers.flags,
        FLAG_END_STREAM | FLAG_END_HEADERS,
        "ParallaX must set END_STREAM | END_HEADERS on its initial GET /"
    );
    // The provided Safari capture carries a Chinese accept-language setting.
    // ParallaX keeps the same HPACK/order shape but uses the project's
    // English-only default so deployments do not carry a locale-specific
    // Chinese marker by default.
    let before_language = 122;
    let parallax_accept_encoding = 135;
    let safari_accept_encoding = 140;
    assert_eq!(
        parallax_headers.payload.len(),
        150,
        "ParallaX HPACK payload must include Safari browser metadata with English language"
    );
    assert_eq!(
        &parallax_headers.payload[..before_language],
        &safari_headers.payload[..before_language],
        "ParallaX Safari26 metadata before accept-language diverged from the capture"
    );
    assert_eq!(
        &parallax_headers.payload[before_language..parallax_accept_encoding],
        &hex(b"518b2d4b70ddf45abefb4005df"),
        "ParallaX Safari26 accept-language must be HPACK-Huffman encoded English"
    );
    assert_eq!(
        &parallax_headers.payload[parallax_accept_encoding..],
        &safari_headers.payload[safari_accept_encoding..],
        "ParallaX Safari26 accept-encoding diverged from the capture"
    );
    assert_eq!(SAFARI26_ACCEPT_LANGUAGE, "en-US,en;q=0.9");
    assert!(!SAFARI26_ACCEPT_LANGUAGE.contains("zh"));
}

fn hex(s: &[u8]) -> Vec<u8> {
    fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("non-hex byte"),
        }
    }
    s.chunks(2)
        .map(|c| (nibble(c[0]) << 4) | nibble(c[1]))
        .collect()
}
