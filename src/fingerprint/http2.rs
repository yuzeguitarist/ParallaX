use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2Setting {
    pub id: u16,
    pub value: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2Fingerprint {
    pub settings: Vec<Http2Setting>,
    pub initial_window_update: Option<u32>,
}

pub const SAFARI26_USER_AGENT: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 \
     (KHTML, like Gecko) Version/26.4 Safari/605.1.15";
pub const SAFARI26_ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";

// Safari 26.4 main-document (navigation) request values. accept/priority are the
// main-document shape (not the old sub-resource `*/*` / `u=3`), and
// accept-encoding gained zstd. Ground truth: safari26_h2_request_localhost.bin.
const SAFARI26_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const SAFARI26_PRIORITY: &str = "u=0, i";
const SAFARI26_ACCEPT_ENCODING: &str = "gzip, deflate, br, zstd";
const SAFARI26_SEC_FETCH_DEST: &str = "document";
const SAFARI26_SEC_FETCH_SITE: &str = "none";
const SAFARI26_SEC_FETCH_MODE: &str = "navigate";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Http2FingerprintError {
    #[error("HTTP/2 frame payload is too large")]
    FrameTooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2FrameHeader {
    pub len: usize,
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,
}

impl Http2Fingerprint {
    pub fn safari26() -> Self {
        // Safari 26.4 (macOS Tahoe) HTTP/2 preface, observed against a local
        // TLS-terminating capture (ALPN h2). The 4 SETTINGS (order ENABLE_PUSH,
        // MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, NO_RFC7540_PRIORITIES) and
        // the connection-level WINDOW_UPDATE increment of 10_420_225 (raising the
        // 65535 default to 10 MiB) are byte-for-byte stable across fresh
        // connections.
        // Ground truth: `tests/fixtures/safari26_h2_request_localhost.bin`.
        Self {
            settings: vec![
                Http2Setting { id: 0x2, value: 0 },
                Http2Setting {
                    id: 0x3,
                    value: 100,
                },
                Http2Setting {
                    id: 0x4,
                    value: 2_097_152,
                },
                Http2Setting { id: 0x9, value: 1 },
            ],
            initial_window_update: Some(10_420_225),
        }
    }

    pub fn settings_frame(&self) -> Result<Vec<u8>, Http2FingerprintError> {
        let mut payload = Vec::with_capacity(self.settings.len() * 6);
        for setting in &self.settings {
            payload.extend_from_slice(&setting.id.to_be_bytes());
            payload.extend_from_slice(&setting.value.to_be_bytes());
        }
        frame(0x4, 0, 0, &payload)
    }

    pub fn initial_window_update_frame(&self) -> Result<Option<Vec<u8>>, Http2FingerprintError> {
        let Some(increment) = self.initial_window_update else {
            return Ok(None);
        };
        let value = increment & 0x7fff_ffff;
        Ok(Some(frame(0x8, 0, 0, &value.to_be_bytes())?))
    }

    pub fn connection_preface(&self) -> Result<Vec<u8>, Http2FingerprintError> {
        let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        out.extend_from_slice(&self.settings_frame()?);
        if let Some(window_update) = self.initial_window_update_frame()? {
            out.extend_from_slice(&window_update);
        }
        Ok(out)
    }

    pub fn settings_ack_frame() -> Result<Vec<u8>, Http2FingerprintError> {
        frame(0x4, 0x1, 0, &[])
    }

    pub fn headers_frame(&self, authority: &str) -> Result<Vec<u8>, Http2FingerprintError> {
        // Safari 26.4 main-document request, field order as captured:
        // :method :scheme :authority :path, then sec-fetch-dest, user-agent,
        // accept, sec-fetch-site, sec-fetch-mode, accept-language, priority,
        // accept-encoding. accept-language is the project's en-US default (the
        // capture carries zh-CN); everything else matches the wire byte-for-byte.
        let mut payload = Vec::with_capacity(260 + authority.len());
        payload.push(0x82); // :method: GET
        payload.push(0x87); // :scheme: https
        push_hpack_literal_with_indexed_name(&mut payload, 1, authority.as_bytes(), true);
        payload.push(0x84); // :path: /
        push_hpack_literal_with_new_name(
            &mut payload,
            b"sec-fetch-dest",
            true,
            SAFARI26_SEC_FETCH_DEST.as_bytes(),
            true,
        );
        push_hpack_literal_with_indexed_name(
            &mut payload,
            58,
            SAFARI26_USER_AGENT.as_bytes(),
            true,
        );
        push_hpack_literal_with_indexed_name(&mut payload, 19, SAFARI26_ACCEPT.as_bytes(), true);
        push_hpack_literal_with_new_name(
            &mut payload,
            b"sec-fetch-site",
            true,
            SAFARI26_SEC_FETCH_SITE.as_bytes(),
            true,
        );
        push_hpack_literal_with_new_name(
            &mut payload,
            b"sec-fetch-mode",
            true,
            SAFARI26_SEC_FETCH_MODE.as_bytes(),
            true,
        );
        push_hpack_literal_with_indexed_name(
            &mut payload,
            17,
            SAFARI26_ACCEPT_LANGUAGE.as_bytes(),
            true,
        );
        push_hpack_literal_with_new_name(
            &mut payload,
            b"priority",
            true,
            SAFARI26_PRIORITY.as_bytes(),
            true,
        );
        push_hpack_literal_with_indexed_name(
            &mut payload,
            16,
            SAFARI26_ACCEPT_ENCODING.as_bytes(),
            true,
        );
        frame(0x1, 0x5, 1, &payload)
    }
}

impl Http2FrameHeader {
    pub const SIZE: usize = 9;

    pub fn parse_complete(input: &[u8]) -> Option<(Self, usize)> {
        if input.len() < Self::SIZE {
            return None;
        }

        let len = ((input[0] as usize) << 16) | ((input[1] as usize) << 8) | input[2] as usize;
        let total = Self::SIZE + len;
        if input.len() < total {
            return None;
        }

        let stream_id = u32::from_be_bytes([input[5], input[6], input[7], input[8]]) & 0x7fff_ffff;
        Some((
            Self {
                len,
                frame_type: input[3],
                flags: input[4],
                stream_id,
            },
            total,
        ))
    }

    pub fn is_settings(&self) -> bool {
        self.frame_type == 0x4 && self.stream_id == 0
    }

    pub fn is_settings_ack(&self) -> bool {
        self.is_settings() && self.len == 0 && (self.flags & 0x1) != 0
    }
}

fn frame(
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> Result<Vec<u8>, Http2FingerprintError> {
    if payload.len() > 0x00ff_ffff {
        return Err(Http2FingerprintError::FrameTooLarge);
    }

    let mut out = Vec::with_capacity(9 + payload.len());
    let len = payload.len() as u32;
    out.push(((len >> 16) & 0xff) as u8);
    out.push(((len >> 8) & 0xff) as u8);
    out.push((len & 0xff) as u8);
    out.push(frame_type);
    out.push(flags);
    out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn push_hpack_literal_with_indexed_name(
    out: &mut Vec<u8>,
    static_name_index: usize,
    value: &[u8],
    huffman: bool,
) {
    push_hpack_integer(out, static_name_index, 6, 0x40);
    push_hpack_string(out, value, huffman);
}

fn push_hpack_literal_with_new_name(
    out: &mut Vec<u8>,
    name: &[u8],
    name_huffman: bool,
    value: &[u8],
    value_huffman: bool,
) {
    push_hpack_integer(out, 0, 6, 0x40);
    push_hpack_string(out, name, name_huffman);
    push_hpack_string(out, value, value_huffman);
}

fn push_hpack_integer(out: &mut Vec<u8>, value: usize, prefix_bits: u8, first_byte_mask: u8) {
    let max_prefix_value = (1_usize << prefix_bits) - 1;
    if value < max_prefix_value {
        out.push(first_byte_mask | value as u8);
        return;
    }

    out.push(first_byte_mask | max_prefix_value as u8);
    let mut remaining = value - max_prefix_value;
    while remaining >= 128 {
        out.push((remaining as u8 & 0x7f) | 0x80);
        remaining >>= 7;
    }
    out.push(remaining as u8);
}

fn push_hpack_string(out: &mut Vec<u8>, value: &[u8], huffman: bool) {
    if huffman {
        push_hpack_huffman_string(out, value);
        return;
    }

    push_hpack_integer(out, value.len(), 7, 0);
    out.extend_from_slice(value);
}

/// HPACK Huffman-encode `value` and emit it as an HPACK string literal with the
/// huffman flag set (high bit of the length prefix byte). The static code table
/// is RFC 7541 Appendix B; padding follows § 5.2 (pad with the high bits of the
/// EOS code, which is just 1-bits, up to the next byte boundary).
fn push_hpack_huffman_string(out: &mut Vec<u8>, value: &[u8]) {
    let mut encoded: Vec<u8> = Vec::with_capacity(value.len());
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;
    for &byte in value {
        let (code, code_len) = HPACK_HUFFMAN[byte as usize];
        let code = code as u64;
        let code_len = code_len as u32;
        acc = (acc << code_len) | code;
        bits += code_len;
        while bits >= 8 {
            bits -= 8;
            encoded.push((acc >> bits) as u8);
        }
        if bits == 0 {
            acc = 0;
        } else {
            acc &= (1u64 << bits) - 1;
        }
    }
    if bits > 0 {
        let pad = 8 - bits;
        acc = (acc << pad) | ((1u64 << pad) - 1);
        encoded.push(acc as u8);
    }
    push_hpack_integer(out, encoded.len(), 7, 0x80);
    out.extend_from_slice(&encoded);
}

/// RFC 7541 Appendix B HPACK static Huffman table: `(code, bit_length)` indexed
/// by the source byte 0..255. Verified by encoding `localhost:8443` and
/// matching the bytes Safari 26.4 emitted in the captured H2 request
/// (`tests/fixtures/safari26_h2_request_localhost.bin`).
#[rustfmt::skip]
const HPACK_HUFFMAN: [(u32, u8); 256] = [
    (0x1ff8, 13),     (0x7fffd8, 23),   (0xfffffe2, 28),  (0xfffffe3, 28),
    (0xfffffe4, 28),  (0xfffffe5, 28),  (0xfffffe6, 28),  (0xfffffe7, 28),
    (0xfffffe8, 28),  (0xffffea, 24),   (0x3ffffffc, 30), (0xfffffe9, 28),
    (0xfffffea, 28),  (0x3ffffffd, 30), (0xfffffeb, 28),  (0xfffffec, 28),
    (0xfffffed, 28),  (0xfffffee, 28),  (0xfffffef, 28),  (0xffffff0, 28),
    (0xffffff1, 28),  (0xffffff2, 28),  (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28),  (0xffffff5, 28),  (0xffffff6, 28),  (0xffffff7, 28),
    (0xffffff8, 28),  (0xffffff9, 28),  (0xffffffa, 28),  (0xffffffb, 28),
    (0x14, 6),        (0x3f8, 10),      (0x3f9, 10),      (0xffa, 12),
    (0x1ff9, 13),     (0x15, 6),        (0xf8, 8),        (0x7fa, 11),
    (0x3fa, 10),      (0x3fb, 10),      (0xf9, 8),        (0x7fb, 11),
    (0xfa, 8),        (0x16, 6),        (0x17, 6),        (0x18, 6),
    (0x0, 5),         (0x1, 5),         (0x2, 5),         (0x19, 6),
    (0x1a, 6),        (0x1b, 6),        (0x1c, 6),        (0x1d, 6),
    (0x1e, 6),        (0x1f, 6),        (0x5c, 7),        (0xfb, 8),
    (0x7ffc, 15),     (0x20, 6),        (0xffb, 12),      (0x3fc, 10),
    (0x1ffa, 13),     (0x21, 6),        (0x5d, 7),        (0x5e, 7),
    (0x5f, 7),        (0x60, 7),        (0x61, 7),        (0x62, 7),
    (0x63, 7),        (0x64, 7),        (0x65, 7),        (0x66, 7),
    (0x67, 7),        (0x68, 7),        (0x69, 7),        (0x6a, 7),
    (0x6b, 7),        (0x6c, 7),        (0x6d, 7),        (0x6e, 7),
    (0x6f, 7),        (0x70, 7),        (0x71, 7),        (0x72, 7),
    (0xfc, 8),        (0x73, 7),        (0xfd, 8),        (0x1ffb, 13),
    (0x7fff0, 19),    (0x1ffc, 13),     (0x3ffc, 14),     (0x22, 6),
    (0x7ffd, 15),     (0x3, 5),         (0x23, 6),        (0x4, 5),
    (0x24, 6),        (0x5, 5),         (0x25, 6),        (0x26, 6),
    (0x27, 6),        (0x6, 5),         (0x74, 7),        (0x75, 7),
    (0x28, 6),        (0x29, 6),        (0x2a, 6),        (0x7, 5),
    (0x2b, 6),        (0x76, 7),        (0x2c, 6),        (0x8, 5),
    (0x9, 5),         (0x2d, 6),        (0x77, 7),        (0x78, 7),
    (0x79, 7),        (0x7a, 7),        (0x7b, 7),        (0x7ffe, 15),
    (0x7fc, 11),      (0x3ffd, 14),     (0x1ffd, 13),     (0xffffffc, 28),
    (0xfffe6, 20),    (0x3fffd2, 22),   (0xfffe7, 20),    (0xfffe8, 20),
    (0x3fffd3, 22),   (0x3fffd4, 22),   (0x3fffd5, 22),   (0x7fffd9, 23),
    (0x3fffd6, 22),   (0x7fffda, 23),   (0x7fffdb, 23),   (0x7fffdc, 23),
    (0x7fffdd, 23),   (0x7fffde, 23),   (0xffffeb, 24),   (0x7fffdf, 23),
    (0xffffec, 24),   (0xffffed, 24),   (0x3fffd7, 22),   (0x7fffe0, 23),
    (0xffffee, 24),   (0x7fffe1, 23),   (0x7fffe2, 23),   (0x7fffe3, 23),
    (0x7fffe4, 23),   (0x1fffdc, 21),   (0x3fffd8, 22),   (0x7fffe5, 23),
    (0x3fffd9, 22),   (0x7fffe6, 23),   (0x7fffe7, 23),   (0xffffef, 24),
    (0x3fffda, 22),   (0x1fffdd, 21),   (0xfffe9, 20),    (0x3fffdb, 22),
    (0x3fffdc, 22),   (0x7fffe8, 23),   (0x7fffe9, 23),   (0x1fffde, 21),
    (0x7fffea, 23),   (0x3fffdd, 22),   (0x3fffde, 22),   (0xfffff0, 24),
    (0x1fffdf, 21),   (0x3fffdf, 22),   (0x7fffeb, 23),   (0x7fffec, 23),
    (0x1fffe0, 21),   (0x1fffe1, 21),   (0x3fffe0, 22),   (0x1fffe2, 21),
    (0x7fffed, 23),   (0x3fffe1, 22),   (0x7fffee, 23),   (0x7fffef, 23),
    (0xfffea, 20),    (0x3fffe2, 22),   (0x3fffe3, 22),   (0x3fffe4, 22),
    (0x7ffff0, 23),   (0x3fffe5, 22),   (0x3fffe6, 22),   (0x7ffff1, 23),
    (0x3ffffe0, 26),  (0x3ffffe1, 26),  (0xfffeb, 20),    (0x7fff1, 19),
    (0x3fffe7, 22),   (0x7ffff2, 23),   (0x3fffe8, 22),   (0x1ffffec, 25),
    (0x3ffffe2, 26),  (0x3ffffe3, 26),  (0x3ffffe4, 26),  (0x7ffffde, 27),
    (0x7ffffdf, 27),  (0x3ffffe5, 26),  (0xfffff1, 24),   (0x1ffffed, 25),
    (0x7fff2, 19),    (0x1fffe3, 21),   (0x3ffffe6, 26),  (0x7ffffe0, 27),
    (0x7ffffe1, 27),  (0x3ffffe7, 26),  (0x7ffffe2, 27),  (0xfffff2, 24),
    (0x1fffe4, 21),   (0x1fffe5, 21),   (0x3ffffe8, 26),  (0x3ffffe9, 26),
    (0xffffffd, 28),  (0x7ffffe3, 27),  (0x7ffffe4, 27),  (0x7ffffe5, 27),
    (0xfffec, 20),    (0xfffff3, 24),   (0xfffed, 20),    (0x1fffe6, 21),
    (0x3fffe9, 22),   (0x1fffe7, 21),   (0x1fffe8, 21),   (0x7ffff3, 23),
    (0x3fffea, 22),   (0x3fffeb, 22),   (0x1ffffee, 25),  (0x1ffffef, 25),
    (0xfffff4, 24),   (0xfffff5, 24),   (0x3ffffea, 26),  (0x7ffff4, 23),
    (0x3ffffeb, 26),  (0x7ffffe6, 27),  (0x3ffffec, 26),  (0x3ffffed, 26),
    (0x7ffffe7, 27),  (0x7ffffe8, 27),  (0x7ffffe9, 27),  (0x7ffffea, 27),
    (0x7ffffeb, 27),  (0xffffffe, 28),  (0x7ffffec, 27),  (0x7ffffed, 27),
    (0x7ffffee, 27),  (0x7ffffef, 27),  (0x7fffff0, 27),  (0x3ffffee, 26),
];

#[cfg(test)]
mod tests {
    use super::*;

    // COMPOSED expected value — NOT a raw first-party capture: real Safari 26.4
    // HEADERS metadata bytes with this project's English accept-language HPACK
    // segment spliced in (the genuine capture carries Chinese; see
    // tests/safari_h2_parity_baseline.rs). The accept-language slice here is thus
    // the encoder's own output, which is why the test below ALSO checks it against
    // an independent RFC 7541 oracle rather than only against this constant.
    const SAFARI26_HEADERS_EXPECTED_HEX: &str = concat!(
        "8287418aa0e41d139d09b8f34d3384408a4148b4a549275a42a13f8690e4b692d49f7ad8d07f66a281b0dae053",
        "fad0321aa49d13fda992a49685340c8a6adca7e28104416e277fb521aeba0bc8b1e63258700dae15c2da9fd66c",
        "7bf467fa5283752a988a4ea7fed4e25b1063d4c09c5da5370e51d8661c036b8570b753b0497ca589d34d1f43ae",
        "ba0c41a4c7a98f33a69a3fdf9a68fa1d75d0620d263d4c79a68fbed00177febe58f9fbed00177b408a4148b4a5",
        "49275906497f83a8f517408a4148b4a549275a93c85f86a87dcd30d25f518b2d4b70ddf45abefb4005df4086ae",
        "c31ec327d785b6007d286f50929bd9abfa5242cb40d25fa523b3e94f684c9f",
    );

    #[test]
    fn builds_http2_preface() {
        let fp = Http2Fingerprint::safari26();
        let preface = fp.connection_preface().unwrap();
        assert!(preface.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
        assert!(preface.len() > 24);
    }

    #[test]
    fn settings_frame_has_expected_length() {
        let fp = Http2Fingerprint::safari26();
        let frame = fp.settings_frame().unwrap();
        assert_eq!(&frame[0..3], &[0, 0, 24]);
        assert_eq!(frame[3], 0x4);
    }

    #[test]
    fn builds_settings_ack_frame() {
        let frame = Http2Fingerprint::settings_ack_frame().unwrap();
        assert_eq!(&frame, &[0, 0, 0, 0x4, 0x1, 0, 0, 0, 0]);
    }

    #[test]
    fn builds_opening_headers_frame() {
        let fp = Http2Fingerprint::safari26();
        let frame = fp.headers_frame("example.com").unwrap();
        let (header, total) = Http2FrameHeader::parse_complete(&frame).unwrap();

        assert_eq!(total, frame.len());
        assert_eq!(header.frame_type, 0x1);
        assert_eq!(header.flags, 0x5);
        assert_eq!(header.stream_id, 1);
        assert_eq!(
            &frame[9..12],
            &[0x82, 0x87, 0x41],
            "main-document pseudo order: :method :scheme :authority (authority before path)"
        );
        assert!(
            header.len > 15,
            "Safari HEADERS must include browser metadata"
        );
    }

    #[test]
    fn parses_complete_settings_ack_frame() {
        let frame = Http2Fingerprint::settings_ack_frame().unwrap();
        let (header, total) = Http2FrameHeader::parse_complete(&frame).unwrap();

        assert_eq!(total, frame.len());
        assert!(header.is_settings_ack());
    }

    /// Encode `value` with HPACK Huffman and strip the length-prefix byte so the
    /// test can assert on the raw Huffman payload.
    fn huffman_payload(value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        push_hpack_huffman_string(&mut out, value);
        // Length prefix is a single byte for our short test inputs.
        assert_eq!(out[0] & 0x80, 0x80, "huffman flag must be set");
        out[1..].to_vec()
    }

    // RFC 7541 Appendix C.4 / C.6 worked examples — the canonical reference
    // values for an HPACK Huffman encoder.
    #[test]
    fn hpack_huffman_matches_rfc7541_examples() {
        assert_eq!(huffman_payload(b"302"), hex(b"6402"));
        assert_eq!(huffman_payload(b"private"), hex(b"aec3771a4b"));
        assert_eq!(
            huffman_payload(b"Mon, 21 Oct 2013 20:13:21 GMT"),
            hex(b"d07abe941054d444a8200595040b8166e082a62d1bff"),
        );
        assert_eq!(
            huffman_payload(b"https://www.example.com"),
            hex(b"9d29ad171863c78f0b97c8e9ae82ae43d3"),
        );
    }

    /// RFC 7541 §5.1 variable-length integer encoding — the canonical worked
    /// example and the prefix/continuation boundaries. This encoder is exercised
    /// only indirectly by the full-header tests; pin it directly so an off-by-one
    /// in the `< max_prefix` boundary or the 7-bit continuation loop turns RED
    /// here rather than surfacing as a subtle wire drift in a fingerprint frame.
    #[test]
    fn hpack_integer_matches_rfc7541_examples_and_boundaries() {
        fn enc(value: usize, prefix_bits: u8) -> Vec<u8> {
            let mut out = Vec::new();
            push_hpack_integer(&mut out, value, prefix_bits, 0);
            out
        }

        // RFC 7541 §5.1: encoding 1337 with a 5-bit prefix yields 0x1F 0x9A 0x0A.
        assert_eq!(enc(1337, 5), vec![0x1F, 0x9A, 0x0A]);
        // RFC 7541 §5.1: 10 in a 5-bit prefix fits in the prefix (single byte).
        assert_eq!(enc(10, 5), vec![0x0A]);

        // 7-bit prefix (the string-length encoding used throughout HPACK):
        //   max_prefix_value = 127; values below it are a single prefix byte.
        assert_eq!(enc(0, 7), vec![0x00]);
        assert_eq!(enc(126, 7), vec![0x7E]);
        // 127 hits the prefix ceiling: prefix byte 0x7F then a single 0x00.
        assert_eq!(enc(127, 7), vec![0x7F, 0x00]);
        // 128 = 127 + 1: prefix 0x7F, then remaining 1 in one continuation byte.
        assert_eq!(enc(128, 7), vec![0x7F, 0x01]);
        // 255 = 127 + 128: remaining 128 needs a continuation (0x80|0) then 0x01.
        assert_eq!(enc(255, 7), vec![0x7F, 0x80, 0x01]);

        // The first-byte mask is OR'd into the prefix byte only (not continuation
        // bytes): a masked single-byte value keeps its mask, and the continuation
        // bytes of a multi-byte value are unaffected by the mask.
        let mut masked = Vec::new();
        push_hpack_integer(&mut masked, 5, 6, 0x40);
        assert_eq!(masked, vec![0x45]);
        let mut masked_multi = Vec::new();
        push_hpack_integer(&mut masked_multi, 1337, 5, 0xE0);
        // Prefix byte carries the mask (0xE0 | 0x1F = 0xFF); the two continuation
        // bytes stay 0x9A 0x0A exactly as in the unmasked RFC example.
        assert_eq!(masked_multi, vec![0xFF, 0x9A, 0x0A]);
    }

    /// Safari 26.4 emitted exactly these 11 bytes on the wire for the
    /// `:authority` literal of `localhost:8443`: `8a` (huffman | length=10)
    /// followed by `a0 e4 1d 13 9d 09 b8 f3 4d 33`. Capture: see
    /// `tests/fixtures/safari26_h2_request_localhost.bin`.
    #[test]
    fn safari26_authority_matches_captured_huffman_bytes() {
        let fp = Http2Fingerprint::safari26();
        let frame = fp.headers_frame("localhost:8443").unwrap();
        let payload = &frame[9..];
        // Main-document order: :method :scheme :authority :path.
        assert_eq!(
            &payload[..3],
            &[0x82, 0x87, 0x41],
            ":method :scheme then :authority literal (authority precedes path)",
        );
        assert_eq!(
            &payload[3..14],
            &[0x8a, 0xa0, 0xe4, 0x1d, 0x13, 0x9d, 0x09, 0xb8, 0xf3, 0x4d, 0x33],
            "Safari26 :authority huffman bytes drifted from captured baseline",
        );
        assert_eq!(payload[14], 0x84, ":path / (indexed) follows :authority");
    }

    #[test]
    fn safari26_headers_include_browser_metadata_with_english_language() {
        let fp = Http2Fingerprint::safari26();
        let frame = fp.headers_frame("localhost:8443").unwrap();
        let (header, total) = Http2FrameHeader::parse_complete(&frame).unwrap();
        let payload = &frame[Http2FrameHeader::SIZE..total];

        assert_eq!(header.len, 256);
        assert_eq!(
            payload,
            hex(SAFARI26_HEADERS_EXPECTED_HEX.as_bytes()),
            concat!(
                "Safari26 HEADERS metadata should match the composed expected ",
                "value (real capture metadata + English accept-language)",
            ),
        );
        assert!(SAFARI26_ACCEPT_LANGUAGE.starts_with("en-US"));
        assert!(
            !SAFARI26_ACCEPT_LANGUAGE.contains("zh"),
            "Safari26 accept-language must stay English-only"
        );

        // Independent oracle: derive the accept-language HPACK segment from the
        // source STRING via the RFC-7541-validated Huffman helper (not from the
        // composed constant), so a wrong-but-internally-consistent encoding of the
        // accept-language value cannot pass unnoticed. 0x51 = literal header field
        // with incremental indexing, static-table name index 17 (accept-language);
        // 0x80|len is the Huffman-coded value-length prefix.
        let al = huffman_payload(SAFARI26_ACCEPT_LANGUAGE.as_bytes());
        let mut expected_al = vec![0x51_u8, 0x80 | al.len() as u8];
        expected_al.extend_from_slice(&al);
        assert!(
            payload
                .windows(expected_al.len())
                .any(|window| window == expected_al),
            "accept-language segment must match the RFC 7541 Huffman encoding of \
             SAFARI26_ACCEPT_LANGUAGE, independent of the composed expected constant",
        );
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
}
