//! HTTP/3 (RFC 9114) codec data layer with QPACK (RFC 9204) field-section
//! encoding, mirroring [`crate::fingerprint::http2`] for the QUIC fast-plane H3
//! façade. This module is a pure library: it builds and parses H3 frames and
//! QPACK field sections, but does NOT touch quinn, stream orchestration, the
//! probe, or relay framing — those are later transport slices.
//!
//! Scope of the QPACK implementation here:
//! - Full static table (RFC 9204 Appendix A, indices 0..=98).
//! - Huffman encode/decode (RFC 7541 Appendix B, reused verbatim by QPACK).
//! - Encoded field section: a fixed `0x00 0x00` prefix (Required Insert
//!   Count = 0, Sign = 0, Delta Base = 0) followed by Indexed Field Line,
//!   Literal Field Line With Name Reference, and Literal With Literal Name
//!   representations.
//!
//! Out of scope (deliberately): the QPACK encoder/decoder dynamic table
//! (insert/eviction) and blocked-streams logic. ParallaX controls both ends and
//! uses static-only encoding, which is fully RFC-compliant.
//!
//! QPACK dynamic table (encoder-stream inserts): confirmed NOT needed for Safari
//! parity. Real Safari 26.4 (2026-06-22 browser h3 wire capture, server-side
//! keylog decrypt) encodes its request HEADERS entirely with literal / static
//! representations: Required Insert Count = 0, no encoder-stream insert
//! instructions. So ParallaX advertises a non-zero QPACK_MAX_TABLE_CAPACITY
//! (matching Safari's 16383) but only ever emits Required Insert Count = 0
//! (static + literal) field sections — which is exactly what Safari does. The
//! decoder still must tolerate a server response that uses the dynamic table.

use thiserror::Error;

/// Safari 26 `accept-language`. Same source value as the HTTP/2 façade.
pub use crate::fingerprint::http2::SAFARI26_ACCEPT_LANGUAGE;
/// Safari 26 request User-Agent. Reused from the HTTP/2 façade so the H2 and H3
/// fingerprints stay in lockstep.
pub use crate::fingerprint::http2::SAFARI26_USER_AGENT;

const SAFARI26_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const SAFARI26_PRIORITY: &str = "u=0, i";
const SAFARI26_ACCEPT_ENCODING: &str = "gzip, deflate, br, zstd";
const SAFARI26_SEC_FETCH_DEST: &str = "document";
const SAFARI26_SEC_FETCH_SITE: &str = "none";
const SAFARI26_SEC_FETCH_MODE: &str = "navigate";

/// HTTP/3 frame type codes (RFC 9114 §7.2).
pub const FRAME_TYPE_DATA: u64 = 0x00;
pub const FRAME_TYPE_HEADERS: u64 = 0x01;
pub const FRAME_TYPE_SETTINGS: u64 = 0x04;

/// HTTP/3 unidirectional stream type codes (RFC 9114 §6.2 / RFC 9204 §4.2). The
/// first byte(s) of a uni stream are a varint naming the stream's role; ParallaX's
/// QUIC façade opens a control stream (carrying SETTINGS) and a (static-only,
/// therefore empty) QPACK encoder stream to match a real H3 client's stream set.
pub const STREAM_TYPE_CONTROL: u64 = 0x00;
pub const STREAM_TYPE_QPACK_ENCODER: u64 = 0x02;
pub const STREAM_TYPE_QPACK_DECODER: u64 = 0x03;

/// Encode an HTTP/3 unidirectional stream-type prefix (a single QUIC varint), the
/// first bytes written on a freshly opened uni stream (RFC 9114 §6.2).
pub fn encode_stream_type(stream_type: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    put_varint(&mut out, stream_type);
    out
}

/// Read the leading unidirectional stream-type varint from `buf`, returning
/// `(stream_type, consumed)` or `None` if `buf` is too short to hold it.
pub fn read_stream_type(buf: &[u8]) -> Option<(u64, usize)> {
    read_varint(buf)
}

/// HTTP/3 SETTINGS identifiers (RFC 9114 §7.2.4.1, RFC 9204 §5).
pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;

/// Maximum frame/field-section payload this codec will allocate or accept. H3
/// has no protocol-imposed frame-size ceiling, so this is a defensive bound to
/// keep decoding fail-closed against hostile lengths.
pub const MAX_PAYLOAD_LEN: usize = 1 << 20; // 1 MiB

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Http3Error {
    #[error("HTTP/3 frame payload is too large")]
    FrameTooLarge,
    #[error("HTTP/3 frame is truncated or malformed")]
    Truncated,
    #[error("QPACK field section is truncated or malformed")]
    QpackTruncated,
    #[error("QPACK static table index {0} is out of range")]
    QpackBadStaticIndex(u64),
    #[error("QPACK Huffman-coded string is malformed")]
    QpackBadHuffman,
    #[error("QPACK requires dynamic-table state ParallaX does not maintain")]
    QpackDynamicUnsupported,
}

// ---------------------------------------------------------------------------
// QUIC varint (RFC 9000 §16) — H3/QPACK frame headers use this encoding.
// ---------------------------------------------------------------------------

/// QUIC varint encode `v` into `out` (RFC 9000 §16).
fn put_varint(out: &mut Vec<u8>, v: u64) {
    if v < 0x40 {
        out.push(v as u8);
    } else if v < 0x4000 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 0x4000_0000 {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/// Read one QUIC varint from the front of `buf`, returning `(value, consumed)`
/// or `None` if `buf` is too short.
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for &b in &buf[1..len] {
        value = (value << 8) | u64::from(b);
    }
    Some((value, len))
}

// ---------------------------------------------------------------------------
// H3 frame codec (RFC 9114 §7.1): frame = varint(type) varint(length) payload.
// ---------------------------------------------------------------------------

/// A decoded HTTP/3 frame: its type and the byte range of its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http3FrameHeader {
    pub frame_type: u64,
    pub len: usize,
}

/// Encode an HTTP/3 frame (RFC 9114 §7.1) with `frame_type` and `payload`.
pub fn encode_frame(frame_type: u64, payload: &[u8]) -> Result<Vec<u8>, Http3Error> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(Http3Error::FrameTooLarge);
    }
    let mut out = Vec::with_capacity(payload.len() + 16);
    put_varint(&mut out, frame_type);
    put_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decode one complete HTTP/3 frame from the front of `input`, returning the
/// `(header, payload, total_bytes_consumed)`. Fails closed if the buffer does
/// not yet hold the full frame or if the advertised length exceeds
/// [`MAX_PAYLOAD_LEN`].
pub fn decode_frame(input: &[u8]) -> Result<(Http3FrameHeader, &[u8], usize), Http3Error> {
    let (frame_type, type_len) = read_varint(input).ok_or(Http3Error::Truncated)?;
    let rest = &input[type_len..];
    let (len_u64, len_len) = read_varint(rest).ok_or(Http3Error::Truncated)?;
    // Compare the u64 length against the cap BEFORE narrowing to usize: on a
    // 32-bit target `len_u64 as usize` would truncate a large advertised length
    // and could slip past the bound (matches `read_one_h3_frame`'s u64-first
    // check). Downstream is fail-closed, but checking pre-cast is correct.
    if len_u64 > MAX_PAYLOAD_LEN as u64 {
        return Err(Http3Error::FrameTooLarge);
    }
    let len = len_u64 as usize;
    let header_len = type_len + len_len;
    let total = header_len.checked_add(len).ok_or(Http3Error::Truncated)?;
    if input.len() < total {
        return Err(Http3Error::Truncated);
    }
    let payload = &input[header_len..total];
    Ok((Http3FrameHeader { frame_type, len }, payload, total))
}

// ---------------------------------------------------------------------------
// SETTINGS builder — Safari-26 control-stream first frame (RFC 9114 §7.2.4).
// ---------------------------------------------------------------------------

/// One HTTP/3 SETTINGS parameter `id := value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http3Setting {
    pub id: u64,
    pub value: u64,
}

/// GREASE SETTINGS ids are reserved as `0x1f * N + 0x21` (RFC 9114 §7.2.4.1), so
/// peers ignore them. Safari emits a FRESH random GREASE id AND value on every H3
/// connection (confirmed across independent captures), so a fixed pair would
/// itself be a static, fingerprintable tell — generate per connection (see
/// [`grease_setting_from_seed`]) and verify only the *form* on receipt (see
/// [`is_grease_setting_id`]).
const SETTINGS_GREASE_BASE: u64 = 0x21;
const SETTINGS_GREASE_STRIDE: u64 = 0x1f;

/// True iff `id` is a reserved GREASE SETTINGS id of the form `0x1f * N + 0x21`.
pub fn is_grease_setting_id(id: u64) -> bool {
    id >= SETTINGS_GREASE_BASE && (id - SETTINGS_GREASE_BASE) % SETTINGS_GREASE_STRIDE == 0
}

/// Derive a per-connection GREASE SETTINGS from 8 random bytes: a reserved id
/// (`0x1f * N + 0x21`, `N` from the first 4 bytes) and a random value (last 4
/// bytes). Pure so it stays testable; the transport draws the seed from the system
/// CSPRNG once per control stream. Both id and value vary per connection, matching
/// Safari.
pub fn grease_setting_from_seed(seed: [u8; 8]) -> Http3Setting {
    let n = u64::from(u32::from_be_bytes([seed[0], seed[1], seed[2], seed[3]]));
    let value = u64::from(u32::from_be_bytes([seed[4], seed[5], seed[6], seed[7]]));
    Http3Setting {
        id: SETTINGS_GREASE_STRIDE * n + SETTINGS_GREASE_BASE,
        value,
    }
}

/// Safari 26 HTTP/3 SETTINGS for one connection, in the exact on-wire order:
/// QPACK_MAX_TABLE_CAPACITY, QPACK_BLOCKED_STREAMS, then the per-connection
/// `grease` setting. Notably Safari does NOT send MAX_FIELD_SECTION_SIZE (0x06).
pub fn safari26_settings(grease: Http3Setting) -> [Http3Setting; 3] {
    [
        Http3Setting {
            id: SETTINGS_QPACK_MAX_TABLE_CAPACITY,
            value: 16383,
        },
        Http3Setting {
            id: SETTINGS_QPACK_BLOCKED_STREAMS,
            value: 100,
        },
        grease,
    ]
}

/// Verify a peer advertised Safari-26-shaped H3 SETTINGS: the two fixed QPACK
/// params (exact id+value), then exactly one GREASE setting (id form-checked, value
/// free), and nothing else (no MAX_FIELD_SECTION_SIZE). The GREASE id/value are
/// per-connection random, so this checks the SHAPE, not byte-equality with our own
/// SETTINGS.
pub fn is_safari26_settings(settings: &[Http3Setting]) -> bool {
    matches!(
        settings,
        [cap, blocked, grease]
            if cap.id == SETTINGS_QPACK_MAX_TABLE_CAPACITY
                && cap.value == 16383
                && blocked.id == SETTINGS_QPACK_BLOCKED_STREAMS
                && blocked.value == 100
                && is_grease_setting_id(grease.id)
    )
}

/// Encode the SETTINGS frame payload (a sequence of `id value` varint pairs).
fn settings_payload(settings: &[Http3Setting]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(settings.len() * 4);
    for s in settings {
        put_varint(&mut payload, s.id);
        put_varint(&mut payload, s.value);
    }
    payload
}

/// Build Safari 26's SETTINGS frame (the control stream's first frame) with the
/// given per-connection GREASE setting.
pub fn safari26_settings_frame(grease: Http3Setting) -> Result<Vec<u8>, Http3Error> {
    let payload = settings_payload(&safari26_settings(grease));
    encode_frame(FRAME_TYPE_SETTINGS, &payload)
}

/// Parse a SETTINGS frame payload into its `(id, value)` pairs. Fail-closed on
/// truncation.
pub fn parse_settings_payload(mut payload: &[u8]) -> Result<Vec<Http3Setting>, Http3Error> {
    let mut out = Vec::new();
    while !payload.is_empty() {
        let (id, n) = read_varint(payload).ok_or(Http3Error::Truncated)?;
        payload = &payload[n..];
        let (value, m) = read_varint(payload).ok_or(Http3Error::Truncated)?;
        payload = &payload[m..];
        out.push(Http3Setting { id, value });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Request HEADERS builder — Safari-26 field order (RFC 9114 §4.1).
// ---------------------------------------------------------------------------

/// Build Safari 26's opening request HEADERS frame for `authority`.
///
/// Field order is Safari-26's observed main-document H3 order, which is the same
/// field sequence as the H2 main-document request (confirmed against real H3
/// wire): pseudo-headers `:method :scheme :authority :path`, then
/// `sec-fetch-dest, user-agent, accept, sec-fetch-site, sec-fetch-mode,
/// accept-language, priority, accept-encoding`.
pub fn safari26_headers_frame(authority: &str) -> Result<Vec<u8>, Http3Error> {
    safari26_headers_frame_with_language(authority, SAFARI26_ACCEPT_LANGUAGE)
}

/// Build the opening H3 request HEADERS frame with an explicit `accept-language`
/// value (kept in lockstep with the H2 path so the two planes never diverge).
pub fn safari26_headers_frame_with_language(
    authority: &str,
    accept_language: &str,
) -> Result<Vec<u8>, Http3Error> {
    let fields = safari26_request_fields_with_language(authority, accept_language);
    let section = encode_field_section(&fields);
    encode_frame(FRAME_TYPE_HEADERS, &section)
}

/// The ordered `(name, value)` header list Safari 26 sends on its opening H3
/// request, with the default en-US `accept-language`. Exposed for tests and for
/// callers that want the field list without the QPACK/frame wrapping.
pub fn safari26_request_fields(authority: &str) -> Vec<(String, String)> {
    safari26_request_fields_with_language(authority, SAFARI26_ACCEPT_LANGUAGE)
}

/// Like [`safari26_request_fields`] but with an explicit `accept-language`.
pub fn safari26_request_fields_with_language(
    authority: &str,
    accept_language: &str,
) -> Vec<(String, String)> {
    vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), authority.to_string()),
        (":path".to_string(), "/".to_string()),
        (
            "sec-fetch-dest".to_string(),
            SAFARI26_SEC_FETCH_DEST.to_string(),
        ),
        ("user-agent".to_string(), SAFARI26_USER_AGENT.to_string()),
        ("accept".to_string(), SAFARI26_ACCEPT.to_string()),
        (
            "sec-fetch-site".to_string(),
            SAFARI26_SEC_FETCH_SITE.to_string(),
        ),
        (
            "sec-fetch-mode".to_string(),
            SAFARI26_SEC_FETCH_MODE.to_string(),
        ),
        (
            "accept-language".to_string(),
            accept_language.to_string(),
        ),
        ("priority".to_string(), SAFARI26_PRIORITY.to_string()),
        (
            "accept-encoding".to_string(),
            SAFARI26_ACCEPT_ENCODING.to_string(),
        ),
    ]
}

/// Build a minimal HTTP/3 response HEADERS frame carrying only `:status 200`
/// (QPACK static index 25, a full Indexed Field Line). ParallaX's QUIC façade
/// answers its single synthetic request with this; a real origin would add more
/// headers, but the response side faces only the (cooperating) ParallaX client,
/// so a minimal compliant `:status 200` is sufficient and unambiguous.
pub fn response_status_200_headers_frame() -> Result<Vec<u8>, Http3Error> {
    let section = encode_field_section(&[(":status".to_string(), "200".to_string())]);
    encode_frame(FRAME_TYPE_HEADERS, &section)
}

// ---------------------------------------------------------------------------
// QPACK field-section codec (RFC 9204 §4).
// ---------------------------------------------------------------------------

/// How a header field is encoded into the QPACK field section. Safari's exact
/// per-field choice (indexed vs. literal, Huffman vs. raw) is a fingerprint
/// detail; the encoder below picks per-field strategies to match it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldEncoding {
    /// Static-table index fully matches name+value (Indexed Field Line, T=1).
    StaticIndexed(u8),
    /// Static-table index supplies the name; value is a Huffman-coded literal
    /// (Literal Field Line With Name Reference, T=1).
    StaticNameRefHuffman(u8),
    /// Both name and value are Huffman-coded literals (Literal With Literal
    /// Name).
    LiteralHuffman,
}

/// Choose Safari-26's QPACK encoding for one `(name, value)` field. Fully
/// static-table matches use Indexed Field Line; fields whose name is in the
/// static table use a name reference with a Huffman value; everything else uses
/// a fully literal (Huffman name + Huffman value) representation.
fn field_encoding(name: &str, value: &str) -> FieldEncoding {
    if let Some(idx) = static_full_match(name, value) {
        FieldEncoding::StaticIndexed(idx)
    } else if let Some(idx) = static_name_match(name) {
        FieldEncoding::StaticNameRefHuffman(idx)
    } else {
        FieldEncoding::LiteralHuffman
    }
}

/// Encode an ordered list of `(name, value)` fields into a QPACK encoded field
/// section (RFC 9204 §4.5): the `0x00 0x00` prefix (Required Insert Count = 0;
/// Sign = 0, Delta Base = 0) followed by the field representations.
pub fn encode_field_section<S: AsRef<str>>(fields: &[(S, S)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + fields.len() * 8);
    // Field Section Prefix: Required Insert Count = 0, then Sign(0)+Delta Base(0).
    out.push(0x00);
    out.push(0x00);
    for (name, value) in fields {
        let name = name.as_ref();
        let value = value.as_ref();
        match field_encoding(name, value) {
            FieldEncoding::StaticIndexed(idx) => {
                // Indexed Field Line: 1 T(=1, static) N N N N N N (6-bit prefix).
                put_qpack_integer(&mut out, idx as u64, 6, 0b1100_0000);
            }
            FieldEncoding::StaticNameRefHuffman(idx) => {
                // Literal Field Line With Name Reference: 0 1 N T(=1) NNNN
                // (4-bit name-index prefix). N=0 (no never-index).
                put_qpack_integer(&mut out, idx as u64, 4, 0b0101_0000);
                put_qpack_string(&mut out, value.as_bytes(), true);
            }
            FieldEncoding::LiteralHuffman => {
                // Literal Field Line With Literal Name: 0 0 1 N H(=1) LLL
                // (3-bit name-length prefix, Huffman name). N=0.
                put_qpack_string_with_pattern(&mut out, name.as_bytes(), true, 3, 0b0010_1000);
                put_qpack_string(&mut out, value.as_bytes(), true);
            }
        }
    }
    out
}

/// Decode a QPACK encoded field section into its ordered `(name, value)` pairs.
/// Supports the static-table-only subset this module emits: Indexed Field Line
/// (static), Literal Field Line With Name Reference (static name), and Literal
/// Field Line With Literal Name, with or without Huffman. Anything that requires
/// dynamic-table state is rejected fail-closed.
pub fn decode_field_section(input: &[u8]) -> Result<Vec<(String, String)>, Http3Error> {
    // Field Section Prefix: Required Insert Count, then Sign+Delta Base.
    let (required_insert_count, n) =
        read_qpack_integer(input, 8).ok_or(Http3Error::QpackTruncated)?;
    if required_insert_count != 0 {
        return Err(Http3Error::QpackDynamicUnsupported);
    }
    let mut rest = &input[n..];
    let (_base, m) = read_qpack_integer(rest, 7).ok_or(Http3Error::QpackTruncated)?;
    rest = &rest[m..];

    let mut out = Vec::new();
    while let Some(&first) = rest.first() {
        if first & 0b1000_0000 != 0 {
            // Indexed Field Line: 1 T NNNNNN.
            if first & 0b0100_0000 == 0 {
                // T=0 => dynamic table reference, unsupported.
                return Err(Http3Error::QpackDynamicUnsupported);
            }
            let (idx, used) = read_qpack_integer(rest, 6).ok_or(Http3Error::QpackTruncated)?;
            rest = &rest[used..];
            let (name, value) = static_entry(idx)?;
            out.push((name.to_string(), value.to_string()));
        } else if first & 0b0100_0000 != 0 {
            // Literal Field Line With Name Reference: 0 1 N T NNNN.
            if first & 0b0001_0000 == 0 {
                // T=0 => dynamic table name reference, unsupported.
                return Err(Http3Error::QpackDynamicUnsupported);
            }
            let (idx, used) = read_qpack_integer(rest, 4).ok_or(Http3Error::QpackTruncated)?;
            rest = &rest[used..];
            let (name, _) = static_entry(idx)?;
            let (value, vused) = read_qpack_string(rest)?;
            rest = &rest[vused..];
            out.push((name.to_string(), string_from_utf8(value)?));
        } else if first & 0b0010_0000 != 0 {
            // Literal Field Line With Literal Name: 0 0 1 N H LLL.
            let (name, nused) = read_qpack_string_with_prefix(rest, 3)?;
            rest = &rest[nused..];
            let (value, vused) = read_qpack_string(rest)?;
            rest = &rest[vused..];
            out.push((string_from_utf8(name)?, string_from_utf8(value)?));
        } else {
            // 0 0 0 1 = dynamic table size update / post-base index, unsupported.
            return Err(Http3Error::QpackDynamicUnsupported);
        }
    }
    Ok(out)
}

fn string_from_utf8(bytes: Vec<u8>) -> Result<String, Http3Error> {
    String::from_utf8(bytes).map_err(|_| Http3Error::QpackTruncated)
}

// ---------------------------------------------------------------------------
// QPACK integer + string primitives (RFC 9204 §4.1 / RFC 7541 §5).
// ---------------------------------------------------------------------------

/// Encode a QPACK/HPACK prefix integer of `value` with an `prefix_bits`-bit
/// prefix, OR-ing `pattern` into the leading byte (RFC 7541 §5.1).
fn put_qpack_integer(out: &mut Vec<u8>, value: u64, prefix_bits: u8, pattern: u8) {
    let max_prefix = (1u64 << prefix_bits) - 1;
    if value < max_prefix {
        out.push(pattern | value as u8);
        return;
    }
    out.push(pattern | max_prefix as u8);
    let mut remaining = value - max_prefix;
    while remaining >= 128 {
        out.push((remaining as u8 & 0x7f) | 0x80);
        remaining >>= 7;
    }
    out.push(remaining as u8);
}

/// Read a QPACK/HPACK prefix integer from `buf` whose leading byte uses an
/// `prefix_bits`-bit value field, returning `(value, bytes_consumed)`.
fn read_qpack_integer(buf: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let max_prefix = (1u64 << prefix_bits) - 1;
    let prefix = u64::from(first) & max_prefix;
    if prefix < max_prefix {
        return Some((prefix, 1));
    }
    let mut value = max_prefix;
    let mut shift = 0u32;
    let mut idx = 1usize;
    loop {
        let b = *buf.get(idx)?;
        idx += 1;
        value = value.checked_add(u64::from(b & 0x7f).checked_shl(shift)?)?;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    Some((value, idx))
}

/// Encode a QPACK string literal with the canonical 7-bit length prefix
/// (Huffman flag in bit 0x80), per RFC 9204 §4.1.2.
fn put_qpack_string(out: &mut Vec<u8>, value: &[u8], huffman: bool) {
    put_qpack_string_with_pattern(out, value, huffman, 7, 0);
}

/// Encode a QPACK string literal whose length uses a `prefix_bits`-bit prefix
/// with a representation-specific `pattern` and Huffman flag (the bit just above
/// the length prefix). Used for both the 7-bit value-length form and the 3-bit
/// literal-name form.
fn put_qpack_string_with_pattern(
    out: &mut Vec<u8>,
    value: &[u8],
    huffman: bool,
    prefix_bits: u8,
    pattern: u8,
) {
    let huff_bit = if huffman { 1u8 << prefix_bits } else { 0 };
    let pattern = pattern | huff_bit;
    if huffman {
        let encoded = huffman_encode(value);
        put_qpack_integer(out, encoded.len() as u64, prefix_bits, pattern);
        out.extend_from_slice(&encoded);
    } else {
        put_qpack_integer(out, value.len() as u64, prefix_bits, pattern);
        out.extend_from_slice(value);
    }
}

/// Read a QPACK string literal with the canonical 7-bit length prefix, returning
/// the decoded bytes and the total bytes consumed.
fn read_qpack_string(buf: &[u8]) -> Result<(Vec<u8>, usize), Http3Error> {
    read_qpack_string_with_prefix(buf, 7)
}

/// Read a QPACK string literal whose length uses a `prefix_bits`-bit prefix with
/// the Huffman flag in the bit just above the prefix.
fn read_qpack_string_with_prefix(
    buf: &[u8],
    prefix_bits: u8,
) -> Result<(Vec<u8>, usize), Http3Error> {
    let first = *buf.first().ok_or(Http3Error::QpackTruncated)?;
    let huffman = first & (1u8 << prefix_bits) != 0;
    let (len_u64, len_bytes) =
        read_qpack_integer(buf, prefix_bits).ok_or(Http3Error::QpackTruncated)?;
    let len = len_u64 as usize;
    if len > MAX_PAYLOAD_LEN {
        return Err(Http3Error::FrameTooLarge);
    }
    let end = len_bytes
        .checked_add(len)
        .ok_or(Http3Error::QpackTruncated)?;
    if buf.len() < end {
        return Err(Http3Error::QpackTruncated);
    }
    let raw = &buf[len_bytes..end];
    let bytes = if huffman {
        huffman_decode(raw)?
    } else {
        raw.to_vec()
    };
    Ok((bytes, end))
}

// ---------------------------------------------------------------------------
// QPACK static table (RFC 9204 Appendix A, indices 0..=98).
// ---------------------------------------------------------------------------

/// Look up the static-table entry at `index`, failing closed if out of range.
fn static_entry(index: u64) -> Result<(&'static str, &'static str), Http3Error> {
    QPACK_STATIC_TABLE
        .get(index as usize)
        .copied()
        .ok_or(Http3Error::QpackBadStaticIndex(index))
}

/// First static-table index whose name AND value both equal the field, if any.
fn static_full_match(name: &str, value: &str) -> Option<u8> {
    QPACK_STATIC_TABLE
        .iter()
        .position(|&(n, v)| n == name && v == value)
        .map(|i| i as u8)
}

/// First static-table index whose name equals `name`, if any.
fn static_name_match(name: &str) -> Option<u8> {
    QPACK_STATIC_TABLE
        .iter()
        .position(|&(n, _)| n == name)
        .map(|i| i as u8)
}

/// RFC 9204 Appendix A QPACK static table: 99 `(name, value)` entries indexed
/// 0..=98.
#[rustfmt::skip]
const QPACK_STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000; includesubdomains"),
    ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

// ---------------------------------------------------------------------------
// Huffman codec (RFC 7541 Appendix B, reused verbatim by QPACK / RFC 9204 §4.1.2).
// ---------------------------------------------------------------------------

/// Huffman-encode `value` (RFC 7541 §5.2): MSB-first, padded to a byte boundary
/// with the high bits of the all-ones EOS code.
fn huffman_encode(value: &[u8]) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::with_capacity(value.len());
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;
    for &byte in value {
        let (code, code_len) = HUFFMAN_TABLE[byte as usize];
        acc = (acc << code_len) | u64::from(code);
        bits += u32::from(code_len);
        while bits >= 8 {
            bits -= 8;
            encoded.push((acc >> bits) as u8);
        }
        acc &= if bits == 0 { 0 } else { (1u64 << bits) - 1 };
    }
    if bits > 0 {
        let pad = 8 - bits;
        acc = (acc << pad) | ((1u64 << pad) - 1);
        encoded.push(acc as u8);
    }
    encoded
}

/// Huffman-decode `input` (RFC 7541 §5.2 / RFC 9204 §4.1.2). Walks the bit
/// stream one bit at a time, emitting a symbol as soon as the accumulated bits
/// form a complete code (the table is a prefix code, so the first complete match
/// is unambiguous). Validates the trailing padding (must be all-ones and shorter
/// than 8 bits, with no fully padded final byte and no EOS symbol), failing
/// closed otherwise.
fn huffman_decode(input: &[u8]) -> Result<Vec<u8>, Http3Error> {
    let mut out = Vec::with_capacity(input.len() * 2);
    let mut cur: u32 = 0;
    let mut cur_len: u8 = 0;
    for &byte in input {
        for bit_pos in (0..8).rev() {
            let bit = (byte >> bit_pos) & 1;
            cur = (cur << 1) | u32::from(bit);
            cur_len += 1;
            if cur_len > 30 {
                // No code is longer than 30 bits; an over-long run means the
                // stream is not a valid Huffman encoding.
                return Err(Http3Error::QpackBadHuffman);
            }
            if let Some(sym) = huffman_lookup(cur, cur_len) {
                out.push(sym);
                cur = 0;
                cur_len = 0;
            }
        }
    }
    // Any residual bits must be all-ones EOS padding strictly shorter than 8
    // bits. RFC 7541 §5.2: padding longer than 7 bits, padding not composed of
    // EOS high bits, or a decoded EOS are all errors.
    if cur_len >= 8 {
        return Err(Http3Error::QpackBadHuffman);
    }
    if cur_len > 0 {
        let mask = (1u32 << cur_len) - 1;
        if cur & mask != mask {
            return Err(Http3Error::QpackBadHuffman);
        }
    }
    Ok(out)
}

/// Match a `code_len`-bit Huffman code against the table, returning the source
/// byte if exactly one symbol uses this `(code, code_len)`.
fn huffman_lookup(code: u32, code_len: u8) -> Option<u8> {
    for (sym, &(c, l)) in HUFFMAN_TABLE.iter().enumerate() {
        if l == code_len && c == code {
            return Some(sym as u8);
        }
    }
    None
}

/// RFC 7541 Appendix B Huffman table: `(code, bit_length)` indexed by source
/// byte 0..=255. Reused verbatim by QPACK (RFC 9204 §4.1.2). Index 256 (EOS) is
/// intentionally omitted — it must never appear in a valid encoding.
#[rustfmt::skip]
const HUFFMAN_TABLE: [(u32, u8); 256] = [
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

    fn hex(s: &str) -> Vec<u8> {
        fn nibble(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("non-hex byte"),
            }
        }
        s.as_bytes()
            .chunks(2)
            .map(|c| (nibble(c[0]) << 4) | nibble(c[1]))
            .collect()
    }

    // --- H3 frame round-trips (RFC 9114 §7.1) -----------------------------

    #[test]
    fn stream_type_prefix_roundtrip() {
        for ty in [
            STREAM_TYPE_CONTROL,
            STREAM_TYPE_QPACK_ENCODER,
            STREAM_TYPE_QPACK_DECODER,
        ] {
            let encoded = encode_stream_type(ty);
            let (decoded, consumed) = read_stream_type(&encoded).unwrap();
            assert_eq!(decoded, ty);
            assert_eq!(consumed, encoded.len());
        }
        // Control/encoder/decoder are all single-byte varints.
        assert_eq!(encode_stream_type(STREAM_TYPE_CONTROL), vec![0x00]);
        assert_eq!(encode_stream_type(STREAM_TYPE_QPACK_ENCODER), vec![0x02]);
        assert_eq!(encode_stream_type(STREAM_TYPE_QPACK_DECODER), vec![0x03]);
    }

    #[test]
    fn read_stream_type_too_short_is_none() {
        assert!(read_stream_type(&[]).is_none());
    }

    #[test]
    fn frame_roundtrip_data() {
        let payload = b"hello world";
        let frame = encode_frame(FRAME_TYPE_DATA, payload).unwrap();
        let (hdr, body, total) = decode_frame(&frame).unwrap();
        assert_eq!(hdr.frame_type, FRAME_TYPE_DATA);
        assert_eq!(hdr.len, payload.len());
        assert_eq!(body, payload);
        assert_eq!(total, frame.len());
    }

    #[test]
    fn frame_roundtrip_headers() {
        let payload = vec![0x00, 0x00, 0xd1];
        let frame = encode_frame(FRAME_TYPE_HEADERS, &payload).unwrap();
        let (hdr, body, total) = decode_frame(&frame).unwrap();
        assert_eq!(hdr.frame_type, FRAME_TYPE_HEADERS);
        assert_eq!(body, &payload[..]);
        assert_eq!(total, frame.len());
    }

    #[test]
    fn frame_roundtrip_settings() {
        let payload = settings_payload(&safari26_settings(grease_setting_from_seed([0; 8])));
        let frame = encode_frame(FRAME_TYPE_SETTINGS, &payload).unwrap();
        let (hdr, body, total) = decode_frame(&frame).unwrap();
        assert_eq!(hdr.frame_type, FRAME_TYPE_SETTINGS);
        assert_eq!(body, &payload[..]);
        assert_eq!(total, frame.len());
    }

    #[test]
    fn decode_frame_truncated_payload_fails_closed() {
        let frame = encode_frame(FRAME_TYPE_DATA, b"abcdef").unwrap();
        // Drop the last payload byte: the advertised length now exceeds input.
        let truncated = &frame[..frame.len() - 1];
        assert_eq!(decode_frame(truncated), Err(Http3Error::Truncated));
    }

    #[test]
    fn decode_frame_rejects_oversize_length() {
        // type=DATA, length = 2 MiB (8-byte varint), no payload.
        let mut buf = vec![FRAME_TYPE_DATA as u8];
        put_varint(&mut buf, (MAX_PAYLOAD_LEN + 1) as u64);
        assert_eq!(decode_frame(&buf), Err(Http3Error::FrameTooLarge));
    }

    #[test]
    fn decode_frame_rejects_length_above_u32_without_truncation() {
        // A length that exceeds u32::MAX must be rejected as FrameTooLarge. The
        // bound is compared on the u64 BEFORE narrowing to usize; on a 32-bit
        // target `len as usize` would truncate this to a small value and could slip
        // past the cap, so this guards the pre-cast ordering.
        let mut buf = vec![FRAME_TYPE_DATA as u8];
        put_varint(&mut buf, (u32::MAX as u64) + 1);
        assert_eq!(decode_frame(&buf), Err(Http3Error::FrameTooLarge));
    }

    #[test]
    fn encode_frame_rejects_oversize_payload() {
        let big = vec![0u8; MAX_PAYLOAD_LEN + 1];
        assert_eq!(
            encode_frame(FRAME_TYPE_DATA, &big),
            Err(Http3Error::FrameTooLarge)
        );
    }

    // --- Huffman round-trip + RFC 7541 known vectors ----------------------

    #[test]
    fn huffman_matches_rfc7541_examples() {
        // RFC 7541 Appendix C.4 / C.6 worked examples.
        assert_eq!(huffman_encode(b"302"), hex("6402"));
        assert_eq!(huffman_encode(b"private"), hex("aec3771a4b"));
        assert_eq!(
            huffman_encode(b"Mon, 21 Oct 2013 20:13:21 GMT"),
            hex("d07abe941054d444a8200595040b8166e082a62d1bff"),
        );
        assert_eq!(
            huffman_encode(b"https://www.example.com"),
            hex("9d29ad171863c78f0b97c8e9ae82ae43d3"),
        );
    }

    #[test]
    fn huffman_decode_matches_rfc7541_examples() {
        assert_eq!(huffman_decode(&hex("6402")).unwrap(), b"302");
        assert_eq!(huffman_decode(&hex("aec3771a4b")).unwrap(), b"private");
        assert_eq!(
            huffman_decode(&hex("d07abe941054d444a8200595040b8166e082a62d1bff")).unwrap(),
            b"Mon, 21 Oct 2013 20:13:21 GMT",
        );
        assert_eq!(
            huffman_decode(&hex("9d29ad171863c78f0b97c8e9ae82ae43d3")).unwrap(),
            b"https://www.example.com",
        );
    }

    #[test]
    fn huffman_roundtrip_all_byte_values() {
        let all: Vec<u8> = (0u8..=255).collect();
        assert_eq!(huffman_decode(&huffman_encode(&all)).unwrap(), all);
    }

    #[test]
    fn huffman_decode_rejects_non_eos_padding() {
        // "private" Huffman-encodes to 0xaec3771a4b: 39 data bits + a single
        // trailing 1-bit of EOS padding. Clearing that pad bit makes the padding
        // a 0, which is no longer the EOS high-bit pattern, so decoding must fail.
        let mut bad = hex("aec3771a4b");
        let last = bad.len() - 1;
        bad[last] &= 0xfe;
        assert_eq!(huffman_decode(&bad), Err(Http3Error::QpackBadHuffman));
    }

    // --- QPACK field-section round-trips (RFC 9204 §4) ---------------------

    #[test]
    fn qpack_roundtrip_static_indexed_only() {
        // All three fields are full static-table matches.
        let fields = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (
                "accept-encoding".to_string(),
                "gzip, deflate, br".to_string(),
            ),
        ];
        let section = encode_field_section(&fields);
        // Prefix(0x00 0x00) + three single-byte indexed lines: 0xc0|17, 0xc0|23,
        // 0xc0|31.
        assert_eq!(section, vec![0x00, 0x00, 0xc0 | 17, 0xc0 | 23, 0xc0 | 31]);
        assert_eq!(decode_field_section(&section).unwrap(), fields);
    }

    #[test]
    fn qpack_roundtrip_literal_with_name_ref() {
        // :authority (static index 0, name ref) + Huffman value.
        let fields = vec![(":authority".to_string(), "example.com".to_string())];
        let section = encode_field_section(&fields);
        // First field byte after the 2-byte prefix: 0b0101_0000 | 0 = 0x50.
        assert_eq!(section[2], 0x50);
        assert_eq!(decode_field_section(&section).unwrap(), fields);
    }

    #[test]
    fn qpack_roundtrip_literal_with_literal_name() {
        // "priority" is not in the static table -> literal name + literal value.
        let fields = vec![("priority".to_string(), "u=3".to_string())];
        let section = encode_field_section(&fields);
        // First field byte after prefix: 0b0010_1000 (literal name, Huffman) with
        // a length in the low 3 bits.
        assert_eq!(section[2] & 0b1111_1000, 0b0010_1000);
        assert_eq!(decode_field_section(&section).unwrap(), fields);
    }

    #[test]
    fn qpack_roundtrip_mixed_full_request() {
        let fields = safari26_request_fields("localhost:8443");
        let section = encode_field_section(&fields);
        assert_eq!(decode_field_section(&section).unwrap(), fields);
    }

    #[test]
    fn qpack_section_prefix_is_zero_insert_count() {
        let section = encode_field_section(&[(":path".to_string(), "/".to_string())]);
        assert_eq!(&section[..2], &[0x00, 0x00], "RIC=0, Sign=0, Delta Base=0");
    }

    #[test]
    fn qpack_decode_rejects_dynamic_required_insert_count() {
        // A non-zero Required Insert Count (first prefix byte) means the section
        // depends on dynamic-table entries this codec does not maintain.
        let section = vec![0x05, 0x00];
        assert_eq!(
            decode_field_section(&section),
            Err(Http3Error::QpackDynamicUnsupported)
        );
    }

    #[test]
    fn qpack_decode_rejects_dynamic_indexed_reference() {
        // Indexed Field Line with T=0 (0b1000_0000) => dynamic table reference.
        let section = vec![0x00, 0x00, 0b1000_0000];
        assert_eq!(
            decode_field_section(&section),
            Err(Http3Error::QpackDynamicUnsupported)
        );
    }

    // --- QPACK prefix integer codec (RFC 7541 §5.1) -----------------------

    #[test]
    fn qpack_integer_put_read_roundtrip() {
        // Round-trip a spread of values across every prefix width, including the
        // exact `max_prefix` value (the first continuation case) and multi-byte
        // continuations.
        for prefix_bits in [3u8, 4, 5, 6, 7] {
            let max_prefix = (1u64 << prefix_bits) - 1;
            for value in [
                0,
                1,
                max_prefix - 1,
                max_prefix,
                max_prefix + 1,
                127,
                128,
                255,
                16_383,
                16_384,
                1_000_000,
                u64::MAX,
            ] {
                let mut buf = Vec::new();
                put_qpack_integer(&mut buf, value, prefix_bits, 0);
                let (decoded, consumed) =
                    read_qpack_integer(&buf, prefix_bits).expect("well-formed integer decodes");
                assert_eq!(decoded, value, "value {value} @ {prefix_bits} bits");
                assert_eq!(consumed, buf.len(), "consumes exactly the encoded bytes");
            }
        }
    }

    #[test]
    fn qpack_integer_read_empty_is_none() {
        assert!(read_qpack_integer(&[], 7).is_none());
    }

    #[test]
    fn qpack_integer_read_truncated_continuation_is_none() {
        // Prefix says "max, keep reading" (0x7f for a 7-bit prefix) but the
        // continuation byte that must follow is missing -> fail closed.
        assert!(read_qpack_integer(&[0x7f], 7).is_none());
        // A continuation byte with its high bit set but no successor.
        assert!(read_qpack_integer(&[0x7f, 0x80], 7).is_none());
    }

    #[test]
    fn qpack_integer_read_overflow_is_none() {
        // Ten 0x80 continuation bytes push `shift` past 63 (the guard), so the
        // decoder must reject rather than wrap. Terminate with a final 0x01 that
        // would only be reached if the guard were absent.
        let mut evil = vec![0x7f];
        evil.extend([0x80u8; 10]);
        evil.push(0x01);
        assert!(read_qpack_integer(&evil, 7).is_none());
    }

    // --- SETTINGS: Safari-26 ground truth ---------------------------------

    #[test]
    fn settings_match_safari26_ground_truth() {
        let grease = grease_setting_from_seed([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        let settings = safari26_settings(grease);
        assert_eq!(settings.len(), 3);
        // Exact id set + order for the two fixed QPACK params.
        assert_eq!(settings[0].id, SETTINGS_QPACK_MAX_TABLE_CAPACITY);
        assert_eq!(settings[0].value, 16383);
        assert_eq!(settings[1].id, SETTINGS_QPACK_BLOCKED_STREAMS);
        assert_eq!(settings[1].value, 100);
        // GREASE id must be of the reserved form 0x1f*N + 0x21.
        assert!(is_grease_setting_id(settings[2].id));
        // Must NOT advertise MAX_FIELD_SECTION_SIZE (0x06).
        assert!(settings.iter().all(|s| s.id != 0x06));
        // The whole set is accepted by the shape verifier.
        assert!(is_safari26_settings(&settings));
        // GREASE is per-connection random: a different seed yields a different id
        // AND value (these two distinct seeds differ in every byte).
        let other = grease_setting_from_seed([0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
        assert_ne!(other.id, settings[2].id);
        assert_ne!(other.value, settings[2].value);
        assert!(is_grease_setting_id(other.id));
    }

    #[test]
    fn settings_frame_byte_layout_matches_safari26() {
        let grease = grease_setting_from_seed([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let frame = safari26_settings_frame(grease).unwrap();
        let (hdr, payload, total) = decode_frame(&frame).unwrap();
        assert_eq!(hdr.frame_type, FRAME_TYPE_SETTINGS);
        assert_eq!(total, frame.len());

        let parsed = parse_settings_payload(payload).unwrap();
        assert!(is_safari26_settings(&parsed));
        assert_eq!(parsed.to_vec(), safari26_settings(grease).to_vec());

        // The two fixed QPACK params are byte-exact and lead the payload: 0x01
        // 0x7fff (16383 as 2-byte varint), then 0x07 0x40 0x64 (100 as 2-byte
        // varint), followed by the per-connection GREASE id/value varints.
        let mut fixed_prefix = Vec::new();
        put_varint(&mut fixed_prefix, SETTINGS_QPACK_MAX_TABLE_CAPACITY);
        put_varint(&mut fixed_prefix, 16383);
        put_varint(&mut fixed_prefix, SETTINGS_QPACK_BLOCKED_STREAMS);
        put_varint(&mut fixed_prefix, 100);
        assert!(payload.starts_with(&fixed_prefix));
        let mut grease_bytes = Vec::new();
        put_varint(&mut grease_bytes, grease.id);
        put_varint(&mut grease_bytes, grease.value);
        assert_eq!(&payload[fixed_prefix.len()..], &grease_bytes[..]);
        // No setting advertises MAX_FIELD_SECTION_SIZE (id 0x06).
        assert!(parsed.iter().all(|s| s.id != 0x06));
    }

    // --- HEADERS: Safari-26 order, incl. the H2 divergence points ---------

    #[test]
    fn headers_field_order_matches_safari26() {
        let fields = safari26_request_fields("example.com");
        let names: Vec<&str> = fields.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                ":method",
                ":scheme",
                ":authority",
                ":path",
                "sec-fetch-dest",
                "user-agent",
                "accept",
                "sec-fetch-site",
                "sec-fetch-mode",
                "accept-language",
                "priority",
                "accept-encoding",
            ],
        );
    }

    #[test]
    fn headers_pseudo_order_matches_h2_main_document() {
        // Main-document pseudo order is :method :scheme :authority :path on BOTH
        // H3 and H2 (authority precedes path) — confirmed against real H3 wire.
        let fields = safari26_request_fields("example.com");
        let authority_pos = fields.iter().position(|(n, _)| n == ":authority").unwrap();
        let path_pos = fields.iter().position(|(n, _)| n == ":path").unwrap();
        assert!(
            authority_pos < path_pos,
            "main-document :authority must precede :path"
        );
    }

    #[test]
    fn headers_regular_order_matches_h2_main_document() {
        // Main-document regular order (H3 == H2): sec-fetch-dest, user-agent,
        // accept, sec-fetch-site, sec-fetch-mode, accept-language, priority,
        // accept-encoding. user-agent precedes priority (the main-document
        // shape), and sec-fetch-dest leads the regular headers.
        let fields = safari26_request_fields("example.com");
        let pos = |name: &str| fields.iter().position(|(n, _)| n == name).unwrap();
        assert!(pos("sec-fetch-dest") < pos("user-agent"));
        assert!(pos("user-agent") < pos("accept"));
        assert!(pos("accept") < pos("priority"));
        assert!(pos("priority") < pos("accept-encoding"));
    }

    #[test]
    fn headers_frame_decodes_to_safari26_fields() {
        let authority = "localhost:8443";
        let frame = safari26_headers_frame(authority).unwrap();
        let (hdr, payload, total) = decode_frame(&frame).unwrap();
        assert_eq!(hdr.frame_type, FRAME_TYPE_HEADERS);
        assert_eq!(total, frame.len());
        let decoded = decode_field_section(payload).unwrap();
        assert_eq!(decoded, safari26_request_fields(authority));
    }

    #[test]
    fn response_status_200_headers_frame_decodes_to_status_200() {
        let frame = response_status_200_headers_frame().unwrap();
        let (hdr, payload, total) = decode_frame(&frame).unwrap();
        assert_eq!(hdr.frame_type, FRAME_TYPE_HEADERS);
        assert_eq!(total, frame.len());
        let decoded = decode_field_section(payload).unwrap();
        assert_eq!(decoded, vec![(":status".to_string(), "200".to_string())]);
    }

    #[test]
    fn headers_reuse_http2_constants() {
        let fields = safari26_request_fields("example.com");
        let ua = &fields[5].1;
        let al = &fields[9].1;
        assert_eq!(ua, SAFARI26_USER_AGENT);
        assert_eq!(al, SAFARI26_ACCEPT_LANGUAGE);
        // accept-language stays English-only, matching the H2 façade.
        assert!(al.starts_with("en-US"));
        assert!(!al.contains("zh"));
    }
}
