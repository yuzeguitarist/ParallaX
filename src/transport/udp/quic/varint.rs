//! QUIC variable-length integer codec (RFC 9000 §16).
//!
//! The two most-significant bits of the first byte select a 1/2/4/8-byte
//! big-endian encoding; the remaining 62 bits carry the value, so the maximum
//! representable integer is `2^62 - 1`. ParallaX's pre-existing Safari transport-
//! parameter encoder uses this identical construction; this is the one shared
//! primitive the hand-written packet / frame / transport-parameter codecs all
//! build on.

/// Largest value a QUIC varint can represent: `2^62 - 1` (RFC 9000 §16).
pub const MAX: u64 = (1 << 62) - 1;

/// Encoded length in bytes of `value` (1, 2, 4, or 8 per the §16 size classes).
///
/// Debug-asserts `value <= MAX`; an over-large value cannot be represented and
/// would silently truncate.
pub fn size(value: u64) -> usize {
    debug_assert!(value <= MAX, "varint value {value:#x} exceeds 2^62-1");
    if value < 0x40 {
        1
    } else if value < 0x4000 {
        2
    } else if value < 0x4000_0000 {
        4
    } else {
        8
    }
}

/// Append the minimal QUIC-varint encoding of `value` to `out` (RFC 9000 §16).
///
/// Debug-asserts `value <= MAX`.
pub fn encode(value: u64, out: &mut Vec<u8>) {
    debug_assert!(value <= MAX, "varint value {value:#x} exceeds 2^62-1");
    if value < 0x40 {
        out.push(value as u8);
    } else if value < 0x4000 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 0x4000_0000 {
        out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/// Decode one QUIC varint from the front of `buf`, returning `(value, len)` where
/// `len` is the number of bytes consumed.
///
/// Returns `None` if `buf` is empty or shorter than the length its prefix
/// announces. Non-minimal encodings (e.g. a 2-byte encoding of a value that would
/// fit in 1) are accepted: RFC 9000 §16 requires the decoder to treat them as
/// equivalent rather than reject them.
pub fn decode(buf: &[u8]) -> Option<(u64, usize)> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The four worked examples from RFC 9000 §16 (the decoder MUST reproduce
    /// each, including the non-minimal `0x4025` form of 37).
    #[test]
    fn decode_matches_rfc9000_section16_examples() {
        assert_eq!(
            decode(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]),
            Some((151_288_809_941_952_652, 8))
        );
        assert_eq!(decode(&[0x9d, 0x7f, 0x3e, 0x7d]), Some((494_878_333, 4)));
        assert_eq!(decode(&[0x7b, 0xbd]), Some((15_293, 2)));
        assert_eq!(decode(&[0x25]), Some((37, 1)));
        // Non-minimal 2-byte encoding of 37 — MUST decode to the same value.
        assert_eq!(decode(&[0x40, 0x25]), Some((37, 2)));
    }

    #[test]
    fn encode_is_minimal_and_round_trips_across_size_classes() {
        // (value, expected encoded length) — boundaries of each size class.
        let cases = [
            (0u64, 1usize),
            (0x3f, 1),
            (0x40, 2),
            (0x3fff, 2),
            (0x4000, 4),
            (0x3fff_ffff, 4),
            (0x4000_0000, 8),
            (MAX, 8),
        ];
        for (v, expected_len) in cases {
            assert_eq!(size(v), expected_len, "size mismatch for {v:#x}");
            let mut buf = Vec::new();
            encode(v, &mut buf);
            assert_eq!(
                buf.len(),
                expected_len,
                "encoded length mismatch for {v:#x}"
            );
            assert_eq!(
                decode(&buf),
                Some((v, expected_len)),
                "round-trip for {v:#x}"
            );
        }
    }

    #[test]
    fn decode_rejects_empty_and_truncated() {
        assert_eq!(decode(&[]), None);
        // First byte announces an 8-byte encoding but only 1 byte is present.
        assert_eq!(decode(&[0xc2]), None);
        // 4-byte prefix, 3 bytes present.
        assert_eq!(decode(&[0x9d, 0x7f, 0x3e]), None);
    }

    #[test]
    fn decode_reports_exact_consumed_length() {
        // Trailing bytes after a complete varint are left for the caller.
        let mut buf = Vec::new();
        encode(0x3fff, &mut buf);
        buf.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(decode(&buf), Some((0x3fff, 2)));
    }
}
