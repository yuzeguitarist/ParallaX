//! Lowercase hex encoding shared across the crate.
//!
//! Pure text encoding — these helpers do not touch keys, AEAD state, or any
//! security-sensitive material. They emit the same `0-9a-f` digits that the
//! runtime-guard fingerprint log and the replay-cache journal have always
//! produced, so the on-disk/observable text is byte-for-byte unchanged.

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Append the lowercase hex encoding of `bytes` to `out`.
pub fn push_hex(out: &mut String, bytes: &[u8]) {
    out.reserve(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        out.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
    }
}

/// Return the lowercase hex encoding of `bytes` as a new `String`.
pub fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    push_hex(&mut out, bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_known_vectors() {
        assert_eq!(hex_lower(&[]), "");
        assert_eq!(hex_lower(&[0x00]), "00");
        assert_eq!(hex_lower(&[0xff]), "ff");
        assert_eq!(hex_lower(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_lower(&[0x01, 0x23, 0x45, 0x67, 0x89]), "0123456789");
    }

    #[test]
    fn push_hex_appends_without_clearing() {
        let mut out = String::from("prefix:");
        push_hex(&mut out, &[0xab, 0xcd]);
        assert_eq!(out, "prefix:abcd");
    }
}
