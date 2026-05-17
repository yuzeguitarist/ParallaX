//! ASCII printability + popcount tables used by the USENIX'23 first-packet heuristic.
//!
//! See [Wu et al., USENIX Security 2023, *How the Great Firewall of China Detects and
//! Blocks Fully Encrypted Traffic*][paper], §4 / Algorithm 1.
//!
//! [paper]: https://www.usenix.org/system/files/usenixsecurity23-wu-mingshi.pdf

/// Returns `true` if the byte is a printable ASCII character in the range 0x20..=0x7e.
///
/// This matches Wu et al.'s definition of "printable ASCII" used in exemption rules
/// Ex2, Ex3 and Ex4. The DEL character (0x7f) is *not* considered printable.
#[inline]
pub fn is_printable_ascii(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte)
}

/// Number of bits set in `byte` (Hamming weight / population count).
#[inline]
pub fn popcount(byte: u8) -> u32 {
    byte.count_ones()
}

/// Sum of `popcount` over a buffer, the numerator of the bit-density metric in Ex1.
pub fn popcount_sum(bytes: &[u8]) -> u32 {
    bytes.iter().map(|byte| byte.count_ones()).sum()
}

/// Bit density (set bits / byte) over `bytes`. Returns 0.0 for empty input.
///
/// Wu et al. report that uniformly random bytes have a bit density very tightly
/// clustered around 4.0 ± 0.05 (the binomial mean), while ASCII / structured
/// traffic skews much further from 4.0. The GFW's Ex1 rule exempts traffic
/// whose bit density falls *outside* the open interval (3.4, 4.6).
pub fn bit_density(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let total = popcount_sum(bytes) as f64;
    total / bytes.len() as f64
}

/// Fraction of bytes in `bytes` that are printable ASCII.
pub fn printable_fraction(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let count = bytes
        .iter()
        .filter(|byte| is_printable_ascii(**byte))
        .count();
    count as f64 / bytes.len() as f64
}

/// Length of the longest run of consecutive printable-ASCII bytes anywhere in `bytes`.
pub fn longest_printable_run(bytes: &[u8]) -> usize {
    let mut longest = 0;
    let mut current = 0;
    for byte in bytes {
        if is_printable_ascii(*byte) {
            current += 1;
            if current > longest {
                longest = current;
            }
        } else {
            current = 0;
        }
    }
    longest
}

/// Length of the leading run of consecutive printable-ASCII bytes at the start of
/// `bytes`. The USENIX'23 paper triggers Ex2 when this run is at least 6.
pub fn leading_printable_run(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .take_while(|byte| is_printable_ascii(**byte))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printable_classification_matches_usenix_definition() {
        assert!(is_printable_ascii(b' '));
        assert!(is_printable_ascii(b'A'));
        assert!(is_printable_ascii(b'~'));
        assert!(!is_printable_ascii(b'\x1f'));
        assert!(!is_printable_ascii(b'\x7f'));
        assert!(!is_printable_ascii(b'\x80'));
    }

    #[test]
    fn bit_density_matches_hand_computed() {
        let buf = [0xff_u8; 8];
        assert!((bit_density(&buf) - 8.0).abs() < f64::EPSILON);
        let buf = [0x00_u8; 8];
        assert!(bit_density(&buf).abs() < f64::EPSILON);
        let buf = [0x55_u8; 8]; // alternating bits -> 4.0
        assert!((bit_density(&buf) - 4.0).abs() < f64::EPSILON);
    }

    #[test]
    fn longest_run_is_a_real_run() {
        // 7 printable then 1 non-printable then 3 printable.
        let buf = b"abcdef \x00xyz";
        assert_eq!(longest_printable_run(buf), 7);
        assert_eq!(leading_printable_run(buf), 7);
    }

    #[test]
    fn leading_run_handles_non_printable_prefix() {
        let buf = b"\x16\x03\x01abcdef";
        assert_eq!(leading_printable_run(buf), 0);
        assert_eq!(longest_printable_run(buf), 6);
    }
}
