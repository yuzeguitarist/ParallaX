//! USENIX'23 first-packet "fully-encrypted traffic" heuristic.
//!
//! This module reproduces Algorithm 1 from Wu et al., *How the Great Firewall of
//! China Detects and Blocks Fully Encrypted Traffic*, USENIX Security 2023.
//!
//! Algorithm summary
//! -----------------
//! For each new TCP flow, the GFW captures the *first* TCP payload (`pkt`) and
//! applies five exemption rules; if **all** of them fail (i.e. the packet doesn't
//! look like any benign protocol), the flow is treated as "fully encrypted
//! traffic" and blocked with probability `p ≈ 0.263`.
//!
//! After a block, a *residual* rule kicks in: any new TCP flow with the same
//! (client IP, server IP, server port) 3-tuple is blocked unconditionally for
//! 180 s. The residual rule is implemented in [`super::super::injection`].
//!
//! Exemption rules
//! ---------------
//!  - **Ex1** — popcount(pkt) / len(pkt) ≤ 3.4 *or* ≥ 4.6 bits/byte
//!  - **Ex2** — at least the first 6 bytes are printable ASCII (0x20..=0x7e)
//!  - **Ex3** — more than 50 % of bytes are printable ASCII
//!  - **Ex4** — there exists a run of more than 20 contiguous printable ASCII
//!  - **Ex5** — the first bytes match a well-known protocol fingerprint
//!    (TLS / HTTP / SSH / SMTP / FTP / BitTorrent / QUIC long header / …)
//!
//! The block-probability sampling is exposed both as a deterministic call (for
//! tests; pass a seeded RNG) and as an info-only verdict so consumers can decide
//! how to apply it.

use super::super::data::{
    ascii_tables::{bit_density, leading_printable_run, longest_printable_run, printable_fraction},
    observed_protocols::classify_first_packet,
};

/// Block probability inferred from Wu et al.'s 10 % IPv4 scan (Table 7):
/// 109,489 affected IPs out of an estimated 416,231 IPs in the censor's pool.
pub const BLOCK_PROBABILITY: f64 = 0.263;

/// Lower / upper bounds for the bit-density exemption.
pub const POPCOUNT_LOWER: f64 = 3.4;
pub const POPCOUNT_UPPER: f64 = 4.6;

/// Minimum printable-ASCII *prefix* length for Ex2.
pub const PRINTABLE_PREFIX_THRESHOLD: usize = 6;

/// Fraction of printable ASCII bytes that triggers Ex3 (strictly greater than).
pub const PRINTABLE_FRACTION_THRESHOLD: f64 = 0.5;

/// Longest contiguous printable run that triggers Ex4 (strictly greater than).
pub const PRINTABLE_RUN_THRESHOLD: usize = 20;

/// Computed signals for a single first-packet sample. The `is_exempt` flag
/// records why a packet was excused from the random-block check.
#[derive(Debug, Clone, PartialEq)]
pub struct FullyEncryptedSignals {
    pub len: usize,
    pub bit_density: f64,
    pub printable_fraction: f64,
    pub leading_printable_run: usize,
    pub longest_printable_run: usize,
    pub protocol_match: Option<&'static str>,
    pub triggered_exemptions: Vec<Exemption>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exemption {
    Ex1PopcountOutOfBand,
    Ex2PrintablePrefix,
    Ex3PrintableMajority,
    Ex4LongPrintableRun,
    Ex5ProtocolFingerprint,
}

impl FullyEncryptedSignals {
    pub fn is_exempt(&self) -> bool {
        !self.triggered_exemptions.is_empty()
    }
}

/// Outcome of a single first-packet evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum FullyEncryptedVerdict {
    /// Packet matched at least one exemption rule. Forwarded unchanged.
    Exempt { signals: FullyEncryptedSignals },
    /// Packet failed all exemptions and is treated as a candidate for blocking.
    /// `block_sampled` reflects whether the configured RNG decided to block this
    /// particular flow on the first pass (the 26.3 % sampling). Even if
    /// `block_sampled == false`, the 3-tuple should be retained because a second
    /// connection from the same triplet would be sampled independently.
    CandidateForBlock {
        signals: FullyEncryptedSignals,
        block_sampled: bool,
    },
}

impl FullyEncryptedVerdict {
    pub fn signals(&self) -> &FullyEncryptedSignals {
        match self {
            FullyEncryptedVerdict::Exempt { signals }
            | FullyEncryptedVerdict::CandidateForBlock { signals, .. } => signals,
        }
    }

    pub fn is_blocking_decision(&self) -> bool {
        matches!(
            self,
            FullyEncryptedVerdict::CandidateForBlock {
                block_sampled: true,
                ..
            }
        )
    }
}

/// Compute the raw signals (no block-probability sampling).
pub fn analyze(bytes: &[u8]) -> FullyEncryptedSignals {
    let mut triggered = Vec::new();
    let density = bit_density(bytes);
    if !bytes.is_empty() && (density <= POPCOUNT_LOWER || density >= POPCOUNT_UPPER) {
        triggered.push(Exemption::Ex1PopcountOutOfBand);
    }
    let lead = leading_printable_run(bytes);
    if lead >= PRINTABLE_PREFIX_THRESHOLD {
        triggered.push(Exemption::Ex2PrintablePrefix);
    }
    let frac = printable_fraction(bytes);
    if frac > PRINTABLE_FRACTION_THRESHOLD {
        triggered.push(Exemption::Ex3PrintableMajority);
    }
    let longest = longest_printable_run(bytes);
    if longest > PRINTABLE_RUN_THRESHOLD {
        triggered.push(Exemption::Ex4LongPrintableRun);
    }
    let proto = classify_first_packet(bytes);
    if proto.is_some() {
        triggered.push(Exemption::Ex5ProtocolFingerprint);
    }
    FullyEncryptedSignals {
        len: bytes.len(),
        bit_density: density,
        printable_fraction: frac,
        leading_printable_run: lead,
        longest_printable_run: longest,
        protocol_match: proto,
        triggered_exemptions: triggered,
    }
}

/// Full evaluation, including the 26.3 % block sampling for non-exempt packets.
pub fn evaluate<R: rand::Rng>(bytes: &[u8], rng: &mut R) -> FullyEncryptedVerdict {
    let signals = analyze(bytes);
    if signals.is_exempt() {
        FullyEncryptedVerdict::Exempt { signals }
    } else {
        let block_sampled = rng.r#gen::<f64>() < BLOCK_PROBABILITY;
        FullyEncryptedVerdict::CandidateForBlock {
            signals,
            block_sampled,
        }
    }
}

/// Deterministic evaluation that forces the sampling outcome. Used by tests so
/// the suite isn't randomized on whether the "26.3 %" gate fires.
pub fn evaluate_deterministic(bytes: &[u8], force_block: bool) -> FullyEncryptedVerdict {
    let signals = analyze(bytes);
    if signals.is_exempt() {
        FullyEncryptedVerdict::Exempt { signals }
    } else {
        FullyEncryptedVerdict::CandidateForBlock {
            signals,
            block_sampled: force_block,
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;

    #[test]
    fn random_bytes_fail_all_exemptions() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let mut buf = [0_u8; 64];
        // Sample until we find a buffer that fails all five exemptions. With a
        // random Rng this happens on the first sample with overwhelming
        // probability; we just guard the test.
        loop {
            rand::RngCore::fill_bytes(&mut rng, &mut buf);
            let signals = analyze(&buf);
            if !signals.is_exempt() {
                break;
            }
        }
        let signals = analyze(&buf);
        assert!(!signals.is_exempt(), "random bytes should not be exempt");
    }

    #[test]
    fn tls_clienthello_triggers_ex5() {
        let bytes = [0x16, 0x03, 0x01, 0x06, 0xd2, 0x01, 0x00, 0x06, 0xce];
        let signals = analyze(&bytes);
        assert!(signals.is_exempt());
        assert!(signals
            .triggered_exemptions
            .contains(&Exemption::Ex5ProtocolFingerprint));
        assert_eq!(signals.protocol_match, Some("TLS"));
    }

    #[test]
    fn http_request_triggers_ex2_and_ex5() {
        let bytes = b"GET /index HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let signals = analyze(bytes);
        assert!(signals
            .triggered_exemptions
            .contains(&Exemption::Ex2PrintablePrefix));
        assert!(signals
            .triggered_exemptions
            .contains(&Exemption::Ex5ProtocolFingerprint));
    }

    #[test]
    fn all_zero_payload_triggers_ex1() {
        let bytes = [0_u8; 64];
        let signals = analyze(&bytes);
        assert!(signals
            .triggered_exemptions
            .contains(&Exemption::Ex1PopcountOutOfBand));
    }

    #[test]
    fn all_ones_payload_triggers_ex1() {
        let bytes = [0xff_u8; 64];
        let signals = analyze(&bytes);
        assert!(signals
            .triggered_exemptions
            .contains(&Exemption::Ex1PopcountOutOfBand));
    }

    #[test]
    fn long_printable_run_buried_in_random_bytes_triggers_ex4() {
        // 30-byte printable run, but mixed into random tails, so:
        //   * Ex1: bit density should be in [3.4, 4.6] (avoid Ex1)
        //   * Ex2: leading bytes are random (avoid Ex2)
        //   * Ex3: <50% printable (avoid Ex3)
        //   * Ex4: 30 contiguous printable bytes -> trigger
        let mut buf = vec![0xa5_u8; 128];
        buf[40..70].copy_from_slice(b"abcdefghijklmnopqrstuvwxyzABCD");
        let signals = analyze(&buf);
        assert!(signals
            .triggered_exemptions
            .contains(&Exemption::Ex4LongPrintableRun));
    }

    #[test]
    fn deterministic_eval_respects_force_block() {
        let bytes = [0x9a_u8; 32]; // bit density 4.0, not printable, no proto
        let blocked = evaluate_deterministic(&bytes, true);
        let allowed = evaluate_deterministic(&bytes, false);
        assert!(blocked.is_blocking_decision());
        assert!(!allowed.is_blocking_decision());
    }
}
