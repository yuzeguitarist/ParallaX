//! Passive traffic-analysis heuristics run by the GFW box over relayed flows.
//!
//! Design intent: emulate the *cheap, deployable* classifiers a national
//! middle-box actually runs at line rate, and check whether a ParallaX flow
//! trips any of them. Because ParallaX's TCP transport is camouflaged as a
//! genuine TLS 1.3 session to a real CDN, a correct flow should look like
//! ordinary HTTPS and trip NONE of the "this is an obfuscated proxy" flags.
//!
//! Heuristics implemented (all from public literature):
//!   * H1 first flight is not a well-formed TLS record (structural).
//!   * H2 "fully encrypted" first-packet test (Frolov & Wustrow, USENIX'23):
//!     a packet is classified as fully-encrypted/obfuscated iff NONE of the
//!     exemptions hold — Ex1 popcount outside [3.4, 4.6], Ex2 first 6 bytes all
//!     printable, Ex3 >50% printable, Ex4 a printable run > 20, Ex5 a known
//!     protocol (here: a valid TLS record). ParallaX's TLS camouflage means the
//!     first flight is a real ClientHello, so Ex5 exempts it.
//!   * H3 ClientHello lacks SNI or lacks h2/h3 ALPN (a real browser to a CDN
//!     always sends both) — weak signal, informational only.

use crate::report::{FlowFeatures, FlowVerdict};
use crate::stats;
use crate::tls;

/// Raw per-flow observation accumulated by the relay.
pub struct FlowObservation {
    pub flow_id: u64,
    pub client_addr: String,
    pub duration_ms: f64,
    pub bytes_c2s: u64,
    pub bytes_s2c: u64,
    pub seg_sizes: Vec<f64>,
    pub segments_c2s: usize,
    pub segments_s2c: usize,
    pub c2s_gaps_ms: Vec<f64>,
    pub first_flight: Vec<u8>,
}

/// The Frolov-Wustrow popcount band: a random payload centres on 4.0 set
/// bits/byte. Values inside (3.4, 4.6) look "high entropy / random".
const POPCOUNT_LOW: f64 = 3.4;
const POPCOUNT_HIGH: f64 = 4.6;

pub fn analyze_flow(obs: &FlowObservation) -> FlowFeatures {
    let ch = tls::inspect_client_hello(&obs.first_flight);

    let bits_per_byte = stats::shannon_bits_per_byte(&obs.first_flight);
    let popcount = stats::mean_popcount_per_byte(&obs.first_flight);
    let printable = stats::printable_ascii_fraction(&obs.first_flight);
    let longest_run = stats::longest_printable_run(&obs.first_flight);
    let first6_printable = obs.first_flight.len() >= 6
        && obs.first_flight[..6]
            .iter()
            .all(|&b| (0x20..=0x7e).contains(&b));

    let mut flags = Vec::new();

    // H2: the exact "fully encrypted" classifier (Frolov & Wustrow, USENIX'23).
    // A packet is blocked as fully-encrypted iff NONE of the five exemptions
    // hold. Each exemption is a reason the payload looks like a *known* or
    // structured protocol rather than a random/obfuscated stream.
    let ex1_popcount_outside = !(POPCOUNT_LOW..=POPCOUNT_HIGH).contains(&popcount);
    let ex2_first6_printable = first6_printable;
    let ex3_mostly_printable = printable > 0.5;
    let ex4_long_printable_run = longest_run > 20;
    let ex5_known_protocol = ch.is_tls_record; // real ClientHello == known proto
    let exempt = ex1_popcount_outside
        || ex2_first6_printable
        || ex3_mostly_printable
        || ex4_long_printable_run
        || ex5_known_protocol;
    let looks_fully_encrypted = obs.first_flight.len() >= 6 && !exempt;
    if looks_fully_encrypted {
        flags.push("fully_encrypted_first_packet".to_string());
    }

    // H1: structural — is it even a TLS record / ClientHello?
    if !ch.is_tls_record {
        flags.push("first_flight_not_tls_record".to_string());
    } else if !ch.is_client_hello {
        flags.push("tls_record_but_not_client_hello".to_string());
    }

    // H3: informational browser-shape checks (do NOT by themselves block).
    if ch.is_client_hello && ch.sni.is_none() {
        flags.push("client_hello_without_sni".to_string());
    }
    if ch.is_client_hello && !ch.alpn.is_empty() && !ch.alpn.iter().any(|a| a == "h2" || a == "h3")
    {
        flags.push("client_hello_without_h2_h3_alpn".to_string());
    }

    // A middle-box blocks when the flow looks like an obfuscated/fully-encrypted
    // tunnel: either it is not TLS at all, or it passes the fully-encrypted
    // test. Missing-SNI/ALPN alone are treated as informational (real clients
    // occasionally omit them), so they do not set `flagged_as_proxy`.
    let flagged_as_proxy = looks_fully_encrypted || !ch.is_tls_record;

    let rationale = if flagged_as_proxy {
        format!(
            "middle-box would flag: tls_record={} fully_encrypted={} (popcount={:.2}, printable={:.2}, run={})",
            ch.is_tls_record, looks_fully_encrypted, popcount, printable, longest_run
        )
    } else {
        format!(
            "looks like genuine TLS to {}: alpn={:?}",
            ch.sni.as_deref().unwrap_or("<none>"),
            ch.alpn
        )
    };

    FlowFeatures {
        flow_id: obs.flow_id,
        client_addr: obs.client_addr.clone(),
        duration_ms: obs.duration_ms,
        bytes_c2s: obs.bytes_c2s,
        bytes_s2c: obs.bytes_s2c,
        down_up_ratio: if obs.bytes_c2s == 0 {
            0.0
        } else {
            obs.bytes_s2c as f64 / obs.bytes_c2s as f64
        },
        segments_c2s: obs.segments_c2s,
        segments_s2c: obs.segments_s2c,
        segment_size: stats::Summary::of(&obs.seg_sizes),
        c2s_interarrival_ms: stats::Summary::of(&obs.c2s_gaps_ms),
        first_flight_len: obs.first_flight.len(),
        first_flight_bits_per_byte: bits_per_byte,
        first_flight_popcount_per_byte: popcount,
        first_flight_printable_fraction: printable,
        first_flight_longest_printable_run: longest_run,
        client_hello: ch,
        verdict: FlowVerdict {
            flags,
            flagged_as_proxy,
            rationale,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs_with(first: Vec<u8>) -> FlowObservation {
        FlowObservation {
            flow_id: 1,
            client_addr: "127.0.0.1:1".into(),
            duration_ms: 1.0,
            bytes_c2s: first.len() as u64,
            bytes_s2c: 0,
            seg_sizes: vec![first.len() as f64],
            segments_c2s: 1,
            segments_s2c: 0,
            c2s_gaps_ms: vec![],
            first_flight: first,
        }
    }

    #[test]
    fn random_first_packet_is_flagged_fully_encrypted() {
        // A pseudo-random 512-byte payload: popcount ~4.0, low printable.
        let mut data = Vec::new();
        let mut x: u32 = 0x1234_5678;
        for _ in 0..512 {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.push((x >> 24) as u8);
        }
        let f = analyze_flow(&obs_with(data));
        assert!(f.verdict.flagged_as_proxy, "random payload must be flagged");
        assert!(f
            .verdict
            .flags
            .contains(&"fully_encrypted_first_packet".to_string()));
    }

    #[test]
    fn plaintext_http_is_not_fully_encrypted_but_not_tls() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let f = analyze_flow(&obs_with(data));
        // Not a TLS record -> flagged, but NOT via the entropy test.
        assert!(f.verdict.flagged_as_proxy);
        assert!(f
            .verdict
            .flags
            .contains(&"first_flight_not_tls_record".to_string()));
        assert!(!f
            .verdict
            .flags
            .contains(&"fully_encrypted_first_packet".to_string()));
    }
}
