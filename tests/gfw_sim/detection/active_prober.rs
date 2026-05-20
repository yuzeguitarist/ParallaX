//! Active probing module.
//!
//! The GFW augments its passive detectors with an active-probing infrastructure
//! that *initiates* connections to suspect server endpoints to verify whether
//! they speak the expected censorship-circumvention protocol. The technique was
//! first measured by Ensafi et al. (USENIX Security 2015 - *Examining how the
//! Great Firewall discovers hidden circumvention servers*) and refined by
//! Frolov et al. (USENIX FOCI 2020). The leaked Geedge documents (per the
//! InterSecLab analysis) catalog at least seven probe families which are all
//! reproduced here.
//!
//! The simulator does **not** open real network sockets - it provides a
//! `Probe` enum, a builder for each canonical probe, and a `ProbeOutcome`
//! summary so the runtime can score what a real Probe robot would conclude.
//! The integration tests in `tests/gfw_simulator.rs` couple this module to a
//! real `parallax::handshake::server` instance and verify how each probe is
//! handled.

use std::time::Duration;

use rand::{Rng, RngCore};

/// Canonical probe families used by the GFW. Each variant carries its own
/// builder so red-team tests can stamp out fresh probes.
#[derive(Debug, Clone)]
pub enum Probe {
    /// Pure random payload of `len` bytes. Used to test whether the server
    /// closes the connection (real proxies often reset on auth failure but
    /// fingerprintable proxies *respond* with a deterministic banner).
    RandomBytes { bytes: Vec<u8> },
    /// TLS ClientHello with characteristic Tor pluggable-transports fields
    /// (obfs4 / meek / lyrebird). Real GFW reuses these to look for "Tor-style"
    /// fronting endpoints.
    TorPtClientHello { bytes: Vec<u8> },
    /// Replay of a captured ClientHello, often the one from the target's last
    /// honest connection.
    ReplayClientHello { bytes: Vec<u8> },
    /// Empty payload - the prober opens the connection, sends 0 bytes, and
    /// observes server behavior. Real Shadowsocks closes immediately; ParallaX
    /// falls back to camouflage.
    EmptyPayload,
    /// Shadowsocks-style AEAD blob: salt + arbitrary ciphertext.
    ShadowsocksLike { bytes: Vec<u8> },
    /// SSH banner test.
    SshBannerTest,
    /// HTTP `CONNECT` test.
    HttpConnectTest { target_host: String },
}

impl Probe {
    pub fn random_bytes_with_seed(seed: u64, len: usize) -> Self {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let mut bytes = vec![0_u8; len];
        rng.fill_bytes(&mut bytes);
        Probe::RandomBytes { bytes }
    }

    pub fn tor_pt_client_hello() -> Self {
        // A simplified obfs4-style fingerprint: standard TLS record header,
        // TLS 1.2 ClientHello, ALPN containing "obfs4". Real Tor PTs vary but
        // the SNI/ALPN combo is the canonical tell.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x16, 0x03, 0x01]); // record header (no length yet)
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x01]); // ClientHello
        hello.extend_from_slice(&[0x00, 0x00, 0x00]); // length placeholder
        hello.extend_from_slice(&[0x03, 0x03]); // legacy_version
        hello.extend_from_slice(&[0xaa; 32]); // random
        hello.push(0); // session_id_len
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // ciphers: TLS_AES_128_GCM_SHA256
        hello.extend_from_slice(&[0x01, 0x00]); // compression: null

        // SNI extension: "obfs4.example"
        let sni_bytes = b"obfs4.example";
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&[0x00, 0x00]); // ext_type
        sni_ext.extend_from_slice(&((sni_bytes.len() + 5) as u16).to_be_bytes());
        // server_name_list_len
        sni_ext.extend_from_slice(&((sni_bytes.len() + 3) as u16).to_be_bytes());
        sni_ext.push(0); // host_name
        sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(sni_bytes);
        // ALPN ext with "obfs4"
        let alpn = b"obfs4";
        let mut alpn_ext = Vec::new();
        alpn_ext.extend_from_slice(&[0x00, 0x10]); // ext_type
        alpn_ext.extend_from_slice(&((alpn.len() + 3) as u16).to_be_bytes());
        // protocol_name_list_len
        alpn_ext.extend_from_slice(&((alpn.len() + 1) as u16).to_be_bytes());
        alpn_ext.push(alpn.len() as u8);
        alpn_ext.extend_from_slice(alpn);

        let mut exts = Vec::new();
        exts.extend_from_slice(&sni_ext);
        exts.extend_from_slice(&alpn_ext);
        hello.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hello.extend_from_slice(&exts);

        let hs_len = (hello.len() - 4) as u32;
        hello[1] = ((hs_len >> 16) & 0xff) as u8;
        hello[2] = ((hs_len >> 8) & 0xff) as u8;
        hello[3] = (hs_len & 0xff) as u8;

        let rec_len = hello.len() as u16;
        bytes.extend_from_slice(&rec_len.to_be_bytes());
        bytes.extend_from_slice(&hello);
        Probe::TorPtClientHello { bytes }
    }

    pub fn replay(bytes: Vec<u8>) -> Self {
        Probe::ReplayClientHello { bytes }
    }

    pub fn shadowsocks_like<R: RngCore + Rng>(
        rng: &mut R,
        key_size: usize,
        body_size: usize,
    ) -> Self {
        let mut bytes = vec![0_u8; key_size + body_size];
        rng.fill_bytes(&mut bytes);
        Probe::ShadowsocksLike { bytes }
    }

    pub fn ssh_banner_test() -> Self {
        Probe::SshBannerTest
    }

    pub fn http_connect_test(host: impl Into<String>) -> Self {
        Probe::HttpConnectTest {
            target_host: host.into(),
        }
    }

    /// Serialize the probe payload for sending on the wire (or to feed a fake
    /// server in tests). `None` for `EmptyPayload` and `SshBannerTest` (the
    /// prober only opens / inspects but doesn't send).
    pub fn payload(&self) -> Option<&[u8]> {
        match self {
            Probe::RandomBytes { bytes }
            | Probe::TorPtClientHello { bytes }
            | Probe::ReplayClientHello { bytes }
            | Probe::ShadowsocksLike { bytes } => Some(bytes),
            Probe::EmptyPayload | Probe::SshBannerTest | Probe::HttpConnectTest { .. } => None,
        }
    }
}

/// Synthetic record of what the prober observed when it ran a probe against an
/// endpoint. This is the input that the simulator's scoring function consumes.
#[derive(Debug, Clone)]
pub struct ProbeObservation {
    pub probe_label: &'static str,
    /// `true` if the server held the connection open after the probe payload
    /// (or for `EmptyPayload`, after the probe's 5-second idle).
    pub server_held_connection: bool,
    /// `true` if the server replied with at least one application-layer byte.
    pub server_replied_with_bytes: bool,
    /// `true` if those bytes look like a legitimate camouflage response
    /// (e.g. a real TLS ServerHello forwarded from the fallback target). This
    /// captures the "ParallaX fallback to legitimate site" defense.
    pub server_response_looks_legitimate: bool,
    /// `true` if the server immediately RST'd the connection (typical for raw
    /// circumvention proxies that fail auth and have no camouflage).
    pub server_immediately_reset: bool,
    /// Wall-clock delay between probe send and server response (or RST).
    pub delay: Duration,
}

impl ProbeObservation {
    /// Score a single probe observation. Returns a "suspicion score" in
    /// 0.0..=1.0, where 1.0 is "definitely a censorship-circumvention proxy".
    pub fn suspicion_score(&self) -> f64 {
        let mut score: f64 = 0.0;
        // Held open + no bytes back is the classic "Shadowsocks waiting for
        // more input" pattern.
        if self.server_held_connection && !self.server_replied_with_bytes {
            score += 0.55;
        }
        if self.server_replied_with_bytes && !self.server_response_looks_legitimate {
            score += 0.45;
        }
        if self.server_immediately_reset {
            // RST is suspicious for SSH-banner probes (a real SSH server would
            // send a banner) but expected for raw-random probes against an HTTP
            // server. The runtime decides per-probe whether to weight RST.
            score += 0.20;
        }
        if !self.server_held_connection
            && !self.server_replied_with_bytes
            && !self.server_immediately_reset
        {
            score += 0.40;
        }
        if self.delay > Duration::from_secs(10) {
            score += 0.15;
        }
        score.min(1.0)
    }
}

/// Top-level prober. Runs `probes` (in priority order) and aggregates per-probe
/// suspicion scores. The aggregate verdict is decided by a configurable
/// threshold; the default of `0.7` reflects the Geedge documentation's
/// "high-confidence flag" tier.
pub struct ActiveProber {
    pub probes: Vec<Probe>,
    pub flag_threshold: f64,
}

impl Default for ActiveProber {
    fn default() -> Self {
        Self::with_default_probes()
    }
}

impl ActiveProber {
    pub fn with_default_probes() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            probes: vec![
                Probe::random_bytes_with_seed(1, 64),
                Probe::tor_pt_client_hello(),
                Probe::replay(vec![]),
                Probe::EmptyPayload,
                Probe::shadowsocks_like(&mut rng, 32, 96),
                Probe::ssh_banner_test(),
                Probe::http_connect_test("example.com:443"),
            ],
            flag_threshold: 0.7,
        }
    }

    pub fn score_observations(&self, obs: &[ProbeObservation]) -> ProbeAggregate {
        let mut scores: Vec<f64> = obs.iter().map(|o| o.suspicion_score()).collect();
        scores.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
        let max = scores.first().copied().unwrap_or(0.0);
        // Geedge documentation describes ensemble voting: top-2 must agree for
        // a "Sure" classification. We approximate by averaging the top two.
        let top2 = if scores.len() >= 2 {
            (scores[0] + scores[1]) / 2.0
        } else {
            max
        };
        // Consistency rule: if 3+ probes all individually look proxy-like
        // (score >= the "suspicious" floor 0.45), confirm even if the
        // strongest pair did not reach `flag_threshold` on its own. This
        // reflects the Geedge "ensemble vote" model where ≥3 of N probes
        // agreeing is treated as a positive classification.
        let suspicious_floor = 0.45;
        let agreeing = scores.iter().filter(|&&s| s >= suspicious_floor).count();
        let verdict = if top2 >= self.flag_threshold
            || (scores.len() >= 3 && agreeing >= 3 && top2 >= suspicious_floor)
        {
            ProbeAggregateVerdict::ConfirmedProxy
        } else if max >= self.flag_threshold || agreeing >= 1 {
            ProbeAggregateVerdict::Suspicious
        } else {
            ProbeAggregateVerdict::Inconclusive
        };
        ProbeAggregate {
            max_score: max,
            top_two_avg: top2,
            per_probe: scores,
            verdict,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProbeAggregateVerdict {
    ConfirmedProxy,
    Suspicious,
    Inconclusive,
}

#[derive(Debug, Clone)]
pub struct ProbeAggregate {
    pub max_score: f64,
    pub top_two_avg: f64,
    pub per_probe: Vec<f64>,
    pub verdict: ProbeAggregateVerdict,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(
        label: &'static str,
        held: bool,
        bytes: bool,
        looks_legit: bool,
        rst: bool,
    ) -> ProbeObservation {
        ProbeObservation {
            probe_label: label,
            server_held_connection: held,
            server_replied_with_bytes: bytes,
            server_response_looks_legitimate: looks_legit,
            server_immediately_reset: rst,
            delay: Duration::from_millis(50),
        }
    }

    #[test]
    fn tor_pt_probe_emits_valid_tls_record() {
        let p = Probe::tor_pt_client_hello();
        let payload = p.payload().unwrap();
        // Starts with TLS record header.
        assert_eq!(payload[0], 0x16);
        // Contains the "obfs4" ALPN substring.
        assert!(payload.windows(5).any(|w| w == b"obfs4"));
    }

    #[test]
    fn camouflage_response_is_not_suspicious() {
        // ParallaX fallback to a legitimate site: server replies with real
        // ServerHello bytes after the probe. Should score low.
        let o = obs("tor-pt", false, true, true, false);
        assert!(o.suspicion_score() < 0.3);
    }

    #[test]
    fn idle_proxy_is_highly_suspicious() {
        // Classic Shadowsocks: server holds the connection without responding.
        let o = obs("random-bytes", true, false, false, false);
        assert!(o.suspicion_score() > 0.5);
    }

    #[test]
    fn aggregate_classifies_confirmed_proxy_on_consistent_high_scores() {
        let prober = ActiveProber::default();
        let observations = vec![
            obs("random-bytes", true, false, false, false),
            obs("tor-pt", true, false, false, false),
            obs("replay", false, true, false, false),
        ];
        let agg = prober.score_observations(&observations);
        assert_eq!(agg.verdict, ProbeAggregateVerdict::ConfirmedProxy);
    }

    #[test]
    fn aggregate_inconclusive_when_all_legitimate() {
        let prober = ActiveProber::default();
        let observations = vec![
            obs("random-bytes", false, true, true, false),
            obs("tor-pt", false, true, true, false),
            obs("replay", false, true, true, false),
        ];
        let agg = prober.score_observations(&observations);
        assert_eq!(agg.verdict, ProbeAggregateVerdict::Inconclusive);
    }
}
