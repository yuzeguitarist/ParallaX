//! DNS injection subsystem.
//!
//! Models the GFW's DNS keyword filter, which observes UDP/53 queries inline at
//! the border, matches each requested name against an internal keyword list,
//! and (on match) races the legitimate resolver with a forged A/AAAA response
//! pointing at a sinkhole address. See:
//!
//! - Anonymous, *Towards a Comprehensive Picture of the GFW's DNS Censorship*,
//!   FOCI 2014.
//! - Hoang et al., *Measuring the Deployment of DNS Manipulation*, IMC 2021.
//! - InterSecLab, *The Internet Coup* (2025), §"DNS-layer enforcement".
//!
//! The real GFW issues several different response patterns; this simulator
//! models the common A-record sinkhole, the three-injector race observed in
//! Triplet Censors measurements, and a newer "drop" mode.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::super::data::sni_blocklist::DnsKeywordBlocklist;

// ---------------------- DNS qtype constants ----------------------

pub const QTYPE_A: u16 = 1;
pub const QTYPE_AAAA: u16 = 28;
pub const QTYPE_OPT: u16 = 41;
pub const QTYPE_SVCB: u16 = 64;
pub const QTYPE_HTTPS: u16 = 65;

/// DNS RCODE for "name does not exist" (NXDOMAIN), returned by the response-
/// rewriting path when a name matches the blocklist.
pub const RCODE_NXDOMAIN: u16 = 3;

// ---------------------- Domain matcher (exact + suffix) ----------------------

/// How a domain entry was classified in the blocklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainMatchKind {
    /// Matched a full-name exact rule (`DOMAIN`).
    Exact,
    /// Matched a parent-suffix rule (`DOMAIN-SUFFIX`).
    Suffix,
}

/// A matched domain rule: the pattern that fired and how it matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainMatch {
    pub pattern: String,
    pub kind: DomainMatchKind,
}

/// Domain blocklist supporting exact (`DOMAIN`) and label-anchored suffix
/// (`DOMAIN-SUFFIX`) matching. Suffix rules are indexed by reversed label list
/// so a name only matches at a label boundary, never mid-label (which a plain
/// substring matcher would wrongly accept).
#[derive(Debug, Clone, Default)]
pub struct DnsDomainBlocklist {
    exact: HashMap<String, String>,
    suffix: SuffixTrie,
}

impl DnsDomainBlocklist {
    /// Build from rules. A `*.` prefix or a bare parent label is treated as a
    /// `DOMAIN-SUFFIX`; anything else is an exact `DOMAIN`.
    pub fn from_rules<I, S>(rules: I) -> Self
    where
        I: IntoIterator<Item = (S, DomainMatchKind)>,
        S: AsRef<str>,
    {
        let mut exact = HashMap::new();
        let mut suffix = SuffixTrie::default();
        for (rule, kind) in rules {
            let raw = rule
                .as_ref()
                .trim()
                .trim_start_matches("*.")
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if raw.is_empty() {
                continue;
            }
            match kind {
                DomainMatchKind::Exact => {
                    exact.insert(raw.clone(), raw);
                }
                DomainMatchKind::Suffix => suffix.insert(&raw),
            }
        }
        Self { exact, suffix }
    }

    /// Returns the matched rule (if any) for `name`.
    pub fn matched(&self, name: &str) -> Option<DomainMatch> {
        let needle = name.trim().trim_end_matches('.').to_ascii_lowercase();
        if needle.is_empty() {
            return None;
        }
        if let Some(pattern) = self.exact.get(&needle) {
            return Some(DomainMatch {
                pattern: pattern.clone(),
                kind: DomainMatchKind::Exact,
            });
        }
        self.suffix.matched(&needle).map(|pattern| DomainMatch {
            pattern: format!("*.{pattern}"),
            kind: DomainMatchKind::Suffix,
        })
    }
}

/// Reversed-label trie for suffix matching. Each inserted suffix is stored as a
/// reversed label chain terminating in a node flagged as a rule.
#[derive(Debug, Clone, Default)]
struct SuffixTrie {
    root: TrieNode,
}

#[derive(Debug, Clone, Default)]
struct TrieNode {
    children: HashMap<String, TrieNode>,
    /// Full suffix pattern stored at a terminal node (for reporting).
    terminal: Option<String>,
}

impl SuffixTrie {
    fn insert(&mut self, suffix: &str) {
        let mut node = &mut self.root;
        for label in suffix.split('.').rev() {
            node = node.children.entry(label.to_owned()).or_default();
        }
        node.terminal = Some(suffix.to_owned());
    }

    /// Return the matched suffix pattern if `name` ends at a rule boundary.
    fn matched(&self, name: &str) -> Option<String> {
        let mut node = &self.root;
        let mut best: Option<String> = None;
        for label in name.split('.').rev() {
            match node.children.get(label) {
                Some(child) => {
                    node = child;
                    if let Some(t) = &node.terminal {
                        best = Some(t.clone());
                    }
                }
                None => break,
            }
        }
        best
    }
}

/// Default sinkhole A-record that the GFW historically returned when injecting
/// fake responses. These IPs have been documented many times in the academic
/// literature - see the FOCI 2014 paper and the GFW Report DNS injection corpus.
pub const SINKHOLE_A_RECORDS: &[[u8; 4]] = &[
    [4, 36, 66, 178],
    [8, 7, 198, 45],
    [37, 61, 54, 158],
    [46, 82, 174, 68],
    [59, 24, 3, 173],
    [78, 16, 49, 15],
    [93, 46, 8, 89],
    [128, 121, 126, 139],
    [159, 106, 121, 75],
    [203, 98, 7, 65],
];

/// Single parsed DNS question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// A decoded DNS query (we only care about questions; the answer section is empty
/// for queries).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub transaction_id: u16,
    pub flags: u16,
    pub questions: Vec<DnsQuestion>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DnsParseError {
    #[error("DNS packet shorter than 12-byte header")]
    TooShort,
    #[error("only standard queries are supported (qr/opcode mismatch)")]
    NotAQuery,
    #[error("question section ran off the end of the packet")]
    QuestionTruncated,
    #[error("compressed name labels are not supported in DNS questions")]
    CompressedQuestion,
    #[error("name label exceeds 63 bytes")]
    OverlongLabel,
    #[error("invalid UTF-8 in name label")]
    Utf8(#[from] std::str::Utf8Error),
}

/// Parse a DNS query (request) packet per RFC 1035 §4.1. Only the question
/// section is required; the answer / authority / additional sections are
/// ignored (queries SHOULD have those at 0 but middleboxes have to be lenient).
pub fn parse_query(bytes: &[u8]) -> Result<DnsQuery, DnsParseError> {
    if bytes.len() < 12 {
        return Err(DnsParseError::TooShort);
    }
    let transaction_id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    // QR bit (bit 15) must be 0 for a query, opcode (bits 11-14) must be 0 for
    // standard query.
    if flags & 0x8000 != 0 {
        return Err(DnsParseError::NotAQuery);
    }
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let mut cur = 12;
    let mut questions = Vec::with_capacity(qdcount);
    for _ in 0..qdcount {
        let (name, after) = read_name(bytes, cur)?;
        if after + 4 > bytes.len() {
            return Err(DnsParseError::QuestionTruncated);
        }
        let qtype = u16::from_be_bytes([bytes[after], bytes[after + 1]]);
        let qclass = u16::from_be_bytes([bytes[after + 2], bytes[after + 3]]);
        questions.push(DnsQuestion {
            name,
            qtype,
            qclass,
        });
        cur = after + 4;
    }
    Ok(DnsQuery {
        transaction_id,
        flags,
        questions,
    })
}

fn read_name(bytes: &[u8], start: usize) -> Result<(String, usize), DnsParseError> {
    let mut labels: Vec<String> = Vec::new();
    let mut cur = start;
    loop {
        if cur >= bytes.len() {
            return Err(DnsParseError::QuestionTruncated);
        }
        let len = bytes[cur];
        if len == 0 {
            cur += 1;
            break;
        }
        if len & 0xc0 != 0 {
            // Compressed pointer - queries SHOULD never have these, and middleboxes
            // see them as malformed. We surface them as a distinct error.
            return Err(DnsParseError::CompressedQuestion);
        }
        if len > 63 {
            return Err(DnsParseError::OverlongLabel);
        }
        cur += 1;
        if cur + len as usize > bytes.len() {
            return Err(DnsParseError::QuestionTruncated);
        }
        let label = std::str::from_utf8(&bytes[cur..cur + len as usize])?;
        labels.push(label.to_owned());
        cur += len as usize;
    }
    Ok((labels.join("."), cur))
}

/// Action chosen by [`DnsInjector`] when it sees a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsInjectionTrace {
    pub injector: &'static str,
    pub ttl: u32,
    pub sinkhole: [u8; 4],
    pub echoes_probe_ttl: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsAction {
    /// Forward upstream; no injection.
    Allow,
    /// Race the legitimate resolver with a forged response. `forged_response`
    /// is the byte vector that the simulator would send back to the client.
    /// `matched_keyword` records which rule fired.
    InjectFakeResponse {
        forged_response: Vec<u8>,
        matched_keyword: String,
        injector_trace: Vec<DnsInjectionTrace>,
    },
    /// Newer drop-mode: silently swallow the query (the real resolver also
    /// answers, but the response is RST'd by the residual rule).
    Drop { matched_keyword: String },
    /// Rewrite the answer to NXDOMAIN (RCODE 3). A resolver-side enforcement
    /// path returns this for a blocklisted name instead of a sinkhole address,
    /// which is an independently observable censorship fingerprint.
    NxDomain {
        forged_response: Vec<u8>,
        matched_keyword: String,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum InjectionMode {
    /// Forge a fake A-record response (classic GFW behavior, ~2014-2020).
    FakeResponse,
    /// Drop the query (newer behavior on some sub-networks).
    Drop,
    /// Rewrite the answer to NXDOMAIN (resolver-side enforcement).
    NxDomain,
}

pub struct DnsInjector {
    blocklist: DnsKeywordBlocklist,
    domain_blocklist: Option<DnsDomainBlocklist>,
    mode: InjectionMode,
    sinkhole_idx: std::cell::Cell<usize>,
    pub stats: std::cell::RefCell<DnsInjectorStats>,
}

#[derive(Debug, Clone, Default)]
pub struct DnsInjectorStats {
    pub queries_seen: u64,
    pub injections_issued: u64,
    pub drops_issued: u64,
    pub nxdomains_issued: u64,
    /// Number of queries whose qtype was SVCB (64) or HTTPS (65). Such queries
    /// carry the ECH configuration in the answer, so the GFW records them as
    /// reconnaissance of ECH-capable destinations.
    pub ech_recon_observed: u64,
    pub last_injection: Option<Instant>,
}

impl Default for DnsInjector {
    fn default() -> Self {
        Self::with_mode(InjectionMode::FakeResponse)
    }
}

impl DnsInjector {
    pub fn with_mode(mode: InjectionMode) -> Self {
        Self {
            blocklist: DnsKeywordBlocklist::default_set(),
            domain_blocklist: None,
            mode,
            sinkhole_idx: std::cell::Cell::new(0),
            stats: std::cell::RefCell::new(DnsInjectorStats::default()),
        }
    }

    pub fn with_blocklist(blocklist: DnsKeywordBlocklist, mode: InjectionMode) -> Self {
        Self {
            blocklist,
            domain_blocklist: None,
            mode,
            sinkhole_idx: std::cell::Cell::new(0),
            stats: std::cell::RefCell::new(DnsInjectorStats::default()),
        }
    }

    /// Attach an exact + suffix domain blocklist. When present it is consulted
    /// before the substring keyword list, modelling the resolver-side rule
    /// table that matches `DOMAIN` / `DOMAIN-SUFFIX` entries at label
    /// boundaries.
    pub fn with_domain_blocklist(mut self, domains: DnsDomainBlocklist) -> Self {
        self.domain_blocklist = Some(domains);
        self
    }

    /// Inspect a UDP/53 payload. Returns the action the simulator should take.
    pub fn inspect(&self, bytes: &[u8]) -> DnsAction {
        self.stats.borrow_mut().queries_seen += 1;
        let query = match parse_query(bytes) {
            Ok(q) => q,
            Err(_) => return DnsAction::Allow,
        };
        for question in &query.questions {
            // A SVCB/HTTPS query exposes that the client is resolving an
            // ECH-capable destination; record it as reconnaissance regardless
            // of the blocklist outcome.
            if matches!(question.qtype, QTYPE_SVCB | QTYPE_HTTPS) {
                self.stats.borrow_mut().ech_recon_observed += 1;
            }
            if let Some(matched_keyword) = self.matched_rule(&question.name) {
                match self.mode {
                    InjectionMode::FakeResponse => {
                        let (resp, trace) = self.forge_a_response(&query, question);
                        let mut stats = self.stats.borrow_mut();
                        stats.injections_issued += 1;
                        stats.last_injection = Some(Instant::now());
                        return DnsAction::InjectFakeResponse {
                            forged_response: resp,
                            matched_keyword,
                            injector_trace: trace,
                        };
                    }
                    InjectionMode::Drop => {
                        self.stats.borrow_mut().drops_issued += 1;
                        return DnsAction::Drop { matched_keyword };
                    }
                    InjectionMode::NxDomain => {
                        let resp = self.forge_nxdomain(&query, question);
                        self.stats.borrow_mut().nxdomains_issued += 1;
                        return DnsAction::NxDomain {
                            forged_response: resp,
                            matched_keyword,
                        };
                    }
                }
            }
        }
        DnsAction::Allow
    }

    /// Resolve a name against the domain blocklist (exact + suffix) first, then
    /// the substring keyword list. Returns the rule string that fired.
    fn matched_rule(&self, name: &str) -> Option<String> {
        if let Some(domains) = &self.domain_blocklist {
            if let Some(m) = domains.matched(name) {
                return Some(m.pattern);
            }
        }
        self.blocklist.matched(name).map(|k| k.to_owned())
    }

    fn forge_nxdomain(&self, query: &DnsQuery, question: &DnsQuestion) -> Vec<u8> {
        let mut resp = Vec::with_capacity(32);
        resp.extend_from_slice(&query.transaction_id.to_be_bytes());
        // QR=1, opcode=0, AA=1, RD=1, RA=1, RCODE=3 (NXDOMAIN) -> 0x8583
        resp.extend_from_slice(&(0x8580_u16 | RCODE_NXDOMAIN).to_be_bytes());
        resp.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT
        resp.extend_from_slice(&0_u16.to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&0_u16.to_be_bytes()); // NSCOUNT
        resp.extend_from_slice(&0_u16.to_be_bytes()); // ARCOUNT
        encode_name(&mut resp, &question.name);
        resp.extend_from_slice(&question.qtype.to_be_bytes());
        resp.extend_from_slice(&question.qclass.to_be_bytes());
        resp
    }

    fn forge_a_response(
        &self,
        query: &DnsQuery,
        question: &DnsQuestion,
    ) -> (Vec<u8>, Vec<DnsInjectionTrace>) {
        let idx = self.sinkhole_idx.get();
        self.sinkhole_idx.set((idx + 1) % SINKHOLE_A_RECORDS.len());
        let sink = SINKHOLE_A_RECORDS[idx];
        let trace = self.three_injector_trace(idx);

        let mut resp = Vec::with_capacity(64);
        resp.extend_from_slice(&query.transaction_id.to_be_bytes());
        // QR=1, opcode=0, AA=1, TC=0, RD=1, RA=1, RCODE=0  -> 0x8580
        resp.extend_from_slice(&0x8580_u16.to_be_bytes());
        resp.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT
        resp.extend_from_slice(&1_u16.to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&0_u16.to_be_bytes()); // NSCOUNT
        resp.extend_from_slice(&0_u16.to_be_bytes()); // ARCOUNT

        encode_name(&mut resp, &question.name);
        resp.extend_from_slice(&question.qtype.to_be_bytes());
        resp.extend_from_slice(&question.qclass.to_be_bytes());

        encode_name(&mut resp, &question.name);
        resp.extend_from_slice(&1_u16.to_be_bytes()); // TYPE = A
        resp.extend_from_slice(&1_u16.to_be_bytes()); // CLASS = IN

        // Classic GFW responses use a high TTL to make them stick in
        // resolvers. The leaked Tiangou configs picked 86400 (24h);
        // we mirror that.
        resp.extend_from_slice(&trace[0].ttl.to_be_bytes());
        resp.extend_from_slice(&4_u16.to_be_bytes()); // RDLENGTH
        resp.extend_from_slice(&sink);
        (resp, trace)
    }

    fn three_injector_trace(&self, idx: usize) -> Vec<DnsInjectionTrace> {
        vec![
            DnsInjectionTrace {
                injector: "dns-a-static-ttl",
                ttl: 86_400,
                sinkhole: SINKHOLE_A_RECORDS[idx % SINKHOLE_A_RECORDS.len()],
                echoes_probe_ttl: false,
            },
            DnsInjectionTrace {
                injector: "dns-b-ttl-echo",
                ttl: 0,
                sinkhole: SINKHOLE_A_RECORDS[(idx + 3) % SINKHOLE_A_RECORDS.len()],
                echoes_probe_ttl: true,
            },
            DnsInjectionTrace {
                injector: "dns-c-keyword-cluster",
                ttl: 600,
                sinkhole: SINKHOLE_A_RECORDS[(idx + 7) % SINKHOLE_A_RECORDS.len()],
                echoes_probe_ttl: false,
            },
        ]
    }

    pub fn stats_snapshot(&self) -> DnsInjectorStats {
        self.stats.borrow().clone()
    }
}

fn encode_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// Returns true if `now - then` is within the GFW's injection window (the
/// forged response must arrive before the real resolver). 50 ms is a generous
/// upper bound for inline injection in a backbone deployment.
pub fn within_injection_window(then: Instant, now: Instant) -> bool {
    now.saturating_duration_since(then) <= Duration::from_millis(50)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_query(name: &str) -> Vec<u8> {
        build_query_qtype(name, QTYPE_A)
    }

    fn build_query_qtype(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&0x1234_u16.to_be_bytes()); // txid
        q.extend_from_slice(&0x0100_u16.to_be_bytes()); // recursion desired
        q.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&0_u16.to_be_bytes());
        q.extend_from_slice(&0_u16.to_be_bytes());
        q.extend_from_slice(&0_u16.to_be_bytes());
        encode_name(&mut q, name);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&1_u16.to_be_bytes()); // QCLASS=IN
        q
    }

    #[test]
    fn parses_simple_query() {
        let bytes = build_query("example.com");
        let q = parse_query(&bytes).unwrap();
        assert_eq!(q.transaction_id, 0x1234);
        assert_eq!(q.questions.len(), 1);
        assert_eq!(q.questions[0].name, "example.com");
        assert_eq!(q.questions[0].qtype, 1);
        assert_eq!(q.questions[0].qclass, 1);
    }

    #[test]
    fn rejects_compressed_question() {
        let mut bytes = build_query("example.com");
        // Splice a compressed-pointer label into the middle.
        bytes[12] = 0xc0;
        bytes[13] = 0x00;
        assert_eq!(parse_query(&bytes), Err(DnsParseError::CompressedQuestion));
    }

    #[test]
    fn allows_unknown_name() {
        let injector = DnsInjector::default();
        let q = build_query("example.com");
        assert_eq!(injector.inspect(&q), DnsAction::Allow);
        assert_eq!(injector.stats_snapshot().injections_issued, 0);
    }

    #[test]
    fn injects_on_circumvention_keyword() {
        let injector = DnsInjector::default();
        let q = build_query("cdn.v2raycloud.io");
        let action = injector.inspect(&q);
        match action {
            DnsAction::InjectFakeResponse {
                forged_response,
                matched_keyword,
                injector_trace,
            } => {
                assert_eq!(matched_keyword, "v2ray");
                assert!(forged_response.len() > 12);
                assert_eq!(injector_trace.len(), 3);
                assert!(injector_trace.iter().any(|entry| entry.echoes_probe_ttl));
                // The forged response is a valid DNS message with QR=1.
                let flags = u16::from_be_bytes([forged_response[2], forged_response[3]]);
                assert_eq!(flags & 0x8000, 0x8000, "QR bit must be set");
            }
            other => panic!("expected injection, got {other:?}"),
        }
        assert_eq!(injector.stats_snapshot().injections_issued, 1);
    }

    #[test]
    fn drop_mode_swallows_query() {
        let injector = DnsInjector::with_mode(InjectionMode::Drop);
        let q = build_query("snowflake.example.com");
        let action = injector.inspect(&q);
        match action {
            DnsAction::Drop { matched_keyword } => {
                assert_eq!(matched_keyword, "snowflake");
            }
            other => panic!("expected drop, got {other:?}"),
        }
        assert_eq!(injector.stats_snapshot().drops_issued, 1);
    }

    #[test]
    fn suffix_trie_matches_only_at_label_boundary() {
        let bl = DnsDomainBlocklist::from_rules([
            ("*.shadowsocks.io", DomainMatchKind::Suffix),
            ("blocked.example", DomainMatchKind::Exact),
        ]);
        // Suffix matches the apex and any subdomain.
        assert_eq!(
            bl.matched("relay7.shadowsocks.io").map(|m| m.kind),
            Some(DomainMatchKind::Suffix)
        );
        assert_eq!(
            bl.matched("shadowsocks.io").map(|m| m.kind),
            Some(DomainMatchKind::Suffix)
        );
        // Mid-label coincidence must NOT match (a substring matcher would).
        assert!(bl.matched("notshadowsocks.io").is_none());
        assert!(bl.matched("shadowsocks.io.evil.com").is_none());
        // Exact rule matches only the full name.
        assert_eq!(
            bl.matched("blocked.example").map(|m| m.kind),
            Some(DomainMatchKind::Exact)
        );
        assert!(bl.matched("sub.blocked.example").is_none());
    }

    #[test]
    fn nxdomain_mode_rewrites_answer() {
        let injector = DnsInjector::with_mode(InjectionMode::NxDomain);
        let q = build_query("cdn.v2raycloud.io");
        match injector.inspect(&q) {
            DnsAction::NxDomain {
                forged_response,
                matched_keyword,
            } => {
                assert_eq!(matched_keyword, "v2ray");
                let flags = u16::from_be_bytes([forged_response[2], forged_response[3]]);
                assert_eq!(flags & 0x8000, 0x8000, "QR bit set");
                assert_eq!(flags & 0x000f, RCODE_NXDOMAIN, "RCODE is NXDOMAIN");
                // No answer records in an NXDOMAIN reply.
                let ancount = u16::from_be_bytes([forged_response[6], forged_response[7]]);
                assert_eq!(ancount, 0);
            }
            other => panic!("expected NxDomain, got {other:?}"),
        }
        assert_eq!(injector.stats_snapshot().nxdomains_issued, 1);
    }

    #[test]
    fn domain_blocklist_takes_priority_over_keywords() {
        let domains = DnsDomainBlocklist::from_rules([("*.example.net", DomainMatchKind::Suffix)]);
        let injector = DnsInjector::with_mode(InjectionMode::Drop).with_domain_blocklist(domains);
        // Name matches the domain suffix rule but no substring keyword.
        match injector.inspect(&build_query("host.example.net")) {
            DnsAction::Drop { matched_keyword } => assert_eq!(matched_keyword, "*.example.net"),
            other => panic!("expected Drop via domain rule, got {other:?}"),
        }
    }

    #[test]
    fn https_qtype_is_recorded_as_ech_recon() {
        let injector = DnsInjector::default();
        // A benign HTTPS-record lookup: not blocklisted, but recorded as recon.
        let action = injector.inspect(&build_query_qtype("example.com", QTYPE_HTTPS));
        assert_eq!(action, DnsAction::Allow);
        assert_eq!(injector.stats_snapshot().ech_recon_observed, 1);
        // An A lookup does not count as ECH recon.
        injector.inspect(&build_query_qtype("example.com", QTYPE_A));
        assert_eq!(injector.stats_snapshot().ech_recon_observed, 1);
    }
}
