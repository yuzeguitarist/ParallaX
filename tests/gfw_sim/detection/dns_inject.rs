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
//! models the most common one (A-record sinkhole) plus a "drop" mode used in
//! more recent deployments.

use std::time::{Duration, Instant};

use super::super::data::sni_blocklist::DnsKeywordBlocklist;

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
pub enum DnsAction {
    /// Forward upstream; no injection.
    Allow,
    /// Race the legitimate resolver with a forged response. `forged_response`
    /// is the byte vector that the simulator would send back to the client.
    /// `matched_keyword` records which rule fired.
    InjectFakeResponse {
        forged_response: Vec<u8>,
        matched_keyword: String,
    },
    /// Newer drop-mode: silently swallow the query (the real resolver also
    /// answers, but the response is RST'd by the residual rule).
    Drop { matched_keyword: String },
}

#[derive(Debug, Clone, Copy)]
pub enum InjectionMode {
    /// Forge a fake A-record response (classic GFW behavior, ~2014-2020).
    FakeResponse,
    /// Drop the query (newer behavior on some sub-networks).
    Drop,
}

pub struct DnsInjector {
    blocklist: DnsKeywordBlocklist,
    mode: InjectionMode,
    sinkhole_idx: std::cell::Cell<usize>,
    pub stats: std::cell::RefCell<DnsInjectorStats>,
}

#[derive(Debug, Clone, Default)]
pub struct DnsInjectorStats {
    pub queries_seen: u64,
    pub injections_issued: u64,
    pub drops_issued: u64,
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
            mode,
            sinkhole_idx: std::cell::Cell::new(0),
            stats: std::cell::RefCell::new(DnsInjectorStats::default()),
        }
    }

    pub fn with_blocklist(blocklist: DnsKeywordBlocklist, mode: InjectionMode) -> Self {
        Self {
            blocklist,
            mode,
            sinkhole_idx: std::cell::Cell::new(0),
            stats: std::cell::RefCell::new(DnsInjectorStats::default()),
        }
    }

    /// Inspect a UDP/53 payload. Returns the action the simulator should take.
    pub fn inspect(&self, bytes: &[u8]) -> DnsAction {
        self.stats.borrow_mut().queries_seen += 1;
        let query = match parse_query(bytes) {
            Ok(q) => q,
            Err(_) => return DnsAction::Allow,
        };
        for question in &query.questions {
            if let Some(keyword) = self.blocklist.matched(&question.name) {
                let matched_keyword = keyword.to_owned();
                match self.mode {
                    InjectionMode::FakeResponse => {
                        let resp = self.forge_a_response(&query, question);
                        let mut stats = self.stats.borrow_mut();
                        stats.injections_issued += 1;
                        stats.last_injection = Some(Instant::now());
                        return DnsAction::InjectFakeResponse {
                            forged_response: resp,
                            matched_keyword,
                        };
                    }
                    InjectionMode::Drop => {
                        self.stats.borrow_mut().drops_issued += 1;
                        return DnsAction::Drop { matched_keyword };
                    }
                }
            }
        }
        DnsAction::Allow
    }

    fn forge_a_response(&self, query: &DnsQuery, question: &DnsQuestion) -> Vec<u8> {
        let idx = self.sinkhole_idx.get();
        self.sinkhole_idx.set((idx + 1) % SINKHOLE_A_RECORDS.len());
        let sink = SINKHOLE_A_RECORDS[idx];

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
                                                      // Classic GFW responses use a high TTL to make them stick in resolvers.
                                                      // The leaked Tiangou configs picked 86400 (24h); we mirror that.
        resp.extend_from_slice(&86_400_u32.to_be_bytes());
        resp.extend_from_slice(&4_u16.to_be_bytes()); // RDLENGTH
        resp.extend_from_slice(&sink);
        resp
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
        let mut q = Vec::new();
        q.extend_from_slice(&0x1234_u16.to_be_bytes()); // txid
        q.extend_from_slice(&0x0100_u16.to_be_bytes()); // recursion desired
        q.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&0_u16.to_be_bytes());
        q.extend_from_slice(&0_u16.to_be_bytes());
        q.extend_from_slice(&0_u16.to_be_bytes());
        encode_name(&mut q, name);
        q.extend_from_slice(&1_u16.to_be_bytes()); // QTYPE=A
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
            } => {
                assert_eq!(matched_keyword, "v2ray");
                assert!(forged_response.len() > 12);
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
}
