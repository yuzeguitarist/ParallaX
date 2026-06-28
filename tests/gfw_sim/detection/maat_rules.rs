//! General boolean rule engine for byte-level traffic matching.
//!
//! The per-layer detectors elsewhere in this crate hard-code a single attribute
//! (an SNI wildcard, a JA3 hash). A production DPI policy engine is far more
//! general: it evaluates conjunctive-normal-form rules whose literals are typed
//! match primitives — exact/prefix/suffix/substring strings, byte patterns at a
//! fixed offset and depth, numeric intervals, flag bitmasks, and IP
//! single/range/CIDR tests — scoped to named attributes of the flow. A rule
//! fires when any of its conditions is satisfied, and each condition is a small
//! AND of literals (optionally negated). This module reproduces that evaluator
//! so red-team scenarios can check whether a ParallaX wire carries any fixed
//! byte feature a censor could match with a single offset+hex rule.

use std::collections::HashMap;
use std::net::IpAddr;

/// Maximum number of literals AND-ed inside a single condition.
pub const MAX_ITEMS_PER_CONDITION: usize = 8;

/// A named attribute of the flow that a literal can match against.
#[derive(Debug, Clone)]
pub enum AttrValue {
    /// A textual attribute (SNI, HTTP Host, ALPN, ...).
    Text(String),
    /// A raw byte attribute (first packet, a decrypted payload, ...).
    Bytes(Vec<u8>),
    /// A numeric attribute (a port, a length, a count).
    Number(i64),
    /// A bitfield attribute (TCP flags, a header byte).
    Flags(u64),
    /// An address attribute (source / destination IP).
    Addr(IpAddr),
}

/// The set of attributes describing one flow under evaluation.
#[derive(Debug, Clone, Default)]
pub struct MatchContext {
    attrs: HashMap<String, AttrValue>,
}

impl MatchContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(mut self, key: &str, value: AttrValue) -> Self {
        self.attrs.insert(key.to_owned(), value);
        self
    }

    pub fn insert(&mut self, key: &str, value: AttrValue) {
        self.attrs.insert(key.to_owned(), value);
    }

    fn get(&self, key: &str) -> Option<&AttrValue> {
        self.attrs.get(key)
    }
}

/// How a string literal matches its attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringMatch {
    Exact,
    Prefix,
    Suffix,
    Substring,
}

/// A single typed match primitive bound to a named attribute.
#[derive(Debug, Clone)]
pub enum Literal {
    /// Match a string attribute (case-insensitive).
    Str {
        attr: String,
        mode: StringMatch,
        value: String,
    },
    /// Match `pattern` against a byte attribute at `offset`, searching forward
    /// up to `depth` bytes from that offset (depth 0 means exactly at offset).
    Bytes {
        attr: String,
        offset: usize,
        depth: usize,
        pattern: Vec<u8>,
    },
    /// Match a numeric attribute against an inclusive interval.
    Interval { attr: String, min: i64, max: i64 },
    /// Match `(value & mask) == expected` on a flags attribute.
    Flag {
        attr: String,
        mask: u64,
        expected: u64,
    },
    /// Match an address attribute against a single IP.
    IpExact { attr: String, ip: IpAddr },
    /// Match an address attribute against an inclusive IPv4 range.
    IpRange { attr: String, low: u32, high: u32 },
    /// Match an address attribute against an IPv4 CIDR.
    IpCidr {
        attr: String,
        network: u32,
        prefix: u8,
    },
}

impl Literal {
    fn eval(&self, ctx: &MatchContext) -> bool {
        match self {
            Literal::Str { attr, mode, value } => match ctx.get(attr) {
                Some(AttrValue::Text(t)) => {
                    let hay = t.to_ascii_lowercase();
                    let needle = value.to_ascii_lowercase();
                    match mode {
                        StringMatch::Exact => hay == needle,
                        StringMatch::Prefix => hay.starts_with(&needle),
                        StringMatch::Suffix => hay.ends_with(&needle),
                        StringMatch::Substring => hay.contains(&needle),
                    }
                }
                _ => false,
            },
            Literal::Bytes {
                attr,
                offset,
                depth,
                pattern,
            } => match ctx.get(attr) {
                Some(AttrValue::Bytes(b)) => byte_match(b, *offset, *depth, pattern),
                _ => false,
            },
            Literal::Interval { attr, min, max } => match ctx.get(attr) {
                Some(AttrValue::Number(n)) => n >= min && n <= max,
                _ => false,
            },
            Literal::Flag {
                attr,
                mask,
                expected,
            } => match ctx.get(attr) {
                Some(AttrValue::Flags(f)) => (f & mask) == *expected,
                _ => false,
            },
            Literal::IpExact { attr, ip } => match ctx.get(attr) {
                Some(AttrValue::Addr(a)) => a == ip,
                _ => false,
            },
            Literal::IpRange { attr, low, high } => match ctx.get(attr) {
                Some(AttrValue::Addr(IpAddr::V4(v4))) => {
                    let n = u32::from(*v4);
                    n >= *low && n <= *high
                }
                _ => false,
            },
            Literal::IpCidr {
                attr,
                network,
                prefix,
            } => match ctx.get(attr) {
                Some(AttrValue::Addr(IpAddr::V4(v4))) => {
                    let mask = cidr_mask(*prefix);
                    (u32::from(*v4) & mask) == (network & mask)
                }
                _ => false,
            },
        }
    }
}

/// `pattern` appears in `data` starting at some position in `[offset, offset+depth]`.
fn byte_match(data: &[u8], offset: usize, depth: usize, pattern: &[u8]) -> bool {
    if pattern.is_empty() {
        return false;
    }
    let last_start = offset.saturating_add(depth);
    let mut start = offset;
    while start <= last_start {
        let end = start + pattern.len();
        if end > data.len() {
            break;
        }
        if &data[start..end] == pattern {
            return true;
        }
        start += 1;
    }
    false
}

fn cidr_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    }
}

/// One literal plus whether it is negated.
#[derive(Debug, Clone)]
pub struct Item {
    pub literal: Literal,
    pub negate: bool,
}

impl Item {
    pub fn of(literal: Literal) -> Self {
        Self {
            literal,
            negate: false,
        }
    }

    pub fn not(literal: Literal) -> Self {
        Self {
            literal,
            negate: true,
        }
    }
}

/// A conjunction (AND) of up to [`MAX_ITEMS_PER_CONDITION`] items.
#[derive(Debug, Clone, Default)]
pub struct Condition {
    items: Vec<Item>,
}

impl Condition {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an item. Items beyond the per-condition cap are ignored, mirroring
    /// the engine's hard limit on conjunction width.
    pub fn and(mut self, item: Item) -> Self {
        if self.items.len() < MAX_ITEMS_PER_CONDITION {
            self.items.push(item);
        }
        self
    }

    fn eval(&self, ctx: &MatchContext) -> bool {
        if self.items.is_empty() {
            return false;
        }
        self.items
            .iter()
            .all(|item| item.literal.eval(ctx) != item.negate)
    }
}

/// A rule fires when ANY of its conditions is satisfied (disjunction of
/// conjunctions = CNF). An optional set of exclusion conditions suppresses the
/// match (a "super object": include AND NOT exclude).
#[derive(Debug, Clone, Default)]
pub struct Rule {
    pub id: u32,
    pub label: String,
    include: Vec<Condition>,
    exclude: Vec<Condition>,
}

impl Rule {
    pub fn new(id: u32, label: &str) -> Self {
        Self {
            id,
            label: label.to_owned(),
            include: Vec::new(),
            exclude: Vec::new(),
        }
    }

    pub fn include(mut self, cond: Condition) -> Self {
        self.include.push(cond);
        self
    }

    pub fn exclude(mut self, cond: Condition) -> Self {
        self.exclude.push(cond);
        self
    }

    pub fn matches(&self, ctx: &MatchContext) -> bool {
        let included = self.include.iter().any(|c| c.eval(ctx));
        if !included {
            return false;
        }
        let excluded = self.exclude.iter().any(|c| c.eval(ctx));
        !excluded
    }
}

/// A named set of rules evaluated together.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_rule(mut self, rule: Rule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Return the label of every rule that fires for `ctx`.
    pub fn matching_labels(&self, ctx: &MatchContext) -> Vec<String> {
        self.rules
            .iter()
            .filter(|r| r.matches(ctx))
            .map(|r| r.label.clone())
            .collect()
    }

    /// Return the first matching rule, if any.
    pub fn first_match(&self, ctx: &MatchContext) -> Option<&Rule> {
        self.rules.iter().find(|r| r.matches(ctx))
    }
}

/// Parse a dotted IPv4 string into its `u32` form (test/helper convenience).
pub fn ipv4(s: &str) -> u32 {
    let mut acc: u32 = 0;
    for octet in s.split('.') {
        acc = (acc << 8) | octet.parse::<u32>().unwrap_or(0);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_bytes(attr: &str, bytes: &[u8]) -> MatchContext {
        MatchContext::new().set(attr, AttrValue::Bytes(bytes.to_vec()))
    }

    #[test]
    fn byte_offset_pattern_matches_at_fixed_position() {
        // A rule that fires on a 4-byte marker at offset 8, depth 4.
        let lit = Literal::Bytes {
            attr: "payload".into(),
            offset: 8,
            depth: 4,
            pattern: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let rule = Rule::new(1, "marker").include(Condition::new().and(Item::of(lit)));
        let set = RuleSet::new().with_rule(rule);

        let mut data = vec![0u8; 16];
        data[10..14].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // within [8, 12]
        assert_eq!(
            set.matching_labels(&ctx_bytes("payload", &data)),
            ["marker"]
        );

        // Same marker outside the depth window does not match.
        let mut data2 = vec![0u8; 16];
        data2[0..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(set
            .matching_labels(&ctx_bytes("payload", &data2))
            .is_empty());
    }

    #[test]
    fn condition_is_an_and_of_literals() {
        let cond = Condition::new()
            .and(Item::of(Literal::Str {
                attr: "sni".into(),
                mode: StringMatch::Suffix,
                value: "shadowsocks.io".into(),
            }))
            .and(Item::of(Literal::Interval {
                attr: "port".into(),
                min: 440,
                max: 450,
            }));
        let rule = Rule::new(2, "ss-on-443").include(cond);
        let set = RuleSet::new().with_rule(rule);

        let hit = MatchContext::new()
            .set("sni", AttrValue::Text("relay.shadowsocks.io".into()))
            .set("port", AttrValue::Number(443));
        assert_eq!(set.matching_labels(&hit), ["ss-on-443"]);

        // Wrong port: the AND fails.
        let miss = MatchContext::new()
            .set("sni", AttrValue::Text("relay.shadowsocks.io".into()))
            .set("port", AttrValue::Number(8080));
        assert!(set.matching_labels(&miss).is_empty());
    }

    #[test]
    fn flag_bitmask_matches() {
        // TCP flags: SYN(0x02)+ACK(0x10) set, nothing else required.
        let lit = Literal::Flag {
            attr: "tcp_flags".into(),
            mask: 0x12,
            expected: 0x12,
        };
        let rule = Rule::new(3, "syn-ack").include(Condition::new().and(Item::of(lit)));
        let set = RuleSet::new().with_rule(rule);
        let hit = MatchContext::new().set("tcp_flags", AttrValue::Flags(0x12));
        let miss = MatchContext::new().set("tcp_flags", AttrValue::Flags(0x10));
        assert!(!set.matching_labels(&hit).is_empty());
        assert!(set.matching_labels(&miss).is_empty());
    }

    #[test]
    fn ip_cidr_and_range_match() {
        let cidr =
            Rule::new(4, "rfc1918-10").include(Condition::new().and(Item::of(Literal::IpCidr {
                attr: "src".into(),
                network: ipv4("10.0.0.0"),
                prefix: 8,
            })));
        let set = RuleSet::new().with_rule(cidr);
        let inside = MatchContext::new().set("src", AttrValue::Addr("10.5.6.7".parse().unwrap()));
        let outside = MatchContext::new().set("src", AttrValue::Addr("11.0.0.1".parse().unwrap()));
        assert!(!set.matching_labels(&inside).is_empty());
        assert!(set.matching_labels(&outside).is_empty());
    }

    #[test]
    fn negated_literal_and_super_object_exclusion() {
        // include: substring "vmess" in payload-as-text-ish; exclude: a known
        // benign marker present.
        let include = Condition::new().and(Item::of(Literal::Bytes {
            attr: "first".into(),
            offset: 0,
            depth: 32,
            pattern: b"vmess".to_vec(),
        }));
        let exclude = Condition::new().and(Item::of(Literal::Bytes {
            attr: "first".into(),
            offset: 0,
            depth: 4,
            pattern: vec![0x16, 0x03], // looks like a TLS record start
        }));
        let rule = Rule::new(5, "vmess-not-tls")
            .include(include)
            .exclude(exclude);
        let set = RuleSet::new().with_rule(rule);

        let bare = ctx_bytes("first", b"....vmess....");
        assert_eq!(set.matching_labels(&bare), ["vmess-not-tls"]);

        let mut tls_like = vec![0x16, 0x03, 0x03, 0x00];
        tls_like.extend_from_slice(b"vmess");
        assert!(set
            .matching_labels(&ctx_bytes("first", &tls_like))
            .is_empty());
    }

    #[test]
    fn condition_caps_conjunction_width() {
        let mut cond = Condition::new();
        for _ in 0..20 {
            cond = cond.and(Item::of(Literal::Interval {
                attr: "n".into(),
                min: 0,
                max: 100,
            }));
        }
        // Internally capped; still evaluates as an AND of the retained items.
        let ctx = MatchContext::new().set("n", AttrValue::Number(50));
        let rule = Rule::new(6, "capped").include(cond);
        assert!(rule.matches(&ctx));
    }
}
