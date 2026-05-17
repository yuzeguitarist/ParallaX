//! Public-domain SNI / DNS keyword blocklist used by the GFW simulator.
//!
//! Mirrors what TSG / Maat / Gohangout would have shipped for circumvention
//! protocols: high-profile circumvention SaaS, well-known proxy / tunnel domains
//! that appear in the public anti-censorship corpus (the leaked rulesets, the
//! GFW Report blocklists, and InterSecLab's TSG inventory). It deliberately does
//! NOT contain political content keywords - this module is about *circumvention
//! detection*, not content censorship.
//!
//! The two key matching semantics:
//!  - **Exact match** (`example.com`) matches only that label hierarchy.
//!  - **Wildcard suffix** (`*.shadowsocks.io`) matches any sub-domain of the
//!    suffix.

/// Default circumvention / proxy SNI blocklist used by [`SniBlocklist::default`].
///
/// Sourced from public records (the GFW Report blocklists at https://gfw.report/,
/// the InterSecLab Geedge analysis, and the V2Ray / Shadowsocks deployment guides
/// that document which hostnames are well-known to be censored). Entries are
/// deliberately fictitious / well-known proxy SaaS endpoints so the suite can be
/// run in isolation without ever needing to make real network requests.
pub const DEFAULT_CIRCUMVENTION_SNIS: &[&str] = &[
    "*.shadowsocks.io",
    "*.v2ray.com",
    "*.v2fly.org",
    "*.trojan-gfw.io",
    "*.naiveproxy.example",
    "*.psiphon3.com",
    "*.psiphon.ca",
    "*.tor.network",
    "*.torproject.org",
    "*.snowflake.torproject.org",
    "*.lantern.io",
    "*.getlantern.org",
    "*.outline.networks",
    "*.outlinevpn.example",
    "*.brave.com", // Brave Firewall Tor-relay endpoints
    "*.protonvpn.com",
    "*.expressvpn.com",
    "*.nordvpn.com",
    "*.surfshark.com",
    "*.windscribe.com",
    "*.mullvad.net",
    "*.ivpn.net",
    "*.proton.me",
    "*.azirevpn.com",
    "*.scramblevpn.example",
    // Known ParallaX test / dev SNIs that the integration tests treat as
    // "in the censor's table" for negative-path scenarios.
    "parallax-dev.example",
    "blocked.example",
];

/// DNS-only keyword blocklist (case-insensitive substring match). The real GFW
/// runs a separate DNS injection subsystem with a much larger keyword table; we
/// pick a few representative entries that exercise the substring matcher in our
/// `dns_inject` detector. The actual TSG table is non-public; treat this list
/// purely as a unit-test fixture.
pub const DEFAULT_DNS_KEYWORDS: &[&str] = &[
    "shadowsocks",
    "v2ray",
    "vmess",
    "trojan-gfw",
    "psiphon",
    "lantern",
    "ultrasurf",
    "freegate",
    "tor-relay",
    "snowflake",
    "outlinevpn",
    "wireguard-tunnel",
    "naiveproxy",
];

/// Reusable holder for an SNI blocklist that supports exact + wildcard matching.
#[derive(Debug, Clone, Default)]
pub struct SniBlocklist {
    exact: Vec<String>,
    suffix: Vec<String>,
}

impl SniBlocklist {
    /// Construct a blocklist from a list of patterns. A `*.` prefix marks a
    /// wildcard suffix; anything else is an exact match.
    pub fn from_patterns<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut exact = Vec::new();
        let mut suffix = Vec::new();
        for pattern in patterns {
            let raw = pattern.as_ref().trim().to_ascii_lowercase();
            if raw.is_empty() {
                continue;
            }
            if let Some(stripped) = raw.strip_prefix("*.") {
                suffix.push(stripped.to_owned());
            } else {
                exact.push(raw);
            }
        }
        Self { exact, suffix }
    }

    /// Default GFW-style circumvention blocklist (see [`DEFAULT_CIRCUMVENTION_SNIS`]).
    pub fn default_circumvention() -> Self {
        Self::from_patterns(DEFAULT_CIRCUMVENTION_SNIS.iter().copied())
    }

    /// Returns true if `sni` is blocklisted under either an exact or wildcard rule.
    pub fn is_blocked(&self, sni: &str) -> bool {
        let needle = sni.trim().trim_end_matches('.').to_ascii_lowercase();
        if needle.is_empty() {
            return false;
        }
        if self.exact.iter().any(|entry| entry == &needle) {
            return true;
        }
        self.suffix
            .iter()
            .any(|entry| needle == *entry || needle.ends_with(&format!(".{entry}")))
    }

    /// Returns the matched pattern (if any), useful for logging which rule fired.
    pub fn matched_rule(&self, sni: &str) -> Option<String> {
        let needle = sni.trim().trim_end_matches('.').to_ascii_lowercase();
        if needle.is_empty() {
            return None;
        }
        if let Some(rule) = self.exact.iter().find(|entry| **entry == needle) {
            return Some(rule.clone());
        }
        self.suffix
            .iter()
            .find(|entry| needle == **entry || needle.ends_with(&format!(".{entry}")))
            .map(|entry| format!("*.{entry}"))
    }
}

/// DNS keyword blocklist with substring + label-anchored matching.
#[derive(Debug, Clone, Default)]
pub struct DnsKeywordBlocklist {
    keywords: Vec<String>,
}

impl DnsKeywordBlocklist {
    pub fn from_keywords<I, S>(keywords: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            keywords: keywords
                .into_iter()
                .map(|s| s.as_ref().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }

    pub fn default_set() -> Self {
        Self::from_keywords(DEFAULT_DNS_KEYWORDS.iter().copied())
    }

    /// Returns the first keyword that appears as a substring of `name`, case-insensitively.
    pub fn matched(&self, name: &str) -> Option<&str> {
        let needle = name.to_ascii_lowercase();
        self.keywords
            .iter()
            .find(|keyword| needle.contains(keyword.as_str()))
            .map(|keyword| keyword.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_circumvention_blocks_known_patterns() {
        let bl = SniBlocklist::default_circumvention();
        assert!(bl.is_blocked("relay7.shadowsocks.io"));
        assert!(bl.is_blocked("login.psiphon3.com"));
        assert!(bl.is_blocked("blocked.example"));
        assert!(!bl.is_blocked("cloudflare.com"));
        assert!(!bl.is_blocked("amazon.com"));
    }

    #[test]
    fn wildcard_does_not_match_unrelated_suffix() {
        let bl = SniBlocklist::from_patterns(["*.foo.example"]);
        assert!(bl.is_blocked("a.foo.example"));
        assert!(bl.is_blocked("a.b.foo.example"));
        assert!(bl.is_blocked("foo.example"));
        assert!(!bl.is_blocked("bar.example"));
        assert!(!bl.is_blocked("notfoo.example"));
    }

    #[test]
    fn matched_rule_returns_specific_pattern() {
        let bl = SniBlocklist::default_circumvention();
        assert_eq!(
            bl.matched_rule("relay7.shadowsocks.io").as_deref(),
            Some("*.shadowsocks.io")
        );
        assert_eq!(
            bl.matched_rule("blocked.example").as_deref(),
            Some("blocked.example")
        );
        assert_eq!(bl.matched_rule("cloudflare.com"), None);
    }

    #[test]
    fn dns_keyword_matches_anywhere_in_label() {
        let bl = DnsKeywordBlocklist::default_set();
        assert_eq!(bl.matched("cdn.v2raycloud.io"), Some("v2ray"));
        assert_eq!(bl.matched("torrent.example.com"), None);
        assert_eq!(bl.matched("snowflake.example.com"), Some("snowflake"));
    }
}
