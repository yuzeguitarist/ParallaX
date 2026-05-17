//! HTTP Host / CONNECT authority filtering.
//!
//! Public GFW measurements consistently show HTTP Host and plaintext keyword
//! filters alongside DNS and TLS SNI filters. This detector models that legacy
//! plaintext path without opening sockets: it parses a single client-to-server
//! HTTP request payload and matches its Host authority against the same
//! circumvention blocklist used by SNI.

use super::super::data::sni_blocklist::SniBlocklist;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpHostVerdict {
    Allow { host: String },
    Block { host: String, matched_rule: String },
    NoHost,
    NotHttp,
}

pub struct HttpHostFilter {
    blocklist: SniBlocklist,
}

impl Default for HttpHostFilter {
    fn default() -> Self {
        Self {
            blocklist: SniBlocklist::default_circumvention(),
        }
    }
}

impl HttpHostFilter {
    pub fn new(blocklist: SniBlocklist) -> Self {
        Self { blocklist }
    }

    pub fn evaluate(&self, bytes: &[u8]) -> HttpHostVerdict {
        let Some(host) = parse_http_host(bytes) else {
            return if looks_like_http(bytes) {
                HttpHostVerdict::NoHost
            } else {
                HttpHostVerdict::NotHttp
            };
        };

        if let Some(rule) = self.blocklist.matched_rule(&host) {
            HttpHostVerdict::Block {
                host,
                matched_rule: rule,
            }
        } else {
            HttpHostVerdict::Allow { host }
        }
    }
}

pub fn parse_http_host(bytes: &[u8]) -> Option<String> {
    if !looks_like_http(bytes) {
        return None;
    }
    let header_end = find_header_end(bytes).unwrap_or(bytes.len());
    let text = std::str::from_utf8(&bytes[..header_end]).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    if let Some(authority) = request_line.strip_prefix("CONNECT ") {
        let authority = authority.split_whitespace().next()?;
        return normalize_authority(authority);
    }

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("host") {
            return normalize_authority(value.trim());
        }
    }
    None
}

fn looks_like_http(bytes: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"HEAD ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
    ];
    METHODS.iter().any(|method| bytes.starts_with(method))
}

fn normalize_authority(authority: &str) -> Option<String> {
    let trimmed = authority.trim().trim_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    let host = if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']')?;
        &rest[..end]
    } else {
        trimmed.split(':').next().unwrap_or(trimmed)
    };
    let host = host.trim().trim_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_header_case_insensitively() {
        let req = b"GET / HTTP/1.1\r\nhOsT: Relay7.ShadowSocks.IO:443\r\n\r\n";
        assert_eq!(
            parse_http_host(req).as_deref(),
            Some("relay7.shadowsocks.io")
        );
    }

    #[test]
    fn parses_connect_authority() {
        let req = b"CONNECT relay7.shadowsocks.io:443 HTTP/1.1\r\nHost: ignored\r\n\r\n";
        assert_eq!(
            parse_http_host(req).as_deref(),
            Some("relay7.shadowsocks.io")
        );
    }

    #[test]
    fn ignores_malformed_header_before_host() {
        let req = b"GET / HTTP/1.1\r\nmalformed\r\nHost: relay7.shadowsocks.io\r\n\r\n";
        assert_eq!(
            parse_http_host(req).as_deref(),
            Some("relay7.shadowsocks.io")
        );
    }

    #[test]
    fn blocks_known_circumvention_host() {
        let filter = HttpHostFilter::default();
        match filter.evaluate(b"GET / HTTP/1.1\r\nHost: relay7.shadowsocks.io\r\n\r\n") {
            HttpHostVerdict::Block { host, matched_rule } => {
                assert_eq!(host, "relay7.shadowsocks.io");
                assert_eq!(matched_rule, "*.shadowsocks.io");
            }
            other => panic!("expected block, got {other:?}"),
        }
    }

    #[test]
    fn allows_unlisted_host() {
        let filter = HttpHostFilter::default();
        assert!(matches!(
            filter.evaluate(b"GET / HTTP/1.1\r\nHost: cloudflare.com\r\n\r\n"),
            HttpHostVerdict::Allow { .. }
        ));
    }

    #[test]
    fn random_bytes_are_not_http() {
        let filter = HttpHostFilter::default();
        assert_eq!(
            filter.evaluate(b"\x16\x03\x03\x00"),
            HttpHostVerdict::NotHttp
        );
    }
}
