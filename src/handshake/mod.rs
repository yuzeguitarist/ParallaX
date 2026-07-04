pub mod client;
pub mod server;
pub mod source_limit;
pub mod transcript;

/// Record-count term of the pre-key-exchange camouflage window: the multiplier
/// behind [`MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_BYTES`], and the server's pre-PQ cap
/// on camouflage records read from the CLIENT before its PQ rekey
/// (`server::PRE_PQ_FALLBACK_FORWARD_RECORD_LIMIT`). 64 full-size records is far
/// above any real handshake flight while still bounding forwarding.
pub(crate) const MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_RECORDS: usize = 64;

/// Maximum BYTES of camouflage (non-ParallaX) TLS records that may precede the
/// server's ParallaX key-exchange record on the server->client stream.
///
/// This is the SINGLE source of truth for two values that MUST stay equal across
/// the client and server, because they describe the two ends of the same window:
///
///   * server: the pre-PQ byte ceiling on fallback-origin camouflage forwarded
///     verbatim to the client before the key-exchange is injected
///     (`server::PRE_PQ_FALLBACK_FORWARD_BYTE_LIMIT`), and
///   * client: the residual-skip budget — how many bytes of undecryptable
///     records the client tolerates before it gives up looking for the
///     key-exchange (`MAX_RESIDUAL_CAMOUFLAGE_BYTES_BEFORE_KEY_EXCHANGE` in
///     `crate::client::runtime`).
///
/// The invariant is `client_budget >= server_forward_limit`, measured in the
/// SAME UNIT — bytes. The unit matters as much as the value: the server's
/// verbatim forward preserves the origin's own record segmentation, and real
/// origins split H2 response bodies into many sub-16KiB records, so far more
/// than 64 records fit under this ~1 MiB byte cap. Two past divergences broke
/// the window the same way: the client budget was once 16 records vs the
/// server's 64, and later the client counted 64 RECORDS against the server's
/// ~1 MiB BYTE cap. Either way, on a high-RTT link the camouflage origin's
/// HTTP/2 response body keeps arriving after the TLS handshake completes and
/// leaks past the client's `.complete()` into its residual-skip loop; once the
/// client budget is exhausted before the key-exchange, the client wrongly
/// concludes the peer is not a ParallaX server and aborts with an
/// AEAD/"residual budget" error. That made ~33-75% of fresh handshakes fail
/// from China->Germany while never reproducing on localhost (where the response
/// body does not pile up). Binding both ends to this one byte constant — with
/// the server capping its final pre-PQ read at the remaining budget so it can
/// never overshoot mid-read — keeps the window symmetric by construction.
pub(crate) const MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_BYTES: usize =
    MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_RECORDS
        * (crate::tls::record::MAX_TLS_RECORD_PAYLOAD + crate::tls::record::TLS_HEADER_LEN);

/// Whether `sni` is on the operator's authorized list (case-insensitive exact
/// match). The SINGLE source of truth for the authorized-SNI check across both
/// transports: the TCP plane gates an authenticated ClientHello on it
/// (`server::authenticated_decision`) and the QUIC plane gates a valid auth marker
/// on it (`tls::quic::server::ServerHandshake::process_client_hello`). Keeping one
/// implementation prevents the two transports from drifting into "one strict, one
/// lax" — an unauthorized SNI is fronted to the camouflage origin on both.
pub(crate) fn is_authorized_sni(sni: &str, authorized_sni: &[String]) -> bool {
    authorized_sni
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(sni))
}

#[cfg(test)]
mod tests {
    use super::is_authorized_sni;

    fn list(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn empty_authorized_list_denies_everything() {
        // Fail-closed: with no authorized SNI configured, nothing is authorized
        // (an empty `any(..)` is false). Both transports then front to camouflage.
        assert!(!is_authorized_sni("example.com", &[]));
    }

    #[test]
    fn exact_match_is_authorized_case_insensitively() {
        let allow = list(&["example.com"]);
        assert!(is_authorized_sni("example.com", &allow));
        // TLS SNI is compared case-insensitively (ASCII), matching the DNS/TLS norm.
        assert!(is_authorized_sni("EXAMPLE.COM", &allow));
        assert!(is_authorized_sni("Example.Com", &allow));
    }

    #[test]
    fn substring_or_superstring_is_not_a_match() {
        // The check is EXACT, not substring: a hostname that merely contains or
        // extends an authorized name must not be authorized (otherwise
        // `example.com.attacker.com` or `notexample.com` would slip through).
        let allow = list(&["example.com"]);
        assert!(!is_authorized_sni("example.com.attacker.com", &allow));
        assert!(!is_authorized_sni("notexample.com", &allow));
        assert!(!is_authorized_sni("example.co", &allow));
        assert!(!is_authorized_sni("", &allow));
    }

    #[test]
    fn matches_any_entry_in_a_multi_host_list() {
        let allow = list(&["a.example.com", "b.example.com"]);
        assert!(is_authorized_sni("b.example.com", &allow));
        assert!(!is_authorized_sni("c.example.com", &allow));
    }
}
