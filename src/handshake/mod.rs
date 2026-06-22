pub mod client;
pub mod server;
pub mod source_limit;
pub mod transcript;

/// Maximum number of camouflage (non-ParallaX) TLS records that may precede the
/// server's ParallaX key-exchange record on the server->client stream.
///
/// This is the SINGLE source of truth for two values that MUST stay equal across
/// the client and server, because they describe the two ends of the same window:
///
///   * server: the pre-PQ cap on fallback-origin records forwarded to the client
///     before the key-exchange is injected
///     (`server::PRE_PQ_FALLBACK_FORWARD_RECORD_LIMIT`), and
///   * client: the residual-skip budget — how many undecryptable records the
///     client tolerates before it gives up looking for the key-exchange
///     (`MAX_RESIDUAL_CAMOUFLAGE_RECORDS_BEFORE_KEY_EXCHANGE` in
///     `crate::client::runtime`).
///
/// The invariant is `client_budget >= server_forward_limit`: the server may push
/// up to this many camouflage records, so the client must be willing to skip at
/// least that many. Before this constant existed they diverged (client 16 vs
/// server 64). On a high-RTT link the camouflage origin's HTTP/2 response body
/// keeps arriving after the TLS handshake completes and leaks past the client's
/// `.complete()` into its residual-skip loop; when more than the client budget of
/// those records arrive before the key-exchange, the client wrongly concludes the
/// peer is not a ParallaX server and aborts with an AEAD/"residual budget" error.
/// That made ~33-75% of fresh handshakes fail from China->Germany while never
/// reproducing on localhost (where the response body does not pile up). Binding
/// both ends to one constant keeps the window symmetric by construction.
pub(crate) const MAX_PRE_KEY_EXCHANGE_CAMOUFLAGE_RECORDS: usize = 64;
