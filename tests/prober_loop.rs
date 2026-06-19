//! Active-probe-resistance regression harness for ParallaX's fallback behavior
//! (Phase 2 #3 — probe-robot-in-the-loop).
//!
//! What this is
//! ------------
//! `tests/gfw_simulator.rs` scenarios 6 / 6b feed the simulator's `ActiveProber`
//! **hand-typed** `ProbeObservation` booleans (e.g. `server_replied_with_bytes:
//! true`, `server_response_looks_legitimate: true`). That is a tautology: a
//! regression that made the real server hold the connection, RST it, or return
//! junk to a failed-auth probe would not change those constants, so scenario 6b
//! would keep passing while the product became trivially probe-confirmable.
//!
//! This file removes the constants from the loop. It drives the **real**
//! `parallax::handshake::server::handle_connection` over loopback against a fake
//! camouflage origin, then for each canonical GFW probe family it *measures* the
//! prober-visible response (RST? held open? bytes? do those bytes parse as a TLS
//! ServerHello?), feeds the **measured** `ProbeObservation`s into the simulator's
//! own `ActiveProber`, and asserts the real server is NOT `ConfirmedProxy`.
//!
//! Teeth
//! -----
//! A passing "real server is fine" assertion proves nothing on its own — a
//! classifier wired to always emit benign observations would also pass. So the
//! same measurement + scoring pipeline is run against a deliberately broken
//! `spawn_strawman` server that holds every probe open with no reply (the classic
//! Shadowsocks tell). That MUST score `ConfirmedProxy`. If you "fix" the strawman
//! to splice to the origin like the real server, that assertion fails — which is
//! the point: the harness measures behavior, it does not assert constants.
//! `classify_read` (the read-outcome -> observation-fields mapper) additionally
//! has a standalone unit self-test over the FIN / RST / ServerHello-bytes cases.
//!
//! What it cannot catch
//! --------------------
//! This is a *coarse* behavioral oracle: presence/absence of a RST, a hang, or
//! parseable ServerHello bytes. It deliberately does NOT model fine-grained
//! timing distinguishers (a real prober can fingerprint the *latency profile* of
//! a splice vs. a native origin, or jitter introduced by the fallback dial), nor
//! TCP-layer tells (window scaling, TTL, MSS). A server that returned a perfect
//! ServerHello but with a tell-tale constant 40ms splice delay would pass here.
//! Those distinguishers belong to the passive GFW-simulator detectors, not this
//! active-probe harness.
//!
//! In particular, this harness intentionally normalizes away the *first-record
//! wait*: a probe that sends no ClientHello is held open for the server's full
//! 8–15s give-up window before the camouflage origin's ServerHello is spliced
//! back (see `MEASURE_TIMEOUT`). A real prober could treat "took 12s to answer a
//! bare TCP open" as itself a weak tell. We wait it out and check the *eventual*
//! response is legitimate, because the alternative — flagging a held-open empty
//! connection as a proxy — would also flag every real CDN origin, which holds an
//! idle pre-ClientHello connection open exactly the same way.
//!
//! Test-only: nothing under `src/` is touched and no existing test is weakened.
//! The live-socket tests are `#[ignore]`d to match the loopback-server tests in
//! `src/client/runtime.rs` ("requires loopback TCP sockets"); run them with
//! `cargo test --test prober_loop -- --ignored --test-threads=1`. Each probes
//! concurrently, so each test takes ~one first-record window (~15-18s), not 7x.

mod gfw_sim;

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::SeedableRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use parallax::config::{ServerConfig, TrafficConfig, UdpConfig};
use parallax::crypto::identity;
use parallax::crypto::session::X25519KeyPair;
use parallax::handshake::server;
use parallax::tls::server_hello::parse_server_hello;

use crate::gfw_sim::detection::active_prober::{
    ActiveProber, Probe, ProbeAggregateVerdict, ProbeObservation,
};

/// Shared with the rest of the loopback tests; any 32-byte PSK works because the
/// probes never present a valid authenticator, so they always take the
/// fallback path regardless of its value.
const PSK: &[u8] = b"0123456789abcdef0123456789abcdef";

/// How long `measure_probe` waits for the server's first response byte before it
/// concludes "held open with no reply".
///
/// This must comfortably exceed the live server's *first-record wait* — the
/// window it gives a fresh connection to send a complete ClientHello before it
/// gives up and falls back to the camouflage origin. That window is NOT taken
/// from the `ServerConfig` we build below: `handle_connection` reads it from a
/// process-global `OnceLock` (`server::TIMEOUT_TUNING`) that is only ever
/// installed by `server::run()`, which these tests do not call. So the server
/// uses the built-in default of an 8s floor + up to 7s jitter (max 15s) no
/// matter what `first_record_wait_floor_ms` we set.
///
/// Consequence: the probe families that send a full record (random-bytes /
/// tor-pt / shadowsocks-like) fall back and get spliced *immediately*, but the
/// zero-byte families (EmptyPayload / SshBannerTest / HttpConnectTest, and the
/// empty default `replay`) must wait out that 8–15s before the server dials the
/// origin and the fake origin's ServerHello splices back. 30s gives the worst
/// case (15s wait + dial + localhost splice) generous headroom under CI load so a
/// *legitimate* fallback is never misclassified as a hang. The held-open teeth
/// come from `MEASURE_TIMEOUT` being << infinity (a real hang is caught because
/// the bound elapses), so widening it from a tight 18s is safe. Probes are
/// measured concurrently (see `real_server_resists_active_probes`), so wall-clock
/// cost is ~one window, not seven.
const MEASURE_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// A minimal, syntactically valid TLS 1.3 ServerHello record.
//
// Built inline (the crate's own `server_hello_fixture` lives in a `#[cfg(test)]`
// module and is not reachable from an integration test). Mirrors that fixture's
// shape and is self-checked with `parse_server_hello` before use, so if the
// parser's acceptance criteria ever tighten this constant is caught at the top
// of every run rather than silently producing `looks_legitimate: false`.
// ---------------------------------------------------------------------------

fn make_server_hello() -> Vec<u8> {
    const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
    const TLS_CONTENT_HANDSHAKE: u8 = 0x16;
    const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
    const TLS13_VERSION: u16 = 0x0304;

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&[0x44; 32]); // random
    body.push(32); // session_id len
    body.extend_from_slice(&[0x55; 32]); // echoed session id
    body.extend_from_slice(&[0x13, 0x01]); // cipher_suite TLS_AES_128_GCM_SHA256
    body.push(0); // compression_method = null

    // Single extension: supported_versions -> TLS 1.3.
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
    extensions.extend_from_slice(&2_u16.to_be_bytes()); // ext data len
    extensions.extend_from_slice(&TLS13_VERSION.to_be_bytes());
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(HANDSHAKE_SERVER_HELLO);
    let body_len = body.len() as u32;
    handshake.push(((body_len >> 16) & 0xff) as u8);
    handshake.push(((body_len >> 8) & 0xff) as u8);
    handshake.push((body_len & 0xff) as u8);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(TLS_CONTENT_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x03]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

// ---------------------------------------------------------------------------
// Fake camouflage origin.
//
// CRITICAL: it WRITES the ServerHello immediately on accept, BEFORE reading
// anything. The real server splices the prober straight through to this origin,
// and several probe families (EmptyPayload / SshBannerTest / HttpConnectTest)
// send zero bytes. A read-then-write origin would deadlock those: the origin
// would block on a read that never comes, the prober would block on a read of
// bytes the origin never sends, and the probe would be misclassified as "held".
// Writing first makes the origin behave like a CDN that greets every TCP
// connection with a ServerHello (which is what TLS 1.3 servers do once the
// ClientHello arrives — here the ClientHello is the spliced probe bytes, but for
// the empty probes we greet unconditionally so the measurement still resolves).
// ---------------------------------------------------------------------------

async fn spawn_fallback_origin() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let server_hello = make_server_hello();
    // Self-check the bytes parse before any test relies on them.
    assert!(
        parse_server_hello(&server_hello).is_ok(),
        "fake origin's ServerHello must parse, else the harness's \
         looks_legitimate signal is meaningless"
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        // Serve every probe (the prober may open several connections).
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let server_hello = server_hello.clone();
            tokio::spawn(async move {
                // Greet first so empty-payload probes still see bytes.
                if stream.write_all(&server_hello).await.is_err() {
                    return;
                }
                let _ = stream.flush().await;
                // Then drain whatever the probe sends until it closes, so the
                // server-side splice reaches a clean EOF rather than a RST.
                let mut buf = [0_u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
        }
    });
    (addr, task)
}

// ---------------------------------------------------------------------------
// Live ParallaX server: the real handle_connection over loopback.
// ---------------------------------------------------------------------------

fn live_server_config(fallback_addr: SocketAddr) -> ServerConfig {
    let server_keys = X25519KeyPair::generate();
    let server_identity_keys = identity::keypair();
    let replay_dir = tempfile::tempdir().unwrap();
    let replay_cache_path = replay_dir.path().join("parallax-replay.cache");
    // Keep the tempdir alive for the process: leak it (test-only). Dropping it
    // would unlink the path, but the no-replay handle_connection path never
    // opens it, so this is belt-and-suspenders.
    std::mem::forget(replay_dir);

    ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        fallback_addr: fallback_addr.to_string(),
        // No fixed data_target: irrelevant here, every probe fails auth and
        // takes the fallback splice before data mode is ever reached.
        data_target: None,
        private_key: STANDARD.encode(server_keys.private),
        identity_secret_key: STANDARD.encode(&server_identity_keys.secret),
        replay_cache_path,
        // DEFAULT_REPLAY_CACHE_CAPACITY is pub(crate); a literal is fine since
        // the replay cache is not constructed on this code path.
        replay_cache_capacity: 49_152,
        authorized_sni: vec![String::from("example.com")],
        strict_tls13: true,
        max_concurrent_per_source_v4: 256,
        max_concurrent_per_source_v6: 256,
        source_ipv6_prefix_len: 64,
        // NOTE: these first-record knobs are effectively ignored here.
        // `handle_connection` reads the first-record wait from the process-global
        // `server::TIMEOUT_TUNING` (a OnceLock installed only by `server::run()`,
        // which these tests do not call), so the server uses the built-in default
        // 8s floor + 7s jitter regardless of what we set. We populate the fields
        // with the production-style values for documentation/realism; `MEASURE_
        // TIMEOUT` is sized against the actual 8–15s default, not these numbers.
        first_record_wait_floor_ms: 8_000,
        first_record_wait_jitter_ms: 7_000,
        fallback_idle_floor_ms: 600_000,
        fallback_idle_jitter_ms: 0,
        tcp_congestion: None,
    }
}

/// Bind a real ParallaX server on loopback and serve every accepted connection
/// through `handle_connection`. Returns its address; the accept loop runs until
/// the returned task is dropped at end of test.
async fn spawn_live_parallax(
    fallback_addr: SocketAddr,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let config = live_server_config(fallback_addr);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let config = config.clone();
            tokio::spawn(async move {
                // A fallback splice that the probe closes mid-stream surfaces as
                // an Err; that is an expected teardown, not a test failure.
                let _ = server::handle_connection(
                    stream,
                    &config,
                    TrafficConfig::default(),
                    &UdpConfig::default(),
                    PSK,
                )
                .await;
            });
        }
    });
    (addr, task)
}

// ---------------------------------------------------------------------------
// Strawman: a deliberately broken server that gives the harness teeth.
//
// It accepts and then holds every connection open without ever replying — the
// canonical "Shadowsocks waiting for more input" tell. Measured + scored, this
// MUST come out `ConfirmedProxy`. Flip it to splice to the origin and the teeth
// assertion fails, proving the verdict tracks behavior, not a constant.
// ---------------------------------------------------------------------------

async fn spawn_strawman() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            match listener.accept().await {
                Ok((stream, _)) => held.push(stream), // keep open, send nothing
                Err(_) => return,
            }
        }
    });
    (addr, task)
}

// ---------------------------------------------------------------------------
// Read-outcome classifier (pure, unit-tested) + the live measurement.
// ---------------------------------------------------------------------------

/// What a single bounded read of the server's response yielded.
#[derive(Debug, Clone, PartialEq)]
enum ReadOutcome {
    /// `read()` returned >=1 byte; carries the prefix actually read.
    Bytes(Vec<u8>),
    /// `read()` returned Ok(0): a clean FIN/EOF with no application bytes.
    Eof,
    /// `read()` errored with ConnectionReset (the peer RST'd).
    Reset,
    /// The bounded timeout elapsed with no byte and no EOF: held open.
    HeldOpen,
}

/// The measured fields a `ReadOutcome` maps to. Pure so it can be unit-tested
/// without sockets — this is the classifier whose correctness the whole harness
/// rests on.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Classification {
    held: bool,
    bytes: bool,
    looks_legit: bool,
    reset: bool,
}

fn classify_read(outcome: &ReadOutcome) -> Classification {
    match outcome {
        ReadOutcome::Bytes(buf) => Classification {
            held: false,
            bytes: true,
            looks_legit: parse_server_hello(buf).is_ok(),
            reset: false,
        },
        ReadOutcome::Eof => Classification {
            held: false,
            bytes: false,
            looks_legit: false,
            reset: false,
        },
        ReadOutcome::Reset => Classification {
            held: false,
            bytes: false,
            looks_legit: false,
            reset: true,
        },
        ReadOutcome::HeldOpen => Classification {
            held: true,
            bytes: false,
            looks_legit: false,
            reset: false,
        },
    }
}

/// Connect to `addr`, send the probe's payload (zero bytes for the open-only
/// probes), then perform one bounded read and classify the outcome into a
/// `ProbeObservation` the simulator's `ActiveProber` can score.
async fn measure_probe(addr: SocketAddr, probe: &Probe, label: &'static str) -> ProbeObservation {
    let started = Instant::now();
    let mut stream = TcpStream::connect(addr).await.expect("probe connect");

    if let Some(payload) = probe.payload() {
        // Best-effort: a server that RSTs on the payload write is itself a
        // measurement (the read below will surface it).
        let _ = stream.write_all(payload).await;
        let _ = stream.flush().await;
    }

    let mut buf = vec![0_u8; 8192];
    let outcome = match timeout(MEASURE_TIMEOUT, stream.read(&mut buf)).await {
        Ok(Ok(0)) => ReadOutcome::Eof,
        Ok(Ok(n)) => ReadOutcome::Bytes(buf[..n].to_vec()),
        Ok(Err(e)) if e.kind() == ErrorKind::ConnectionReset => ReadOutcome::Reset,
        // A non-reset IO error on read (e.g. broken pipe) is, for the prober's
        // purposes, the connection going away without a believable reply.
        Ok(Err(_)) => ReadOutcome::Eof,
        Err(_) => ReadOutcome::HeldOpen,
    };
    let delay = started.elapsed();
    let c = classify_read(&outcome);

    ProbeObservation {
        probe_label: label,
        server_held_connection: c.held,
        server_replied_with_bytes: c.bytes,
        server_response_looks_legitimate: c.looks_legit,
        server_immediately_reset: c.reset,
        delay,
    }
}

/// The canonical GFW probe families, each with a stable label for diagnostics.
/// Covers every `Probe` variant the default prober uses.
fn probe_battery() -> Vec<(&'static str, Probe)> {
    // Seed the shadowsocks probe RNG deterministically so the battery is
    // reproducible run-to-run (thread_rng would vary the random payload).
    let mut rng = rand::rngs::StdRng::seed_from_u64(2);
    vec![
        ("random-bytes", Probe::random_bytes_with_seed(1, 64)),
        ("tor-pt", Probe::tor_pt_client_hello()),
        ("replay-empty", Probe::replay(vec![])),
        ("empty-payload", Probe::EmptyPayload),
        (
            "shadowsocks-like",
            Probe::shadowsocks_like(&mut rng, 32, 96),
        ),
        ("ssh-banner", Probe::ssh_banner_test()),
        ("http-connect", Probe::http_connect_test("example.com:443")),
    ]
}

/// Measure the whole probe battery against `addr` concurrently (one TCP
/// connection per probe, all in flight at once — what a real probe robot does).
/// Concurrency is what keeps wall-clock at ~one `MEASURE_TIMEOUT` rather than
/// `7 * MEASURE_TIMEOUT`, since the zero-byte families each sit through the
/// server's multi-second first-record wait. Results come back in `probe_battery`
/// order so failure messages are stable.
async fn measure_all(addr: SocketAddr) -> Vec<ProbeObservation> {
    let handles: Vec<_> = probe_battery()
        .into_iter()
        .map(|(label, probe)| tokio::spawn(async move { measure_probe(addr, &probe, label).await }))
        .collect();

    let mut observations = Vec::with_capacity(handles.len());
    for handle in handles {
        observations.push(handle.await.expect("probe measurement task panicked"));
    }
    observations
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Unit self-test of the classifier itself (no sockets). Proves the FIN / RST /
/// ServerHello-bytes / held cases map to the expected observation fields, so a
/// later regression in `classify_read` can't make the live tests vacuously pass.
#[test]
fn classifier_maps_read_outcomes_to_observation_fields() {
    // Real ServerHello bytes -> replied + legitimate.
    let sh = make_server_hello();
    let legit = classify_read(&ReadOutcome::Bytes(sh));
    assert!(legit.bytes && legit.looks_legit && !legit.held && !legit.reset);

    // Junk bytes -> replied but NOT legitimate (this is the regression a real
    // server returning garbage would trip).
    let junk = classify_read(&ReadOutcome::Bytes(vec![0xde, 0xad, 0xbe, 0xef]));
    assert!(junk.bytes && !junk.looks_legit && !junk.held && !junk.reset);

    // Clean FIN with no bytes -> silent close: not held, not bytes, not reset.
    let eof = classify_read(&ReadOutcome::Eof);
    assert!(!eof.held && !eof.bytes && !eof.looks_legit && !eof.reset);

    // RST -> reset only.
    let rst = classify_read(&ReadOutcome::Reset);
    assert!(rst.reset && !rst.bytes && !rst.looks_legit && !rst.held);

    // Timeout -> held open with no reply (the Shadowsocks tell).
    let held = classify_read(&ReadOutcome::HeldOpen);
    assert!(held.held && !held.bytes && !held.looks_legit && !held.reset);
}

/// Sanity: the strawman's held-open behavior, run through the SAME measurement
/// and scoring pipeline as the real server, MUST be `ConfirmedProxy`. This is
/// the teeth: if it weren't, the real-server assertion below would be vacuous.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback TCP sockets"]
async fn strawman_is_confirmed_proxy() {
    let (straw_addr, straw_task) = spawn_strawman().await;

    let observations = measure_all(straw_addr).await;

    // Every probe should have been held open with no reply.
    let held = observations
        .iter()
        .filter(|o| o.server_held_connection && !o.server_replied_with_bytes)
        .count();
    assert!(
        held >= 3,
        "strawman should hold >=3 probes open with no reply (got {held}); \
         observations: {observations:#?}"
    );

    let agg = ActiveProber::with_default_probes().score_observations(&observations);
    assert_eq!(
        agg.verdict,
        ProbeAggregateVerdict::ConfirmedProxy,
        "a hold-open-no-reply server MUST be confirmed; if you made the strawman \
         behave correctly this assertion is SUPPOSED to fail. aggregate: {agg:#?}"
    );

    straw_task.abort();
}

/// The real harness: drive the REAL `handle_connection` against a fake
/// camouflage origin, MEASURE each probe's prober-visible response, and assert
/// the measured observations do NOT score `ConfirmedProxy`. Replaces the
/// hand-typed booleans of `gfw_simulator.rs` scenario 6b with measured values.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback TCP sockets"]
async fn real_server_resists_active_probes() {
    let (origin_addr, origin_task) = spawn_fallback_origin().await;
    let (parallax_addr, parallax_task) = spawn_live_parallax(origin_addr).await;

    let observations = measure_all(parallax_addr).await;

    for obs in &observations {
        let label = obs.probe_label;
        // Per-probe behavioral invariants the real server must satisfy:
        // (1) it must never hold a probe open with no eventual reply (the
        //     Shadowsocks tell — note `MEASURE_TIMEOUT` waits out the full
        //     first-record window, so a legitimate slow fallback is NOT a hang),
        //     and (2) it must never RST a failed-auth probe (a raw-proxy tell —
        //     the fallback splice yields a graceful close, not a RST).
        let held_with_no_reply = obs.server_held_connection && !obs.server_replied_with_bytes;
        assert!(
            !held_with_no_reply,
            "probe {label}: real server held the connection open with no reply \
             within {MEASURE_TIMEOUT:?} (Shadowsocks tell) — regression. obs: {obs:#?}"
        );
        assert!(
            !obs.server_immediately_reset,
            "probe {label}: real server RST the connection (raw-proxy tell) \
             instead of gracefully splicing/closing — regression. obs: {obs:#?}"
        );
        // (3) PRESENCE of the camouflage signal: the server must actually return a
        // legitimate (parseable) ServerHello within the window. Asserting only the
        // ABSENCE of bad tells (held/reset) above is insufficient — a regression
        // where the server silently FINs every failed-auth probe (stops splicing to
        // the camouflage origin) would leave held=false/reset=false and merely
        // score ~0.40 < 0.45 -> Inconclusive, so the `assert_ne!(ConfirmedProxy)`
        // below would still pass. A silent FIN or unparseable bytes is itself an
        // active-probe tell, so require the positive signal here.
        assert!(
            obs.server_replied_with_bytes && obs.server_response_looks_legitimate,
            "probe {label}: real server did not return a legitimate camouflage \
             ServerHello within {MEASURE_TIMEOUT:?} — silent FIN or unparseable \
             bytes is itself an active-probe tell. obs: {obs:#?}"
        );
    }

    let agg = ActiveProber::with_default_probes().score_observations(&observations);
    assert_ne!(
        agg.verdict,
        ProbeAggregateVerdict::ConfirmedProxy,
        "the REAL server's MEASURED probe responses were scored ConfirmedProxy \
         — the fallback camouflage is not resisting active probing. \
         observations: {observations:#?}; aggregate: {agg:#?}"
    );

    parallax_task.abort();
    origin_task.abort();
}
