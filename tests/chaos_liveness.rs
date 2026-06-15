//! Chaos liveness harness (Phase 3 #5, Part 2).
//!
//! Proves that the REAL server entry point
//! `parallax::handshake::server::handle_connection` TERMINATES — and therefore
//! releases its task, admission permits and fds (all RAII-bound to the task) —
//! within a bounded wall-clock time when the client misbehaves. A hang (an
//! unbounded inbound-read loop) would make the `tokio::time::timeout` below
//! elapse, turning the test RED: that is exactly the missing-timeout DoS class.
//!
//! This is the dynamic companion to the static `no_timeout_ratchet.rs` guard:
//! the ratchet stops a *new* untimed read loop from being added; this proves the
//! reachable teardown paths actually terminate under byzantine input.
//!
//! Design notes (why these specific faults):
//!   * Every fault sends its bytes (if any) and then CLOSES the client (FIN).
//!     An EOF ends `read_first_client_record` immediately, so none of these
//!     cases parks on the ~8s first-record-wait floor, and the client FIN tears
//!     down the fallback relay's client->origin direction promptly — so none
//!     parks on the ~600s relay idle timeout either. Each case completes well
//!     under a second; the generous 10s bound only fires on a genuine
//!     (unbounded / ~600s) hang.
//!   * The fallback origin accepts and immediately closes, so the relay's
//!     origin->client direction also EOFs promptly.
//!
//! Test-only: drives the server purely through public APIs; no `src/` change.
//! Live-socket tests are `#[ignore]`d to match the repo's loopback convention.

use std::net::SocketAddr;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use parallax::config::{ServerConfig, TrafficConfig, UdpConfig};
use parallax::crypto::{identity, pq, session::X25519KeyPair};
use parallax::handshake::server;

const PSK: &[u8] = b"0123456789abcdef0123456789abcdef";

/// Generous ceiling: every fault below completes in well under a second, so this
/// only elapses on a real unbounded hang (the ~600s relay idle path or an
/// infinite untimed loop). Kept below the 600s relay idle so such a hang is
/// caught, and above the 8s first-record floor so a (avoided) floor wait would
/// not flake.
const TERMINATE_BOUND: Duration = Duration::from_secs(10);

/// A real Safari 26 ClientHello capture — a *complete*, well-formed TLS record
/// that is unauthenticated against this test server's freshly-generated keys, so
/// `decide_inbound` routes it to the fallback splice (exercising the post-decide
/// relay teardown rather than the early prefix path).
const REAL_CLIENT_HELLO: &[u8] = include_bytes!("fixtures/safari26_apple_com_clienthello.bin");

/// Build the same real `ServerConfig` shape the production server runs with
/// (fresh keys, a leaked tempdir replay path). Mirrors the proven setup in
/// `tests/prober_loop.rs` / `src/client/runtime.rs` tests.
fn live_server_config(fallback_addr: SocketAddr) -> ServerConfig {
    let server_keys = X25519KeyPair::generate();
    let server_pq_keys = pq::keypair();
    let server_identity_keys = identity::keypair();
    let replay_dir = tempfile::tempdir().unwrap();
    let replay_cache_path = replay_dir.path().join("parallax-replay.cache");
    // Leak the tempdir (test-only): the no-replay handle_connection fallback path
    // never opens it, but this keeps the path valid for the whole process.
    std::mem::forget(replay_dir);

    ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        fallback_addr: fallback_addr.to_string(),
        data_target: None,
        private_key: STANDARD.encode(server_keys.private),
        pq_secret_key: STANDARD.encode(&server_pq_keys.secret),
        identity_secret_key: STANDARD.encode(&server_identity_keys.secret),
        replay_cache_path,
        replay_cache_capacity: 49_152,
        authorized_sni: vec![String::from("example.com")],
        strict_tls13: true,
        max_concurrent_per_source_v4: 256,
        max_concurrent_per_source_v6: 256,
        source_ipv6_prefix_len: 64,
        first_record_wait_floor_ms: 8_000,
        first_record_wait_jitter_ms: 7_000,
        fallback_idle_floor_ms: 600_000,
        fallback_idle_jitter_ms: 0,
        tcp_congestion: None,
    }
}

/// A fake fallback origin: accept every dial and immediately close it (drop the
/// stream -> FIN). That makes the server's fallback relay see an origin EOF and
/// tear down promptly, so a fault that reaches the splice still terminates fast.
async fn spawn_closing_origin() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => drop(stream),
                Err(_) => return,
            }
        }
    });
    (addr, task)
}

/// Bind a server on loopback, accept ONE connection, run the real
/// `handle_connection` on it, and return the address plus the JoinHandle of that
/// handler task. The test asserts the handle completes within the bound.
async fn spawn_one_shot_server(
    fallback_addr: SocketAddr,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let config = live_server_config(fallback_addr);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept chaos client");
        // Either Ok (clean fallback teardown) or Err (relay closed mid-stream) is
        // fine — both mean the task RETURNED, releasing its permits/fds. Only a
        // hang (never returning) is a failure, and that is what the outer
        // timeout detects.
        let _ = server::handle_connection(
            stream,
            &config,
            TrafficConfig::default(),
            &UdpConfig::default(),
            PSK,
        )
        .await;
    });
    (addr, handle)
}

/// How the chaos client delivers its (optional) payload before closing.
enum Delivery {
    /// Write the whole payload at once, then FIN.
    AllAtOnce,
    /// Drip one byte at a time with a small gap, then FIN (fragmented reads).
    Drip,
}

/// Connect, deliver `payload` per `delivery`, FIN, then assert the server's
/// `handle_connection` task terminates within `TERMINATE_BOUND`.
async fn assert_terminates(label: &str, payload: &[u8], delivery: Delivery) {
    let (origin_addr, origin_task) = spawn_closing_origin().await;
    let (server_addr, server_handle) = spawn_one_shot_server(origin_addr).await;

    let mut client = TcpStream::connect(server_addr)
        .await
        .expect("connect chaos client");
    match delivery {
        Delivery::AllAtOnce => {
            if !payload.is_empty() {
                let _ = client.write_all(payload).await;
            }
        }
        Delivery::Drip => {
            for byte in payload {
                if client.write_all(&[*byte]).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        }
    }
    // FIN: signal end-of-stream and drop the socket.
    let _ = client.shutdown().await;
    drop(client);

    let outcome = tokio::time::timeout(TERMINATE_BOUND, server_handle).await;
    assert!(
        outcome.is_ok(),
        "[{label}] handle_connection did NOT terminate within {TERMINATE_BOUND:?} \
         after a client fault — an unbounded inbound-read loop (DoS) is the likely cause"
    );
    // Surface a panic inside the handler task as a test failure too.
    outcome.unwrap().expect("handle_connection task panicked");

    origin_task.abort();
}

/// META-TEST (teeth for the liveness detector): a task that never completes MUST
/// trip the timeout-based detector. Without this, a green chaos result could
/// mean "the detector is broken" rather than "the server terminated". Fast,
/// not ignored.
#[tokio::test]
async fn liveness_timeout_detects_a_hang() {
    let hang = tokio::spawn(async { std::future::pending::<()>().await });
    let outcome = tokio::time::timeout(Duration::from_millis(100), hang).await;
    assert!(
        outcome.is_err(),
        "the liveness detector must report a never-completing task as a hang"
    );
}

/// The chaos battery: each byzantine client fault must leave `handle_connection`
/// terminating within the bound. A regression that drops a timeout on a
/// reachable inbound-read loop would hang one of these and turn the build RED.
#[tokio::test]
#[ignore = "requires loopback TCP sockets"]
async fn handle_connection_terminates_under_client_faults() {
    // 1. Connect then immediately close, never sending a byte (immediate EOF).
    assert_terminates("abrupt_close_no_data", &[], Delivery::AllAtOnce).await;

    // 2. A partial TLS record header, then EOF (incomplete first record).
    assert_terminates(
        "partial_record_then_close",
        &[0x16, 0x03, 0x01, 0x05],
        Delivery::AllAtOnce,
    )
    .await;

    // 3. Non-TLS garbage, then EOF.
    assert_terminates(
        "garbage_then_close",
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\njunk-bytes-not-tls",
        Delivery::AllAtOnce,
    )
    .await;

    // 4. A complete, well-formed but unauthenticated ClientHello, then EOF:
    //    decide_inbound -> Fallback(AuthFailed) -> fallback splice -> teardown.
    assert_terminates(
        "full_unauth_clienthello_then_close",
        REAL_CLIENT_HELLO,
        Delivery::AllAtOnce,
    )
    .await;

    // 5. A short prefix dripped one byte at a time (fragmented reads), then EOF.
    //    Kept short so it never approaches the 8s first-record floor.
    assert_terminates(
        "dripped_prefix_then_close",
        &[0x16, 0x03, 0x01, 0x05, 0xf7],
        Delivery::Drip,
    )
    .await;
}
