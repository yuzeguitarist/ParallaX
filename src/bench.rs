//! ParallaX protocol benchmark suite.
//!
//! CPU-only, fixed-parameter performance baseline for the entire protocol.
//! Every case, payload size, and iteration count is intentionally hard-coded
//! so that numbers stay comparable across releases and act as a long-lived
//! performance contract. Run the suite with `plx bench`; pair with `--json`
//! for machine-readable output or `--quick` for a smoke run that fits in CI.
//!
//! Design notes:
//!
//! * 23 cases across six groups exercise the asymmetric primitives, KDFs,
//!   handshake composition, application-data AEAD pipeline, traffic shaping,
//!   and replay-cache bookkeeping that dominate ParallaX's wall-clock cost.
//! * Each case declares an iteration [`Tier`]. Tiers are static constants so
//!   the trade-off between accuracy and total wall-time is auditable from a
//!   single source location.
//! * Errors propagate via `?`; no fallback branches, no silent suppression.

use std::{
    fmt::Write as _,
    hint::black_box,
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use rand::{rngs::StdRng, SeedableRng};

use crate::{
    crypto::{
        auth::{derive_client_auth_key, derive_server_auth_key, verify_client_hello_auth},
        identity, pq,
        replay::{ReplayCache, ReplayEntry},
        session::{
            derive_client_keys, x25519_shared_secret, AeadCodec, X25519KeyPair, KEY_LEN, NONCE_LEN,
        },
    },
    protocol::data::{DataRecordCodec, SealedRecord, CLIENT_TO_SERVER_AAD},
    tls::{
        client_hello::parse_client_hello,
        client_hello_builder::{BrowserProfile, ClientHelloTemplate},
    },
    traffic::PaddingProfile,
};

/// Pre-shared key used by every handshake-flavoured benchmark.
///
/// Exactly 32 bytes — matches the canonical ParallaX PSK length — so that the
/// HMAC/HKDF code paths run with realistic key material rather than a stub.
const BENCH_PSK: &[u8] = b"ParallaX-bench-psk-32bytes-fixed";
/// SNI used by ClientHello-related benchmarks.
const BENCH_SNI: &str = "example.com";
/// Deterministic seed for every benchmark that consumes pseudo-random bytes,
/// chosen so timings are reproducible across runs.
const RNG_SEED: u64 = 0x504c_5842_5f42_454e; // "PLXB_BEN"

/// Canonical payload sizes used by the symmetric and pipeline benchmarks.
const SIZE_64B: usize = 64;
const SIZE_1K: usize = 1024;
const SIZE_16K: usize = 16 * 1024;
const SIZE_1M: usize = 1024 * 1024;

/// Padding profile applied to every [`DataRecordCodec`] benchmark. Fixed at
/// the ParallaX-default 0..1500 envelope so record sizes (and the resulting
/// throughput numbers) stay stable as long as the protocol does.
const RECORD_PADDING_MIN: u16 = 0;
const RECORD_PADDING_MAX: u16 = 1500;

/// Iteration / warmup pair for one benchmark case.
///
/// Tiers are declared as constants so each case's accuracy/time trade-off is
/// visible in one place and easy to audit alongside the case list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tier {
    iterations: u64,
    warmup: u64,
}

/// Sub-microsecond hot path: HMAC, padding apply/remove, tiny AEAD seals.
const TIER_HOT: Tier = Tier {
    iterations: 100_000,
    warmup: 5_000,
};
/// Single-digit microseconds: HKDF, ClientHello parse, AEAD on small records.
const TIER_FAST: Tier = Tier {
    iterations: 10_000,
    warmup: 500,
};
/// Tens of microseconds: X25519, ML-KEM, larger AEAD, ClientHello build.
const TIER_MEDIUM: Tier = Tier {
    iterations: 2_000,
    warmup: 100,
};
/// Hundreds of microseconds: ML-DSA-87 keygen/sign/verify.
const TIER_SLOW: Tier = Tier {
    iterations: 200,
    warmup: 20,
};
/// Millisecond-scale bulk-data round-trips.
const TIER_BULK: Tier = Tier {
    iterations: 50,
    warmup: 5,
};

/// Smoke profile divides every tier's iteration count by this factor so that
/// `cargo test` and CI runs complete in a couple of seconds.
const QUICK_SCALE: u64 = 100;
/// Floor for quick-mode iteration counts so even rounded-down tiers still
/// exercise the code path more than once.
const QUICK_MIN_ITERATIONS: u64 = 2;

/// Top-level configuration for [`run`].
///
/// Deliberately minimal: a stable suite must not expose tuning knobs that
/// would let the operator silently change the baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BenchmarkOptions {
    /// When set, run the smoke profile rather than the full suite.
    pub quick: bool,
}

impl BenchmarkOptions {
    /// Full benchmark suite with the canonical iteration counts.
    pub fn standard() -> Self {
        Self { quick: false }
    }

    /// Smoke profile that runs every case with [`QUICK_SCALE`]-reduced
    /// iteration counts. Intended for unit tests and CI smoke runs.
    pub fn quick() -> Self {
        Self { quick: true }
    }
}

/// Logical grouping for related cases. Reported alongside the case name so
/// JSON consumers can roll up timings by subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BenchGroup {
    /// Asymmetric primitives and KDF building blocks.
    HandshakeCrypto,
    /// Composed handshake operations (ClientHello build/parse/verify).
    HandshakeProtocol,
    /// Raw AEAD seal/open at fixed payload sizes.
    RecordAead,
    /// Full application-data record pipeline including padding shaping.
    RecordPipeline,
    /// Traffic shaping helpers exercised standalone.
    Traffic,
    /// Replay cache and other state-tracking primitives.
    State,
}

impl BenchGroup {
    /// Stable dotted label used in textual output and the JSON `group` field.
    pub fn label(self) -> &'static str {
        match self {
            BenchGroup::HandshakeCrypto => "handshake.crypto",
            BenchGroup::HandshakeProtocol => "handshake.protocol",
            BenchGroup::RecordAead => "record.aead",
            BenchGroup::RecordPipeline => "record.pipeline",
            BenchGroup::Traffic => "traffic",
            BenchGroup::State => "state",
        }
    }
}

/// Result of timing one benchmark case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchmarkCase {
    pub group: BenchGroup,
    pub name: &'static str,
    pub iterations: u64,
    pub warmup: u64,
    pub elapsed: Duration,
    pub processed_bytes: u64,
}

impl BenchmarkCase {
    /// `<group>.<name>` for table output and JSON consumers that want a flat
    /// identifier per case.
    pub fn full_name(&self) -> String {
        format!("{}.{}", self.group.label(), self.name)
    }

    /// Mean operation cost in nanoseconds.
    pub fn ns_per_op(&self) -> f64 {
        if self.iterations == 0 {
            return 0.0;
        }
        self.elapsed.as_nanos() as f64 / self.iterations as f64
    }

    /// Operations completed per second.
    pub fn ops_per_second(&self) -> f64 {
        self.iterations as f64 / seconds(self.elapsed)
    }

    /// Throughput in MiB/sec, or zero for cases that don't process payload
    /// bytes (handshake setup, KDF, etc.).
    pub fn mib_per_second(&self) -> f64 {
        if self.processed_bytes == 0 {
            return 0.0;
        }
        (self.processed_bytes as f64 / (1024.0 * 1024.0)) / seconds(self.elapsed)
    }
}

/// Aggregate benchmark output for a single invocation of [`run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchmarkReport {
    pub options: BenchmarkOptions,
    pub cases: Vec<BenchmarkCase>,
    pub total_elapsed: Duration,
}

impl BenchmarkReport {
    /// Human-readable table covering every case plus a trailing total.
    pub fn to_text(&self) -> String {
        let mode = if self.options.quick {
            "quick"
        } else {
            "standard"
        };
        let mut out = String::new();
        let _ = writeln!(
            out,
            "ParallaX benchmark v1 ({} mode, {} cases)",
            mode,
            self.cases.len(),
        );
        let _ = writeln!(
            out,
            "{:<18}  {:<28}  {:>10}  {:>14}  {:>14}  {:>10}",
            "group", "case", "iters", "ns/op", "ops/sec", "MiB/sec",
        );
        for case in &self.cases {
            let mib_label = if case.processed_bytes == 0 {
                "-".to_string()
            } else {
                format!("{:.2}", case.mib_per_second())
            };
            let _ = writeln!(
                out,
                "{:<18}  {:<28}  {:>10}  {:>14.0}  {:>14.1}  {:>10}",
                case.group.label(),
                case.name,
                case.iterations,
                case.ns_per_op(),
                case.ops_per_second(),
                mib_label,
            );
        }
        let _ = writeln!(out, "total_elapsed={}", format_duration(self.total_elapsed));
        out
    }

    /// Compact JSON document describing the run and every case.
    ///
    /// The schema is stable so external dashboards can diff numbers across
    /// releases without breaking. All field names — group labels, case names
    /// — are static identifiers controlled by this module, so no escaping is
    /// required for the JSON encoding.
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        let _ = write!(
            out,
            "{{\"version\":1,\"quick\":{},\"total_elapsed_ns\":{},\"cases\":[",
            self.options.quick,
            self.total_elapsed.as_nanos(),
        );
        for (idx, case) in self.cases.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                "{{\"group\":\"{}\",\"name\":\"{}\",\"iterations\":{},\"warmup\":{},\"elapsed_ns\":{},\"ns_per_op\":{:.4},\"ops_per_second\":{:.4},\"processed_bytes\":{},\"mib_per_second\":{:.4}}}",
                case.group.label(),
                case.name,
                case.iterations,
                case.warmup,
                case.elapsed.as_nanos(),
                case.ns_per_op(),
                case.ops_per_second(),
                case.processed_bytes,
                case.mib_per_second(),
            );
        }
        out.push_str("]}");
        out
    }
}

/// Function pointer type used by [`CASES`] so the suite is a flat,
/// inspectable table rather than ad-hoc code in [`run`].
type CaseRunner = fn(BenchmarkOptions) -> Result<BenchmarkCase>;

/// Canonical ordered list of benchmark cases.
///
/// Adding a case here changes the baseline schema, so it should be treated as
/// a deliberate, reviewed action — this is the source of the "hard standard"
/// the benchmark suite advertises.
const CASES: &[CaseRunner] = &[
    bench_x25519_keypair,
    bench_x25519_dh,
    bench_mlkem_keypair,
    bench_mlkem_encapsulate,
    bench_mlkem_decapsulate,
    bench_mldsa_keypair,
    bench_mldsa_sign,
    bench_mldsa_verify,
    bench_hkdf_session_keys,
    bench_hkdf_hybrid_rekey,
    bench_clienthello_build_signed,
    bench_clienthello_parse,
    bench_clienthello_verify_auth,
    bench_aead_seal_64b,
    bench_aead_seal_1k,
    bench_aead_seal_16k,
    bench_aead_round_trip_1k,
    bench_record_seal_1k,
    bench_record_round_trip_1k,
    bench_record_bulk_1mb,
    bench_padding_apply_1k,
    bench_padding_remove_1k,
    bench_replay_cache_insert,
];

/// Run the full benchmark suite and collect a report.
///
/// Errors fail the entire run — there is no per-case fallback. This is
/// intentional: a benchmark that silently degrades to "skipped" hides
/// regressions instead of surfacing them.
pub fn run(options: BenchmarkOptions) -> Result<BenchmarkReport> {
    let start = Instant::now();
    let mut cases = Vec::with_capacity(CASES.len());
    for runner in CASES {
        cases.push(runner(options)?);
    }
    Ok(BenchmarkReport {
        options,
        cases,
        total_elapsed: start.elapsed(),
    })
}

// ---------------------------------------------------------------------------
// handshake.crypto
// ---------------------------------------------------------------------------

fn bench_x25519_keypair(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    run_case(
        BenchGroup::HandshakeCrypto,
        "x25519.keypair",
        TIER_MEDIUM,
        options,
        || {
            let pair = X25519KeyPair::generate();
            Ok(black_box(pair.public.len() as u64))
        },
    )
}

fn bench_x25519_dh(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let alice = X25519KeyPair::generate();
    let bob = X25519KeyPair::generate();
    run_case(
        BenchGroup::HandshakeCrypto,
        "x25519.dh",
        TIER_MEDIUM,
        options,
        || {
            let shared = x25519_shared_secret(&alice.private, &bob.public);
            Ok(black_box(shared.len() as u64))
        },
    )
}

fn bench_mlkem_keypair(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    run_case(
        BenchGroup::HandshakeCrypto,
        "mlkem.keypair",
        TIER_MEDIUM,
        options,
        || {
            let pair = pq::keypair();
            Ok(black_box((pair.public.len() + pair.secret.len()) as u64))
        },
    )
}

fn bench_mlkem_encapsulate(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let keys = pq::keypair();
    run_case(
        BenchGroup::HandshakeCrypto,
        "mlkem.encapsulate",
        TIER_MEDIUM,
        options,
        || {
            let enc = pq::encapsulate(&keys.public)?;
            Ok(black_box(enc.ciphertext.len() as u64))
        },
    )
}

fn bench_mlkem_decapsulate(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let keys = pq::keypair();
    let enc = pq::encapsulate(&keys.public)?;
    run_case(
        BenchGroup::HandshakeCrypto,
        "mlkem.decapsulate",
        TIER_MEDIUM,
        options,
        || {
            let shared = pq::decapsulate(&enc.ciphertext, &keys.secret)?;
            if shared != enc.shared_secret {
                bail!("ML-KEM decapsulation produced an unexpected shared secret");
            }
            Ok(black_box(shared.len() as u64))
        },
    )
}

fn bench_mldsa_keypair(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    run_case(
        BenchGroup::HandshakeCrypto,
        "mldsa.keypair",
        TIER_SLOW,
        options,
        || {
            let pair = identity::keypair();
            Ok(black_box((pair.public.len() + pair.secret.len()) as u64))
        },
    )
}

fn bench_mldsa_sign(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let keys = identity::keypair();
    let transcript = [0x33_u8; KEY_LEN];
    let server_x25519 = X25519KeyPair::generate().public;
    run_case(
        BenchGroup::HandshakeCrypto,
        "mldsa.sign",
        TIER_SLOW,
        options,
        || {
            let signature =
                identity::sign_server_identity(&keys.secret, &transcript, &server_x25519, 0)?;
            Ok(black_box(signature.len() as u64))
        },
    )
}

fn bench_mldsa_verify(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let keys = identity::keypair();
    let transcript = [0x33_u8; KEY_LEN];
    let server_x25519 = X25519KeyPair::generate().public;
    let signature = identity::sign_server_identity(&keys.secret, &transcript, &server_x25519, 0)?;
    run_case(
        BenchGroup::HandshakeCrypto,
        "mldsa.verify",
        TIER_SLOW,
        options,
        || {
            identity::verify_server_identity(
                &keys.public,
                &signature,
                &transcript,
                &server_x25519,
                0,
            )?;
            Ok(black_box(signature.len() as u64))
        },
    )
}

fn bench_hkdf_session_keys(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let client = X25519KeyPair::generate();
    let server = X25519KeyPair::generate();
    let transcript = [0x42_u8; KEY_LEN];
    run_case(
        BenchGroup::HandshakeCrypto,
        "hkdf.session_keys",
        TIER_FAST,
        options,
        || {
            let keys = derive_client_keys(&client.private, &server.public, &transcript)?;
            Ok(black_box(keys.client_key.len() as u64))
        },
    )
}

fn bench_hkdf_hybrid_rekey(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let chain = [0x11_u8; KEY_LEN];
    let x25519_shared = [0x22_u8; KEY_LEN];
    let pq_shared = [0x33_u8; KEY_LEN];
    run_case(
        BenchGroup::HandshakeCrypto,
        "hkdf.hybrid_rekey",
        TIER_FAST,
        options,
        || {
            let derived = pq::hybrid_rekey(&chain, &x25519_shared, &pq_shared)?;
            Ok(black_box(derived.len() as u64))
        },
    )
}

// ---------------------------------------------------------------------------
// handshake.protocol
// ---------------------------------------------------------------------------

fn bench_clienthello_build_signed(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let client = X25519KeyPair::generate();
    let server = X25519KeyPair::generate();
    let auth_key = derive_client_auth_key(BENCH_PSK, &client.private, &server.public)?;
    let template = ClientHelloTemplate {
        sni: BENCH_SNI.to_owned(),
        x25519_public_key: client.public,
        profile: BrowserProfile::Safari17,
    };
    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    run_case(
        BenchGroup::HandshakeProtocol,
        "clienthello.build_signed",
        TIER_MEDIUM,
        options,
        || {
            let record = template.build_signed(&auth_key, &mut rng)?;
            Ok(black_box(record.len() as u64))
        },
    )
}

fn bench_clienthello_parse(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let (record, _server_auth) = signed_client_hello_fixture()?;
    run_case(
        BenchGroup::HandshakeProtocol,
        "clienthello.parse",
        TIER_FAST,
        options,
        || {
            let parsed = parse_client_hello(&record)?;
            Ok(black_box(parsed.record_len as u64))
        },
    )
}

fn bench_clienthello_verify_auth(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let (record, server_auth) = signed_client_hello_fixture()?;
    run_case(
        BenchGroup::HandshakeProtocol,
        "clienthello.verify_auth",
        TIER_FAST,
        options,
        || {
            let auth = verify_client_hello_auth(&record, &server_auth)?;
            if !auth.authenticated {
                bail!("benchmark ClientHello did not authenticate");
            }
            Ok(black_box(record.len() as u64))
        },
    )
}

/// Build a signed ClientHello together with the matching server-side auth key
/// so verification benchmarks can run without re-deriving keys per call.
fn signed_client_hello_fixture() -> Result<(Vec<u8>, [u8; KEY_LEN])> {
    let client = X25519KeyPair::generate();
    let server = X25519KeyPair::generate();
    let client_auth = derive_client_auth_key(BENCH_PSK, &client.private, &server.public)?;
    let server_auth = derive_server_auth_key(BENCH_PSK, &server.private, &client.public)?;
    let template = ClientHelloTemplate {
        sni: BENCH_SNI.to_owned(),
        x25519_public_key: client.public,
        profile: BrowserProfile::Safari17,
    };
    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    let record = template.build_signed(&client_auth, &mut rng)?;
    Ok((record, server_auth))
}

// ---------------------------------------------------------------------------
// record.aead
// ---------------------------------------------------------------------------

fn bench_aead_seal_64b(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    bench_aead_seal(options, "aead.seal_64b", TIER_HOT, SIZE_64B)
}

fn bench_aead_seal_1k(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    bench_aead_seal(options, "aead.seal_1k", TIER_FAST, SIZE_1K)
}

fn bench_aead_seal_16k(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    bench_aead_seal(options, "aead.seal_16k", TIER_MEDIUM, SIZE_16K)
}

fn bench_aead_seal(
    options: BenchmarkOptions,
    name: &'static str,
    tier: Tier,
    payload_size: usize,
) -> Result<BenchmarkCase> {
    let key = [0x07_u8; KEY_LEN];
    let nonce_base = [0x09_u8; NONCE_LEN];
    let mut codec = AeadCodec::new(key, nonce_base);
    let plaintext = vec![0x42_u8; payload_size];
    run_case(BenchGroup::RecordAead, name, tier, options, || {
        let ciphertext = codec.seal(&plaintext, CLIENT_TO_SERVER_AAD)?;
        Ok(black_box(ciphertext.len() as u64))
    })
}

fn bench_aead_round_trip_1k(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let key = [0x07_u8; KEY_LEN];
    let nonce_base = [0x09_u8; NONCE_LEN];
    let mut enc = AeadCodec::new(key, nonce_base);
    let mut dec = AeadCodec::new(key, nonce_base);
    let plaintext = vec![0x42_u8; SIZE_1K];
    run_case(
        BenchGroup::RecordAead,
        "aead.round_trip_1k",
        TIER_FAST,
        options,
        || {
            let ciphertext = enc.seal(&plaintext, CLIENT_TO_SERVER_AAD)?;
            let recovered = dec.open(&ciphertext, CLIENT_TO_SERVER_AAD)?;
            if recovered.len() != plaintext.len() {
                bail!("AEAD round-trip plaintext length mismatch");
            }
            Ok(black_box((ciphertext.len() + recovered.len()) as u64))
        },
    )
}

// ---------------------------------------------------------------------------
// record.pipeline
// ---------------------------------------------------------------------------

fn bench_record_seal_1k(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let padding = PaddingProfile::new(RECORD_PADDING_MIN, RECORD_PADDING_MAX)?;
    let mut codec = DataRecordCodec::new(
        AeadCodec::new([0x07; KEY_LEN], [0x09; NONCE_LEN]),
        padding,
        CLIENT_TO_SERVER_AAD,
    );
    let payload = vec![0x42_u8; SIZE_1K];
    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    run_case(
        BenchGroup::RecordPipeline,
        "record.seal_1k",
        TIER_FAST,
        options,
        || {
            let record = codec.seal(&payload, &mut rng)?;
            Ok(black_box(record.len() as u64))
        },
    )
}

fn bench_record_round_trip_1k(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let padding = PaddingProfile::new(RECORD_PADDING_MIN, RECORD_PADDING_MAX)?;
    let mut enc = DataRecordCodec::new(
        AeadCodec::new([0x07; KEY_LEN], [0x09; NONCE_LEN]),
        padding,
        CLIENT_TO_SERVER_AAD,
    );
    let mut dec = DataRecordCodec::new(
        AeadCodec::new([0x07; KEY_LEN], [0x09; NONCE_LEN]),
        padding,
        CLIENT_TO_SERVER_AAD,
    );
    let payload = vec![0x42_u8; SIZE_1K];
    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    run_case(
        BenchGroup::RecordPipeline,
        "record.round_trip_1k",
        TIER_FAST,
        options,
        || {
            let record = enc.seal(&payload, &mut rng)?;
            let plaintext = dec.open(&record)?;
            if plaintext.len() != payload.len() {
                bail!("DataRecord round-trip length mismatch");
            }
            Ok(black_box((record.len() + plaintext.len()) as u64))
        },
    )
}

fn bench_record_bulk_1mb(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let padding = PaddingProfile::new(RECORD_PADDING_MIN, RECORD_PADDING_MAX)?;
    let mut enc = DataRecordCodec::new(
        AeadCodec::new([0x07; KEY_LEN], [0x09; NONCE_LEN]),
        padding,
        CLIENT_TO_SERVER_AAD,
    );
    let mut dec = DataRecordCodec::new(
        AeadCodec::new([0x07; KEY_LEN], [0x09; NONCE_LEN]),
        padding,
        CLIENT_TO_SERVER_AAD,
    );
    let payload = vec![0x42_u8; SIZE_1M];
    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    let mut buf: Vec<u8> = Vec::with_capacity(SIZE_1M * 2);
    let mut records: Vec<SealedRecord> = Vec::with_capacity(128);
    run_case(
        BenchGroup::RecordPipeline,
        "record.bulk_1mb",
        TIER_BULK,
        options,
        || {
            buf.clear();
            records.clear();
            enc.seal_chunks_into_reusing(&payload, &mut rng, &mut buf, &mut records)?;
            let mut recovered = 0_usize;
            for sealed in &records {
                let plaintext = dec.open(&buf[sealed.range.clone()])?;
                recovered += plaintext.len();
            }
            if recovered != payload.len() {
                bail!(
                    "record.bulk_1mb lost {} bytes of plaintext",
                    payload.len() - recovered
                );
            }
            Ok(black_box((buf.len() + payload.len()) as u64))
        },
    )
}

// ---------------------------------------------------------------------------
// traffic
// ---------------------------------------------------------------------------

fn bench_padding_apply_1k(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let padding = PaddingProfile::new(RECORD_PADDING_MIN, RECORD_PADDING_MAX)?;
    let payload = vec![0x42_u8; SIZE_1K];
    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    run_case(
        BenchGroup::Traffic,
        "padding.apply_1k",
        TIER_HOT,
        options,
        || {
            let padded = padding.apply(&payload, &mut rng);
            Ok(black_box(padded.len() as u64))
        },
    )
}

fn bench_padding_remove_1k(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let padding = PaddingProfile::new(RECORD_PADDING_MIN, RECORD_PADDING_MAX)?;
    let payload = vec![0x42_u8; SIZE_1K];
    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    let template = padding.apply(&payload, &mut rng);
    let mut scratch: Vec<u8> = Vec::with_capacity(template.len());
    run_case(
        BenchGroup::Traffic,
        "padding.remove_1k",
        TIER_HOT,
        options,
        || {
            scratch.clear();
            scratch.extend_from_slice(&template);
            PaddingProfile::remove_in_place(&mut scratch)?;
            Ok(black_box(scratch.len() as u64))
        },
    )
}

// ---------------------------------------------------------------------------
// state
// ---------------------------------------------------------------------------

fn bench_replay_cache_insert(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let (iterations, warmup) = effective_tier(TIER_FAST, options);
    let capacity = iterations.saturating_add(warmup).saturating_add(16) as usize;
    let mut cache = ReplayCache::new(capacity);
    let now = 1_700_000_000_u64;
    let mut counter: u64 = 0;
    run_case(
        BenchGroup::State,
        "replay_cache.insert",
        TIER_FAST,
        options,
        || {
            counter = counter.wrapping_add(1);
            let mut nonce = [0_u8; 8];
            nonce.copy_from_slice(&counter.to_be_bytes());
            let mut fingerprint = [0_u8; 32];
            fingerprint[..8].copy_from_slice(&counter.to_be_bytes());
            let entry = ReplayEntry {
                timestamp: now,
                nonce,
                transcript_fingerprint: fingerprint,
            };
            if !cache.insert_new(entry, now)? {
                bail!("replay cache rejected a unique entry");
            }
            Ok(black_box((nonce.len() + fingerprint.len()) as u64))
        },
    )
}

// ---------------------------------------------------------------------------
// runtime helpers
// ---------------------------------------------------------------------------

fn run_case<F>(
    group: BenchGroup,
    name: &'static str,
    tier: Tier,
    options: BenchmarkOptions,
    mut op: F,
) -> Result<BenchmarkCase>
where
    F: FnMut() -> Result<u64>,
{
    let (iterations, warmup) = effective_tier(tier, options);
    for _ in 0..warmup {
        op()?;
    }
    let start = Instant::now();
    let mut processed_bytes: u64 = 0;
    for _ in 0..iterations {
        processed_bytes = processed_bytes.saturating_add(op()?);
    }
    Ok(BenchmarkCase {
        group,
        name,
        iterations,
        warmup,
        elapsed: start.elapsed(),
        processed_bytes,
    })
}

/// Apply the quick-mode scaling factor to a tier, clamping iterations so the
/// case still runs at least [`QUICK_MIN_ITERATIONS`] times.
fn effective_tier(tier: Tier, options: BenchmarkOptions) -> (u64, u64) {
    if !options.quick {
        return (tier.iterations, tier.warmup);
    }
    let iterations = (tier.iterations / QUICK_SCALE).max(QUICK_MIN_ITERATIONS);
    let warmup = tier.warmup / QUICK_SCALE;
    (iterations, warmup)
}

fn seconds(duration: Duration) -> f64 {
    duration.as_secs_f64().max(f64::MIN_POSITIVE)
}

fn format_duration(duration: Duration) -> String {
    let nanos = duration.as_nanos();
    if nanos < 1_000 {
        format!("{nanos}ns")
    } else if nanos < 1_000_000 {
        format!("{:.2}µs", nanos as f64 / 1_000.0)
    } else if nanos < 1_000_000_000 {
        format!("{:.2}ms", nanos as f64 / 1_000_000.0)
    } else {
        format!("{:.2}s", duration.as_secs_f64())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn quick_run_completes_every_case() {
        let report = run(BenchmarkOptions::quick()).expect("quick run should succeed");
        assert_eq!(report.cases.len(), CASES.len());
        for case in &report.cases {
            assert!(
                case.iterations >= QUICK_MIN_ITERATIONS,
                "{} ran fewer than the quick-mode floor",
                case.full_name(),
            );
        }
    }

    #[test]
    fn every_declared_group_is_represented() {
        let report = run(BenchmarkOptions::quick()).expect("quick run should succeed");
        let groups: HashSet<BenchGroup> = report.cases.iter().map(|case| case.group).collect();
        for expected in [
            BenchGroup::HandshakeCrypto,
            BenchGroup::HandshakeProtocol,
            BenchGroup::RecordAead,
            BenchGroup::RecordPipeline,
            BenchGroup::Traffic,
            BenchGroup::State,
        ] {
            assert!(groups.contains(&expected), "missing group {:?}", expected);
        }
    }

    #[test]
    fn report_formats_expose_stable_fields() {
        let report = run(BenchmarkOptions::quick()).expect("quick run should succeed");

        let text = report.to_text();
        assert!(text.contains("ParallaX benchmark v1"));
        assert!(text.contains("handshake.crypto"));
        assert!(text.contains("record.pipeline"));

        let json = report.to_json();
        assert!(json.starts_with('{') && json.ends_with('}'));
        assert!(json.contains("\"version\":1"));
        assert!(json.contains("\"quick\":true"));
        assert!(json.contains("\"cases\""));
        assert!(json.contains("\"ns_per_op\""));
        assert!(json.contains("\"mib_per_second\""));
    }

    #[test]
    fn quick_mode_floors_iteration_count() {
        let (iters, warmup) = effective_tier(
            Tier {
                iterations: 50,
                warmup: 5,
            },
            BenchmarkOptions::quick(),
        );
        assert_eq!(iters, QUICK_MIN_ITERATIONS);
        assert_eq!(warmup, 0);
    }

    #[test]
    fn standard_mode_uses_full_iteration_count() {
        let (iters, warmup) = effective_tier(TIER_MEDIUM, BenchmarkOptions::standard());
        assert_eq!(iters, TIER_MEDIUM.iterations);
        assert_eq!(warmup, TIER_MEDIUM.warmup);
    }
}
