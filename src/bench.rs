use std::{
    fmt::Write as _,
    hint::black_box,
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use rand::{rngs::OsRng, rngs::StdRng, SeedableRng};

use crate::{
    config::TrafficConfig,
    crypto::{
        auth::{derive_client_auth_key, derive_server_auth_key, verify_client_hello_auth},
        pq,
        replay::{ReplayCache, ReplayEntry},
        session::{AeadCodec, X25519KeyPair, NONCE_LEN},
    },
    protocol::data::{max_plaintext_len, DataRecordCodec, CLIENT_TO_SERVER_AAD},
    tls::{
        backend::{CamouflageTlsBackend, NativeCamouflageBackend},
        client_hello::parse_client_hello,
        client_hello_builder::{BrowserProfile, ClientHelloTemplate},
    },
    traffic::PaddingProfile,
};

const BENCH_PSK: &[u8] = b"0123456789abcdef0123456789abcdef";
const BENCH_SNI: &str = "example.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BenchmarkOptions {
    pub iterations: u64,
    pub warmup: u64,
    pub payload_size: usize,
}

impl BenchmarkOptions {
    pub fn new(iterations: u64, warmup: u64, payload_size: usize) -> Result<Self> {
        if iterations == 0 {
            bail!("benchmark iterations must be greater than zero");
        }
        let max_payload = max_plaintext_len(TrafficConfig::default().max_padding);
        if payload_size == 0 || payload_size > max_payload {
            bail!(
                "benchmark payload size must be in 1..={max_payload} bytes for the default traffic profile"
            );
        }
        Ok(Self {
            iterations,
            warmup,
            payload_size,
        })
    }
}

impl Default for BenchmarkOptions {
    fn default() -> Self {
        Self {
            iterations: 1_000,
            warmup: 100,
            payload_size: 1_024,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BenchmarkReport {
    pub options: BenchmarkOptions,
    pub cases: Vec<BenchmarkCase>,
    pub total_elapsed: Duration,
}

impl BenchmarkReport {
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "ParallaX benchmark: iterations={}, warmup={}, payload={} bytes",
            self.options.iterations, self.options.warmup, self.options.payload_size
        );
        let _ = writeln!(
            out,
            "{:<34} {:>10} {:>12} {:>14} {:>14} {:>14}",
            "case", "iters", "avg", "ops/sec", "MiB/sec", "total"
        );
        for case in &self.cases {
            let _ = writeln!(
                out,
                "{:<34} {:>10} {:>12} {:>14.2} {:>14.2} {:>14}",
                case.name,
                case.iterations,
                format_duration(case.average_duration()),
                case.ops_per_second(),
                case.mib_per_second(),
                format_duration(case.elapsed),
            );
        }
        let _ = writeln!(out, "total_elapsed={}", format_duration(self.total_elapsed));
        out
    }

    pub fn to_json(&self) -> String {
        let mut out = String::new();
        let _ = write!(
            out,
            "{{\"iterations\":{},\"warmup\":{},\"payload_size\":{},\"total_elapsed_ns\":{},\"cases\":[",
            self.options.iterations,
            self.options.warmup,
            self.options.payload_size,
            self.total_elapsed.as_nanos()
        );
        for (idx, case) in self.cases.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                "{{\"name\":\"{}\",\"iterations\":{},\"elapsed_ns\":{},\"avg_ns\":{},\"ops_per_second\":{:.4},\"processed_bytes\":{},\"mib_per_second\":{:.4}}}",
                escape_json(&case.name),
                case.iterations,
                case.elapsed.as_nanos(),
                case.average_duration().as_nanos(),
                case.ops_per_second(),
                case.processed_bytes,
                case.mib_per_second()
            );
        }
        out.push_str("]}");
        out
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BenchmarkCase {
    pub name: String,
    pub iterations: u64,
    pub warmup: u64,
    pub elapsed: Duration,
    pub processed_bytes: u64,
}

impl BenchmarkCase {
    pub fn average_duration(&self) -> Duration {
        duration_div(self.elapsed, self.iterations)
    }

    pub fn ops_per_second(&self) -> f64 {
        self.iterations as f64 / seconds(self.elapsed)
    }

    pub fn mib_per_second(&self) -> f64 {
        if self.processed_bytes == 0 {
            return 0.0;
        }
        (self.processed_bytes as f64 / 1_048_576.0) / seconds(self.elapsed)
    }
}

pub fn run(options: BenchmarkOptions) -> Result<BenchmarkReport> {
    let start = Instant::now();
    let cases = vec![
        bench_client_hello(options)?,
        bench_data_record(options)?,
        bench_mlkem(options)?,
        bench_replay_cache(options)?,
    ];

    Ok(BenchmarkReport {
        options,
        cases,
        total_elapsed: start.elapsed(),
    })
}

fn bench_client_hello(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let server = X25519KeyPair::generate();

    run_case(
        "tls_clienthello_auth",
        options.iterations,
        options.warmup,
        || {
            let client = X25519KeyPair::generate();
            let auth_key = derive_client_auth_key(BENCH_PSK, &client.private, &server.public)?;
            let template = ClientHelloTemplate {
                sni: BENCH_SNI.to_owned(),
                x25519_public_key: client.public,
                profile: BrowserProfile::Safari17,
            };
            let record = NativeCamouflageBackend.client_hello(&template, &auth_key, &mut OsRng)?;
            let parsed = parse_client_hello(&record)?;
            let client_public = parsed.client_random;
            let server_auth_key =
                derive_server_auth_key(BENCH_PSK, &server.private, &client_public)?;
            let auth = verify_client_hello_auth(&record, &server_auth_key)?;
            if !auth.authenticated {
                bail!("benchmark ClientHello authentication failed");
            }
            Ok(black_box(record.len() as u64))
        },
    )
}

fn bench_data_record(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let payload = vec![0x42; options.payload_size];
    let traffic = TrafficConfig::default();
    let padding = PaddingProfile::from_config(traffic)?;
    let mut rng = StdRng::seed_from_u64(0x504c_5842);
    let mut seal = DataRecordCodec::new(
        AeadCodec::new([1; 32], [3; NONCE_LEN]),
        padding,
        CLIENT_TO_SERVER_AAD,
    );
    let mut open = DataRecordCodec::new(
        AeadCodec::new([1; 32], [3; NONCE_LEN]),
        padding,
        CLIENT_TO_SERVER_AAD,
    );

    run_case(
        "appdata_seal_open",
        options.iterations,
        options.warmup,
        || {
            let record = seal.seal(black_box(&payload), &mut rng)?;
            let plaintext = open.open(&record)?;
            if plaintext.len() != payload.len() {
                bail!("benchmark data record round trip length mismatch");
            }
            Ok(black_box((record.len() + plaintext.len()) as u64))
        },
    )
}

fn bench_mlkem(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let iterations = scaled_pq_iterations(options.iterations);
    let warmup = scaled_pq_iterations(options.warmup);
    let keys = pq::keypair();

    run_case("mlkem_rekey", iterations, warmup, || {
        let encapsulation = pq::encapsulate(&keys.public)?;
        let shared = pq::decapsulate(&encapsulation.ciphertext, &keys.secret)?;
        if shared != encapsulation.shared_secret {
            bail!("benchmark ML-KEM shared secret mismatch");
        }
        let chain_secret = pq::hybrid_rekey(&[1; 32], &[2; 32], &shared)?;
        Ok(black_box(
            encapsulation.ciphertext.len() as u64 + chain_secret.len() as u64,
        ))
    })
}

fn bench_replay_cache(options: BenchmarkOptions) -> Result<BenchmarkCase> {
    let mut cache = ReplayCache::new(options.iterations as usize + options.warmup as usize + 16);
    let mut counter = 0_u64;
    let now = 1_700_000_000_u64;

    run_case(
        "replay_cache_insert",
        options.iterations,
        options.warmup,
        || {
            counter = counter.wrapping_add(1);
            let mut fingerprint = [0_u8; 32];
            fingerprint[..8].copy_from_slice(&counter.to_be_bytes());
            let mut nonce = [0_u8; 8];
            nonce.copy_from_slice(&counter.to_be_bytes());
            let entry = ReplayEntry {
                timestamp: now,
                nonce,
                transcript_fingerprint: fingerprint,
            };
            if !cache.insert_new(entry, now)? {
                bail!("benchmark replay cache rejected a unique fingerprint");
            }
            Ok(black_box(fingerprint.len() as u64))
        },
    )
}

fn run_case<F>(name: &str, iterations: u64, warmup: u64, mut op: F) -> Result<BenchmarkCase>
where
    F: FnMut() -> Result<u64>,
{
    for _ in 0..warmup {
        let _ = op()?;
    }

    let start = Instant::now();
    let mut processed_bytes = 0_u64;
    for _ in 0..iterations {
        processed_bytes = processed_bytes.saturating_add(op()?);
    }

    Ok(BenchmarkCase {
        name: name.to_owned(),
        iterations,
        warmup,
        elapsed: start.elapsed(),
        processed_bytes,
    })
}

fn scaled_pq_iterations(iterations: u64) -> u64 {
    if iterations == 0 {
        0
    } else {
        (iterations / 10).max(1)
    }
}

fn duration_div(duration: Duration, divisor: u64) -> Duration {
    if divisor == 0 {
        return Duration::ZERO;
    }
    Duration::from_nanos((duration.as_nanos() / divisor as u128) as u64)
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

fn escape_json(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect(),
            '\n' => "\\n".chars().collect(),
            '\r' => "\\r".chars().collect(),
            '\t' => "\\t".chars().collect(),
            other => vec![other],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_benchmark_options() {
        assert!(BenchmarkOptions::new(0, 0, 128).is_err());
        assert!(BenchmarkOptions::new(1, 0, 0).is_err());
        assert!(BenchmarkOptions::new(
            1,
            0,
            max_plaintext_len(TrafficConfig::default().max_padding) + 1
        )
        .is_err());
    }

    #[test]
    fn benchmark_smoke_report_contains_core_cases() {
        let options = BenchmarkOptions::new(2, 0, 128).unwrap();
        let report = run(options).unwrap();

        assert_eq!(report.cases.len(), 4);
        assert!(report
            .cases
            .iter()
            .any(|case| case.name == "tls_clienthello_auth"));
        assert!(report
            .cases
            .iter()
            .any(|case| case.name == "appdata_seal_open"));
        assert!(report.to_text().contains("ParallaX benchmark"));
        assert!(report.to_json().contains("\"cases\""));
    }
}
