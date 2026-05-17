use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::Context;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use tracing_subscriber::EnvFilter;

use crate::{
    bench::{self, BenchmarkOptions},
    client::runtime,
    config::Config,
    crypto::{
        identity, pq,
        session::{derive_client_keys, AeadCodec, X25519KeyPair},
    },
    handshake::server,
    probe,
    transport::{quic_runtime, tcp::bump_nofile_soft_limit},
};

#[derive(Debug, Parser)]
#[command(
    name = "parallax",
    version,
    about = "ParallaX proxy protocol CLI (plx)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate parallax.toml and fail fast on unsafe or incomplete settings.
    Check {
        #[arg(short, long, default_value = "parallax.toml")]
        config: PathBuf,
    },
    /// Generate an X25519 key pair for the ParallaX control plane.
    Keygen,
    /// Locally verify AEAD key derivation with generated ephemeral material.
    CryptoSelfTest,
    /// Run the ParallaX server handshake/fallback listener.
    Serve {
        #[arg(short, long, default_value = "parallax.toml")]
        config: PathBuf,
        /// Use UDP/QUIC transport instead of TCP camouflage transport.
        #[arg(long)]
        quic: bool,
    },
    /// Run the ParallaX local SOCKS5 client.
    Client {
        #[arg(short, long, default_value = "parallax.toml")]
        config: PathBuf,
        /// Use UDP/QUIC transport instead of TCP camouflage transport.
        #[arg(long)]
        quic: bool,
    },
    /// Run local CPU-only protocol benchmarks without touching system networking.
    #[command(name = "bench")]
    Benchmark {
        #[arg(long, default_value_t = 1_000)]
        iterations: u64,
        #[arg(long, default_value_t = 100)]
        warmup: u64,
        #[arg(long, default_value_t = 1_024)]
        payload_size: usize,
        #[arg(long)]
        json: bool,
    },
    /// Print paired client/server parallax.toml templates with fresh keys.
    ConfigTemplate {
        #[arg(long, default_value = "0.0.0.0:443")]
        server_listen: String,
        #[arg(long, default_value = "127.0.0.1:1080")]
        client_listen: String,
        #[arg(long, default_value = "YOUR_VPS_IP:443")]
        server_addr: String,
        #[arg(long, default_value = "example.com:443")]
        fallback_addr: String,
        #[arg(long, default_value = "example.com")]
        sni: String,
    },
    /// Check a camouflage target. Easy mode: plx probe example.com
    Probe {
        /// Domain, domain:port, or https://domain. If omitted, read parallax.toml.
        dest: Option<String>,
        #[arg(short, long, default_value = "parallax.toml")]
        config: PathBuf,
    },
    /// Generate a ready-to-edit config from one camouflage domain.
    Init {
        /// Camouflage domain, domain:port, or https://domain.
        dest: String,
        #[arg(long, default_value = "YOUR_VPS_IP:443")]
        server_addr: String,
        #[arg(long, default_value = "0.0.0.0:443")]
        server_listen: String,
        #[arg(long, default_value = "127.0.0.1:1080")]
        client_listen: String,
        /// Directory for parallax.server.toml and parallax.client.toml.
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },
}

pub async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    match Cli::parse().command {
        Command::Check { config } => {
            let cfg = Config::load(&config)
                .with_context(|| format!("failed to load {}", config.display()))?;
            cfg.validate()?;
            println!(
                "ok: {} mode config is valid ({})",
                cfg.mode,
                config.display()
            );
        }
        Command::Keygen => {
            let pair = X25519KeyPair::generate();
            println!("private_key = \"{}\"", STANDARD.encode(pair.private));
            println!("public_key = \"{}\"", STANDARD.encode(pair.public));
        }
        Command::CryptoSelfTest => {
            let server = X25519KeyPair::generate();
            let client = X25519KeyPair::generate();
            let transcript_hash = [0x53_u8; 32];
            let keys = derive_client_keys(&client.private, &server.public, &transcript_hash)?;
            let mut enc = AeadCodec::new(keys.client_key, keys.client_nonce);
            let mut dec = AeadCodec::new(keys.client_key, keys.client_nonce);
            let ciphertext = enc.seal(b"parallax", b"self-test")?;
            let plaintext = dec.open(&ciphertext, b"self-test")?;
            anyhow::ensure!(plaintext == b"parallax", "AEAD self-test mismatch");
            println!("ok: crypto self-test passed");
        }
        Command::Serve { config, quic } => {
            bump_nofile_soft_limit();
            let cfg = Config::load(&config)
                .with_context(|| format!("failed to load {}", config.display()))?;
            if quic {
                quic_runtime::run_server(cfg).await?;
            } else {
                server::run(cfg).await?;
            }
        }
        Command::Client { config, quic } => {
            bump_nofile_soft_limit();
            let cfg = Config::load(&config)
                .with_context(|| format!("failed to load {}", config.display()))?;
            if quic {
                quic_runtime::run_client(cfg).await?;
            } else {
                runtime::run(cfg).await?;
            }
        }
        Command::Benchmark {
            iterations,
            warmup,
            payload_size,
            json,
        } => {
            let options = BenchmarkOptions::new(iterations, warmup, payload_size)?;
            let report = bench::run(options)?;
            if json {
                println!("{}", report.to_json());
            } else {
                print!("{}", report.to_text());
            }
        }
        Command::ConfigTemplate {
            server_listen,
            client_listen,
            server_addr,
            fallback_addr,
            sni,
        } => print_config_template(
            &server_listen,
            &client_listen,
            &server_addr,
            &fallback_addr,
            &sni,
        ),
        Command::Probe { dest, config } => {
            let (target, sni) = match dest {
                Some(dest) => {
                    let target = probe::ProbeTarget::parse(&dest)?;
                    let sni = target.host.clone();
                    (target, sni)
                }
                None => {
                    let cfg = Config::load(&config)
                        .with_context(|| format!("failed to load {}", config.display()))?;
                    probe::target_from_config(&cfg)?
                }
            };
            let report = probe::probe(target, sni).await?;
            print!("{}", report.summary());
        }
        Command::Init {
            dest,
            server_addr,
            server_listen,
            client_listen,
            output,
        } => {
            let target = probe::ProbeTarget::parse(&dest)?;
            let generated = generate_config_template(
                &server_listen,
                &client_listen,
                &server_addr,
                &target.authority(),
                &target.host,
            );
            write_init_files(&output, &generated)?;
        }
    }

    Ok(())
}

fn print_config_template(
    server_listen: &str,
    client_listen: &str,
    server_addr: &str,
    fallback_addr: &str,
    sni: &str,
) {
    let generated = generate_config_template(
        server_listen,
        client_listen,
        server_addr,
        fallback_addr,
        sni,
    );
    println!(
        "# ===== server parallax.toml =====\n{}# ===== client parallax.toml =====\n{}",
        generated.server, generated.client
    );
}

struct GeneratedConfig {
    server: String,
    client: String,
}

fn generate_config_template(
    server_listen: &str,
    client_listen: &str,
    server_addr: &str,
    fallback_addr: &str,
    sni: &str,
) -> GeneratedConfig {
    let mut psk = [0_u8; 32];
    OsRng.fill_bytes(&mut psk);
    let server_keys = X25519KeyPair::generate();
    let server_pq_keys = pq::keypair();
    let server_identity_keys = identity::keypair();

    let psk = STANDARD.encode(psk);
    let server_private = STANDARD.encode(server_keys.private);
    let server_public = STANDARD.encode(server_keys.public);
    let pq_secret = STANDARD.encode(&server_pq_keys.secret);
    let pq_public = STANDARD.encode(&server_pq_keys.public);
    let identity_secret = STANDARD.encode(&server_identity_keys.secret);
    let identity_public = STANDARD.encode(&server_identity_keys.public);

    let server = format!(
        r#"mode = "server"

[crypto]
psk = "{}"

[traffic]
min_padding = 0
max_padding = 512
min_delay_ms = 0
max_delay_ms = 0
cover_min_interval_ms = 5000
cover_max_interval_ms = 15000
max_concurrent_streams = 1

[server]
listen = "{}"
fallback_addr = "{}"
private_key = "{}"
pq_secret_key = "{}"
identity_secret_key = "{}"
replay_cache_path = "parallax-replay.cache"
authorized_sni = ["{}"]
strict_tls13 = true

"#,
        psk, server_listen, fallback_addr, server_private, pq_secret, identity_secret, sni,
    );

    let client = format!(
        r#"mode = "client"

[crypto]
psk = "{}"

[traffic]
min_padding = 0
max_padding = 512
min_delay_ms = 0
max_delay_ms = 0
cover_min_interval_ms = 5000
cover_max_interval_ms = 15000
max_concurrent_streams = 1

[client]
listen = "{}"
server_addr = "{}"
sni = "{}"
server_public_key = "{}"
server_pq_public_key = "{}"
server_identity_public_key = "{}"
tls_profile = "safari17"
"#,
        psk, client_listen, server_addr, sni, server_public, pq_public, identity_public,
    );

    GeneratedConfig { server, client }
}

fn write_init_files(output: &Path, generated: &GeneratedConfig) -> anyhow::Result<()> {
    let server_path = output.join("parallax.server.toml");
    let client_path = output.join("parallax.client.toml");
    anyhow::ensure!(
        output.is_dir(),
        "output directory does not exist: {}",
        output.display()
    );
    anyhow::ensure!(
        !server_path.exists() && !client_path.exists(),
        "refusing to overwrite existing config files in {}",
        output.display()
    );

    write_secret_file(&server_path, &generated.server)?;
    write_secret_file(&client_path, &generated.client)?;
    println!("Configs written:");
    println!("  server: {}", server_path.display());
    println!("  client: {}", client_path.display());
    println!("Next: upload the server file to the VPS and keep the client file on this machine.");
    Ok(())
}

fn write_secret_file(path: &Path, contents: &str) -> anyhow::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn init_files_are_user_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let generated = generate_config_template(
            "127.0.0.1:0",
            "127.0.0.1:1080",
            "example.com:443",
            "example.com:443",
            "example.com",
        );

        write_init_files(dir.path(), &generated).unwrap();

        for name in ["parallax.server.toml", "parallax.client.toml"] {
            let mode = fs::metadata(dir.path().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        let server_path = dir.path().join("parallax.server.toml");
        Config::load(server_path).unwrap();
    }
}
