use std::path::PathBuf;

use anyhow::Context;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use tracing_subscriber::EnvFilter;

use crate::{
    client::runtime,
    config::Config,
    crypto::{
        identity, pq,
        session::{derive_client_keys, AeadCodec, X25519KeyPair},
    },
    handshake::server,
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
    },
    /// Run the ParallaX local SOCKS5 client.
    Client {
        #[arg(short, long, default_value = "parallax.toml")]
        config: PathBuf,
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
        Command::Serve { config } => {
            let cfg = Config::load(&config)
                .with_context(|| format!("failed to load {}", config.display()))?;
            server::run(cfg).await?;
        }
        Command::Client { config } => {
            let cfg = Config::load(&config)
                .with_context(|| format!("failed to load {}", config.display()))?;
            runtime::run(cfg).await?;
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
    let mut psk = [0_u8; 32];
    OsRng.fill_bytes(&mut psk);
    let server_keys = X25519KeyPair::generate();
    let server_pq_keys = pq::keypair();
    let server_identity_keys = identity::keypair();

    println!(
        r#"# ===== server parallax.toml =====
mode = "server"

[crypto]
psk = "{}"

[traffic]
min_padding = 0
max_padding = 128
min_delay_ms = 0
max_delay_ms = 12
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

# ===== client parallax.toml =====
mode = "client"

[crypto]
psk = "{}"

[traffic]
min_padding = 0
max_padding = 128
min_delay_ms = 0
max_delay_ms = 12
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
        STANDARD.encode(psk),
        server_listen,
        fallback_addr,
        STANDARD.encode(server_keys.private),
        STANDARD.encode(&server_pq_keys.secret),
        STANDARD.encode(&server_identity_keys.secret),
        sni,
        STANDARD.encode(psk),
        client_listen,
        server_addr,
        sni,
        STANDARD.encode(server_keys.public),
        STANDARD.encode(&server_pq_keys.public),
        STANDARD.encode(&server_identity_keys.public),
    );
}
