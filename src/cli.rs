use std::path::PathBuf;

use anyhow::Context;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::{
    config::Config,
    crypto::session::{derive_client_keys, AeadCodec, X25519KeyPair},
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
            let keys =
                derive_client_keys(&client.private, &server.public, b"parallax-cli-self-test")?;
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
    }

    Ok(())
}
