use std::{
    fmt::Write as _,
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
    config::{Config, DEFAULT_REPLAY_CACHE_PATH},
    crypto::{
        identity, pq,
        session::{derive_client_keys, AeadCodec, X25519KeyPair},
    },
    handshake::server,
    probe, process_hardening,
    runtime_guard::RuntimeGuard,
    speed,
    transport::tcp::bump_nofile_soft_limit,
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
    /// Run a one-shot ParallaX network speed test against the configured server.
    Speed {
        #[arg(short, long, default_value = "parallax.toml")]
        config: PathBuf,
        /// Emit a machine-readable evidence report.
        #[arg(long)]
        json: bool,
    },
    /// Run the ParallaX protocol benchmark suite (CPU-only, fixed-parameter).
    ///
    /// The suite is intentionally non-configurable: case counts and payload
    /// sizes are baked into the binary so reported numbers stay comparable
    /// across releases.
    #[command(name = "bench")]
    Benchmark {
        /// Run the smoke profile (~1% of the iteration budget). Useful for
        /// CI checks and quick sanity sweeps.
        #[arg(long)]
        quick: bool,
        /// Emit a machine-readable JSON document instead of the text table.
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

    handle_command(Cli::parse().command).await
}

async fn handle_command(command: Command) -> anyhow::Result<()> {
    // Disable core dumps / ptrace dumpability before any subcommand runs. The
    // one-shot key-generating commands (Keygen, CryptoSelfTest, Init,
    // ConfigTemplate) mint X25519/ML-KEM/ML-DSA secrets and a PSK; without this
    // a crash mid-keygen could spill fresh private keys into a core file. The
    // call is idempotent and best-effort, so the long-lived paths that also
    // harden via prepare_long_lived_process() are unaffected.
    process_hardening::harden_current_process();
    match command {
        Command::Check { config } => check_config(config)?,
        Command::Keygen => print_keypair(),
        Command::CryptoSelfTest => crypto_self_test()?,
        Command::Serve { config } => run_server(config).await?,
        Command::Client { config } => run_client(config).await?,
        Command::Speed { config, json } => run_speed(config, json).await?,
        Command::Benchmark { quick, json } => run_benchmark(quick, json)?,
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
        Command::Probe { dest, config } => run_probe(dest, config).await?,
        Command::Init {
            dest,
            server_addr,
            server_listen,
            client_listen,
            output,
        } => write_init_config(&dest, &server_addr, &server_listen, &client_listen, &output)?,
    }
    Ok(())
}

fn check_config(config: PathBuf) -> anyhow::Result<()> {
    let cfg = load_config(&config)?;
    cfg.validate()?;
    println!(
        "ok: {} mode config is valid ({})",
        cfg.mode,
        config.display()
    );
    Ok(())
}

fn print_keypair() {
    let pair = X25519KeyPair::generate();
    println!("private_key = \"{}\"", STANDARD.encode(pair.private));
    println!("public_key = \"{}\"", STANDARD.encode(pair.public));
}

fn crypto_self_test() -> anyhow::Result<()> {
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
    Ok(())
}

async fn run_server(config: PathBuf) -> anyhow::Result<()> {
    prepare_long_lived_process();
    let cfg = load_config(&config)?;
    cfg.protect_secret_memory();
    server::run(cfg).await?;
    Ok(())
}

async fn run_client(config: PathBuf) -> anyhow::Result<()> {
    prepare_long_lived_process();
    let cfg = load_config(&config)?;
    cfg.protect_secret_memory();
    let _guard = RuntimeGuard::acquire_client(&cfg)?;
    runtime::run(cfg).await?;
    Ok(())
}

async fn run_speed(config: PathBuf, json: bool) -> anyhow::Result<()> {
    prepare_long_lived_process();
    let cfg = load_config(&config)?;
    cfg.protect_secret_memory();
    let _guard = RuntimeGuard::acquire_speed(&cfg)?;
    let report = speed::run(cfg).await?;
    if json {
        print!("{}", report.to_json());
    } else {
        print!("{}", report.to_text());
    }
    Ok(())
}

fn run_benchmark(quick: bool, json: bool) -> anyhow::Result<()> {
    let options = if quick {
        BenchmarkOptions::quick()
    } else {
        BenchmarkOptions::standard()
    };
    let report = bench::run(options)?;
    if json {
        println!("{}", report.to_json());
    } else {
        print!("{}", report.to_text());
    }
    Ok(())
}

async fn run_probe(dest: Option<String>, config: PathBuf) -> anyhow::Result<()> {
    let (target, sni) = probe_target(dest, &config)?;
    let report = probe::probe(target, sni).await?;
    print!("{}", report.summary());
    // Exit non-zero on a "Not recommended" verdict (including TCP/TLS connection
    // failures, which score as Bad). This lets callers — notably the guided
    // deploy, which only surfaces probe output on a non-zero exit — detect an
    // unsuitable camouflage target instead of silently deploying it.
    if matches!(report.verdict, probe::ProbeVerdict::Bad) {
        anyhow::bail!(
            "camouflage target is Not recommended (score {}/100); pick a reachable TLS 1.3 origin",
            report.score
        );
    }
    Ok(())
}

fn write_init_config(
    dest: &str,
    server_addr: &str,
    server_listen: &str,
    client_listen: &str,
    output: &Path,
) -> anyhow::Result<()> {
    let target = probe::ProbeTarget::parse(dest)?;
    let generated = generate_config_template(
        server_listen,
        client_listen,
        server_addr,
        &target.authority(),
        &target.host,
    );
    write_init_files(output, &generated)
}

fn prepare_long_lived_process() {
    process_hardening::harden_current_process();
    bump_nofile_soft_limit();
}

fn load_config(config: &Path) -> anyhow::Result<Config> {
    Config::load(config).with_context(|| format!("failed to load {}", config.display()))
}

fn probe_target(
    dest: Option<String>,
    config: &Path,
) -> anyhow::Result<(probe::ProbeTarget, String)> {
    match dest {
        Some(dest) => {
            let target = probe::ProbeTarget::parse(&dest)?;
            let sni = target.host.clone();
            Ok((target, sni))
        }
        None => {
            let cfg = load_config(config)?;
            Ok(probe::target_from_config(&cfg)?)
        }
    }
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

fn toml_basic_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ch if ch <= '\u{1f}' || ch == '\u{7f}' => {
                write!(&mut out, "\\u{:04X}", ch as u32).expect("writing to a String cannot fail");
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
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
    let server_listen = toml_basic_string(server_listen);
    let client_listen = toml_basic_string(client_listen);
    let server_addr = toml_basic_string(server_addr);
    let fallback_addr = toml_basic_string(fallback_addr);
    let sni = toml_basic_string(sni);

    let server = format!(
        r#"mode = "server"

[crypto]
psk = "{}"

[traffic]
min_padding = 0
max_padding = 0
min_delay_ms = 0
max_delay_ms = 0
cover_min_interval_ms = 0
cover_max_interval_ms = 0
max_concurrent_streams = 4

[server]
listen = {}
fallback_addr = {}
private_key = "{}"
pq_secret_key = "{}"
identity_secret_key = "{}"
replay_cache_path = "{}"
authorized_sni = [{}]
strict_tls13 = true

"#,
        psk,
        server_listen,
        fallback_addr,
        server_private,
        pq_secret,
        identity_secret,
        DEFAULT_REPLAY_CACHE_PATH,
        sni,
    );

    let client = format!(
        r#"mode = "client"

[crypto]
psk = "{}"

[traffic]
min_padding = 0
max_padding = 0
min_delay_ms = 0
max_delay_ms = 0
cover_min_interval_ms = 0
cover_max_interval_ms = 0
max_concurrent_streams = 4

[client]
listen = {}
server_addr = {}
sni = {}
server_public_key = "{}"
server_pq_public_key = "{}"
server_identity_public_key = "{}"
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

    #[test]
    fn generated_templates_validate_and_share_key_material() {
        let generated = generate_config_template(
            "0.0.0.0:443",
            "127.0.0.1:1080",
            "203.0.113.10:443",
            "cloudflare.com:443",
            "cloudflare.com",
        );

        let server = toml::from_str::<Config>(&generated.server).unwrap();
        let client = toml::from_str::<Config>(&generated.client).unwrap();

        server.validate().unwrap();
        client.validate().unwrap();
        assert_eq!(server.mode, crate::config::Mode::Server);
        assert_eq!(client.mode, crate::config::Mode::Client);
        assert_eq!(server.crypto.psk, client.crypto.psk);

        let server_cfg = server.server.as_ref().unwrap();
        let client_cfg = client.client.as_ref().unwrap();
        let server_private =
            crate::config::decode_key32_secret("server.private_key", &server_cfg.private_key)
                .unwrap();
        let server_public =
            crate::config::decode_key32("client.server_public_key", &client_cfg.server_public_key)
                .unwrap();

        assert_eq!(
            crate::crypto::session::x25519_public_from_private(&server_private),
            server_public
        );
        assert_eq!(server_cfg.fallback_addr, "cloudflare.com:443");
        assert_eq!(
            server_cfg.authorized_sni,
            vec![String::from("cloudflare.com")]
        );
        assert_eq!(
            server_cfg.replay_cache_path,
            PathBuf::from(DEFAULT_REPLAY_CACHE_PATH)
        );
        assert_eq!(client_cfg.server_addr, "203.0.113.10:443");
        assert_eq!(client_cfg.sni, "cloudflare.com");
    }

    #[test]
    fn generated_templates_escape_toml_string_values() {
        let fallback_addr = "fallback.example:443\"\ndata_target = \"127.0.0.1:25";
        let sni = "safe.example\", \"extra.example";
        let generated = generate_config_template(
            "0.0.0.0:443",
            "127.0.0.1:1080",
            "203.0.113.10:443",
            fallback_addr,
            sni,
        );

        let server = toml::from_str::<toml::Value>(&generated.server).unwrap();
        let server_table = server["server"].as_table().unwrap();
        assert_eq!(server_table["fallback_addr"].as_str(), Some(fallback_addr));
        assert!(server_table.get("data_target").is_none());

        let authorized_sni = server_table["authorized_sni"].as_array().unwrap();
        assert_eq!(authorized_sni.len(), 1);
        assert_eq!(authorized_sni[0].as_str(), Some(sni));

        let client = toml::from_str::<toml::Value>(&generated.client).unwrap();
        assert_eq!(client["client"]["sni"].as_str(), Some(sni));
    }

    #[test]
    fn init_files_refuse_to_overwrite_existing_config() {
        let dir = tempfile::tempdir().unwrap();
        let server_path = dir.path().join("parallax.server.toml");
        fs::write(&server_path, "existing").unwrap();
        let generated = GeneratedConfig {
            server: "server".to_owned(),
            client: "client".to_owned(),
        };

        let err = write_init_files(dir.path(), &generated).unwrap_err();

        assert!(err.to_string().contains("refusing to overwrite"));
        assert_eq!(fs::read_to_string(server_path).unwrap(), "existing");
        assert!(!dir.path().join("parallax.client.toml").exists());
    }

    #[test]
    fn toml_basic_string_escapes_control_and_meta_characters() {
        assert_eq!(toml_basic_string("plain"), "\"plain\"");
        assert_eq!(
            toml_basic_string("tab\there\nand\"quotes\\\u{08}\u{0c}\r"),
            "\"tab\\there\\nand\\\"quotes\\\\\\b\\f\\r\""
        );

        let with_unicode_control = toml_basic_string("abc\u{7f}d\u{1}");
        assert_eq!(with_unicode_control, "\"abc\\u007Fd\\u0001\"");
    }

    #[test]
    fn check_config_returns_error_for_invalid_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.toml");
        let err = check_config(missing.clone()).unwrap_err();
        let chain = format!("{:?}", err);
        assert!(chain.contains("failed to load"));
    }

    #[test]
    fn check_config_accepts_valid_template() {
        let dir = tempfile::tempdir().unwrap();
        let generated = generate_config_template(
            "127.0.0.1:0",
            "127.0.0.1:1080",
            "example.com:443",
            "example.com:443",
            "example.com",
        );
        let server_path = dir.path().join("parallax.server.toml");
        fs::write(&server_path, &generated.server).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&server_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        check_config(server_path).unwrap();
    }

    #[test]
    fn crypto_self_test_round_trips() {
        crypto_self_test().unwrap();
    }

    #[test]
    fn run_benchmark_quick_text_and_json() {
        run_benchmark(true, false).unwrap();
        run_benchmark(true, true).unwrap();
    }

    #[test]
    fn probe_target_uses_explicit_dest_string() {
        let (target, sni) = probe_target(
            Some("example.com:8443".to_owned()),
            Path::new("/does/not/exist"),
        )
        .unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 8443);
        assert_eq!(sni, "example.com");
    }

    #[test]
    fn probe_target_falls_back_to_config_when_dest_missing() {
        let dir = tempfile::tempdir().unwrap();
        let generated = generate_config_template(
            "127.0.0.1:0",
            "127.0.0.1:1080",
            "203.0.113.10:443",
            "cloudflare.com:443",
            "cloudflare.com",
        );
        let client_path = dir.path().join("parallax.client.toml");
        fs::write(&client_path, &generated.client).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&client_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let (target, sni) = probe_target(None, &client_path).unwrap();
        assert_eq!(target.host, "cloudflare.com");
        assert_eq!(target.port, 443);
        assert_eq!(sni, "cloudflare.com");
    }

    #[test]
    fn write_init_config_creates_paired_files_for_dest() {
        let dir = tempfile::tempdir().unwrap();
        write_init_config(
            "example.com",
            "203.0.113.10:443",
            "0.0.0.0:443",
            "127.0.0.1:1080",
            dir.path(),
        )
        .unwrap();
        let server_path = dir.path().join("parallax.server.toml");
        let client_path = dir.path().join("parallax.client.toml");
        assert!(server_path.exists());
        assert!(client_path.exists());

        let server: Config = toml::from_str(&fs::read_to_string(&server_path).unwrap()).unwrap();
        server.validate().unwrap();
        let client: Config = toml::from_str(&fs::read_to_string(&client_path).unwrap()).unwrap();
        client.validate().unwrap();
        assert_eq!(client.client.unwrap().server_addr, "203.0.113.10:443");
        assert_eq!(
            server.server.unwrap().authorized_sni,
            vec![String::from("example.com")]
        );
    }

    #[test]
    fn write_init_config_rejects_malformed_dest() {
        let dir = tempfile::tempdir().unwrap();
        let err = write_init_config(
            "",
            "203.0.113.10:443",
            "0.0.0.0:443",
            "127.0.0.1:1080",
            dir.path(),
        )
        .unwrap_err();
        assert!(format!("{err:?}").contains("target cannot be empty"));
    }

    #[test]
    fn init_files_require_existing_output_directory() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does/not/exist");
        let err = write_init_files(
            &missing,
            &GeneratedConfig {
                server: "server".to_owned(),
                client: "client".to_owned(),
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("output directory does not exist"));
    }

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
