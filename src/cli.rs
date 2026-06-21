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
use zeroize::Zeroizing;

use crate::{
    bench::{self, BenchmarkOptions},
    client::runtime,
    config::{Config, DEFAULT_REPLAY_CACHE_PATH},
    crypto::{
        identity,
        session::{derive_client_keys, AeadCodec, X25519KeyPair},
    },
    handshake::server,
    netmatrix, probe, process_hardening,
    runtime_guard::RuntimeGuard,
    secret_store, speed,
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
    /// Run a reproducible controlled-network (RTT/bandwidth) speed matrix
    /// against the configured server, via an emulated loopback shaper.
    #[command(name = "netmatrix")]
    NetMatrix {
        #[arg(short, long, default_value = "parallax.toml")]
        config: PathBuf,
        /// Emit a machine-readable JSON document instead of the text table.
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
        /// Write secrets inline into the config files (legacy, leak-unsafe).
        /// By default secrets go into separate 0600 sidecar files the config
        /// only references, so a leaked config alone is not a bearer credential.
        #[arg(long)]
        inline_secrets: bool,
    },
    /// Machine-bind a config's secrets: encrypt them into a sealed bundle under a
    /// host-local key and rewrite the config to reference it. After sealing, the
    /// config and bundle are useless on any other machine.
    Seal {
        #[arg(short, long, default_value = "parallax.toml")]
        config: PathBuf,
        /// Sealed bundle output path (default: <config-dir>/parallax.secrets.enc).
        #[arg(long)]
        output: Option<PathBuf>,
        /// Host keyfile path (default: $PARALLAX_HOST_KEY_FILE or
        /// /var/lib/parallax/host.key). Created if it does not exist.
        #[arg(long)]
        host_key: Option<PathBuf>,
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
        Command::NetMatrix { config, json } => run_netmatrix(config, json).await?,
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
            inline_secrets,
        } => write_init_config(
            &dest,
            &server_addr,
            &server_listen,
            &client_listen,
            &output,
            inline_secrets,
        )?,
        Command::Seal {
            config,
            output,
            host_key,
        } => seal_config(&config, output.as_deref(), host_key.as_deref())?,
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
    let inline = cfg.inline_secret_fields();
    if inline.is_empty() {
        println!("ok: secrets are referenced/sealed; this config file alone is not a credential");
    } else {
        println!(
            "warning: secrets are stored inline ({}); this config file is a bearer credential.",
            inline.join(", ")
        );
        println!(
            "         Anyone who obtains it can use or impersonate this deployment. Run \
             `plx seal` to machine-bind the secrets, or move them into a 0600 sidecar file."
        );
    }
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

async fn run_netmatrix(config: PathBuf, json: bool) -> anyhow::Result<()> {
    prepare_long_lived_process();
    let cfg = load_config(&config)?;
    cfg.protect_secret_memory();
    let _guard = RuntimeGuard::acquire_speed(&cfg)?;
    netmatrix::run(cfg, json).await?;
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
    inline_secrets: bool,
) -> anyhow::Result<()> {
    let target = probe::ProbeTarget::parse(dest)?;
    if inline_secrets {
        let generated = generate_config_template(
            server_listen,
            client_listen,
            server_addr,
            &target.authority(),
            &target.host,
        );
        write_init_files(output, &generated)
    } else {
        let generated = generate_referenced_config(
            server_listen,
            client_listen,
            server_addr,
            &target.authority(),
            &target.host,
        );
        write_referenced_init_files(output, &generated)
    }
}

/// Encrypt a config's secrets into a machine-bound sealed bundle and rewrite the
/// config to reference it. See [`crate::secret_store`] for the crypto + threat
/// model.
fn seal_config(
    config: &Path,
    output: Option<&Path>,
    host_key: Option<&Path>,
) -> anyhow::Result<()> {
    // Load (and thus resolve any existing references) so we seal the real secret
    // values regardless of how the source config stored them.
    let cfg = load_config(config)?;
    cfg.validate()?;

    // Hold the resolved secrets in Zeroizing so the plaintext base64 is scrubbed
    // when sealing finishes, matching the Zeroizing discipline used elsewhere.
    let mut secrets: Vec<(&'static str, Zeroizing<String>)> =
        vec![("psk", Zeroizing::new(cfg.crypto.psk.as_b64().to_owned()))];
    if let Some(server) = cfg.server.as_ref() {
        secrets.push((
            "private_key",
            Zeroizing::new(server.private_key.as_b64().to_owned()),
        ));
        secrets.push((
            "identity_secret_key",
            Zeroizing::new(server.identity_secret_key.as_b64().to_owned()),
        ));
    }

    let host_key_bytes = match secret_store::load_host_key(host_key) {
        Ok(key) => key,
        Err(secret_store::SealError::HostKeyMissing { path }) => {
            let key = secret_store::create_host_key(host_key)?;
            println!("Created host keyfile: {}", path.display());
            key
        }
        Err(err) => return Err(err.into()),
    };

    let bundle = secret_store::seal_all(
        &host_key_bytes,
        secrets
            .iter()
            .map(|(field, value)| (*field, value.as_str())),
    );

    let config_dir = config
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let bundle_path = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| config_dir.join("parallax.secrets.enc"));

    fs::write(&bundle_path, secret_store::bundle_to_toml(&bundle))
        .with_context(|| format!("failed to write {}", bundle_path.display()))?;

    // The bundle is on disk now, so canonicalization succeeds: build a reference
    // the config can actually resolve, even when `--output` points elsewhere.
    let bundle_ref = sealed_bundle_reference(&config_dir, &bundle_path)?;

    let original = fs::read_to_string(config)
        .with_context(|| format!("failed to re-read {}", config.display()))?;
    let rewritten = rewrite_secrets_to_sealed(
        &original,
        &bundle_ref,
        secrets.iter().map(|(field, _)| *field),
    );
    write_secret_file_overwrite(config, &rewritten)?;

    println!(
        "Sealed {} secret(s) into {}",
        secrets.len(),
        bundle_path.display()
    );
    println!(
        "Rewrote {} to reference the sealed bundle.",
        config.display()
    );
    println!(
        "The host keyfile stays on THIS machine only. The config and bundle are \
         now safe to back up; they cannot be used elsewhere without it."
    );
    Ok(())
}

/// Build the reference a sealed config should use to find its bundle. A relative
/// reference resolves against the config's own directory, so when the bundle sits
/// next to the config we store just its file name (portable). When `--output`
/// puts the bundle in another directory we store its absolute path, otherwise the
/// directory component would be lost and the config would fail to load.
fn sealed_bundle_reference(config_dir: &Path, bundle_path: &Path) -> anyhow::Result<String> {
    let file_name = bundle_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("sealed bundle output path has no file name")?;
    let bundle_dir = bundle_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let same_dir = match (bundle_dir.canonicalize(), config_dir.canonicalize()) {
        (Ok(bundle), Ok(config)) => bundle == config,
        _ => false,
    };
    if same_dir {
        return Ok(file_name.to_owned());
    }
    let absolute = bundle_path
        .canonicalize()
        .unwrap_or_else(|_| bundle_path.to_path_buf());
    absolute
        .to_str()
        .map(str::to_owned)
        .context("sealed bundle output path must be valid UTF-8")
}

/// Rewrite each named secret assignment line to a `{ sealed = "<bundle>#<field>" }`
/// reference, preserving the rest of the file (comments, formatting, ordering).
/// Secrets are always single-line assignments, so a line-targeted rewrite is
/// safe and avoids a lossy TOML round-trip.
fn rewrite_secrets_to_sealed<'a>(
    original: &str,
    bundle_name: &str,
    fields: impl IntoIterator<Item = &'a str>,
) -> String {
    let targets: Vec<&str> = fields.into_iter().collect();
    let mut out = String::with_capacity(original.len());
    for line in original.lines() {
        let trimmed = line.trim_start();
        let indent = &line[..line.len() - trimmed.len()];
        let mut replaced = false;
        for field in &targets {
            // Match `psk = ...` / `private_key= ...` etc. at the start of the
            // logical assignment (after indentation), not as a substring.
            if let Some(rest) = trimmed.strip_prefix(field) {
                let rest = rest.trim_start();
                if rest.starts_with('=') {
                    out.push_str(indent);
                    out.push_str(field);
                    out.push_str(&format!(" = {{ sealed = \"{bundle_name}#{field}\" }}"));
                    out.push('\n');
                    replaced = true;
                    break;
                }
            }
        }
        if !replaced {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
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
    let server_identity_keys = identity::keypair();

    let psk = STANDARD.encode(psk);
    let server_private = STANDARD.encode(server_keys.private);
    let server_public = STANDARD.encode(server_keys.public);
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
identity_secret_key = "{}"
replay_cache_path = "{}"
authorized_sni = [{}]
strict_tls13 = true

"#,
        psk,
        server_listen,
        fallback_addr,
        server_private,
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
server_identity_public_key = "{}"
"#,
        psk, client_listen, server_addr, sni, server_public, identity_public,
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
    if let Err(err) = write_secret_file(&client_path, &generated.client) {
        // Client write failed after the secret-bearing server file was created;
        // best-effort remove the orphan so a later `init` retry isn't blocked.
        let _ = fs::remove_file(&server_path);
        return Err(err);
    }
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

/// Overwrite an existing 0600 secret file in place (used by `plx seal` to rewrite
/// a config). Unlike [`write_secret_file`] this truncates rather than refusing
/// when the file exists, and (re)asserts owner-only permissions.
fn write_secret_file_overwrite(path: &Path, contents: &str) -> anyhow::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).truncate(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW: refuse to follow a symlink at the final path component, so a
        // pre-planted link can't redirect this 0600 write onto another file. This
        // matches the hardened read path in `read_secret_config_file`.
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }
    file.write_all(contents.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Config files plus the separate secret sidecars they reference (leak-safe
/// default for `plx init`).
struct ReferencedConfig {
    server: String,
    client: String,
    server_secrets: String,
    client_secrets: String,
}

const SERVER_SECRETS_FILE: &str = "parallax.server.secrets.toml";
const CLIENT_SECRETS_FILE: &str = "parallax.client.secrets.toml";

/// Build paired configs whose secrets live in separate 0600 sidecar files that
/// the configs only reference. A leaked config alone is then not a credential.
fn generate_referenced_config(
    server_listen: &str,
    client_listen: &str,
    server_addr: &str,
    fallback_addr: &str,
    sni: &str,
) -> ReferencedConfig {
    let mut psk = [0_u8; 32];
    OsRng.fill_bytes(&mut psk);
    let server_keys = X25519KeyPair::generate();
    let server_identity_keys = identity::keypair();

    let psk = STANDARD.encode(psk);
    let server_private = STANDARD.encode(server_keys.private);
    let server_public = STANDARD.encode(server_keys.public);
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
psk = {{ file = "{SERVER_SECRETS_FILE}#psk" }}

[traffic]
min_padding = 0
max_padding = 0
min_delay_ms = 0
max_delay_ms = 0
cover_min_interval_ms = 0
cover_max_interval_ms = 0
max_concurrent_streams = 4

[server]
listen = {server_listen}
fallback_addr = {fallback_addr}
private_key = {{ file = "{SERVER_SECRETS_FILE}#private_key" }}
identity_secret_key = {{ file = "{SERVER_SECRETS_FILE}#identity_secret_key" }}
replay_cache_path = "{DEFAULT_REPLAY_CACHE_PATH}"
authorized_sni = [{sni}]
strict_tls13 = true
"#
    );

    let client = format!(
        r#"mode = "client"

[crypto]
psk = {{ file = "{CLIENT_SECRETS_FILE}#psk" }}

[traffic]
min_padding = 0
max_padding = 0
min_delay_ms = 0
max_delay_ms = 0
cover_min_interval_ms = 0
cover_max_interval_ms = 0
max_concurrent_streams = 4

[client]
listen = {client_listen}
server_addr = {server_addr}
sni = {sni}
server_public_key = "{server_public}"
server_identity_public_key = "{identity_public}"
"#
    );

    let server_secrets = format!(
        "# ParallaX SERVER secrets — SENSITIVE. Keep mode 0600. Never commit, never paste.\n\
         psk = \"{psk}\"\n\
         private_key = \"{server_private}\"\n\
         identity_secret_key = \"{identity_secret}\"\n"
    );
    let client_secrets = format!(
        "# ParallaX CLIENT secrets — SENSITIVE. Keep mode 0600. Never commit, never paste.\n\
         psk = \"{psk}\"\n"
    );

    ReferencedConfig {
        server,
        client,
        server_secrets,
        client_secrets,
    }
}

fn write_referenced_init_files(output: &Path, generated: &ReferencedConfig) -> anyhow::Result<()> {
    let files = [
        (output.join("parallax.server.toml"), &generated.server),
        (output.join("parallax.client.toml"), &generated.client),
        (output.join(SERVER_SECRETS_FILE), &generated.server_secrets),
        (output.join(CLIENT_SECRETS_FILE), &generated.client_secrets),
    ];
    anyhow::ensure!(
        output.is_dir(),
        "output directory does not exist: {}",
        output.display()
    );
    for (path, _) in &files {
        anyhow::ensure!(
            !path.exists(),
            "refusing to overwrite existing file in {}: {}",
            output.display(),
            path.display()
        );
    }

    let mut written: Vec<&Path> = Vec::new();
    for (path, contents) in &files {
        if let Err(err) = write_secret_file(path, contents) {
            // Roll back any partial set so a retry isn't blocked by orphans.
            for done in &written {
                let _ = fs::remove_file(done);
            }
            return Err(err);
        }
        written.push(path);
    }

    println!("Configs written (secrets kept in separate 0600 sidecar files):");
    println!("  server: {}", files[0].0.display());
    println!("  client: {}", files[1].0.display());
    println!("  server secrets: {}", files[2].0.display());
    println!("  client secrets: {}", files[3].0.display());
    println!(
        "Next: upload BOTH parallax.server.toml and {SERVER_SECRETS_FILE} to the VPS (same \
         directory), and keep the client files on this machine. Add *.secrets.toml to .gitignore."
    );
    println!(
        "Tip: on the VPS, run `plx seal -c parallax.server.toml` to machine-bind the secrets."
    );
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
        assert_eq!(server.crypto.psk.as_b64(), client.crypto.psk.as_b64());

        let server_cfg = server.server.as_ref().unwrap();
        let client_cfg = client.client.as_ref().unwrap();
        let server_private = crate::config::decode_key32_secret(
            "server.private_key",
            server_cfg.private_key.as_b64(),
        )
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
            true,
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
            true,
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

    #[cfg(unix)]
    #[test]
    fn referenced_init_splits_secrets_into_sidecars_and_loads() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        write_init_config(
            "example.com",
            "203.0.113.10:443",
            "0.0.0.0:443",
            "127.0.0.1:1080",
            dir.path(),
            false,
        )
        .unwrap();

        for name in [
            "parallax.server.toml",
            "parallax.client.toml",
            SERVER_SECRETS_FILE,
            CLIENT_SECRETS_FILE,
        ] {
            let path = dir.path().join(name);
            assert!(path.exists(), "missing {name}");
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{name} should be 0600");
        }

        // The config file alone must NOT contain the raw secret bytes.
        let server_text = fs::read_to_string(dir.path().join("parallax.server.toml")).unwrap();
        assert!(server_text.contains("file = \"parallax.server.secrets.toml#psk\""));

        // It loads (resolving the sidecars) and reports no inline secrets.
        let server = Config::load(dir.path().join("parallax.server.toml")).unwrap();
        assert!(server.inline_secret_fields().is_empty());
        let client = Config::load(dir.path().join("parallax.client.toml")).unwrap();
        client.validate().unwrap();

        // Client and server resolve to the SAME shared PSK.
        assert_eq!(server.crypto.psk.as_b64(), client.crypto.psk.as_b64());
    }

    #[cfg(unix)]
    #[test]
    fn seal_round_trips_and_strips_inline_secrets() {
        use std::os::unix::fs::PermissionsExt;

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
        fs::set_permissions(&server_path, fs::Permissions::from_mode(0o600)).unwrap();

        // Capture an inline secret value so we can prove it is gone post-seal.
        let before = Config::load(&server_path).unwrap();
        let private_b64 = before
            .server
            .as_ref()
            .unwrap()
            .private_key
            .as_b64()
            .to_owned();
        assert!(generated.server.contains(&private_b64));
        assert!(!before.inline_secret_fields().is_empty());

        // Use a temp host keyfile (both seal and runtime read it via the env var).
        let host_key = dir.path().join("host.key");
        std::env::set_var(crate::secret_store::HOST_KEY_ENV, &host_key);

        seal_config(&server_path, None, None).unwrap();

        let bundle_path = dir.path().join("parallax.secrets.enc");
        assert!(bundle_path.exists());
        let rewritten = fs::read_to_string(&server_path).unwrap();
        assert!(
            !rewritten.contains(&private_b64),
            "sealed config must not retain the raw private key"
        );
        assert!(rewritten.contains("sealed = \"parallax.secrets.enc#private_key\""));

        // Reload resolves the sealed bundle back to the original secret bytes.
        let after = Config::load(&server_path).unwrap();
        std::env::remove_var(crate::secret_store::HOST_KEY_ENV);
        assert_eq!(
            after.server.as_ref().unwrap().private_key.as_b64(),
            private_b64
        );
        assert!(after.inline_secret_fields().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn seal_output_in_other_dir_resolves() {
        use std::os::unix::fs::PermissionsExt;

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
        fs::set_permissions(&server_path, fs::Permissions::from_mode(0o600)).unwrap();

        let before = Config::load(&server_path).unwrap();
        let psk_b64 = before.crypto.psk.as_b64().to_owned();

        // Seal the bundle into a *different* directory than the config.
        let bundle_dir = dir.path().join("vault");
        fs::create_dir(&bundle_dir).unwrap();
        let bundle_path = bundle_dir.join("parallax.secrets.enc");
        let host_key = dir.path().join("host.key");
        seal_config(&server_path, Some(&bundle_path), Some(&host_key)).unwrap();

        // The rewritten reference must keep the directory (absolute), not drop it.
        let rewritten = fs::read_to_string(&server_path).unwrap();
        let expected = bundle_path.canonicalize().unwrap();
        assert!(
            rewritten.contains(&format!("{}#psk", expected.display())),
            "sealed reference must retain the bundle directory: {rewritten}"
        );

        // And it still resolves back to the original PSK.
        std::env::set_var(crate::secret_store::HOST_KEY_ENV, &host_key);
        let after = Config::load(&server_path).unwrap();
        std::env::remove_var(crate::secret_store::HOST_KEY_ENV);
        assert_eq!(after.crypto.psk.as_b64(), psk_b64);
    }
}
