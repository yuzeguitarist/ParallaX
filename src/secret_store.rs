//! Machine-bound secret sealing (Phase 2 of config-leak hardening).
//!
//! Long-lived ParallaX secrets (`crypto.psk`, `server.private_key`,
//! `server.identity_secret_key`) can be encrypted into a *sealed bundle* under a
//! key-encryption key (KEK) derived from a host-local keyfile. The sealed bundle
//! and any config that references it are then safe to leak: without the host
//! keyfile they decrypt to nothing on any other machine.
//!
//! Threat model (matches issue #51 / `SECURITY.md`): this protects against
//! accidental *config / bundle* leakage — a paste into an issue or chat, a commit
//! to git, a backup or upload. It does NOT protect against an attacker who can
//! read the host keyfile itself (a root/kernel compromise, the stated non-goal).
//!
//! Crypto: per-secret KEK = HKDF-SHA256(ikm = host_key, salt = random 32B,
//! info = "parallax-seal-v1|<field>"). The base64 secret text is then sealed with
//! XChaCha20-Poly1305 (random 24B nonce) using the logical field name as AAD, so
//! an entry cannot be silently swapped between fields.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

/// Default host keyfile location. Co-located with the replay cache under the
/// package state dir so an operator only has to protect one directory.
pub const DEFAULT_HOST_KEY_PATH: &str = "/var/lib/parallax/host.key";
/// Environment override for the host keyfile path (used by tests and operators
/// who keep state elsewhere, e.g. systemd `StateDirectory`).
pub const HOST_KEY_ENV: &str = "PARALLAX_HOST_KEY_FILE";

const BUNDLE_VERSION: u32 = 1;
const HKDF_INFO: &[u8] = b"parallax-seal-v1";
const NONCE_LEN: usize = 24;

#[derive(Debug, Error)]
pub enum SealError {
    #[error("host keyfile {path:?} not found; create one with `plx seal` first")]
    HostKeyMissing { path: PathBuf },
    #[error("host keyfile {path:?} has insecure permissions (must be 0600 and owned by you)")]
    HostKeyPermissions { path: PathBuf },
    #[error("host keyfile is malformed (expected base64 of exactly 32 bytes)")]
    HostKeyMalformed,
    #[error("host keyfile {path:?} already exists; refusing to overwrite")]
    HostKeyExists { path: PathBuf },
    #[error("sealed bundle is missing, malformed, or has an unsupported version")]
    BundleMalformed,
    #[error("sealed reference must name an entry, e.g. \"parallax.secrets.enc#psk\"")]
    EntryUnspecified,
    #[error("sealed bundle has no entry named {field:?}")]
    EntryMissing { field: String },
    #[error("failed to decrypt sealed secret (wrong host key or tampered bundle)")]
    Decrypt,
    #[error("secret store I/O error")]
    Io(#[source] std::io::Error),
}

/// One encrypted secret entry inside a [`SealedBundle`]. All fields are base64.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedEntry {
    salt: String,
    nonce: String,
    ciphertext: String,
}

/// On-disk sealed bundle: a versioned, named map of encrypted secrets. Safe to
/// store next to the config and even commit, because it is useless without the
/// host keyfile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBundle {
    version: u32,
    #[serde(default)]
    entries: BTreeMap<String, SealedEntry>,
}

impl Default for SealedBundle {
    fn default() -> Self {
        Self {
            version: BUNDLE_VERSION,
            entries: BTreeMap::new(),
        }
    }
}

impl SealedBundle {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Resolve the host keyfile path: the explicit override wins, then the
/// environment variable, then the compiled-in default.
pub fn host_key_path(over: Option<&Path>) -> PathBuf {
    if let Some(path) = over {
        return path.to_path_buf();
    }
    std::env::var_os(HOST_KEY_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_HOST_KEY_PATH))
}

/// Split a reference spec into `(path, Some(fragment))`, e.g.
/// `"parallax.secrets.enc#psk"` -> `("parallax.secrets.enc", Some("psk"))`.
pub(crate) fn split_fragment(spec: &str) -> (&str, Option<&str>) {
    match spec.rsplit_once('#') {
        Some((path, frag)) => (path, Some(frag)),
        None => (spec, None),
    }
}

fn resolve_path(base: &Path, spec: &str) -> PathBuf {
    let candidate = Path::new(spec);
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base.join(candidate)
    }
}

/// Load and validate the host keyfile (base64 of exactly 32 bytes). The file
/// must be 0600 and owned by the current user — the same bar as a secret config.
pub fn load_host_key(over: Option<&Path>) -> Result<Zeroizing<[u8; 32]>, SealError> {
    let path = host_key_path(over);
    let text = crate::config::read_secret_config_file(&path).map_err(|err| match err {
        crate::config::ConfigError::Read(io) if io.kind() == std::io::ErrorKind::NotFound => {
            SealError::HostKeyMissing { path: path.clone() }
        }
        crate::config::ConfigError::InsecureConfigPermissions { .. } => {
            SealError::HostKeyPermissions { path: path.clone() }
        }
        crate::config::ConfigError::Read(io) => SealError::Io(io),
        _ => SealError::HostKeyMalformed,
    })?;
    let decoded = Zeroizing::new(
        STANDARD
            .decode(text.trim())
            .map_err(|_| SealError::HostKeyMalformed)?,
    );
    if decoded.len() != 32 {
        return Err(SealError::HostKeyMalformed);
    }
    let mut key = [0_u8; 32];
    key.copy_from_slice(&decoded);
    Ok(Zeroizing::new(key))
}

/// Create a fresh random host keyfile (0600). Refuses to overwrite an existing
/// one so a re-run of `plx seal` never silently orphans already-sealed bundles.
pub fn create_host_key(over: Option<&Path>) -> Result<Zeroizing<[u8; 32]>, SealError> {
    let path = host_key_path(over);
    if path.exists() {
        return Err(SealError::HostKeyExists { path });
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(SealError::Io)?;
        }
    }

    let mut key = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(key.as_mut_slice());
    let encoded = Zeroizing::new(STANDARD.encode(key.as_slice()));

    write_owner_only(&path, encoded.as_bytes())?;
    Ok(key)
}

fn write_owner_only(path: &Path, contents: &[u8]) -> Result<(), SealError> {
    use std::io::Write as _;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(SealError::Io)?;
    file.write_all(contents).map_err(SealError::Io)?;
    Ok(())
}

fn derive_kek(host_key: &[u8; 32], salt: &[u8], field: &str) -> Zeroizing<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), host_key);
    let mut info = Vec::with_capacity(HKDF_INFO.len() + 1 + field.len());
    info.extend_from_slice(HKDF_INFO);
    info.push(b'|');
    info.extend_from_slice(field.as_bytes());
    let mut okm = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, okm.as_mut_slice())
        .expect("HKDF-SHA256 expand of 32 bytes never fails");
    okm
}

/// Seal one base64 secret string into an encrypted entry bound to `field`.
pub fn seal_secret(host_key: &[u8; 32], field: &str, plaintext_b64: &str) -> SealedEntry {
    let mut salt = [0_u8; 32];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let kek = derive_kek(host_key, &salt, field);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_slice()));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext_b64.as_bytes(),
                aad: field.as_bytes(),
            },
        )
        .expect("XChaCha20-Poly1305 encryption never fails for valid keys");

    SealedEntry {
        salt: STANDARD.encode(salt),
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ciphertext),
    }
}

/// Decrypt one sealed entry back to its base64 secret string.
pub fn open_entry(
    host_key: &[u8; 32],
    field: &str,
    entry: &SealedEntry,
) -> Result<Zeroizing<String>, SealError> {
    let salt = STANDARD
        .decode(&entry.salt)
        .map_err(|_| SealError::BundleMalformed)?;
    let nonce = STANDARD
        .decode(&entry.nonce)
        .map_err(|_| SealError::BundleMalformed)?;
    if nonce.len() != NONCE_LEN {
        return Err(SealError::BundleMalformed);
    }
    let ciphertext = STANDARD
        .decode(&entry.ciphertext)
        .map_err(|_| SealError::BundleMalformed)?;

    let kek = derive_kek(host_key, &salt, field);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_slice()));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: field.as_bytes(),
            },
        )
        .map_err(|_| SealError::Decrypt)?;
    let text = String::from_utf8(plaintext).map_err(|_| SealError::Decrypt)?;
    Ok(Zeroizing::new(text))
}

/// Read a sealed bundle from disk (the bundle itself is ciphertext, so it does
/// not require restrictive permissions).
pub fn read_bundle(path: &Path) -> Result<SealedBundle, SealError> {
    let text = fs::read_to_string(path).map_err(SealError::Io)?;
    let bundle: SealedBundle = toml::from_str(&text).map_err(|_| SealError::BundleMalformed)?;
    if bundle.version != BUNDLE_VERSION {
        return Err(SealError::BundleMalformed);
    }
    Ok(bundle)
}

/// Serialize a sealed bundle to TOML.
pub fn bundle_to_toml(bundle: &SealedBundle) -> String {
    toml::to_string(bundle).expect("sealed bundle always serializes")
}

/// Build a sealed bundle from `(field, base64-secret)` pairs.
pub fn seal_all<'a>(
    host_key: &[u8; 32],
    secrets: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> SealedBundle {
    let mut bundle = SealedBundle::default();
    for (field, plaintext_b64) in secrets {
        bundle.entries.insert(
            field.to_owned(),
            seal_secret(host_key, field, plaintext_b64),
        );
    }
    bundle
}

/// Resolve a `{ sealed = "<path>#<field>" }` reference to its base64 secret.
/// `base` is the config directory; relative bundle paths resolve against it.
pub fn open_sealed_reference(
    base: &Path,
    spec: &str,
    over: Option<&Path>,
) -> Result<Zeroizing<String>, SealError> {
    let (path_part, fragment) = split_fragment(spec);
    let field = fragment.ok_or(SealError::EntryUnspecified)?;
    let bundle = read_bundle(&resolve_path(base, path_part))?;
    let entry = bundle
        .entries
        .get(field)
        .ok_or_else(|| SealError::EntryMissing {
            field: field.to_owned(),
        })?;
    let host_key = load_host_key(over)?;
    open_entry(&host_key, field, entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_host_key() -> (tempfile::TempDir, Zeroizing<[u8; 32]>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host.key");
        let key = create_host_key(Some(&path)).unwrap();
        (dir, key)
    }

    #[test]
    fn seal_open_round_trips() {
        let (_dir, key) = temp_host_key();
        let secret = "c2VjcmV0LXBzay1iYXNlNjQtdmFsdWUtMzJieXRlcw==";
        let entry = seal_secret(&key, "crypto.psk", secret);
        let opened = open_entry(&key, "crypto.psk", &entry).unwrap();
        assert_eq!(opened.as_str(), secret);
    }

    #[test]
    fn open_with_wrong_field_fails() {
        let (_dir, key) = temp_host_key();
        let entry = seal_secret(&key, "crypto.psk", "AAAA");
        // The field is bound as AAD, so decrypting under another name must fail.
        assert!(matches!(
            open_entry(&key, "server.private_key", &entry),
            Err(SealError::Decrypt)
        ));
    }

    #[test]
    fn open_with_wrong_host_key_fails() {
        let (_dir_a, key_a) = temp_host_key();
        let (_dir_b, key_b) = temp_host_key();
        let entry = seal_secret(&key_a, "crypto.psk", "AAAA");
        assert!(matches!(
            open_entry(&key_b, "crypto.psk", &entry),
            Err(SealError::Decrypt)
        ));
    }

    #[test]
    fn create_host_key_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host.key");
        create_host_key(Some(&path)).unwrap();
        assert!(matches!(
            create_host_key(Some(&path)),
            Err(SealError::HostKeyExists { .. })
        ));
    }

    #[test]
    fn bundle_round_trips_through_toml() {
        let (_dir, key) = temp_host_key();
        let bundle = seal_all(
            &key,
            [
                ("crypto.psk", "AAAA"),
                ("server.private_key", "BBBB"),
                ("server.identity_secret_key", "CCCC"),
            ],
        );
        let text = bundle_to_toml(&bundle);
        let parsed: SealedBundle = toml::from_str(&text).unwrap();
        assert_eq!(parsed.version, BUNDLE_VERSION);
        let opened = open_entry(
            &key,
            "server.private_key",
            &parsed.entries["server.private_key"],
        )
        .unwrap();
        assert_eq!(opened.as_str(), "BBBB");
    }

    #[test]
    fn open_sealed_reference_reads_bundle_and_decrypts() {
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("host.key");
        let key = create_host_key(Some(&host)).unwrap();
        let bundle = seal_all(&key, [("crypto.psk", "Zm9vYmFy")]);
        let bundle_path = dir.path().join("parallax.secrets.enc");
        fs::write(&bundle_path, bundle_to_toml(&bundle)).unwrap();

        let opened =
            open_sealed_reference(dir.path(), "parallax.secrets.enc#psk", Some(&host)).unwrap_err();
        // The bundle entry is keyed "crypto.psk", not "psk" -> EntryMissing.
        assert!(matches!(opened, SealError::EntryMissing { .. }));

        let opened =
            open_sealed_reference(dir.path(), "parallax.secrets.enc#crypto.psk", Some(&host))
                .unwrap();
        assert_eq!(opened.as_str(), "Zm9vYmFy");
    }
}
