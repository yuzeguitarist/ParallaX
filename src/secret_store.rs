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
//! XChaCha20-Poly1305 (random 24B nonce) using `version | bundle-id | field` as
//! AAD, so an entry cannot be silently swapped between fields, transplanted into
//! another bundle, or rolled back across a re-seal (each bundle has a fresh id).

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
use zeroize::{Zeroize, Zeroizing};

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
///
/// `id` is a random per-bundle identifier mixed into each entry's AAD so a sealed
/// entry cannot be transplanted between bundles or rolled back across a re-seal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBundle {
    version: u32,
    id: String,
    #[serde(default)]
    entries: BTreeMap<String, SealedEntry>,
}

impl Default for SealedBundle {
    fn default() -> Self {
        let mut id = [0_u8; 16];
        OsRng.fill_bytes(&mut id);
        Self {
            version: BUNDLE_VERSION,
            id: STANDARD.encode(id),
            entries: BTreeMap::new(),
        }
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

/// Resolve a reference path against the config directory: absolute paths are
/// used as-is, relative ones are joined onto `base`. Shared by the `file` and
/// `sealed` reference resolvers.
pub(crate) fn resolve_path(base: &Path, spec: &str) -> PathBuf {
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
        // `InsecureConfigPermissions` only exists on Unix (the 0600/owner check
        // is Unix-only), so this arm must be cfg-gated too — otherwise the crate
        // fails to compile on non-Unix targets (E0599: variant not found).
        #[cfg(unix)]
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
    let out = Zeroizing::new(key);
    // `[u8; 32]` is Copy, so the move into `Zeroizing` above left a plaintext copy
    // of the host key on the stack; wipe it explicitly.
    key.zeroize();
    // The host key is the single value that unlocks every sealed secret; keep it
    // out of swap and core dumps while resident, like the PSK/identity keys.
    crate::process_hardening::protect_secret_bytes("secret_store.host_key", out.as_slice());
    Ok(out)
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
            ensure_host_key_dir(parent)?;
        }
    }

    let mut key = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(key.as_mut_slice());
    // Same rationale as in `load_host_key`: never let the freshly minted host
    // key hit swap or a core dump.
    crate::process_hardening::protect_secret_bytes("secret_store.host_key", key.as_slice());
    let encoded = Zeroizing::new(STANDARD.encode(key.as_slice()));

    write_owner_only(&path, encoded.as_bytes())?;
    Ok(key)
}

/// Ensure the directory that will hold the host keyfile exists with
/// least-privilege permissions. A missing directory (the common first-run
/// `/var/lib/parallax` case, which also stores the sealed bundle and replay
/// cache) is created 0700 — a plain `create_dir_all` under the default umask
/// would yield a world-listable 0755 dir — and the final component is
/// re-opened `O_NOFOLLOW` and fstat-verified to be a euid-owned directory,
/// mirroring `runtime_guard::ensure_state_dir`, so losing the create race to a
/// planted directory or symlink fails closed. A pre-existing directory is left
/// untouched (its mode is the operator's decision — chmod'ing e.g. `.` for a
/// relative `--host-key` would be hostile), with a best-effort warning when it
/// is not owned by the current user.
fn ensure_host_key_dir(dir: &Path) -> Result<(), SealError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

        let euid = rustix::process::geteuid().as_raw();
        if dir.is_dir() {
            if let Ok(metadata) = fs::metadata(dir) {
                if metadata.uid() != euid {
                    tracing::warn!(
                        dir = %dir.display(),
                        uid = metadata.uid(),
                        euid,
                        "host-key directory is not owned by the current user; its owner \
                         can replace the host key or sealed bundle"
                    );
                }
            }
            return Ok(());
        }

        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(SealError::Io)?;

        let dir_file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(dir)
            .map_err(SealError::Io)?;
        let metadata = dir_file.metadata().map_err(SealError::Io)?;
        let uid = metadata.uid();
        if !metadata.is_dir() || uid != euid {
            return Err(SealError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "host-key directory {} is not a euid-owned directory (uid={uid}, euid={euid})",
                    dir.display()
                ),
            )));
        }
        // fchmod through the validated handle: exactly 0700 regardless of umask.
        dir_file
            .set_permissions(fs::Permissions::from_mode(0o700))
            .map_err(SealError::Io)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir).map_err(SealError::Io)
    }
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
    // The KEK decrypts a long-lived secret; exclude it from swap/core dumps for
    // its short lifetime (best-effort, page-granular — see process_hardening).
    crate::process_hardening::protect_secret_bytes("secret_store.kek", okm.as_slice());
    okm
}

/// AEAD associated data binding an entry to its bundle (`version | id | field`).
/// Including the per-bundle `id` and version means a sealed entry only opens in
/// the exact bundle it was sealed into, not after a transplant or rollback.
fn entry_aad(version: u32, bundle_id: &str, field: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(4 + 1 + bundle_id.len() + 1 + field.len());
    aad.extend_from_slice(&version.to_be_bytes());
    aad.push(b'|');
    aad.extend_from_slice(bundle_id.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(field.as_bytes());
    aad
}

/// Seal one base64 secret string into an encrypted entry. `field` keys both the
/// KEK derivation (HKDF info) and `aad`; `aad` additionally binds the bundle
/// (see [`entry_aad`]).
fn seal_secret(host_key: &[u8; 32], field: &str, aad: &[u8], plaintext_b64: &str) -> SealedEntry {
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
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption never fails for valid keys");

    SealedEntry {
        salt: STANDARD.encode(salt),
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ciphertext),
    }
}

/// Decrypt one sealed entry back to its base64 secret string. `field` and `aad`
/// must match the values used at seal time (see [`seal_secret`]).
fn open_entry(
    host_key: &[u8; 32],
    field: &str,
    aad: &[u8],
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
    // Hold the decrypted plaintext in Zeroizing so the buffer is wiped on every
    // path, including the non-UTF-8 error branch below.
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad,
                },
            )
            .map_err(|_| SealError::Decrypt)?,
    );
    let text = std::str::from_utf8(&plaintext).map_err(|_| SealError::Decrypt)?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Read a sealed bundle from disk (the bundle itself is ciphertext, so it does
/// not require restrictive permissions). The final path component is opened with
/// `O_NOFOLLOW` on Unix — matching the project's secret-file discipline
/// (`config::read_secret_config_file`, `replay::read_cache_file`) so a planted
/// symlink cannot redirect the read; a swapped bundle already fails AEAD/parse,
/// but the read path should not be the one place that follows symlinks.
pub fn read_bundle(path: &Path) -> Result<SealedBundle, SealError> {
    #[cfg(unix)]
    let text = {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(SealError::Io)?;
        let mut text = String::new();
        file.read_to_string(&mut text).map_err(SealError::Io)?;
        text
    };
    #[cfg(not(unix))]
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

/// Seal `(field, base64-secret)` pairs into an existing bundle, in place. New
/// fields are added; an existing field is re-sealed (overwritten). Entries are
/// bound to `bundle.id`, so merging keeps every entry openable.
pub fn seal_into<'a>(
    bundle: &mut SealedBundle,
    host_key: &[u8; 32],
    secrets: impl IntoIterator<Item = (&'a str, &'a str)>,
) {
    for (field, plaintext_b64) in secrets {
        let aad = entry_aad(bundle.version, &bundle.id, field);
        bundle.entries.insert(
            field.to_owned(),
            seal_secret(host_key, field, &aad, plaintext_b64),
        );
    }
}

/// Build a fresh sealed bundle from `(field, base64-secret)` pairs.
pub fn seal_all<'a>(
    host_key: &[u8; 32],
    secrets: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> SealedBundle {
    let mut bundle = SealedBundle::default();
    seal_into(&mut bundle, host_key, secrets);
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
    // `load_host_key` protected its own buffer, but returning the Copy array
    // moved the key to this frame and page protection does not follow a move;
    // protect the copy that stays resident while entries decrypt.
    crate::process_hardening::protect_secret_bytes("secret_store.host_key", host_key.as_slice());
    let aad = entry_aad(bundle.version, &bundle.id, field);
    open_entry(&host_key, field, &aad, entry)
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
        // Test fixture, not a real key: base64 of "secret-psk-base64-value-32bytes".
        let secret = "c2VjcmV0LXBzay1iYXNlNjQtdmFsdWUtMzJieXRlcw=="; // gitleaks:allow
        let aad = entry_aad(BUNDLE_VERSION, "test-id", "crypto.psk");
        let entry = seal_secret(&key, "crypto.psk", &aad, secret);
        let opened = open_entry(&key, "crypto.psk", &aad, &entry).unwrap();
        assert_eq!(opened.as_str(), secret);
    }

    #[test]
    fn open_with_wrong_field_fails() {
        let (_dir, key) = temp_host_key();
        let aad = entry_aad(BUNDLE_VERSION, "test-id", "crypto.psk");
        let entry = seal_secret(&key, "crypto.psk", &aad, "AAAA");
        // The field is bound (KEK info + AAD), so decrypting under another name
        // must fail.
        let wrong_aad = entry_aad(BUNDLE_VERSION, "test-id", "server.private_key");
        assert!(matches!(
            open_entry(&key, "server.private_key", &wrong_aad, &entry),
            Err(SealError::Decrypt)
        ));
    }

    #[test]
    fn open_with_wrong_host_key_fails() {
        let (_dir_a, key_a) = temp_host_key();
        let (_dir_b, key_b) = temp_host_key();
        let aad = entry_aad(BUNDLE_VERSION, "test-id", "crypto.psk");
        let entry = seal_secret(&key_a, "crypto.psk", &aad, "AAAA");
        assert!(matches!(
            open_entry(&key_b, "crypto.psk", &aad, &entry),
            Err(SealError::Decrypt)
        ));
    }

    #[test]
    fn entry_does_not_open_after_bundle_transplant() {
        // An entry sealed into one bundle must not decrypt under another bundle's
        // id, even with the same host key and field — defeats transplant/rollback.
        let (_dir, key) = temp_host_key();
        let aad_a = entry_aad(BUNDLE_VERSION, "bundle-a", "crypto.psk");
        let entry = seal_secret(&key, "crypto.psk", &aad_a, "AAAA");
        let aad_b = entry_aad(BUNDLE_VERSION, "bundle-b", "crypto.psk");
        assert!(matches!(
            open_entry(&key, "crypto.psk", &aad_b, &entry),
            Err(SealError::Decrypt)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn create_host_key_creates_owner_only_state_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state").join("parallax");
        create_host_key(Some(&state.join("host.key"))).unwrap();
        // The final state-dir component is exactly owner-only...
        let mode = fs::metadata(&state).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "state dir must be created 0700, got {mode:o}");
        // ...and intermediate components we created grant no group/world access.
        let inter = fs::metadata(dir.path().join("state"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            inter & 0o077,
            0,
            "intermediate dirs must not grant group/world access, got {inter:o}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_host_key_leaves_pre_existing_dir_mode_alone() {
        // A directory the OPERATOR already created keeps its chosen mode: the
        // 0700 tightening applies only to dirs plx creates itself (chmod'ing a
        // pre-existing dir — e.g. `.` for a relative --host-key — is hostile).
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
        create_host_key(Some(&state.join("host.key"))).unwrap();
        let mode = fs::metadata(&state).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "pre-existing dir mode belongs to the operator");
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
        assert_eq!(parsed.id, bundle.id);
        let aad = entry_aad(parsed.version, &parsed.id, "server.private_key");
        let opened = open_entry(
            &key,
            "server.private_key",
            &aad,
            &parsed.entries["server.private_key"],
        )
        .unwrap();
        assert_eq!(opened.as_str(), "BBBB");
    }

    #[test]
    fn seal_into_merges_without_dropping_existing_entries() {
        let (_dir, key) = temp_host_key();
        let mut bundle = seal_all(&key, [("crypto.psk", "AAAA")]);
        seal_into(&mut bundle, &key, [("server.private_key", "BBBB")]);
        // Both the pre-existing and the merged-in entry remain openable.
        for (field, expected) in [("crypto.psk", "AAAA"), ("server.private_key", "BBBB")] {
            let aad = entry_aad(bundle.version, &bundle.id, field);
            let opened = open_entry(&key, field, &aad, &bundle.entries[field]).unwrap();
            assert_eq!(opened.as_str(), expected);
        }
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
