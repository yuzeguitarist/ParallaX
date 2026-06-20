use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process,
};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::{ClientConfig, Config, Mode};

#[derive(Debug, Error)]
pub enum RuntimeGuardError {
    #[error("runtime guard I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Conflict(RuntimeConflict),
    #[error("runtime guard requires mode = \"client\"")]
    WrongMode,
    #[error("runtime guard requires [client] config")]
    MissingClient,
    #[error("runtime guard metadata is invalid: {0}")]
    InvalidMetadata(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConflict {
    message: String,
    pid: u32,
}

impl RuntimeConflict {
    fn client_blocked_by_speed(speed: &RuntimeInstance) -> Self {
        Self::blocked_by_speed(speed.pid)
    }

    fn speed_blocked_by_client(client: &RuntimeInstance) -> Self {
        let pid = client.pid;
        Self {
            message: format!(
                concat!(
                    "A plx client is already active for this server (pid {}). ",
                    "Test a different server or stop the existing plx client first. ",
                    "Stop command: kill -TERM {}"
                ),
                pid, pid
            ),
            pid,
        }
    }

    fn speed_blocked_by_speed(speed: &RuntimeInstance) -> Self {
        Self::blocked_by_speed(speed.pid)
    }

    fn blocked_by_speed(pid: u32) -> Self {
        Self {
            message: format!(
                concat!(
                    "A plx speed run is already active (pid {}). ",
                    "Wait for it to finish or stop it first. ",
                    "Stop command: kill -TERM {}"
                ),
                pid, pid
            ),
            pid,
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }
}

impl fmt::Display for RuntimeConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeRole {
    Client,
    Speed,
}

impl RuntimeRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Speed => "speed",
        }
    }

    fn parse(value: &str) -> Result<Self, RuntimeGuardError> {
        match value {
            "client" => Ok(Self::Client),
            "speed" => Ok(Self::Speed),
            other => Err(RuntimeGuardError::InvalidMetadata(format!(
                "unknown role `{other}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeInstance {
    role: RuntimeRole,
    pid: u32,
    config_id: String,
    server_addr: String,
}

impl RuntimeInstance {
    fn new(role: RuntimeRole, client: &ClientConfig) -> Self {
        Self {
            role,
            pid: process::id(),
            config_id: client_config_fingerprint(client),
            server_addr: client.server_addr.clone(),
        }
    }

    fn encode(&self) -> String {
        format!(
            "role={}\npid={}\nconfig_id={}\nserver_addr={}\n",
            self.role.as_str(),
            self.pid,
            self.config_id,
            self.server_addr
        )
    }

    fn decode(raw: &str) -> Result<Self, RuntimeGuardError> {
        let mut role = None;
        let mut pid = None;
        let mut config_id = None;
        let mut server_addr = None;

        for line in raw.lines() {
            let Some((key, value)) = line.split_once('=') else {
                return Err(RuntimeGuardError::InvalidMetadata(format!(
                    "malformed line `{line}`"
                )));
            };
            match key {
                "role" => role = Some(RuntimeRole::parse(value)?),
                "pid" => {
                    pid = Some(value.parse::<u32>().map_err(|err| {
                        RuntimeGuardError::InvalidMetadata(format!("invalid pid `{value}`: {err}"))
                    })?);
                }
                "config_id" => config_id = Some(value.to_owned()),
                "server_addr" => server_addr = Some(value.to_owned()),
                other => {
                    return Err(RuntimeGuardError::InvalidMetadata(format!(
                        "unknown key `{other}`"
                    )));
                }
            }
        }

        Ok(Self {
            role: role.ok_or_else(|| missing_field("role"))?,
            pid: pid.ok_or_else(|| missing_field("pid"))?,
            config_id: config_id.ok_or_else(|| missing_field("config_id"))?,
            server_addr: server_addr.ok_or_else(|| missing_field("server_addr"))?,
        })
    }
}

fn missing_field(field: &'static str) -> RuntimeGuardError {
    RuntimeGuardError::InvalidMetadata(format!("missing {field}"))
}

#[derive(Debug)]
pub struct RuntimeGuard {
    path: PathBuf,
    file: File,
}

impl RuntimeGuard {
    pub fn acquire_client(config: &Config) -> Result<Self, RuntimeGuardError> {
        let dir = default_state_dir();
        Self::acquire_client_in_dir(config, &dir)
    }

    pub fn acquire_speed(config: &Config) -> Result<Self, RuntimeGuardError> {
        let dir = default_state_dir();
        Self::acquire_speed_in_dir(config, &dir)
    }

    fn acquire_client_in_dir(config: &Config, dir: &Path) -> Result<Self, RuntimeGuardError> {
        let instance = instance_for_config(RuntimeRole::Client, config)?;
        acquire_with_registry(dir, instance, |active, _current| {
            active
                .iter()
                .find(|instance| instance.role == RuntimeRole::Speed)
                .map(RuntimeConflict::client_blocked_by_speed)
        })
    }

    fn acquire_speed_in_dir(config: &Config, dir: &Path) -> Result<Self, RuntimeGuardError> {
        let instance = instance_for_config(RuntimeRole::Speed, config)?;
        acquire_with_registry(dir, instance, |active, current| {
            if let Some(speed) = active
                .iter()
                .find(|instance| instance.role == RuntimeRole::Speed)
            {
                return Some(RuntimeConflict::speed_blocked_by_speed(speed));
            }
            active
                .iter()
                .find(|instance| {
                    instance.role == RuntimeRole::Client && instance.config_id == current.config_id
                })
                .map(RuntimeConflict::speed_blocked_by_client)
        })
    }
}

impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        let _ = unlock_file(&self.file);
        let _ = fs::remove_file(&self.path);
    }
}

fn instance_for_config(
    role: RuntimeRole,
    config: &Config,
) -> Result<RuntimeInstance, RuntimeGuardError> {
    if config.mode != Mode::Client {
        return Err(RuntimeGuardError::WrongMode);
    }
    let client = config
        .client
        .as_ref()
        .ok_or(RuntimeGuardError::MissingClient)?;
    Ok(RuntimeInstance::new(role, client))
}

fn acquire_with_registry<F>(
    dir: &Path,
    instance: RuntimeInstance,
    conflict: F,
) -> Result<RuntimeGuard, RuntimeGuardError>
where
    F: FnOnce(&[RuntimeInstance], &RuntimeInstance) -> Option<RuntimeConflict>,
{
    ensure_state_dir(dir)?;
    let registry_path = dir.join("registry.lock");
    let registry = open_lock_file(&registry_path)?;
    // Block on the registry mutex so concurrent `plx` launches serialize through
    // the read-active / check-conflict / create-lock critical section instead of
    // fail-fasting. The per-instance and liveness locks below stay non-blocking.
    lock_file_blocking(&registry)?;

    let active = active_instances(dir)?;
    if let Some(conflict) = conflict(&active, &instance) {
        return Err(RuntimeGuardError::Conflict(conflict));
    }

    let path = dir.join(format!(
        "{}-{}-{}.lock",
        instance.role.as_str(),
        instance.pid,
        instance.config_id
    ));
    let mut file = open_lock_file(&path)?;
    if !try_lock_file(&file)? {
        return Err(RuntimeGuardError::InvalidMetadata(format!(
            "runtime lock path is already active: {}",
            path.display()
        )));
    }
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(instance.encode().as_bytes())?;
    file.sync_data()?;

    Ok(RuntimeGuard { path, file })
}

fn active_instances(dir: &Path) -> Result<Vec<RuntimeInstance>, RuntimeGuardError> {
    let mut active = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.file_name().and_then(|name| name.to_str()) == Some("registry.lock") {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("lock") {
            continue;
        }

        let mut file = open_lock_file(&path)?;
        if try_lock_file(&file)? {
            unlock_file(&file)?;
            // Tolerate a concurrent reclaim/exit: another process's guard may have
            // dropped (removing its own file) in the window between our try_lock and
            // this remove. NotFound just means the reclaim already happened.
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
            continue;
        }

        let mut raw = String::new();
        file.seek(SeekFrom::Start(0))?;
        // A LIVE peer whose lock file this binary cannot read/decode (a newer plx
        // version with an extra field, or non-UTF-8) must not wedge every
        // acquisition. Skip-and-warn instead: dropping one unrecognized peer from
        // advisory conflict detection is safer than aborting startup — or than
        // risking a wrong conflict from a partially-decoded forward-version peer.
        if let Err(err) = file.read_to_string(&mut raw) {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "skipping unreadable live runtime lock file"
            );
            continue;
        }
        match RuntimeInstance::decode(&raw) {
            Ok(instance) => active.push(instance),
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "skipping undecodable live runtime lock file"
                );
                continue;
            }
        }
    }
    Ok(active)
}

fn ensure_state_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;

        // The state dir path (/tmp/parallax-<euid>/runtime) is predictable, so on
        // a shared host an attacker can pre-create it or plant a symlink before we
        // do. Re-open the final directory with O_NOFOLLOW | O_DIRECTORY and fstat
        // the fd: a symlinked final component fails open() with ELOOP (ENOTDIR on
        // macOS), a non-dir with ENOTDIR, and a foreign owner is rejected here.
        // Mirrors the fd-based ownership check in config.rs::read_secret_config_file.
        // Like that check, O_NOFOLLOW only guards the FINAL component — the parent
        // /tmp/parallax-<euid> is not validated; this raises the bar without fully
        // closing a hostile-parent race on a shared host.
        let dir_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(dir)?;
        let metadata = dir_file.metadata()?;
        let uid = metadata.uid();
        let euid = rustix::process::geteuid().as_raw();
        if !metadata.is_dir() || uid != euid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "runtime state dir {} is not a euid-owned directory (uid={uid}, euid={euid})",
                    dir.display()
                ),
            ));
        }
    }
    Ok(())
}

fn open_lock_file(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        // O_NOFOLLOW: refuse to open through a symlinked final component so an
        // attacker can't redirect our lock-file writes. O_EXCL is NOT usable here
        // because lock files are intentionally reopened across runs (peer locks in
        // active_instances), so it would break normal multi-instance operation.
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
    }
}

fn default_state_dir() -> PathBuf {
    #[cfg(unix)]
    {
        let uid = rustix::process::geteuid().as_raw();
        PathBuf::from(format!("/tmp/parallax-{uid}/runtime"))
    }
    #[cfg(not(unix))]
    {
        std::env::temp_dir().join("parallax").join("runtime")
    }
}

#[cfg(unix)]
fn try_lock_file(file: &File) -> io::Result<bool> {
    use rustix::fs::{flock, FlockOperation};
    use rustix::io::Errno;

    match flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(true),
        Err(err) if err == Errno::WOULDBLOCK || err == Errno::AGAIN => Ok(false),
        Err(err) => Err(err.into()),
    }
}

#[cfg(not(unix))]
fn try_lock_file(_file: &File) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "runtime guard requires Unix file locking",
    ))
}

/// Blocking exclusive flock for the registry mutex: callers WAIT for the short
/// critical section instead of fail-fasting on contention.
#[cfg(unix)]
fn lock_file_blocking(file: &File) -> io::Result<()> {
    use rustix::fs::{flock, FlockOperation};
    use rustix::io::Errno;

    loop {
        match flock(file, FlockOperation::LockExclusive) {
            Ok(()) => return Ok(()),
            Err(Errno::INTR) => continue,
            Err(err) => return Err(err.into()),
        }
    }
}

#[cfg(not(unix))]
fn lock_file_blocking(_file: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "runtime guard requires Unix file locking",
    ))
}

#[cfg(unix)]
fn unlock_file(file: &File) -> io::Result<()> {
    use rustix::fs::{flock, FlockOperation};

    flock(file, FlockOperation::Unlock).map_err(Into::into)
}

#[cfg(not(unix))]
fn unlock_file(_file: &File) -> io::Result<()> {
    Ok(())
}

pub(crate) fn client_config_fingerprint(client: &ClientConfig) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "server_addr", &client.server_addr);
    hash_field(&mut hasher, "sni", &client.sni);
    hash_field(&mut hasher, "server_public_key", &client.server_public_key);
    hash_field(
        &mut hasher,
        "server_identity_public_key",
        &client.server_identity_public_key,
    );
    hex_lower(&hasher.finalize())
}

fn hash_field(hasher: &mut Sha256, name: &str, value: &str) {
    hasher.update(name.as_bytes());
    hasher.update([0]);
    hasher.update(value.as_bytes());
    hasher.update([0]);
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::config::{CryptoConfig, TrafficConfig, UdpConfig};

    fn config(server_addr: &str) -> Config {
        Config {
            mode: Mode::Client,
            crypto: CryptoConfig {
                psk: "test-psk-not-read-by-runtime-guard".to_owned(),
            },
            traffic: TrafficConfig::default(),
            udp: UdpConfig::default(),
            client: Some(ClientConfig {
                listen: "127.0.0.1:1080".parse::<SocketAddr>().unwrap(),
                server_addr: server_addr.to_owned(),
                sni: "example.com".to_owned(),
                server_public_key: "server-public".to_owned(),
                server_identity_public_key: "server-identity-public".to_owned(),
            }),
            server: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn ensure_state_dir_accepts_owned_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("runtime");
        ensure_state_dir(&dir).unwrap();
        assert!(dir.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn ensure_state_dir_rejects_symlinked_final_component() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("real");
        fs::create_dir_all(&target).unwrap();
        let link = tmp.path().join("link");
        symlink(&target, &link).unwrap();
        // O_NOFOLLOW must make the symlinked final component fail closed.
        assert!(ensure_state_dir(&link).is_err());
    }

    #[test]
    fn speed_rejects_same_server_client() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config("203.0.113.10:443");
        let _client = RuntimeGuard::acquire_client_in_dir(&cfg, dir.path()).unwrap();

        let err = RuntimeGuard::acquire_speed_in_dir(&cfg, dir.path()).unwrap_err();
        assert!(matches!(err, RuntimeGuardError::Conflict(_)));
        assert!(err.to_string().contains("Test a different server"));
    }

    #[test]
    fn speed_allows_different_server_client() {
        let dir = tempfile::tempdir().unwrap();
        let client_cfg = config("203.0.113.10:443");
        let speed_cfg = config("203.0.113.11:443");
        let _client = RuntimeGuard::acquire_client_in_dir(&client_cfg, dir.path()).unwrap();

        let _speed = RuntimeGuard::acquire_speed_in_dir(&speed_cfg, dir.path()).unwrap();
    }

    #[test]
    fn client_rejects_any_active_speed() {
        let dir = tempfile::tempdir().unwrap();
        let speed_cfg = config("203.0.113.10:443");
        let client_cfg = config("203.0.113.11:443");
        let _speed = RuntimeGuard::acquire_speed_in_dir(&speed_cfg, dir.path()).unwrap();

        let err = RuntimeGuard::acquire_client_in_dir(&client_cfg, dir.path()).unwrap_err();
        assert!(matches!(err, RuntimeGuardError::Conflict(_)));
        assert!(err.to_string().contains("plx speed run is already active"));
    }

    #[test]
    fn speed_blocks_concurrent_speed_run() {
        let dir = tempfile::tempdir().unwrap();
        let a = config("203.0.113.20:443");
        let b = config("203.0.113.21:443");
        let _first = RuntimeGuard::acquire_speed_in_dir(&a, dir.path()).unwrap();

        let err = RuntimeGuard::acquire_speed_in_dir(&b, dir.path()).unwrap_err();
        match err {
            RuntimeGuardError::Conflict(conflict) => {
                assert!(conflict
                    .to_string()
                    .contains("plx speed run is already active"));
                assert!(conflict.pid() > 0);
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn drop_releases_lock_so_next_acquire_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config("203.0.113.30:443");
        {
            let _guard = RuntimeGuard::acquire_client_in_dir(&cfg, dir.path()).unwrap();
        }
        // After the first guard drops, the directory should be empty of lock files
        // and a fresh acquire should succeed.
        let _guard = RuntimeGuard::acquire_speed_in_dir(&cfg, dir.path()).unwrap();
    }

    #[test]
    fn server_mode_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config("203.0.113.40:443");
        cfg.mode = Mode::Server;
        let err = RuntimeGuard::acquire_client_in_dir(&cfg, dir.path()).unwrap_err();
        assert!(matches!(err, RuntimeGuardError::WrongMode));
    }

    #[test]
    fn missing_client_section_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config("203.0.113.50:443");
        cfg.client = None;
        let err = RuntimeGuard::acquire_client_in_dir(&cfg, dir.path()).unwrap_err();
        assert!(matches!(err, RuntimeGuardError::MissingClient));
    }

    #[test]
    fn instance_decode_rejects_malformed_metadata() {
        assert!(matches!(
            RuntimeInstance::decode("not-a-key-value-line"),
            Err(RuntimeGuardError::InvalidMetadata(_))
        ));
        assert!(matches!(
            RuntimeInstance::decode("role=unknown\npid=1\nconfig_id=a\nserver_addr=b\n"),
            Err(RuntimeGuardError::InvalidMetadata(_))
        ));
        assert!(matches!(
            RuntimeInstance::decode("role=client\npid=not-a-number\nconfig_id=a\nserver_addr=b\n"),
            Err(RuntimeGuardError::InvalidMetadata(_))
        ));
        assert!(matches!(
            RuntimeInstance::decode("role=client\npid=1\nconfig_id=a\n"),
            Err(RuntimeGuardError::InvalidMetadata(_))
        ));
        assert!(matches!(
            RuntimeInstance::decode("role=client\npid=1\nconfig_id=a\nunknown=x\nserver_addr=b\n"),
            Err(RuntimeGuardError::InvalidMetadata(_))
        ));
    }

    #[test]
    fn instance_round_trip_preserves_fields() {
        let raw = "role=speed\npid=4321\nconfig_id=deadbeef\nserver_addr=1.2.3.4:5\n";
        let decoded = RuntimeInstance::decode(raw).unwrap();
        assert_eq!(decoded.role, RuntimeRole::Speed);
        assert_eq!(decoded.pid, 4321);
        assert_eq!(decoded.config_id, "deadbeef");
        assert_eq!(decoded.server_addr, "1.2.3.4:5");
        assert_eq!(decoded.encode(), raw);
    }

    #[test]
    fn client_config_fingerprint_changes_with_each_field() {
        let base = config("203.0.113.60:443");
        let base_id = client_config_fingerprint(base.client.as_ref().unwrap());
        assert_eq!(base_id.len(), 64);

        let mut alt = base.clone();
        alt.client.as_mut().unwrap().server_addr = "203.0.113.61:443".to_owned();
        assert_ne!(
            client_config_fingerprint(alt.client.as_ref().unwrap()),
            base_id
        );

        let mut alt = base.clone();
        alt.client.as_mut().unwrap().sni = "different.example".to_owned();
        assert_ne!(
            client_config_fingerprint(alt.client.as_ref().unwrap()),
            base_id
        );

        let mut alt = base.clone();
        alt.client.as_mut().unwrap().server_public_key = "rotated".to_owned();
        assert_ne!(
            client_config_fingerprint(alt.client.as_ref().unwrap()),
            base_id
        );

        let mut alt = base.clone();
        alt.client.as_mut().unwrap().server_identity_public_key = "rotated-id".to_owned();
        assert_ne!(
            client_config_fingerprint(alt.client.as_ref().unwrap()),
            base_id
        );
    }

    #[cfg(unix)]
    #[test]
    fn registry_blocks_then_serializes_instead_of_erroring() {
        use std::sync::Arc;
        use std::thread;

        // Eight racing acquisitions of DISTINCT clients (which never conflict) into
        // one shared state dir. The registry mutex must serialize them; none may
        // fail with the old "did not block correctly" InvalidMetadata.
        let dir = Arc::new(tempfile::tempdir().unwrap());
        let mut handles = Vec::new();
        for i in 0..8 {
            let dir = Arc::clone(&dir);
            handles.push(thread::spawn(move || {
                let cfg = config(&format!("203.0.113.{i}:443"));
                RuntimeGuard::acquire_client_in_dir(&cfg, dir.path())
            }));
        }
        // Hold every guard until all threads have joined: distinct clients never
        // conflict, so all eight coexisting proves the registry mutex serialized
        // the critical sections, while keeping the guards alive avoids a guard's
        // Drop-time lock-file removal racing another thread's reclaim.
        let mut guards = Vec::new();
        for handle in handles {
            let result = handle.join().expect("acquire thread panicked");
            assert!(
                result.is_ok(),
                "concurrent acquisition must serialize, got {result:?}"
            );
            guards.push(result.unwrap());
        }
        assert_eq!(guards.len(), 8);
    }

    #[cfg(unix)]
    #[test]
    fn unparseable_live_peer_does_not_wedge_acquire() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        // A live peer whose lock file carries a forward-incompatible extra key
        // (a newer plx version). Valid naming so it passes the directory filters.
        let peer_path = dir.path().join("client-999999-deadbeefcafe.lock");
        let mut peer = open_lock_file(&peer_path).unwrap();
        let contents = "role=client\npid=999999\nconfig_id=deadbeefcafe\n\
                        server_addr=203.0.113.9:443\nstarted_at=1234567890\n";
        peer.write_all(contents.as_bytes()).unwrap();
        peer.sync_data().unwrap();
        // Hold an exclusive lock so active_instances sees a live peer it cannot
        // reclaim and must read+decode (decode rejects the unknown `started_at`).
        assert!(try_lock_file(&peer).unwrap());

        // Acquisition must succeed by skipping the undecodable live peer rather
        // than aborting every launch with InvalidMetadata.
        let cfg = config("203.0.113.10:443");
        let guard = RuntimeGuard::acquire_client_in_dir(&cfg, dir.path());
        assert!(
            guard.is_ok(),
            "an unparseable live peer must not wedge acquisition, got {guard:?}"
        );

        drop(peer);
    }
}
