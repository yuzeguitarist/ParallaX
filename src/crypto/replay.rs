use std::{
    collections::{HashSet, VecDeque},
    fmt, fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const DEFAULT_REPLAY_WINDOW_SECS: u64 = 2 * 60;
const AUTH_CACHE_VERSION: &str = "parallax-replay-cache-v2";
const CACHE_FILE_MAC_LABEL: &[u8] = b"ParallaX v1 replay cache file MAC";
const CACHE_LINE_MAC_LABEL: &[u8] = b"ParallaX v1 replay cache line MAC";
const CACHE_KEY_LABEL: &[u8] = b"ParallaX v1 replay cache MAC key";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayEntry {
    pub timestamp: u64,
    pub nonce: [u8; 8],
    pub transcript_fingerprint: [u8; 32],
}

#[derive(Debug, Error)]
pub enum ReplayCacheError {
    #[error("replay cache I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("replay cache line is malformed: {0}")]
    MalformedLine(String),
    #[error("replay cache hex field is malformed")]
    MalformedHex,
    #[error("replay cache MAC mismatch")]
    MacMismatch,
    #[error("system clock is before UNIX epoch")]
    Clock,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct CacheMacKey([u8; 32]);

impl fmt::Debug for CacheMacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Debug)]
pub struct ReplayCache {
    capacity: usize,
    window_secs: u64,
    path: Option<PathBuf>,
    mac_key: Option<CacheMacKey>,
    order: VecDeque<ReplayEntry>,
    nonces: HashSet<[u8; 8]>,
    transcripts: HashSet<[u8; 32]>,
}

impl ReplayCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            window_secs: DEFAULT_REPLAY_WINDOW_SECS,
            path: None,
            mac_key: None,
            order: VecDeque::with_capacity(capacity),
            nonces: HashSet::with_capacity(capacity),
            transcripts: HashSet::with_capacity(capacity),
        }
    }

    pub fn load_or_create(
        path: impl AsRef<Path>,
        capacity: usize,
    ) -> Result<Self, ReplayCacheError> {
        let path = path.as_ref().to_path_buf();
        let mut cache = Self {
            path: Some(path.clone()),
            ..Self::new(capacity)
        };
        if !path.exists() {
            return Ok(cache);
        }

        let raw = fs::read_to_string(&path)?;
        for line in raw.lines().filter(|line| !line.trim().is_empty()) {
            let entry = parse_entry(line)?;
            cache.insert_loaded(entry);
        }
        cache.prune_expired(current_unix_timestamp()?);
        Ok(cache)
    }

    pub fn load_or_create_authenticated(
        path: impl AsRef<Path>,
        capacity: usize,
        key_material: &[u8],
    ) -> Result<Self, ReplayCacheError> {
        let path = path.as_ref().to_path_buf();
        let mac_key = cache_mac_key(key_material);
        let mut cache = Self {
            path: Some(path.clone()),
            mac_key: Some(mac_key),
            ..Self::new(capacity)
        };
        if !path.exists() {
            return Ok(cache);
        }

        let raw = fs::read_to_string(&path)?;
        let mac_key = cache.mac_key.as_ref().expect("authenticated cache has key");
        for entry in parse_authenticated_entries(&raw, mac_key)? {
            cache.insert_loaded(entry);
        }
        cache.prune_expired(current_unix_timestamp()?);
        Ok(cache)
    }

    pub fn insert_new(&mut self, entry: ReplayEntry, now: u64) -> Result<bool, ReplayCacheError> {
        if self.capacity == 0 {
            return Ok(true);
        }

        self.prune_expired(now);
        if !self.is_fresh(entry.timestamp, now)
            || self.nonces.contains(&entry.nonce)
            || self.transcripts.contains(&entry.transcript_fingerprint)
        {
            return Ok(false);
        }

        self.insert_loaded(entry);
        self.prune_capacity();
        self.persist()?;
        Ok(true)
    }

    fn is_fresh(&self, timestamp: u64, now: u64) -> bool {
        timestamp <= now.saturating_add(self.window_secs)
            && timestamp.saturating_add(self.window_secs) >= now
    }

    fn insert_loaded(&mut self, entry: ReplayEntry) {
        self.nonces.insert(entry.nonce);
        self.transcripts.insert(entry.transcript_fingerprint);
        self.order.push_back(entry);
    }

    fn prune_expired(&mut self, now: u64) {
        while let Some(entry) = self.order.front() {
            if self.is_fresh(entry.timestamp, now) {
                break;
            }
            if let Some(old) = self.order.pop_front() {
                self.nonces.remove(&old.nonce);
                self.transcripts.remove(&old.transcript_fingerprint);
            }
        }
    }

    fn prune_capacity(&mut self) {
        while self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.nonces.remove(&old.nonce);
                self.transcripts.remove(&old.transcript_fingerprint);
            }
        }
    }

    fn persist(&self) -> Result<(), ReplayCacheError> {
        let Some(path) = &self.path else {
            return Ok(());
        };

        let raw = match self.mac_key.as_ref() {
            Some(mac_key) => serialize_authenticated_entries(&self.order, mac_key),
            None => {
                let mut raw = String::new();
                for entry in &self.order {
                    raw.push_str(&entry.timestamp.to_string());
                    raw.push(' ');
                    push_hex(&mut raw, &entry.nonce);
                    raw.push(' ');
                    push_hex(&mut raw, &entry.transcript_fingerprint);
                    raw.push('\n');
                }
                raw
            }
        };

        let tmp = path.with_extension("tmp");
        fs::write(&tmp, raw)?;
        fs::rename(tmp, path)?;
        Ok(())
    }
}

pub fn current_unix_timestamp() -> Result<u64, ReplayCacheError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ReplayCacheError::Clock)?
        .as_secs())
}

fn parse_entry(line: &str) -> Result<ReplayEntry, ReplayCacheError> {
    let mut parts = line.split_whitespace();
    let timestamp = parts
        .next()
        .ok_or_else(|| ReplayCacheError::MalformedLine(line.to_owned()))?
        .parse::<u64>()
        .map_err(|_| ReplayCacheError::MalformedLine(line.to_owned()))?;
    let nonce_hex = parts
        .next()
        .ok_or_else(|| ReplayCacheError::MalformedLine(line.to_owned()))?;
    let transcript_hex = parts
        .next()
        .ok_or_else(|| ReplayCacheError::MalformedLine(line.to_owned()))?;
    if parts.next().is_some() {
        return Err(ReplayCacheError::MalformedLine(line.to_owned()));
    }

    let mut nonce = [0_u8; 8];
    decode_hex_exact(nonce_hex, &mut nonce)?;
    let mut transcript_fingerprint = [0_u8; 32];
    decode_hex_exact(transcript_hex, &mut transcript_fingerprint)?;
    Ok(ReplayEntry {
        timestamp,
        nonce,
        transcript_fingerprint,
    })
}

fn parse_authenticated_entries(
    raw: &str,
    mac_key: &CacheMacKey,
) -> Result<Vec<ReplayEntry>, ReplayCacheError> {
    let (header, body) = raw
        .split_once('\n')
        .ok_or_else(|| ReplayCacheError::MalformedLine("missing replay cache header".to_owned()))?;
    let mut header_parts = header.split_whitespace();
    if header_parts.next() != Some(AUTH_CACHE_VERSION) {
        return Err(ReplayCacheError::MalformedLine(header.to_owned()));
    }
    let file_mac_hex = header_parts
        .next()
        .ok_or_else(|| ReplayCacheError::MalformedLine(header.to_owned()))?;
    if header_parts.next().is_some() {
        return Err(ReplayCacheError::MalformedLine(header.to_owned()));
    }
    let mut expected_file_mac = [0_u8; 32];
    decode_hex_exact(file_mac_hex, &mut expected_file_mac)?;
    let actual_file_mac = cache_file_mac(mac_key, body.as_bytes());
    if !bool::from(actual_file_mac.ct_eq(&expected_file_mac)) {
        return Err(ReplayCacheError::MacMismatch);
    }

    let mut entries = Vec::new();
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        entries.push(parse_authenticated_entry(line, mac_key)?);
    }
    Ok(entries)
}

fn parse_authenticated_entry(
    line: &str,
    mac_key: &CacheMacKey,
) -> Result<ReplayEntry, ReplayCacheError> {
    let mut parts = line.split_whitespace();
    let timestamp = parts
        .next()
        .ok_or_else(|| ReplayCacheError::MalformedLine(line.to_owned()))?
        .parse::<u64>()
        .map_err(|_| ReplayCacheError::MalformedLine(line.to_owned()))?;
    let nonce_hex = parts
        .next()
        .ok_or_else(|| ReplayCacheError::MalformedLine(line.to_owned()))?;
    let transcript_hex = parts
        .next()
        .ok_or_else(|| ReplayCacheError::MalformedLine(line.to_owned()))?;
    let line_mac_hex = parts
        .next()
        .ok_or_else(|| ReplayCacheError::MalformedLine(line.to_owned()))?;
    if parts.next().is_some() {
        return Err(ReplayCacheError::MalformedLine(line.to_owned()));
    }

    let mut nonce = [0_u8; 8];
    decode_hex_exact(nonce_hex, &mut nonce)?;
    let mut transcript_fingerprint = [0_u8; 32];
    decode_hex_exact(transcript_hex, &mut transcript_fingerprint)?;
    let mut expected_line_mac = [0_u8; 32];
    decode_hex_exact(line_mac_hex, &mut expected_line_mac)?;
    let actual_line_mac = cache_line_mac(mac_key, timestamp, &nonce, &transcript_fingerprint);
    if !bool::from(actual_line_mac.ct_eq(&expected_line_mac)) {
        return Err(ReplayCacheError::MacMismatch);
    }

    Ok(ReplayEntry {
        timestamp,
        nonce,
        transcript_fingerprint,
    })
}

fn serialize_authenticated_entries(
    entries: &VecDeque<ReplayEntry>,
    mac_key: &CacheMacKey,
) -> String {
    let mut body = String::new();
    for entry in entries {
        body.push_str(&entry.timestamp.to_string());
        body.push(' ');
        push_hex(&mut body, &entry.nonce);
        body.push(' ');
        push_hex(&mut body, &entry.transcript_fingerprint);
        body.push(' ');
        push_hex(
            &mut body,
            &cache_line_mac(
                mac_key,
                entry.timestamp,
                &entry.nonce,
                &entry.transcript_fingerprint,
            ),
        );
        body.push('\n');
    }

    let mut raw = String::new();
    raw.push_str(AUTH_CACHE_VERSION);
    raw.push(' ');
    push_hex(&mut raw, &cache_file_mac(mac_key, body.as_bytes()));
    raw.push('\n');
    raw.push_str(&body);
    raw
}

fn cache_mac_key(key_material: &[u8]) -> CacheMacKey {
    let mut mac = HmacSha256::new_from_slice(key_material).expect("HMAC accepts any key length");
    mac.update(CACHE_KEY_LABEL);
    let digest = mac.finalize().into_bytes();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    CacheMacKey(out)
}

fn cache_file_mac(mac_key: &CacheMacKey, body: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(&mac_key.0).expect("HMAC accepts any key length");
    mac.update(CACHE_FILE_MAC_LABEL);
    mac.update(&(body.len() as u64).to_be_bytes());
    mac.update(body);
    mac.finalize().into_bytes().into()
}

fn cache_line_mac(
    mac_key: &CacheMacKey,
    timestamp: u64,
    nonce: &[u8; 8],
    transcript_fingerprint: &[u8; 32],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(&mac_key.0).expect("HMAC accepts any key length");
    mac.update(CACHE_LINE_MAC_LABEL);
    mac.update(&timestamp.to_be_bytes());
    mac.update(nonce);
    mac.update(transcript_fingerprint);
    mac.finalize().into_bytes().into()
}

fn push_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

fn decode_hex_exact(input: &str, out: &mut [u8]) -> Result<(), ReplayCacheError> {
    if input.len() != out.len() * 2 {
        return Err(ReplayCacheError::MalformedHex);
    }
    for (idx, chunk) in input.as_bytes().chunks_exact(2).enumerate() {
        out[idx] = (hex_value(chunk[0])? << 4) | hex_value(chunk[1])?;
    }
    Ok(())
}

fn hex_value(byte: u8) -> Result<u8, ReplayCacheError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ReplayCacheError::MalformedHex),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_recent_nonce_or_transcript_replay() {
        let mut cache = ReplayCache::new(8);
        let first = ReplayEntry {
            timestamp: 100,
            nonce: [1; 8],
            transcript_fingerprint: [2; 32],
        };

        assert!(cache.insert_new(first.clone(), 100).unwrap());
        assert!(!cache.insert_new(first.clone(), 100).unwrap());
        assert!(!cache
            .insert_new(
                ReplayEntry {
                    timestamp: 101,
                    nonce: [1; 8],
                    transcript_fingerprint: [3; 32],
                },
                101,
            )
            .unwrap());
        assert!(!cache
            .insert_new(
                ReplayEntry {
                    timestamp: 101,
                    nonce: [4; 8],
                    transcript_fingerprint: [2; 32],
                },
                101,
            )
            .unwrap());
    }

    #[test]
    fn rejects_stale_timestamp() {
        let mut cache = ReplayCache::new(8);
        let entry = ReplayEntry {
            timestamp: 1,
            nonce: [1; 8],
            transcript_fingerprint: [2; 32],
        };

        assert!(!cache
            .insert_new(entry, DEFAULT_REPLAY_WINDOW_SECS + 2)
            .unwrap());
    }

    #[test]
    fn persists_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.cache");
        let now = current_unix_timestamp().unwrap();
        let entry = ReplayEntry {
            timestamp: now,
            nonce: [1; 8],
            transcript_fingerprint: [2; 32],
        };

        let mut cache = ReplayCache::load_or_create(&path, 8).unwrap();
        assert!(cache.insert_new(entry.clone(), now).unwrap());

        let mut loaded = ReplayCache::load_or_create(&path, 8).unwrap();
        assert!(!loaded.insert_new(entry, now).unwrap());
    }

    #[test]
    fn authenticated_cache_persists_and_rejects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay-auth.cache");
        let key = b"0123456789abcdef0123456789abcdef";
        let now = current_unix_timestamp().unwrap();
        let entry = ReplayEntry {
            timestamp: now,
            nonce: [3; 8],
            transcript_fingerprint: [4; 32],
        };

        let mut cache = ReplayCache::load_or_create_authenticated(&path, 8, key).unwrap();
        assert!(cache.insert_new(entry.clone(), now).unwrap());
        let mut loaded = ReplayCache::load_or_create_authenticated(&path, 8, key).unwrap();
        assert!(!loaded.insert_new(entry, now).unwrap());

        let raw = fs::read_to_string(&path).unwrap();
        fs::write(&path, raw.replace('3', "7")).unwrap();
        assert!(matches!(
            ReplayCache::load_or_create_authenticated(&path, 8, key),
            Err(ReplayCacheError::MacMismatch) | Err(ReplayCacheError::MalformedHex)
        ));
    }
}
