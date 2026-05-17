use std::{
    collections::{HashSet, VecDeque},
    fmt,
    fs::{self, OpenOptions},
    io::{self, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const DEFAULT_REPLAY_WINDOW_SECS: u64 = 2 * 60;
const AUTH_JOURNAL_VERSION: &str = "parallax-replay-cache-v3";
const CACHE_KEY_LABEL: &[u8] = b"ParallaX v1 replay cache MAC key";
const CACHE_JOURNAL_HEADER_MAC_LABEL: &[u8] = b"ParallaX v1 replay cache journal header MAC";
const CACHE_JOURNAL_ENTRY_MAC_LABEL: &[u8] = b"ParallaX v1 replay cache journal entry MAC";
const AUTH_JOURNAL_HEADER_LEN: usize = 187;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthJournalState {
    count: u64,
    tail_mac: [u8; 32],
}

#[derive(Debug)]
pub struct ReplayCache {
    capacity: usize,
    window_secs: u64,
    path: Option<PathBuf>,
    mac_key: Option<CacheMacKey>,
    auth_journal: Option<AuthJournalState>,
    order: VecDeque<ReplayEntry>,
    encoded_entries: VecDeque<String>,
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
            auth_journal: None,
            order: VecDeque::with_capacity(capacity),
            encoded_entries: VecDeque::with_capacity(capacity),
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
        cache.prune_capacity();
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
            auth_journal: Some(AuthJournalState {
                count: 0,
                tail_mac: [0_u8; 32],
            }),
            ..Self::new(capacity)
        };
        if !path.exists() {
            return Ok(cache);
        }

        let raw = fs::read_to_string(&path)?;
        let mac_key = cache.mac_key.as_ref().expect("authenticated cache has key");
        let (entries, journal) = parse_authenticated_journal_entries(&raw, mac_key)?;
        cache.auth_journal = Some(journal);
        for entry in entries {
            cache.insert_loaded(entry);
        }
        cache.prune_expired(current_unix_timestamp()?);
        cache.prune_capacity();
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
        let encoded = self.mac_key.is_none().then(|| encode_plain_entry(&entry));
        self.nonces.insert(entry.nonce);
        self.transcripts.insert(entry.transcript_fingerprint);
        self.order.push_back(entry);
        if let Some(encoded) = encoded {
            self.encoded_entries.push_back(encoded);
        }
    }

    fn prune_expired(&mut self, now: u64) {
        while let Some(entry) = self.order.front() {
            if self.is_fresh(entry.timestamp, now) {
                break;
            }
            if let Some(old) = self.order.pop_front() {
                let _ = self.encoded_entries.pop_front();
                self.nonces.remove(&old.nonce);
                self.transcripts.remove(&old.transcript_fingerprint);
            }
        }
    }

    fn prune_capacity(&mut self) {
        while self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                let _ = self.encoded_entries.pop_front();
                self.nonces.remove(&old.nonce);
                self.transcripts.remove(&old.transcript_fingerprint);
            }
        }
    }

    fn persist(&mut self) -> Result<(), ReplayCacheError> {
        let Some(path) = self.path.clone() else {
            return Ok(());
        };
        let Some(mac_key) = self.mac_key.clone() else {
            return self.persist_plain(&path);
        };

        self.persist_authenticated(&path, &mac_key)
    }

    fn persist_plain(&self, path: &Path) -> Result<(), ReplayCacheError> {
        let body = serialize_cached_entries(&self.encoded_entries);
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, body)?;
        fs::rename(tmp, path)?;
        Ok(())
    }

    fn persist_authenticated(
        &mut self,
        path: &Path,
        mac_key: &CacheMacKey,
    ) -> Result<(), ReplayCacheError> {
        let Some(journal) = self.auth_journal else {
            return self.compact_authenticated_journal(path, mac_key);
        };
        if self.should_compact_authenticated_journal(journal) {
            return self.compact_authenticated_journal(path, mac_key);
        }
        let Some(entry) = self.order.back() else {
            return self.compact_authenticated_journal(path, mac_key);
        };

        let next_count = journal.count.saturating_add(1);
        let (line, next_tail_mac) =
            encode_authenticated_journal_entry(mac_key, next_count, entry, &journal.tail_mac);
        let next_header = authenticated_journal_header(mac_key, next_count, &next_tail_mac);

        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)?;
        if file.metadata()?.len() == 0 {
            if journal.count != 0 {
                drop(file);
                return self.compact_authenticated_journal(path, mac_key);
            }
            let empty_header = authenticated_journal_header(mac_key, 0, &[0_u8; 32]);
            file.write_all(empty_header.as_bytes())?;
        }
        file.seek(SeekFrom::End(0))?;
        file.write_all(line.as_bytes())?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(next_header.as_bytes())?;
        file.flush()?;
        self.auth_journal = Some(AuthJournalState {
            count: next_count,
            tail_mac: next_tail_mac,
        });
        Ok(())
    }

    fn should_compact_authenticated_journal(&self, journal: AuthJournalState) -> bool {
        let active_len = self.order.len() as u64;
        let stale_entries = journal.count.saturating_sub(active_len);
        let stale_threshold = self.capacity.max(1024) as u64;
        stale_entries > stale_threshold
    }

    fn compact_authenticated_journal(
        &mut self,
        path: &Path,
        mac_key: &CacheMacKey,
    ) -> Result<(), ReplayCacheError> {
        let (raw, journal) = serialize_authenticated_journal(&self.order, mac_key);
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, raw)?;
        fs::rename(tmp, path)?;
        self.auth_journal = Some(journal);
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

fn parse_authenticated_journal_entries(
    raw: &str,
    mac_key: &CacheMacKey,
) -> Result<(Vec<ReplayEntry>, AuthJournalState), ReplayCacheError> {
    let (header, body) = raw
        .split_once('\n')
        .ok_or_else(|| ReplayCacheError::MalformedLine("missing replay cache header".to_owned()))?;
    let journal = parse_authenticated_journal_header(header, mac_key)?;
    let mut entries = Vec::with_capacity(journal.count.min(8192) as usize);
    let mut previous_mac = [0_u8; 32];
    let mut lines = body.lines().filter(|line| !line.trim().is_empty());
    for index in 1..=journal.count {
        let line = lines.next().ok_or_else(|| {
            ReplayCacheError::MalformedLine("truncated replay journal".to_owned())
        })?;
        let (entry, entry_mac) =
            parse_authenticated_journal_entry(line, mac_key, index, &previous_mac)?;
        previous_mac = entry_mac;
        entries.push(entry);
    }
    if !bool::from(previous_mac.ct_eq(&journal.tail_mac)) {
        return Err(ReplayCacheError::MacMismatch);
    }
    Ok((entries, journal))
}

fn parse_authenticated_journal_header(
    header: &str,
    mac_key: &CacheMacKey,
) -> Result<AuthJournalState, ReplayCacheError> {
    let mut parts = header.split_whitespace();
    if parts.next() != Some(AUTH_JOURNAL_VERSION) {
        return Err(ReplayCacheError::MalformedLine(header.to_owned()));
    }
    let count_hex = parts
        .next()
        .and_then(|part| part.strip_prefix("count="))
        .ok_or_else(|| ReplayCacheError::MalformedLine(header.to_owned()))?;
    let tail_hex = parts
        .next()
        .and_then(|part| part.strip_prefix("tail="))
        .ok_or_else(|| ReplayCacheError::MalformedLine(header.to_owned()))?;
    let header_mac_hex = parts
        .next()
        .and_then(|part| part.strip_prefix("mac="))
        .ok_or_else(|| ReplayCacheError::MalformedLine(header.to_owned()))?;
    if parts.next().is_some() {
        return Err(ReplayCacheError::MalformedLine(header.to_owned()));
    }

    let count = u64::from_str_radix(count_hex, 16)
        .map_err(|_| ReplayCacheError::MalformedLine(header.to_owned()))?;
    let mut tail_mac = [0_u8; 32];
    decode_hex_exact(tail_hex, &mut tail_mac)?;
    let mut expected_header_mac = [0_u8; 32];
    decode_hex_exact(header_mac_hex, &mut expected_header_mac)?;
    let actual_header_mac = cache_journal_header_mac(mac_key, count, &tail_mac);
    if !bool::from(actual_header_mac.ct_eq(&expected_header_mac)) {
        return Err(ReplayCacheError::MacMismatch);
    }

    Ok(AuthJournalState { count, tail_mac })
}

fn parse_authenticated_journal_entry(
    line: &str,
    mac_key: &CacheMacKey,
    index: u64,
    expected_previous_mac: &[u8; 32],
) -> Result<(ReplayEntry, [u8; 32]), ReplayCacheError> {
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
    let previous_mac_hex = parts
        .next()
        .ok_or_else(|| ReplayCacheError::MalformedLine(line.to_owned()))?;
    let entry_mac_hex = parts
        .next()
        .ok_or_else(|| ReplayCacheError::MalformedLine(line.to_owned()))?;
    if parts.next().is_some() {
        return Err(ReplayCacheError::MalformedLine(line.to_owned()));
    }

    let mut nonce = [0_u8; 8];
    decode_hex_exact(nonce_hex, &mut nonce)?;
    let mut transcript_fingerprint = [0_u8; 32];
    decode_hex_exact(transcript_hex, &mut transcript_fingerprint)?;
    let mut previous_mac = [0_u8; 32];
    decode_hex_exact(previous_mac_hex, &mut previous_mac)?;
    if !bool::from(previous_mac.ct_eq(expected_previous_mac)) {
        return Err(ReplayCacheError::MacMismatch);
    }
    let mut expected_entry_mac = [0_u8; 32];
    decode_hex_exact(entry_mac_hex, &mut expected_entry_mac)?;
    let actual_entry_mac = cache_journal_entry_mac(
        mac_key,
        index,
        timestamp,
        &nonce,
        &transcript_fingerprint,
        expected_previous_mac,
    );
    if !bool::from(actual_entry_mac.ct_eq(&expected_entry_mac)) {
        return Err(ReplayCacheError::MacMismatch);
    }

    Ok((
        ReplayEntry {
            timestamp,
            nonce,
            transcript_fingerprint,
        },
        actual_entry_mac,
    ))
}

fn serialize_cached_entries(entries: &VecDeque<String>) -> String {
    let mut body = String::with_capacity(entries.iter().map(String::len).sum());
    for entry in entries {
        body.push_str(entry);
    }
    body
}

fn encode_plain_entry(entry: &ReplayEntry) -> String {
    let mut line = String::with_capacity(103);
    line.push_str(&entry.timestamp.to_string());
    line.push(' ');
    push_hex(&mut line, &entry.nonce);
    line.push(' ');
    push_hex(&mut line, &entry.transcript_fingerprint);
    line.push('\n');
    line
}

fn serialize_authenticated_journal(
    entries: &VecDeque<ReplayEntry>,
    mac_key: &CacheMacKey,
) -> (String, AuthJournalState) {
    let mut body = String::new();
    let mut previous_mac = [0_u8; 32];
    let mut count = 0_u64;
    for entry in entries {
        count += 1;
        let (line, entry_mac) =
            encode_authenticated_journal_entry(mac_key, count, entry, &previous_mac);
        body.push_str(&line);
        previous_mac = entry_mac;
    }

    let journal = AuthJournalState {
        count,
        tail_mac: previous_mac,
    };
    let header = authenticated_journal_header(mac_key, count, &journal.tail_mac);
    let mut raw = String::with_capacity(header.len() + body.len());
    raw.push_str(&header);
    raw.push_str(&body);
    (raw, journal)
}

fn authenticated_journal_header(mac_key: &CacheMacKey, count: u64, tail_mac: &[u8; 32]) -> String {
    let header_mac = cache_journal_header_mac(mac_key, count, tail_mac);
    let mut raw = String::with_capacity(AUTH_JOURNAL_HEADER_LEN);
    raw.push_str(AUTH_JOURNAL_VERSION);
    raw.push_str(" count=");
    raw.push_str(&format!("{count:016x}"));
    raw.push_str(" tail=");
    push_hex(&mut raw, tail_mac);
    raw.push_str(" mac=");
    push_hex(&mut raw, &header_mac);
    raw.push('\n');
    debug_assert_eq!(raw.len(), AUTH_JOURNAL_HEADER_LEN);
    raw
}

fn encode_authenticated_journal_entry(
    mac_key: &CacheMacKey,
    index: u64,
    entry: &ReplayEntry,
    previous_mac: &[u8; 32],
) -> (String, [u8; 32]) {
    let entry_mac = cache_journal_entry_mac(
        mac_key,
        index,
        entry.timestamp,
        &entry.nonce,
        &entry.transcript_fingerprint,
        previous_mac,
    );
    let mut line = String::with_capacity(240);
    line.push_str(&entry.timestamp.to_string());
    line.push(' ');
    push_hex(&mut line, &entry.nonce);
    line.push(' ');
    push_hex(&mut line, &entry.transcript_fingerprint);
    line.push(' ');
    push_hex(&mut line, previous_mac);
    line.push(' ');
    push_hex(&mut line, &entry_mac);
    line.push('\n');
    (line, entry_mac)
}

fn cache_mac_key(key_material: &[u8]) -> CacheMacKey {
    let mut mac = HmacSha256::new_from_slice(key_material).expect("HMAC accepts any key length");
    mac.update(CACHE_KEY_LABEL);
    let digest = mac.finalize().into_bytes();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    CacheMacKey(out)
}

fn cache_journal_header_mac(mac_key: &CacheMacKey, count: u64, tail_mac: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(&mac_key.0).expect("HMAC accepts any key length");
    mac.update(CACHE_JOURNAL_HEADER_MAC_LABEL);
    mac.update(&count.to_be_bytes());
    mac.update(tail_mac);
    mac.finalize().into_bytes().into()
}

fn cache_journal_entry_mac(
    mac_key: &CacheMacKey,
    index: u64,
    timestamp: u64,
    nonce: &[u8; 8],
    transcript_fingerprint: &[u8; 32],
    previous_mac: &[u8; 32],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(&mac_key.0).expect("HMAC accepts any key length");
    mac.update(CACHE_JOURNAL_ENTRY_MAC_LABEL);
    mac.update(&index.to_be_bytes());
    mac.update(&timestamp.to_be_bytes());
    mac.update(nonce);
    mac.update(transcript_fingerprint);
    mac.update(previous_mac);
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
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.starts_with(AUTH_JOURNAL_VERSION));
        let mut loaded = ReplayCache::load_or_create_authenticated(&path, 8, key).unwrap();
        assert!(!loaded.insert_new(entry, now).unwrap());

        fs::write(
            &path,
            raw.replacen("0303030303030303", "0703030303030303", 1),
        )
        .unwrap();
        assert!(matches!(
            ReplayCache::load_or_create_authenticated(&path, 8, key),
            Err(ReplayCacheError::MacMismatch) | Err(ReplayCacheError::MalformedHex)
        ));
    }

    #[test]
    fn persisted_cache_tracks_capacity_pruning() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay-prune.cache");
        let key = b"0123456789abcdef0123456789abcdef";
        let now = current_unix_timestamp().unwrap();
        let first = ReplayEntry {
            timestamp: now,
            nonce: [1; 8],
            transcript_fingerprint: [2; 32],
        };
        let second = ReplayEntry {
            timestamp: now,
            nonce: [3; 8],
            transcript_fingerprint: [4; 32],
        };

        let mut cache = ReplayCache::load_or_create_authenticated(&path, 1, key).unwrap();
        assert!(cache.insert_new(first, now).unwrap());
        assert!(cache.insert_new(second.clone(), now).unwrap());

        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.starts_with(AUTH_JOURNAL_VERSION));
        assert!(raw.contains("0101010101010101"));
        assert!(raw.contains("0303030303030303"));

        let mut loaded = ReplayCache::load_or_create_authenticated(&path, 1, key).unwrap();
        assert!(!loaded.insert_new(second, now).unwrap());
    }

    #[test]
    fn authenticated_journal_detects_committed_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay-truncate.cache");
        let key = b"0123456789abcdef0123456789abcdef";
        let now = current_unix_timestamp().unwrap();
        let mut cache = ReplayCache::load_or_create_authenticated(&path, 8, key).unwrap();
        assert!(cache
            .insert_new(
                ReplayEntry {
                    timestamp: now,
                    nonce: [1; 8],
                    transcript_fingerprint: [2; 32],
                },
                now,
            )
            .unwrap());
        assert!(cache
            .insert_new(
                ReplayEntry {
                    timestamp: now,
                    nonce: [3; 8],
                    transcript_fingerprint: [4; 32],
                },
                now,
            )
            .unwrap());

        let raw = fs::read_to_string(&path).unwrap();
        let mut lines = raw.lines();
        let truncated = format!(
            "{}\n{}\n",
            lines.next().expect("journal header"),
            lines.next().expect("first journal entry")
        );
        fs::write(&path, truncated).unwrap();

        assert!(matches!(
            ReplayCache::load_or_create_authenticated(&path, 8, key),
            Err(ReplayCacheError::MalformedLine(_)) | Err(ReplayCacheError::MacMismatch)
        ));
    }
}
