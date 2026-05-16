use std::{
    collections::{HashSet, VecDeque},
    fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use thiserror::Error;

pub const DEFAULT_REPLAY_WINDOW_SECS: u64 = 10 * 60;

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
    #[error("system clock is before UNIX epoch")]
    Clock,
}

#[derive(Debug)]
pub struct ReplayCache {
    capacity: usize,
    window_secs: u64,
    path: Option<PathBuf>,
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

        let mut raw = String::new();
        for entry in &self.order {
            raw.push_str(&entry.timestamp.to_string());
            raw.push(' ');
            push_hex(&mut raw, &entry.nonce);
            raw.push(' ');
            push_hex(&mut raw, &entry.transcript_fingerprint);
            raw.push('\n');
        }

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
}
