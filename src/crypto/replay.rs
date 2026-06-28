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

use crate::util::hex::push_hex;

pub const DEFAULT_REPLAY_WINDOW_SECS: u64 = 2 * 60;
/// Maximum clock skew tolerated on a client-supplied (MAC-bound) handshake
/// timestamp dated in the FUTURE. The past bound stays at `window_secs`, but the
/// future bound is clamped tight: without this, a PSK-holding client could date
/// an entry up to `now + window_secs` ahead, which both doubles that entry's
/// lifetime AND lands it at the FRONT of the arrival-ordered `order` deque, so
/// `prune_expired` (which assumes arrival order == expiry order and stops at the
/// first still-fresh entry) returns early forever and never reaps the genuinely
/// stale entries behind it — accelerating CacheFull fail-close. 5s covers real
/// clock skew without giving an attacker a future-dating lever.
const MAX_FUTURE_SKEW_SECS: u64 = 5;
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

/// Outcome of attempting to record an authenticated handshake in the replay
/// cache. Lets callers distinguish a genuine replay from operational conditions
/// (stale timestamp, capacity exhaustion) so the two are not conflated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayInsertOutcome {
    /// Recorded; this handshake is fresh and unseen (or replay protection is off).
    Inserted,
    /// The nonce or transcript fingerprint was already present — a real replay.
    Replayed,
    /// The timestamp falls outside the freshness window (stale or future-skewed).
    Stale,
    /// The cache is full of still-fresh entries; nothing was evicted (evicting a
    /// fresh entry would re-open it to replay). A load-shed, not an attack.
    CacheFull,
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

    /// Overrides the PAST/retention window (default [`DEFAULT_REPLAY_WINDOW_SECS`]).
    /// This bound governs only how far in the PAST a ClientHello timestamp may be
    /// and how long entries are retained for replay detection (via `prune_expired`);
    /// the FUTURE bound is the fixed [`MAX_FUTURE_SKEW_SECS`] regardless of this
    /// value (see `is_fresh`). Widening it is safe ONLY if the SAME window is also
    /// used for the load-time prune — otherwise entries pruned at load would be
    /// accepted at runtime, opening a post-restart replay gap; construct via
    /// [`Self::load_or_create_authenticated_with_window`] to keep them consistent.
    pub fn with_window_secs(mut self, window_secs: u64) -> Self {
        self.window_secs = window_secs;
        self
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

        let raw = read_cache_file(&path)?;
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
        Self::load_or_create_authenticated_with_window(
            path,
            capacity,
            key_material,
            DEFAULT_REPLAY_WINDOW_SECS,
        )
    }

    /// Like [`load_or_create_authenticated`] but applies `window_secs` BEFORE the
    /// load-time `prune_expired`. Critical: building the cache with the default
    /// window and widening it afterwards prunes entries at load that the wider
    /// runtime window would then ACCEPT — opening a replay-protection gap for the
    /// `(now - window_secs, now - DEFAULT_REPLAY_WINDOW_SECS]` timestamp band
    /// immediately after every restart (the persisted journal exists precisely to
    /// survive restarts). Setting the window first keeps load-prune and runtime
    /// retention consistent.
    pub fn load_or_create_authenticated_with_window(
        path: impl AsRef<Path>,
        capacity: usize,
        key_material: &[u8],
        window_secs: u64,
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
        }
        .with_window_secs(window_secs);
        if !path.exists() {
            return Ok(cache);
        }

        let raw = read_cache_file(&path)?;
        // A crash during the FIRST append can materialize a 0-byte (or, via a
        // partial write, whitespace-only) file before the empty header is written
        // and synced. Treat that the same as "no file": a fresh, empty, loadable
        // journal (auth_journal is already count=0). The header-only crash variant
        // is healed by the count=0 parse below; this covers the pre-header window.
        // The next insert_new -> persist_authenticated sees count==0 and rewrites the
        // file cleanly via compact (tmp-file + rename), discarding any stale bytes.
        if raw.trim().is_empty() {
            return Ok(cache);
        }
        let mac_key_owned = cache.mac_key.clone().expect("authenticated cache has key");
        let (entries, journal, has_uncommitted_tail) =
            parse_authenticated_journal_entries(&raw, &mac_key_owned)?;
        cache.auth_journal = Some(journal);
        for entry in entries {
            cache.insert_loaded(entry);
        }
        cache.prune_expired(current_unix_timestamp()?);
        // Heal an uncommitted trailing entry left by a crash mid-persist by
        // rewriting the file to its committed state, so a later append starts at
        // the correct offset and the cache stays loadable.
        if has_uncommitted_tail {
            cache.compact_authenticated_journal(&path, &mac_key_owned)?;
        }
        Ok(cache)
    }

    pub fn insert_new(&mut self, entry: ReplayEntry, now: u64) -> Result<bool, ReplayCacheError> {
        Ok(self.insert_new_outcome(entry, now)? == ReplayInsertOutcome::Inserted)
    }

    /// Like [`insert_new`] but distinguishes WHY an entry was not inserted.
    ///
    /// The boolean [`insert_new`] collapses four very different conditions —
    /// a genuine replay (nonce/transcript seen), a stale/out-of-window
    /// timestamp, and the cache being full of still-fresh entries — into a
    /// single `false`. Callers that gate a connection on the result must be able
    /// to tell a real replay (close, it is an attack/duplicate) from capacity
    /// exhaustion (a load-shed/operational condition), otherwise once the cache
    /// fills with fresh entries every legitimate handshake is logged and dropped
    /// as a "replay".
    pub fn insert_new_outcome(
        &mut self,
        entry: ReplayEntry,
        now: u64,
    ) -> Result<ReplayInsertOutcome, ReplayCacheError> {
        if self.capacity == 0 {
            return Ok(ReplayInsertOutcome::Inserted);
        }

        self.prune_expired(now);
        if !self.is_fresh(entry.timestamp, now) {
            return Ok(ReplayInsertOutcome::Stale);
        }

        if !self.nonces.insert(entry.nonce) {
            return Ok(ReplayInsertOutcome::Replayed);
        }
        if !self.transcripts.insert(entry.transcript_fingerprint) {
            self.nonces.remove(&entry.nonce);
            return Ok(ReplayInsertOutcome::Replayed);
        }
        if self.order.len() >= self.capacity {
            self.nonces.remove(&entry.nonce);
            self.transcripts.remove(&entry.transcript_fingerprint);
            return Ok(ReplayInsertOutcome::CacheFull);
        }

        let nonce = entry.nonce;
        let transcript = entry.transcript_fingerprint;
        self.push_loaded_entry(entry);
        if let Err(err) = self.persist() {
            // Roll back the in-memory mutation for THIS entry so memory tracks
            // durable state exactly: a legitimate retry can re-insert (no false
            // Replayed), and no later append skips an entry that was never written.
            if self.pop_pushed_entry().is_some() {
                self.nonces.remove(&nonce);
                self.transcripts.remove(&transcript);
            }
            return Err(err);
        }
        Ok(ReplayInsertOutcome::Inserted)
    }

    fn is_fresh(&self, timestamp: u64, now: u64) -> bool {
        // Future bound clamped to MAX_FUTURE_SKEW_SECS (not window_secs) so a
        // future-dated entry cannot linger at the front of `order` and starve
        // prune_expired; past bound stays at the full replay window.
        timestamp <= now.saturating_add(MAX_FUTURE_SKEW_SECS)
            && timestamp.saturating_add(self.window_secs) >= now
    }

    fn insert_loaded(&mut self, entry: ReplayEntry) {
        self.nonces.insert(entry.nonce);
        self.transcripts.insert(entry.transcript_fingerprint);
        self.push_loaded_entry(entry);
    }

    fn push_loaded_entry(&mut self, entry: ReplayEntry) {
        let encoded =
            (self.path.is_some() && self.mac_key.is_none()).then(|| encode_plain_entry(&entry));
        self.order.push_back(entry);
        if let Some(encoded) = encoded {
            self.encoded_entries.push_back(encoded);
        }
    }

    /// Reverses exactly one [`push_loaded_entry`]: pops the just-pushed entry and,
    /// in plain-on-disk mode, its encoded line. Used to roll back a staged insert
    /// when `persist` fails so in-memory state never drifts ahead of the journal.
    fn pop_pushed_entry(&mut self) -> Option<ReplayEntry> {
        let entry = self.order.pop_back()?;
        if self.path.is_some() && self.mac_key.is_none() {
            self.encoded_entries.pop_back();
        }
        Some(entry)
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
        write_cache_file(&tmp, body.as_bytes())?;
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
        // count==0 means no committed header exists yet (fresh file, or a 0-byte/
        // whitespace-only file left by a crash before the empty header was synced).
        // Route the first insert through the atomic tmp-file+rename clean write so
        // any stale prefix bytes are discarded instead of being half-overwritten by
        // the in-place header rewrite below (the in-memory order already holds the
        // just-inserted entry, so this persists it as a clean count=1 journal).
        if journal.count == 0 {
            return self.compact_authenticated_journal(path, mac_key);
        }
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

        let mut file = open_cache_file_for_append(path)?;
        if file.metadata()?.len() == 0 {
            // count >= 1 is guaranteed here (the count == 0 case returned via compact
            // above), so a 0-length file is an externally-truncated journal: rewrite
            // it cleanly via tmp-file + rename rather than appending onto a missing
            // header.
            drop(file);
            return self.compact_authenticated_journal(path, mac_key);
        }
        let committed_len = file.seek(SeekFrom::End(0))?;
        // Append the entry, then rewrite the header. On a failed APPEND (the common
        // ENOSPC/EIO case) truncate the file back to its last committed length so a
        // half-written orphan line cannot desync the journal. NOTE: this is NOT
        // fully crash-atomic for the in-place header rewrite — if the process dies
        // (or the disk errors) DURING the header `write_all`/`sync_data` at offset
        // 0, set_len(committed_len) removes only the trailing line, not a partially
        // overwritten header, so a subsequent restart can still hit a MacMismatch.
        // The append-failure rollback below is the guarantee; a torn header rewrite
        // is a narrower residual (a robust fix would write via tmp-file + rename,
        // like compact_authenticated_journal). committed_len is the prior committed
        // length (a 0-length file already returned via compact above).
        let append_and_commit = |file: &mut fs::File| -> io::Result<()> {
            file.write_all(line.as_bytes())?;
            // Make the appended entry durable BEFORE the header that will advertise
            // it. Without this ordering a reordered/partial writeback could leave a
            // header claiming count N+1 while entry N+1 is absent, which fails to
            // load as a "truncated journal". The reverse (entry durable, header
            // not) is healed on load by truncating the uncommitted tail.
            file.sync_data()?;
            file.seek(SeekFrom::Start(0))?;
            file.write_all(next_header.as_bytes())?;
            file.sync_data()?;
            Ok(())
        };
        if let Err(err) = append_and_commit(&mut file) {
            let _ = file.set_len(committed_len);
            let _ = file.sync_data();
            return Err(err.into());
        }
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
        write_cache_file(&tmp, raw.as_bytes())?;
        fs::rename(tmp, path)?;
        // Make the rename itself durable so a crash right after compaction/heal
        // cannot leave the directory entry pointing at the pre-rename state.
        fsync_parent_dir(path);
        self.auth_journal = Some(journal);
        Ok(())
    }
}

/// Read the replay-cache journal, refusing to follow a symlinked final path
/// component on unix (`O_NOFOLLOW`), matching the project's secret-file discipline
/// (`config::read_secret_config_file`, the cache write helpers' 0600). The journal
/// is MAC-authenticated so a swapped file already fails verification, but reading
/// through a symlink an attacker planted is exactly the path-vs-read race that
/// discipline closes everywhere else; the read path should not be the one exception.
fn read_cache_file(path: &Path) -> io::Result<String> {
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let mut raw = String::new();
        file.read_to_string(&mut raw)?;
        Ok(raw)
    }
    #[cfg(not(unix))]
    {
        fs::read_to_string(path)
    }
}

fn open_cache_file_for_append(path: &Path) -> io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn write_cache_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let _ = fs::remove_file(path);
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.flush()?;
    // Make the contents durable. This helper backs both the runtime journal
    // compaction and the load-time self-heal, and compaction renames this file
    // into place: without the fsync a crash can leave the renamed file empty or
    // truncated (forcing a re-heal or, worse, an unloadable cache). `flush` alone
    // only reaches the OS page cache.
    file.sync_all()
}

/// Best-effort fsync of `path`'s parent directory so a preceding rename into it
/// is durable. Errors are ignored (not all filesystems support directory fsync).
#[cfg(unix)]
fn fsync_parent_dir(path: &Path) {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = parent.unwrap_or_else(|| Path::new("."));
    if let Ok(dir_file) = fs::File::open(dir) {
        let _ = dir_file.sync_all();
    }
}

#[cfg(not(unix))]
fn fsync_parent_dir(_path: &Path) {}

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
) -> Result<(Vec<ReplayEntry>, AuthJournalState, bool), ReplayCacheError> {
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
    // A crash between the durable entry append and the in-place header rewrite can
    // leave one (or more) committed-looking lines beyond `count`. The header (and
    // its validated tail MAC) is authoritative, so we accept the prefix but flag
    // the uncommitted tail so the caller can rewrite the file to the committed
    // length. Without this, the next append seeks past the stale line, and a later
    // restart parses it as the committed next entry and fails with MacMismatch,
    // blocking startup.
    let has_uncommitted_tail = lines.next().is_some();
    Ok((entries, journal, has_uncommitted_tail))
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
    fn transcript_replay_rolls_back_tentative_nonce_insert() {
        let mut cache = ReplayCache::new(8);
        let first = ReplayEntry {
            timestamp: 100,
            nonce: [1; 8],
            transcript_fingerprint: [2; 32],
        };

        assert!(cache.insert_new(first, 100).unwrap());
        assert!(!cache
            .insert_new(
                ReplayEntry {
                    timestamp: 101,
                    nonce: [9; 8],
                    transcript_fingerprint: [2; 32],
                },
                101,
            )
            .unwrap());
        assert!(cache
            .insert_new(
                ReplayEntry {
                    timestamp: 102,
                    nonce: [9; 8],
                    transcript_fingerprint: [10; 32],
                },
                102,
            )
            .unwrap());
    }

    #[test]
    fn insert_outcome_distinguishes_replay_stale_and_capacity_full() {
        let mut cache = ReplayCache::new(1);
        let first = ReplayEntry {
            timestamp: 100,
            nonce: [1; 8],
            transcript_fingerprint: [2; 32],
        };
        // Fresh insert.
        assert_eq!(
            cache.insert_new_outcome(first.clone(), 100).unwrap(),
            ReplayInsertOutcome::Inserted
        );
        // Same entry again -> genuine replay (nonce + transcript already seen).
        assert_eq!(
            cache.insert_new_outcome(first, 100).unwrap(),
            ReplayInsertOutcome::Replayed
        );
        // A distinct fresh entry while the cache is full -> CacheFull, NOT Replayed.
        // This is the crucial distinction: a full cache must not mislabel every new
        // session as a replay (which would fail-close all clients).
        let second = ReplayEntry {
            timestamp: 100,
            nonce: [3; 8],
            transcript_fingerprint: [4; 32],
        };
        assert_eq!(
            cache.insert_new_outcome(second, 100).unwrap(),
            ReplayInsertOutcome::CacheFull
        );
        // A timestamp far outside the freshness window -> Stale.
        let stale = ReplayEntry {
            timestamp: 100,
            nonce: [5; 8],
            transcript_fingerprint: [6; 32],
        };
        assert_eq!(
            cache
                .insert_new_outcome(stale, 100 + DEFAULT_REPLAY_WINDOW_SECS + 10)
                .unwrap(),
            ReplayInsertOutcome::Stale
        );
    }

    #[test]
    fn fresh_within_widened_window_commits() {
        // A widened window (as the server derives from the pre-PQ deadline) must
        // accept a commit whose gap exceeds the default 120s but is within the
        // window, and still retain the entry for replay detection.
        let mut cache = ReplayCache::new(8).with_window_secs(720);
        let entry = ReplayEntry {
            timestamp: 100,
            nonce: [7; 8],
            transcript_fingerprint: [8; 32],
        };
        // Gap of 605s: well past the old 120s window, inside the 720s one.
        let now = 100 + 600 + 5;
        assert_eq!(
            cache.insert_new_outcome(entry.clone(), now).unwrap(),
            ReplayInsertOutcome::Inserted,
        );
        // The widened window retains the entry (does not prune it early), so a
        // replay of the same nonce/transcript at the same instant is caught.
        assert_eq!(
            cache.insert_new_outcome(entry, now).unwrap(),
            ReplayInsertOutcome::Replayed,
        );
        // Sanity: the default-window cache would have rejected the same gap.
        let mut default_cache = ReplayCache::new(8);
        let same = ReplayEntry {
            timestamp: 100,
            nonce: [9; 8],
            transcript_fingerprint: [10; 32],
        };
        assert_eq!(
            default_cache.insert_new_outcome(same, now).unwrap(),
            ReplayInsertOutcome::Stale,
        );
    }

    #[test]
    fn fresh_entry_survives_capacity_pressure() {
        let mut cache = ReplayCache::new(2);
        let first = ReplayEntry {
            timestamp: 100,
            nonce: [1; 8],
            transcript_fingerprint: [2; 32],
        };
        let second = ReplayEntry {
            timestamp: 100,
            nonce: [3; 8],
            transcript_fingerprint: [4; 32],
        };
        let third = ReplayEntry {
            timestamp: 100,
            nonce: [5; 8],
            transcript_fingerprint: [6; 32],
        };

        assert!(cache.insert_new(first.clone(), 100).unwrap());
        assert!(cache.insert_new(second, 100).unwrap());
        assert!(!cache.insert_new(third, 100).unwrap());
        assert!(!cache.insert_new(first, 100).unwrap());
    }

    #[test]
    fn in_memory_cache_skips_plain_journal_encoding() {
        let mut cache = ReplayCache::new(8);

        assert!(cache
            .insert_new(
                ReplayEntry {
                    timestamp: 100,
                    nonce: [1; 8],
                    transcript_fingerprint: [2; 32],
                },
                100,
            )
            .unwrap());
        assert!(cache.encoded_entries.is_empty());
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

    #[cfg(unix)]
    #[test]
    fn persisted_cache_files_are_private_when_created() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let plain_path = dir.path().join("replay.cache");
        let auth_path = dir.path().join("replay-auth.cache");
        let key = b"0123456789abcdef0123456789abcdef";
        let now = current_unix_timestamp().unwrap();

        let mut plain = ReplayCache::load_or_create(&plain_path, 8).unwrap();
        assert!(plain
            .insert_new(
                ReplayEntry {
                    timestamp: now,
                    nonce: [1; 8],
                    transcript_fingerprint: [2; 32],
                },
                now,
            )
            .unwrap());
        let mut authenticated =
            ReplayCache::load_or_create_authenticated(&auth_path, 8, key).unwrap();
        assert!(authenticated
            .insert_new(
                ReplayEntry {
                    timestamp: now,
                    nonce: [3; 8],
                    transcript_fingerprint: [4; 32],
                },
                now,
            )
            .unwrap());

        assert_eq!(
            fs::metadata(&plain_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&auth_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_load_refuses_to_follow_a_symlinked_path() {
        // O_NOFOLLOW (C-2): a cache path whose final component is a symlink must
        // fail to load rather than read through to the symlink target, matching the
        // secret-file discipline used everywhere else.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.cache");
        let key = b"0123456789abcdef0123456789abcdef";
        let now = current_unix_timestamp().unwrap();
        let mut cache = ReplayCache::load_or_create_authenticated(&real, 8, key).unwrap();
        assert!(cache
            .insert_new(
                ReplayEntry {
                    timestamp: now,
                    nonce: [9; 8],
                    transcript_fingerprint: [9; 32],
                },
                now,
            )
            .unwrap());

        let link = dir.path().join("link.cache");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = ReplayCache::load_or_create_authenticated(&link, 8, key)
            .expect_err("loading through a symlinked cache path must fail closed");
        assert!(
            matches!(err, ReplayCacheError::Io(_)),
            "symlinked cache path must surface an I/O error (O_NOFOLLOW), got {err:?}",
        );
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
    fn full_fresh_cache_rejects_new_entries_without_evicting_old_ones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay-full.cache");
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
        assert!(cache.insert_new(first.clone(), now).unwrap());
        assert!(!cache.insert_new(second, now).unwrap());
        assert!(!cache.insert_new(first.clone(), now).unwrap());

        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.starts_with(AUTH_JOURNAL_VERSION));
        assert!(raw.contains("0101010101010101"));
        assert!(!raw.contains("0303030303030303"));

        let mut loaded = ReplayCache::load_or_create_authenticated(&path, 1, key).unwrap();
        assert!(!loaded.insert_new(first, now).unwrap());
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

    #[test]
    fn future_dated_entry_cannot_starve_pruning() {
        // M-11: a PSK-holding client cannot park a far-future-dated entry at the
        // front of `order` to starve prune_expired — anything more than
        // MAX_FUTURE_SKEW_SECS ahead is rejected as Stale and never inserted, so a
        // later legitimate (now-dated) handshake still inserts cleanly.
        let mut cache = ReplayCache::new(8);
        let now = 1_000_000_u64;
        let future = ReplayEntry {
            timestamp: now + DEFAULT_REPLAY_WINDOW_SECS,
            nonce: [1_u8; 8],
            transcript_fingerprint: [1_u8; 32],
        };
        assert_eq!(
            cache.insert_new_outcome(future, now).unwrap(),
            ReplayInsertOutcome::Stale,
            "a far-future-dated entry must be rejected, not parked at the prune front",
        );
        let fresh = ReplayEntry {
            timestamp: now,
            nonce: [2_u8; 8],
            transcript_fingerprint: [2_u8; 32],
        };
        assert_eq!(
            cache.insert_new_outcome(fresh, now).unwrap(),
            ReplayInsertOutcome::Inserted,
        );
    }

    #[test]
    fn accepts_small_future_clock_skew() {
        // A few seconds of genuine future clock skew (<= MAX_FUTURE_SKEW_SECS) is
        // still accepted, so honest clients with a slightly fast clock are not
        // rejected.
        let mut cache = ReplayCache::new(8);
        let now = 2_000_000_u64;
        let skewed = ReplayEntry {
            timestamp: now + 3,
            nonce: [3_u8; 8],
            transcript_fingerprint: [3_u8; 32],
        };
        assert_eq!(
            cache.insert_new_outcome(skewed, now).unwrap(),
            ReplayInsertOutcome::Inserted,
        );
    }

    #[test]
    fn authenticated_cache_heals_empty_file_left_by_first_append_crash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay-empty.cache");
        let key = b"0123456789abcdef0123456789abcdef";
        let now = current_unix_timestamp().unwrap();

        // A crash during the first append leaves the 0-byte file that create(true)
        // materialized before the header was written. It must heal to a fresh
        // journal, not refuse to load (pre-fix: MalformedLine "missing header").
        fs::write(&path, b"").unwrap();
        let mut cache = ReplayCache::load_or_create_authenticated(&path, 8, key)
            .expect("empty cache file must heal to a fresh journal, not error");

        // The healed cache is functional and writes a valid header on first insert.
        let entry = ReplayEntry {
            timestamp: now,
            nonce: [5; 8],
            transcript_fingerprint: [6; 32],
        };
        assert!(cache.insert_new(entry.clone(), now).unwrap());
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.starts_with(AUTH_JOURNAL_VERSION));

        // And it reloads cleanly with the entry recorded.
        let mut loaded = ReplayCache::load_or_create_authenticated(&path, 8, key).unwrap();
        assert!(!loaded.insert_new(entry, now).unwrap());

        // A whitespace-only file (a partial write) heals the same way.
        let ws_path = dir.path().join("replay-ws.cache");
        fs::write(&ws_path, b"   \n").unwrap();
        ReplayCache::load_or_create_authenticated(&ws_path, 8, key)
            .expect("whitespace-only cache file must heal");
    }

    #[cfg(unix)]
    #[test]
    fn persist_failure_rolls_back_in_memory_state() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay-rollback.cache");
        let key = b"0123456789abcdef0123456789abcdef";
        let now = current_unix_timestamp().unwrap();
        let entry1 = ReplayEntry {
            timestamp: now,
            nonce: [1; 8],
            transcript_fingerprint: [2; 32],
        };
        let entry2 = ReplayEntry {
            timestamp: now,
            nonce: [3; 8],
            transcript_fingerprint: [4; 32],
        };

        let mut cache = ReplayCache::load_or_create_authenticated(&path, 8, key).unwrap();
        assert!(cache.insert_new(entry1.clone(), now).unwrap());

        // Force the NEXT persist to fail at the OS level: make the journal file
        // unwritable so open_cache_file_for_append(.write(true)) returns EACCES.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(
            cache.insert_new_outcome(entry2.clone(), now),
            Err(ReplayCacheError::Io(_))
        ));

        // Restore writability and retry the SAME entry. Pre-fix this returned
        // Replayed (Ok(false)) because the nonce was left in memory after the
        // failed persist; post-fix the rollback lets the legitimate retry insert.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            cache.insert_new(entry2.clone(), now).unwrap(),
            "rolled-back entry must be re-insertable, not falsely Replayed"
        );

        // On-disk state is consistent: a fresh load sees both entries (no orphan,
        // no lost entry), so the journal reloads cleanly with both recorded.
        let mut loaded = ReplayCache::load_or_create_authenticated(&path, 8, key).unwrap();
        assert!(
            !loaded.insert_new(entry1, now).unwrap(),
            "entry1 still recorded"
        );
        assert!(
            !loaded.insert_new(entry2, now).unwrap(),
            "entry2 recorded after retry"
        );
    }

    #[test]
    fn widened_window_retains_entries_across_reload_with_no_replay_gap() {
        // Regression for the post-restart replay gap: building the cache with the
        // default window and widening afterwards pruned entries at load that the
        // wider runtime window then accepted. Loading WITH the wide window must
        // retain them so a replay is still caught after a restart.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay-window-reload.cache");
        let key = b"0123456789abcdef0123456789abcdef";
        // `now` from the real clock (prune uses the real clock internally). The
        // entry is dated 300s in the past: inside a 720s window, outside the 120s
        // default. 300s >> test runtime, so the few-ms drift is irrelevant.
        let now = current_unix_timestamp().unwrap();
        let entry = ReplayEntry {
            timestamp: now - 300,
            nonce: [9; 8],
            transcript_fingerprint: [9; 32],
        };

        let mut cache =
            ReplayCache::load_or_create_authenticated_with_window(&path, 8, key, 720).unwrap();
        assert!(cache.insert_new(entry.clone(), now).unwrap());
        drop(cache);

        // Reload with the SAME wide window: the 300s-old entry must survive the
        // load-time prune, so replaying it is caught as Replayed — not silently
        // re-Inserted (which was the gap).
        let mut reloaded =
            ReplayCache::load_or_create_authenticated_with_window(&path, 8, key, 720).unwrap();
        assert_eq!(
            reloaded.insert_new_outcome(entry, now).unwrap(),
            ReplayInsertOutcome::Replayed,
            "a 300s-old entry must be retained by the wide-window load prune, not replayable",
        );
    }
}
