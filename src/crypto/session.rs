use std::{fmt, sync::Arc};

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const AEAD_TAG_LEN: usize = 16;

const HKDF_INFO_STACK_LEN: usize = 128;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519KeyPair {
    pub private: [u8; KEY_LEN],
    pub public: [u8; KEY_LEN],
}

impl X25519KeyPair {
    pub fn generate() -> Self {
        let private = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&private);
        Self {
            private: private.to_bytes(),
            public: public.to_bytes(),
        }
    }
}

pub fn x25519_public_from_private(private: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let private = StaticSecret::from(*private);
    PublicKey::from(&private).to_bytes()
}

pub fn x25519_shared_secret(private: &[u8; KEY_LEN], peer_public: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let private = StaticSecret::from(*private);
    let peer_public = PublicKey::from(*peer_public);
    let shared = private.diffie_hellman(&peer_public);
    *shared.as_bytes()
}

impl fmt::Debug for X25519KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X25519KeyPair")
            .field("private", &"<redacted>")
            .field("public", &self.public)
            .finish()
    }
}

// `PartialEq`/`Eq` are derived ONLY under `cfg(test)`: the derived `==` compares
// the live secret key bytes in variable time, which is fine for `assert_eq!` in
// tests but would be a timing side-channel if a production path ever compared
// two `SessionKeys`. Gating the impls makes such a comparison a compile error in
// a non-test build (verified by `cargo build` / `cargo clippy`, which compile the
// production crate without these impls). If a production path ever needs secret
// equality, implement it explicitly via `subtle::ConstantTimeEq` instead.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct SessionKeys {
    pub client_key: [u8; KEY_LEN],
    pub server_key: [u8; KEY_LEN],
    pub client_nonce: [u8; NONCE_LEN],
    pub server_nonce: [u8; NONCE_LEN],
    pub chain_secret: [u8; KEY_LEN],
    pub epoch: u64,
    pub transcript_hash: [u8; KEY_LEN],
    pub x25519_shared_secret: [u8; KEY_LEN],
}

impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKeys")
            .field("client_key", &"<redacted>")
            .field("server_key", &"<redacted>")
            .field("client_nonce", &"<redacted>")
            .field("server_nonce", &"<redacted>")
            .field("chain_secret", &"<redacted>")
            .field("epoch", &self.epoch)
            .field("transcript_hash", &self.transcript_hash)
            .field("x25519_shared_secret", &"<redacted>")
            .finish()
    }
}

impl SessionKeys {
    /// Best-effort: these are inline `[u8; N]` fields, so if the owning
    /// `SessionKeys` is later moved the lock pins the pre-move page (unlike
    /// [`AeadCodec`], whose key/nonce live behind a stable heap box). The live
    /// AEAD keys the data plane actually uses are copied into `AeadCodec` and
    /// pinned there; this call additionally excludes the derivation material from
    /// core dumps. `ZeroizeOnDrop` wipes every field regardless of pinning.
    pub fn protect_secret_memory(&self) {
        crate::process_hardening::protect_secret_bytes("session.client_key", &self.client_key);
        crate::process_hardening::protect_secret_bytes("session.server_key", &self.server_key);
        crate::process_hardening::protect_secret_bytes("session.client_nonce", &self.client_nonce);
        crate::process_hardening::protect_secret_bytes("session.server_nonce", &self.server_nonce);
        crate::process_hardening::protect_secret_bytes("session.chain_secret", &self.chain_secret);
        crate::process_hardening::protect_secret_bytes(
            "session.x25519_shared_secret",
            &self.x25519_shared_secret,
        );
    }
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("HKDF expansion failed")]
    Hkdf,
    #[error("AEAD operation failed")]
    Aead,
    #[error("AEAD nonce sequence exhausted")]
    NonceExhausted,
    #[error("degenerate (all-zero) X25519 shared secret")]
    DegenerateSharedSecret,
    #[error("PSK (HKDF salt) must not be empty")]
    EmptyPsk,
}

pub fn derive_client_keys(
    psk: &[u8],
    client_private: &[u8; KEY_LEN],
    server_public: &[u8; KEY_LEN],
    transcript_hash: &[u8; KEY_LEN],
) -> Result<SessionKeys, SessionError> {
    derive_keys(psk, client_private, server_public, transcript_hash)
}

pub fn derive_server_keys(
    psk: &[u8],
    server_private: &[u8; KEY_LEN],
    client_public: &[u8; KEY_LEN],
    transcript_hash: &[u8; KEY_LEN],
) -> Result<SessionKeys, SessionError> {
    derive_keys(psk, server_private, client_public, transcript_hash)
}

pub fn derive_client_keys_from_shared(
    psk: &[u8],
    x25519_shared_secret: &[u8; KEY_LEN],
    transcript_hash: &[u8; KEY_LEN],
) -> Result<SessionKeys, SessionError> {
    derive_keys_from_shared(psk, *x25519_shared_secret, transcript_hash)
}

pub fn derive_server_keys_from_shared(
    psk: &[u8],
    x25519_shared_secret: &[u8; KEY_LEN],
    transcript_hash: &[u8; KEY_LEN],
) -> Result<SessionKeys, SessionError> {
    derive_keys_from_shared(psk, *x25519_shared_secret, transcript_hash)
}

fn derive_keys(
    psk: &[u8],
    private: &[u8; KEY_LEN],
    peer_public: &[u8; KEY_LEN],
    transcript_hash: &[u8; KEY_LEN],
) -> Result<SessionKeys, SessionError> {
    let x25519_shared_secret = Zeroizing::new(x25519_shared_secret(private, peer_public));
    derive_keys_from_shared(psk, *x25519_shared_secret, transcript_hash)
}

fn derive_keys_from_shared(
    psk: &[u8],
    x25519_shared_secret: [u8; KEY_LEN],
    transcript_hash: &[u8; KEY_LEN],
) -> Result<SessionKeys, SessionError> {
    // Wrap so the shared-secret stack copy is wiped on every return path below
    // (degenerate-reject and HKDF-error included).
    let x25519_shared_secret = Zeroizing::new(x25519_shared_secret);
    // Defense-in-depth: reject a degenerate (all-zero) X25519 shared secret.
    // x25519-dalek does not reject low-order/contributory base points (RFC 7748
    // leaves the all-zero-output check to the caller), so a peer that supplies a
    // small-order public key can force the shared secret to all-zero. This funnel
    // is post-authentication (the peer already passed PSK/X25519 auth, which is
    // what actually gates exploitability), so this only restores the X25519
    // layer's contributory guarantee in the hybrid rather than fixing a break.
    // Constant-time compare so the rejection itself is not a timing oracle.
    if bool::from(x25519_shared_secret.ct_eq(&[0u8; KEY_LEN])) {
        return Err(SessionError::DegenerateSharedSecret);
    }
    let chain_secret = Zeroizing::new(initial_chain_secret(
        psk,
        &x25519_shared_secret,
        transcript_hash,
    )?);
    expand_epoch_keys(*chain_secret, 0, *transcript_hash, *x25519_shared_secret)
}

pub fn expand_epoch_keys(
    chain_secret: [u8; KEY_LEN],
    epoch: u64,
    transcript_hash: [u8; KEY_LEN],
    x25519_shared_secret: [u8; KEY_LEN],
) -> Result<SessionKeys, SessionError> {
    // Wipe the secret stack copies of the inputs on return; `out` keeps its own
    // copies (zeroized on drop via SessionKeys: ZeroizeOnDrop).
    let chain_secret = Zeroizing::new(chain_secret);
    let x25519_shared_secret = Zeroizing::new(x25519_shared_secret);
    let hk = Hkdf::<Sha256>::from_prk(chain_secret.as_slice()).map_err(|_| SessionError::Hkdf)?;

    let mut out = SessionKeys {
        client_key: [0; KEY_LEN],
        server_key: [0; KEY_LEN],
        client_nonce: [0; NONCE_LEN],
        server_nonce: [0; NONCE_LEN],
        chain_secret: *chain_secret,
        epoch,
        transcript_hash,
        x25519_shared_secret: *x25519_shared_secret,
    };

    expand(
        &hk,
        b"client appdata key",
        epoch,
        &transcript_hash,
        &mut out.client_key,
    )?;
    expand(
        &hk,
        b"server appdata key",
        epoch,
        &transcript_hash,
        &mut out.server_key,
    )?;
    expand(
        &hk,
        b"client appdata nonce",
        epoch,
        &transcript_hash,
        &mut out.client_nonce,
    )?;
    expand(
        &hk,
        b"server appdata nonce",
        epoch,
        &transcript_hash,
        &mut out.server_nonce,
    )?;

    Ok(out)
}

/// Derives an INDEPENDENT `(key, nonce_base)` pair per direction for one mux
/// substream carried on its own QUIC stream, from the live session's
/// `chain_secret`/`epoch`/`transcript_hash`. Each concurrent QUIC bidi has its
/// own ordered record stream, so it CANNOT share a `DataRecordCodec` with another
/// substream (the per-record nonce is `nonce_base XOR sequence` with a per-codec
/// monotonic `sequence` bound to one ordered stream — two streams sharing one base
/// would reuse nonces). This derives a fresh base per `stream_id` so each
/// substream is its own nonce epoch.
///
/// Domain separation (why this never collides with the session/epoch keys nor
/// across substreams):
/// - The HKDF labels here (`b"... mux substream ..."`) are DISTINCT from the
///   epoch labels (`b"client appdata key"` etc.) used by [`expand_epoch_keys`], so
///   a substream base can never equal an epoch base.
/// - `stream_id` is folded into the info, so two distinct `stream_id`s under the
///   same `(chain_secret, epoch)` expand under distinct info and yield distinct
///   bases. (Proven over the nonce-base derivation by the Kani harness below.)
///
/// The result reuses the [`SessionKeys`] shape so the existing codec construction
/// (`data_codecs` / the server's inline `AeadCodec::new`) builds the per-substream
/// pair unchanged; only `client_key/server_key/client_nonce/server_nonce` are
/// substream-specific (the carried `chain_secret`/`x25519_shared_secret` mirror
/// the parent so the returned struct stays self-consistent and zeroizes the same).
pub fn expand_substream_keys(
    session_keys: &SessionKeys,
    stream_id: u64,
) -> Result<SessionKeys, SessionError> {
    let chain_secret = Zeroizing::new(session_keys.chain_secret);
    let hk = Hkdf::<Sha256>::from_prk(chain_secret.as_slice()).map_err(|_| SessionError::Hkdf)?;

    let mut out = SessionKeys {
        client_key: [0; KEY_LEN],
        server_key: [0; KEY_LEN],
        client_nonce: [0; NONCE_LEN],
        server_nonce: [0; NONCE_LEN],
        chain_secret: *chain_secret,
        epoch: session_keys.epoch,
        transcript_hash: session_keys.transcript_hash,
        x25519_shared_secret: session_keys.x25519_shared_secret,
    };

    let epoch = session_keys.epoch;
    let transcript_hash = session_keys.transcript_hash;
    expand_substream(
        &hk,
        b"ParallaX v1 mux substream client key",
        epoch,
        stream_id,
        &transcript_hash,
        &mut out.client_key,
    )?;
    expand_substream(
        &hk,
        b"ParallaX v1 mux substream server key",
        epoch,
        stream_id,
        &transcript_hash,
        &mut out.server_key,
    )?;
    expand_substream(
        &hk,
        b"ParallaX v1 mux substream client nonce",
        epoch,
        stream_id,
        &transcript_hash,
        &mut out.client_nonce,
    )?;
    expand_substream(
        &hk,
        b"ParallaX v1 mux substream server nonce",
        epoch,
        stream_id,
        &transcript_hash,
        &mut out.server_nonce,
    )?;

    Ok(out)
}

fn initial_chain_secret(
    psk: &[u8],
    x25519_shared_secret: &[u8; KEY_LEN],
    transcript_hash: &[u8; KEY_LEN],
) -> Result<[u8; KEY_LEN], SessionError> {
    // Two-secret binding for the initial data-plane key, mirroring the discipline
    // in crypto/auth.rs (`derive_auth_key_from_shared` / `derive_mask_key`) and
    // the PQ sandwich rekey (crypto/pq.rs): the PSK is the HKDF salt and the
    // X25519 shared secret is the IKM, so the initial chain secret requires BOTH.
    // An X25519 compromise alone cannot reproduce the initial session keys without
    // the PSK. Transcript binding stays explicit in the expand `info` below, which
    // also carries the (bumped) domain-separation label. psk non-emptiness is
    // enforced upstream by config validation (crypto.psk >= 32 bytes), but the
    // public `derive_*_keys[_from_shared]` entry points take an unchecked `&[u8]`,
    // so reject an empty PSK at runtime — in release too — because an empty HKDF
    // salt is identical to the all-zero salt and would silently drop the PSK
    // binding. Mirrors the `AuthError::EmptyPsk` guard in crypto/auth.rs.
    if psk.is_empty() {
        return Err(SessionError::EmptyPsk);
    }
    let hk = Hkdf::<Sha256>::new(Some(psk), x25519_shared_secret);
    let mut chain_secret = [0_u8; KEY_LEN];
    expand(
        &hk,
        b"ParallaX v2 initial psk+x25519 chain secret",
        0,
        transcript_hash,
        &mut chain_secret,
    )?;
    Ok(chain_secret)
}

fn expand(
    hk: &Hkdf<Sha256>,
    label: &[u8],
    epoch: u64,
    transcript_hash: &[u8; KEY_LEN],
    out: &mut [u8],
) -> Result<(), SessionError> {
    let info_len = 2 + label.len() + 8 + 2 + transcript_hash.len();
    if info_len <= HKDF_INFO_STACK_LEN {
        let mut info = [0_u8; HKDF_INFO_STACK_LEN];
        let used = write_epoch_hkdf_info(&mut info, label, epoch, transcript_hash);
        hk.expand(&info[..used], out)
            .map_err(|_| SessionError::Hkdf)
    } else {
        let epoch = epoch.to_be_bytes();
        let mut info = Vec::with_capacity(info_len);
        info.extend_from_slice(&(label.len() as u16).to_be_bytes());
        info.extend_from_slice(label);
        info.extend_from_slice(&epoch);
        info.extend_from_slice(&(transcript_hash.len() as u16).to_be_bytes());
        info.extend_from_slice(transcript_hash);
        hk.expand(&info, out).map_err(|_| SessionError::Hkdf)
    }
}

fn write_epoch_hkdf_info(
    out: &mut [u8; HKDF_INFO_STACK_LEN],
    label: &[u8],
    epoch: u64,
    transcript_hash: &[u8; KEY_LEN],
) -> usize {
    let mut offset = 0;
    write_bytes(out, &mut offset, &(label.len() as u16).to_be_bytes());
    write_bytes(out, &mut offset, label);
    write_bytes(out, &mut offset, &epoch.to_be_bytes());
    write_bytes(
        out,
        &mut offset,
        &(transcript_hash.len() as u16).to_be_bytes(),
    );
    write_bytes(out, &mut offset, transcript_hash);
    offset
}

/// HKDF-Expand for a per-substream key/nonce. Identical to [`expand`] but folds
/// the `stream_id` into the info between `epoch` and the transcript hash, so the
/// derivation is unique per `(epoch, stream_id)`. The substream labels are
/// distinct from the epoch labels, so this never aliases an epoch key. The info
/// layout (substream labels are short; `2 + label + 8 + 8 + 2 + 32`) always fits
/// `HKDF_INFO_STACK_LEN`, so no heap fallback is needed.
fn expand_substream(
    hk: &Hkdf<Sha256>,
    label: &[u8],
    epoch: u64,
    stream_id: u64,
    transcript_hash: &[u8; KEY_LEN],
    out: &mut [u8],
) -> Result<(), SessionError> {
    let mut info = [0_u8; HKDF_INFO_STACK_LEN];
    let used = write_substream_hkdf_info(&mut info, label, epoch, stream_id, transcript_hash);
    hk.expand(&info[..used], out)
        .map_err(|_| SessionError::Hkdf)
}

/// Builds the substream HKDF info into `out`, returning the byte length written.
/// Length-prefixing the variable-length `label` and `transcript_hash` (and fixing
/// the widths of `epoch`/`stream_id`) makes the encoding injective in
/// `(label, epoch, stream_id, transcript_hash)`: no two distinct tuples produce
/// the same info string. The Kani proof below pins the property HKDF relies on —
/// distinct `stream_id` ⇒ distinct info ⇒ (under HKDF collision resistance)
/// distinct substream keys ⇒ distinct nonce bases ⇒ no cross-substream nonce
/// reuse.
fn write_substream_hkdf_info(
    out: &mut [u8; HKDF_INFO_STACK_LEN],
    label: &[u8],
    epoch: u64,
    stream_id: u64,
    transcript_hash: &[u8; KEY_LEN],
) -> usize {
    let mut offset = 0;
    write_bytes(out, &mut offset, &(label.len() as u16).to_be_bytes());
    write_bytes(out, &mut offset, label);
    write_bytes(out, &mut offset, &epoch.to_be_bytes());
    write_bytes(out, &mut offset, &stream_id.to_be_bytes());
    write_bytes(
        out,
        &mut offset,
        &(transcript_hash.len() as u16).to_be_bytes(),
    );
    write_bytes(out, &mut offset, transcript_hash);
    offset
}

/// A ChaCha20-Poly1305 key shared (immutably) across the parallel crypto
/// workers. Sealing/opening only needs `&LessSafeKey`, so one session key can
/// drive several records concurrently as long as each uses a distinct nonce.
pub type SharedCipher = Arc<LessSafeKey>;

pub struct AeadCodec {
    // Boxed so the secret bytes live at a stable heap address: an `AeadCodec` is
    // built then moved into its owner (and returned by value from constructors),
    // which would relocate inline `[u8; N]` arrays and leave `protect_secret_memory`
    // pinning a dead pre-move page. The heap allocation does not move with the
    // struct, so the page locked at construction stays the live key's page for the
    // codec's lifetime. We deliberately do NOT munlock on drop: the allocator can
    // pack this 32/12-byte box onto a page shared with other live secrets, so a
    // per-codec munlock would un-pin a neighbor. The kernel releases the lock at
    // process exit; the leaked budget is bounded by the live working set.
    key: Box<[u8; KEY_LEN]>,
    nonce_base: Box<[u8; NONCE_LEN]>,
    sequence: u64,
    suite: CipherSuite,
    cipher: SharedCipher,
    /// Set when a batch open/seal left the sequence counter in an indeterminate
    /// state. Once poisoned, every seal/open entry point refuses to operate so
    /// the session can only fail-close, never silently desynchronize its nonce
    /// stream. Single-record opens never poison the codec.
    poisoned: bool,
}

impl Drop for AeadCodec {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce_base.zeroize();
    }
}

/// The AEAD the data plane uses for a session. Both options are 256-bit AEADs
/// with a 12-byte nonce and 16-byte tag, so the record framing, nonce schedule,
/// and on-wire record sizes are identical — only the cipher core differs. The
/// server picks one per session (AES-256-GCM where AES-NI makes it ~2x faster
/// than ChaCha, else ChaCha20-Poly1305) and signals it in the AEAD-sealed
/// ServerKeyExchange; both ciphers being equally strong, there is no downgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    ChaCha20Poly1305,
    Aes256Gcm,
}

impl CipherSuite {
    /// One-byte wire tag carried (optionally) at the tail of a ServerKeyExchange.
    pub fn to_wire(self) -> u8 {
        match self {
            CipherSuite::ChaCha20Poly1305 => 0,
            CipherSuite::Aes256Gcm => 1,
        }
    }

    pub fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(CipherSuite::ChaCha20Poly1305),
            1 => Some(CipherSuite::Aes256Gcm),
            _ => None,
        }
    }
}

fn make_cipher(suite: CipherSuite, key: &[u8; KEY_LEN]) -> SharedCipher {
    let algorithm = match suite {
        CipherSuite::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        CipherSuite::Aes256Gcm => &AES_256_GCM,
    };
    Arc::new(LessSafeKey::new(
        UnboundKey::new(algorithm, key).expect("AEAD key length is fixed at KEY_LEN"),
    ))
}

/// Derives the per-record nonce by XOR-ing the big-endian sequence number into
/// the low 8 bytes of the session nonce base. Pure function of its inputs, so
/// it is safe to call from the parallel crypto workers.
pub(crate) fn record_nonce_from(nonce_base: &[u8; NONCE_LEN], sequence: u64) -> [u8; NONCE_LEN] {
    let mut nonce = *nonce_base;
    for (dst, src) in nonce[NONCE_LEN - 8..]
        .iter_mut()
        .zip(sequence.to_be_bytes())
    {
        *dst ^= src;
    }
    nonce
}

/// Formal proofs (Kani) over the counter-nonce scheme. Compiled ONLY under
/// `cargo kani` (which sets `cfg(kani)`); absent from a normal build/test.
#[cfg(kani)]
mod kani_proofs {
    use super::{
        record_nonce_from, write_substream_hkdf_info, HKDF_INFO_STACK_LEN, KEY_LEN, NONCE_LEN,
    };

    /// The catastrophic-failure guard: within one epoch (a fixed `nonce_base`)
    /// the per-record nonce MUST be unique per sequence number, or AEAD security
    /// collapses. `record_nonce_from` XORs the big-endian sequence into the low 8
    /// bytes, so it is injective in `sequence` for ANY base. Proven here over the
    /// full u64 sequence space and all 12-byte bases (equal nonces ⇒ equal
    /// sequences ⇒ no two distinct records in an epoch share a nonce).
    #[kani::proof]
    fn record_nonce_from_is_injective_in_sequence() {
        let base: [u8; NONCE_LEN] = kani::any();
        let s1: u64 = kani::any();
        let s2: u64 = kani::any();
        if record_nonce_from(&base, s1) == record_nonce_from(&base, s2) {
            assert_eq!(s1, s2, "equal nonces must imply equal sequences (no reuse)");
        }
    }

    /// Cross-substream guard: two mux substreams on one session each derive their
    /// own `(key, nonce_base)` via `expand_substream`, whose only varying input is
    /// `stream_id` (the label/epoch/transcript are fixed within one direction of
    /// one session). HKDF gives distinct outputs for distinct info under collision
    /// resistance, so the safety property reduces to: the info encoding is
    /// INJECTIVE in `stream_id`. Proven here over all `stream_id` pairs and all
    /// transcript hashes for a fixed substream label — equal info ⇒ equal
    /// `stream_id`, so two distinct substreams never share a derived base (hence
    /// never reuse a nonce across streams).
    #[kani::proof]
    fn substream_info_is_injective_in_stream_id() {
        // A fixed direction's label + epoch (the inputs that are constant across
        // substreams of one session); the transcript hash is left unconstrained.
        const LABEL: &[u8] = b"ParallaX v1 mux substream client nonce";
        let epoch: u64 = kani::any();
        let transcript_hash: [u8; KEY_LEN] = kani::any();
        let id1: u64 = kani::any();
        let id2: u64 = kani::any();

        let mut info1 = [0_u8; HKDF_INFO_STACK_LEN];
        let mut info2 = [0_u8; HKDF_INFO_STACK_LEN];
        let len1 = write_substream_hkdf_info(&mut info1, LABEL, epoch, id1, &transcript_hash);
        let len2 = write_substream_hkdf_info(&mut info2, LABEL, epoch, id2, &transcript_hash);

        if len1 == len2 && info1[..len1] == info2[..len2] {
            assert_eq!(
                id1, id2,
                "equal substream HKDF info must imply equal stream_id (no shared base)"
            );
        }
    }
}

/// Seals `plaintext` in place with an explicit sequence number using a shared
/// cipher. Stateless: it neither reads nor advances any sequence counter, so
/// multiple records can be sealed concurrently on different threads provided
/// each is given a unique `sequence`.
pub(crate) fn seal_in_place_detached_with(
    cipher: &LessSafeKey,
    nonce_base: &[u8; NONCE_LEN],
    sequence: u64,
    plaintext: &mut [u8],
    aad: &[u8],
) -> Result<[u8; AEAD_TAG_LEN], SessionError> {
    if sequence == u64::MAX {
        return Err(SessionError::NonceExhausted);
    }
    let nonce = Nonce::assume_unique_for_key(record_nonce_from(nonce_base, sequence));
    let tag = cipher
        .seal_in_place_separate_tag(nonce, Aad::from(aad), plaintext)
        .map_err(|_| SessionError::Aead)?;
    let mut out = [0_u8; AEAD_TAG_LEN];
    out.copy_from_slice(tag.as_ref());
    Ok(out)
}

/// Opens a contiguous `ciphertext || tag` slice in place with an explicit
/// sequence number using a shared cipher, returning the plaintext length.
/// Stateless counterpart of [`seal_in_place_detached_with`].
pub(crate) fn open_in_place_split_with(
    cipher: &LessSafeKey,
    nonce_base: &[u8; NONCE_LEN],
    sequence: u64,
    ciphertext_with_tag: &mut [u8],
    aad: &[u8],
) -> Result<usize, SessionError> {
    if ciphertext_with_tag.len() < AEAD_TAG_LEN {
        return Err(SessionError::Aead);
    }
    if sequence == u64::MAX {
        return Err(SessionError::NonceExhausted);
    }
    let nonce = Nonce::assume_unique_for_key(record_nonce_from(nonce_base, sequence));
    let plaintext = cipher
        .open_in_place(nonce, Aad::from(aad), ciphertext_with_tag)
        .map_err(|_| SessionError::Aead)?;
    Ok(plaintext.len())
}

impl AeadCodec {
    pub fn new(key: [u8; KEY_LEN], nonce_base: [u8; NONCE_LEN]) -> Self {
        Self::new_with_suite(CipherSuite::ChaCha20Poly1305, key, nonce_base)
    }

    /// Builds a codec for an explicit cipher suite. The data plane uses this
    /// after the PQ rekey to adopt the server-negotiated suite; the initial
    /// handshake session always uses the default ChaCha20-Poly1305 via [`Self::new`].
    pub fn new_with_suite(
        suite: CipherSuite,
        key: [u8; KEY_LEN],
        nonce_base: [u8; NONCE_LEN],
    ) -> Self {
        // The by-value `Copy` params are transient secret copies: wrap them so the
        // local copies are scrubbed on return (best-effort, drop-time-only — same
        // discipline as `expand_epoch_keys`). The live secrets are the boxed
        // fields below, zeroized by the codec's own `Drop`.
        let key = Zeroizing::new(key);
        let nonce_base = Zeroizing::new(nonce_base);
        let codec = Self {
            key: Box::new(*key),
            nonce_base: Box::new(*nonce_base),
            sequence: 0,
            suite,
            cipher: make_cipher(suite, &key),
            poisoned: false,
        };
        codec.protect_secret_memory();
        codec
    }

    /// Rekeys, preserving the current cipher suite.
    pub fn rekey(&mut self, key: [u8; KEY_LEN], nonce_base: [u8; NONCE_LEN]) {
        self.rekey_with_suite(self.suite, key, nonce_base);
    }

    /// Rekeys AND switches to `suite`. The PQ rekey uses this to move the data
    /// plane from the initial ChaCha20-Poly1305 session onto the
    /// server-negotiated suite; the per-record nonce/tag layout is unchanged so
    /// the on-wire record sizes do not move.
    pub fn rekey_with_suite(
        &mut self,
        suite: CipherSuite,
        key: [u8; KEY_LEN],
        nonce_base: [u8; NONCE_LEN],
    ) {
        // Scrub the transient by-value param copies on return (best-effort, as in
        // `new_with_suite`); the live secrets are the boxed fields overwritten below.
        let key = Zeroizing::new(key);
        let nonce_base = Zeroizing::new(nonce_base);
        self.key.zeroize();
        self.nonce_base.zeroize();
        // Overwrite the existing heap allocations in place so the locked pages
        // stay valid across the rekey (re-`protect` below is then idempotent).
        *self.key = *key;
        *self.nonce_base = *nonce_base;
        self.sequence = 0;
        self.suite = suite;
        self.cipher = make_cipher(suite, &key);
        self.protect_secret_memory();
    }

    /// Shared handle to the session cipher for the parallel crypto workers.
    pub(crate) fn cipher(&self) -> SharedCipher {
        Arc::clone(&self.cipher)
    }

    /// Current per-direction record sequence number (the next nonce to use).
    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Session nonce base; combine with a sequence number via
    /// [`record_nonce_from`] to reproduce a record's nonce off-thread.
    pub(crate) fn nonce_base(&self) -> [u8; NONCE_LEN] {
        *self.nonce_base
    }

    /// Advances the sequence counter by `count`. The single checked path for every
    /// counter advance: the batch seal/open paths call it with the batch size, and
    /// the serial `seal_in_place_detached` / `open_in_place_split` call it with `1`.
    ///
    /// The counter is a nonce input, so a silent wrap (the prior `saturating_add`,
    /// which pins it at `u64::MAX`) would risk nonce reuse. Both classes of caller
    /// pre-check the boundary before any record is processed (the batch path via
    /// `sequence + count <= u64::MAX`, the serial path via the `*_with` functions'
    /// `sequence == u64::MAX` rejection), so this never wraps in practice. Fail loud
    /// regardless: a `checked_add` overflow poisons the codec, so every later
    /// seal/open fails closed via `ensure_usable` rather than reusing a nonce. The
    /// pre-checks remain the first gate; this is defence in depth on the primitive.
    pub(crate) fn advance_sequence(&mut self, count: u64) {
        match self.sequence.checked_add(count) {
            Some(next) => self.sequence = next,
            None => self.poison(),
        }
    }

    /// Permanently marks the codec unusable. Called by the batch open paths
    /// when a partial failure may have advanced the sequence counter, turning
    /// the "any failure must fail-close" caller convention into a type-enforced
    /// guarantee.
    pub(crate) fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Returns an error if the codec has been poisoned by a prior batch
    /// failure. Checked at every seal/open entry point.
    pub(crate) fn ensure_usable(&self) -> Result<(), SessionError> {
        if self.poisoned {
            return Err(SessionError::Aead);
        }
        Ok(())
    }

    pub fn protect_secret_memory(&self) {
        crate::process_hardening::protect_secret_bytes("aead.key", self.key.as_slice());
        crate::process_hardening::protect_secret_bytes(
            "aead.nonce_base",
            self.nonce_base.as_slice(),
        );
    }

    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, SessionError> {
        let mut ciphertext = Vec::with_capacity(plaintext.len() + AEAD_TAG_LEN);
        ciphertext.extend_from_slice(plaintext);
        let tag = self.seal_in_place_detached(&mut ciphertext, aad)?;
        ciphertext.extend_from_slice(&tag);
        Ok(ciphertext)
    }

    pub fn seal_in_place_detached(
        &mut self,
        plaintext: &mut [u8],
        aad: &[u8],
    ) -> Result<[u8; AEAD_TAG_LEN], SessionError> {
        self.ensure_usable()?;
        let tag = seal_in_place_detached_with(
            &self.cipher,
            &self.nonce_base,
            self.sequence,
            plaintext,
            aad,
        )?;
        // Advance via the checked path so the nonce counter fails loud (poisons the
        // codec) rather than wrapping. `*_with` already rejected `sequence ==
        // u64::MAX` above, so this never actually overflows today; routing the
        // single-step increment through the same primitive keeps the fail-loud
        // guarantee on the counter itself, not on a caller-side pre-check.
        self.advance_sequence(1);
        Ok(tag)
    }

    pub fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, SessionError> {
        if ciphertext.len() < AEAD_TAG_LEN {
            return Err(SessionError::Aead);
        }
        let mut plaintext = ciphertext.to_vec();
        self.open_in_place(&mut plaintext, aad)?;
        Ok(plaintext)
    }

    pub fn open_in_place(
        &mut self,
        ciphertext_with_tag: &mut Vec<u8>,
        aad: &[u8],
    ) -> Result<(), SessionError> {
        let plaintext_len = self.open_in_place_split(ciphertext_with_tag.as_mut_slice(), aad)?;
        ciphertext_with_tag.truncate(plaintext_len);
        Ok(())
    }

    /// Opens a contiguous `ciphertext || tag` slice in place and returns the
    /// plaintext length (`input.len() - AEAD_TAG_LEN`).
    pub(crate) fn open_in_place_split(
        &mut self,
        ciphertext_with_tag: &mut [u8],
        aad: &[u8],
    ) -> Result<usize, SessionError> {
        self.ensure_usable()?;
        let plaintext_len = open_in_place_split_with(
            &self.cipher,
            &self.nonce_base,
            self.sequence,
            ciphertext_with_tag,
            aad,
        )?;
        // Checked advance (see `seal_in_place_detached`): fail loud on the counter
        // itself instead of relying solely on the `*_with` pre-check.
        self.advance_sequence(1);
        Ok(plaintext_len)
    }
}

fn write_bytes(out: &mut [u8; HKDF_INFO_STACK_LEN], offset: &mut usize, bytes: &[u8]) {
    let end = *offset + bytes.len();
    out[*offset..end].copy_from_slice(bytes);
    *offset = end;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CSPRNG-grade PSK fixture for key-derivation tests (>= 32 distinct bytes).
    const TEST_PSK: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz!@#$";

    #[test]
    fn x25519_derives_same_session_keys() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let transcript_hash = [7_u8; 32];

        let client_keys =
            derive_client_keys(TEST_PSK, &client.private, &server.public, &transcript_hash)
                .unwrap();
        let server_keys =
            derive_server_keys(TEST_PSK, &server.private, &client.public, &transcript_hash)
                .unwrap();

        assert_eq!(client_keys, server_keys);
        assert_eq!(client_keys.epoch, 0);
        assert_eq!(client_keys.transcript_hash, transcript_hash);
    }

    #[test]
    fn initial_session_key_depends_on_psk() {
        // Issue #50 (#1): X25519 compromise alone must not reproduce the initial
        // session keys. Same X25519 secret + transcript, different PSK => different
        // keys.
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let transcript_hash = [7_u8; 32];
        let shared = x25519_shared_secret(&client.private, &server.public);

        let psk_a = derive_client_keys_from_shared(TEST_PSK, &shared, &transcript_hash).unwrap();
        let psk_b = derive_client_keys_from_shared(
            b"a different csprng psk value xyz!",
            &shared,
            &transcript_hash,
        )
        .unwrap();

        assert_ne!(psk_a.client_key, psk_b.client_key);
        assert_ne!(psk_a.server_key, psk_b.server_key);
        assert_ne!(psk_a.chain_secret, psk_b.chain_secret);
    }

    #[test]
    fn cached_x25519_shared_secret_derives_same_session_keys() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let transcript_hash = [7_u8; 32];
        let shared = x25519_shared_secret(&client.private, &server.public);

        let from_private =
            derive_client_keys(TEST_PSK, &client.private, &server.public, &transcript_hash)
                .unwrap();
        let from_shared =
            derive_client_keys_from_shared(TEST_PSK, &shared, &transcript_hash).unwrap();

        assert_eq!(from_private, from_shared);
    }

    #[test]
    fn cached_x25519_shared_secret_derives_same_server_session_keys() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        let transcript_hash = [7_u8; 32];
        let shared = x25519_shared_secret(&server.private, &client.public);

        let from_private =
            derive_server_keys(TEST_PSK, &server.private, &client.public, &transcript_hash)
                .unwrap();
        let from_shared =
            derive_server_keys_from_shared(TEST_PSK, &shared, &transcript_hash).unwrap();

        assert_eq!(from_private, from_shared);
    }

    #[test]
    fn x25519_shared_secret_matches_both_directions() {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();

        assert_eq!(
            x25519_shared_secret(&client.private, &server.public),
            x25519_shared_secret(&server.private, &client.public)
        );
    }

    #[test]
    fn epoch_keys_change_when_epoch_changes() {
        let chain_secret = [1_u8; 32];
        let transcript_hash = [2_u8; 32];
        let x25519_shared_secret = [3_u8; 32];

        let epoch0 =
            expand_epoch_keys(chain_secret, 0, transcript_hash, x25519_shared_secret).unwrap();
        let epoch1 =
            expand_epoch_keys(chain_secret, 1, transcript_hash, x25519_shared_secret).unwrap();

        assert_ne!(epoch0.client_key, epoch1.client_key);
        assert_ne!(epoch0.client_nonce, epoch1.client_nonce);
    }

    #[test]
    fn hkdf_info_uses_length_prefixes() {
        let hk = Hkdf::<Sha256>::new(None, b"test secret");
        let transcript_hash = [2_u8; 32];
        let mut with_nul = [0_u8; 32];
        let mut without_nul = [0_u8; 32];

        expand(&hk, b"label\0suffix", 1, &transcript_hash, &mut with_nul).unwrap();
        expand(&hk, b"label", 1, &transcript_hash, &mut without_nul).unwrap();

        assert_ne!(with_nul, without_nul);
    }

    #[test]
    fn aead_round_trip_and_tamper_reject() {
        let key = [7_u8; KEY_LEN];
        let nonce = [9_u8; NONCE_LEN];
        let mut enc = AeadCodec::new(key, nonce);
        let mut dec = AeadCodec::new(key, nonce);

        let mut ciphertext = enc.seal(b"payload", b"tls-appdata").unwrap();
        assert_eq!(dec.open(&ciphertext, b"tls-appdata").unwrap(), b"payload");

        let mut enc = AeadCodec::new(key, nonce);
        let mut dec = AeadCodec::new(key, nonce);
        ciphertext = enc.seal(b"payload", b"tls-appdata").unwrap();
        ciphertext[0] ^= 1;
        assert!(matches!(
            dec.open(&ciphertext, b"tls-appdata"),
            Err(SessionError::Aead)
        ));
    }

    #[test]
    fn advance_sequence_overflow_poisons_instead_of_wrapping() {
        // DN-4: the sequence counter is a nonce input. A silent wrap (the prior
        // saturating_add, which pins it at u64::MAX) would risk nonce reuse if a
        // path ever reached advance_sequence without the callers' checked_add
        // pre-check. A checked overflow must fail loud: poison the codec so every
        // later seal/open fails closed, never reusing a nonce.
        let key = [7_u8; KEY_LEN];
        let nonce = [9_u8; NONCE_LEN];
        let mut codec = AeadCodec::new(key, nonce);

        // Drive the counter to the edge, then overflow it.
        codec.advance_sequence(u64::MAX - 1);
        assert!(codec.ensure_usable().is_ok(), "edge value is still usable");
        codec.advance_sequence(2); // (u64::MAX - 1) + 2 overflows

        assert!(
            matches!(codec.ensure_usable(), Err(SessionError::Aead)),
            "an overflowing advance must poison the codec, not silently saturate"
        );
        assert!(
            matches!(
                codec.seal(b"payload", b"tls-appdata"),
                Err(SessionError::Aead)
            ),
            "a poisoned codec fails closed on seal"
        );
    }

    #[test]
    fn aes256_gcm_round_trips_and_differs_from_chacha() {
        let key = [7_u8; KEY_LEN];
        let nonce = [9_u8; NONCE_LEN];

        // AES-256-GCM round-trips.
        let mut enc = AeadCodec::new_with_suite(CipherSuite::Aes256Gcm, key, nonce);
        let mut dec = AeadCodec::new_with_suite(CipherSuite::Aes256Gcm, key, nonce);
        let ct = enc.seal(b"payload", b"tls-appdata").unwrap();
        assert_eq!(dec.open(&ct, b"tls-appdata").unwrap(), b"payload");

        // Same key/nonce/plaintext under ChaCha yields different ciphertext, and
        // a ChaCha codec cannot open an AES record: the suite really swaps the
        // cipher core (no silent cross-suite acceptance).
        let mut chacha = AeadCodec::new_with_suite(CipherSuite::ChaCha20Poly1305, key, nonce);
        let chacha_ct = chacha.seal(b"payload", b"tls-appdata").unwrap();
        assert_ne!(
            ct, chacha_ct,
            "AES-GCM and ChaCha must differ for same inputs"
        );
        let mut chacha_dec = AeadCodec::new_with_suite(CipherSuite::ChaCha20Poly1305, key, nonce);
        assert!(matches!(
            chacha_dec.open(&ct, b"tls-appdata"),
            Err(SessionError::Aead)
        ));

        // rekey_with_suite moves an existing (ChaCha) codec onto AES and the
        // rekeyed stream round-trips against an AES peer.
        let mut codec = AeadCodec::new(key, nonce);
        codec.rekey_with_suite(CipherSuite::Aes256Gcm, [3_u8; KEY_LEN], [4_u8; NONCE_LEN]);
        let mut peer =
            AeadCodec::new_with_suite(CipherSuite::Aes256Gcm, [3_u8; KEY_LEN], [4_u8; NONCE_LEN]);
        let rk = codec.seal(b"after-rekey", b"tls-appdata").unwrap();
        assert_eq!(peer.open(&rk, b"tls-appdata").unwrap(), b"after-rekey");
    }

    #[test]
    fn aes256_gcm_codec_matches_independent_impl() {
        // Cross-implementation KAT: the aws-lc-rs-backed AES-256-GCM codec must
        // produce byte-identical ciphertext||tag to the independent RustCrypto
        // `aes-gcm` crate for the same key/nonce/AAD/plaintext. Validates the
        // negotiated suite is genuinely standard AES-256-GCM, checked against a
        // second implementation rather than only round-tripping against itself.
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes256Gcm, Nonce};

        let key = [0x11_u8; KEY_LEN];
        let nonce_base = [0x22_u8; NONCE_LEN];
        let aad = b"parallax-aad";
        let plaintext = b"verify AES-256-GCM against a second implementation";

        // Fresh codec -> sequence 0 -> record nonce == nonce_base.
        let mut codec = AeadCodec::new_with_suite(CipherSuite::Aes256Gcm, key, nonce_base);
        let mine = codec.seal(plaintext, aad).unwrap();

        let independent = Aes256Gcm::new_from_slice(&key).unwrap();
        let theirs = independent
            .encrypt(
                Nonce::from_slice(&nonce_base),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .unwrap();

        assert_eq!(
            mine, theirs,
            "AeadCodec AES-256-GCM must match an independent AES-256-GCM implementation"
        );
    }

    #[test]
    fn aes256_gcm_never_reuses_a_nonce() {
        // GCM nonce reuse is catastrophic, so prove the per-record counter drives
        // a distinct nonce per record: identical plaintext re-encrypts differently,
        // and each record matches an independent AES-256-GCM keyed identically at
        // exactly nonce_base ^ sequence -- confirming the counter, not a fixed
        // nonce, is in effect.
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes256Gcm, Nonce};

        let key = [0x33_u8; KEY_LEN];
        let nonce_base = [0x44_u8; NONCE_LEN];
        let aad = b"aad";
        let mut codec = AeadCodec::new_with_suite(CipherSuite::Aes256Gcm, key, nonce_base);
        let first = codec.seal(b"same plaintext", aad).unwrap();
        let second = codec.seal(b"same plaintext", aad).unwrap();
        assert_ne!(
            first, second,
            "AES-256-GCM must advance the nonce so identical plaintext differs"
        );

        let nonce0 = record_nonce_from(&nonce_base, 0);
        let nonce1 = record_nonce_from(&nonce_base, 1);
        assert_ne!(nonce0, nonce1, "per-record nonces must differ");

        let independent = Aes256Gcm::new_from_slice(&key).unwrap();
        let rc0 = independent
            .encrypt(
                Nonce::from_slice(&nonce0),
                Payload {
                    msg: b"same plaintext",
                    aad,
                },
            )
            .unwrap();
        let rc1 = independent
            .encrypt(
                Nonce::from_slice(&nonce1),
                Payload {
                    msg: b"same plaintext",
                    aad,
                },
            )
            .unwrap();
        assert_eq!(
            first, rc0,
            "record 0 must equal AES-256-GCM at nonce_base^0"
        );
        assert_eq!(
            second, rc1,
            "record 1 must equal AES-256-GCM at nonce_base^1"
        );
    }

    #[test]
    fn aead_open_accepts_exactly_tag_len_and_rejects_shorter() {
        // open()'s length guard is `ciphertext.len() < AEAD_TAG_LEN`. A record of an
        // EMPTY payload seals to exactly AEAD_TAG_LEN (16) bytes — the lone tag — and
        // MUST open back to empty. Pins the `<` boundary: a `< -> ==` or `< -> <=`
        // mutation would reject the valid 16-byte empty-payload record.
        let key = [7_u8; KEY_LEN];
        let nonce = [9_u8; NONCE_LEN];
        let mut enc = AeadCodec::new(key, nonce);
        let mut dec = AeadCodec::new(key, nonce);

        let empty = enc.seal(b"", b"tls-appdata").unwrap();
        assert_eq!(
            empty.len(),
            AEAD_TAG_LEN,
            "empty payload seals to just the tag"
        );
        assert_eq!(
            dec.open(&empty, b"tls-appdata").unwrap(),
            b"",
            "a record of exactly AEAD_TAG_LEN bytes must open to an empty payload"
        );

        // Anything shorter than the tag is structurally impossible and must be
        // rejected (the lower side of the `<` guard).
        let mut dec2 = AeadCodec::new(key, nonce);
        assert!(matches!(
            dec2.open(&[0_u8; AEAD_TAG_LEN - 1], b"tls-appdata"),
            Err(SessionError::Aead)
        ));
    }

    #[test]
    fn aead_opens_in_place() {
        let key = [7_u8; KEY_LEN];
        let nonce = [9_u8; NONCE_LEN];
        let mut enc = AeadCodec::new(key, nonce);
        let mut dec = AeadCodec::new(key, nonce);

        let mut ciphertext = enc.seal(b"payload", b"tls-appdata").unwrap();
        dec.open_in_place(&mut ciphertext, b"tls-appdata").unwrap();

        assert_eq!(ciphertext, b"payload");
    }

    #[test]
    fn aead_ratchet_rejects_replayed_record_after_success() {
        let key = [7_u8; KEY_LEN];
        let nonce = [9_u8; NONCE_LEN];
        let mut enc = AeadCodec::new(key, nonce);
        let mut dec = AeadCodec::new(key, nonce);

        let first = enc.seal(b"same payload", b"tls-appdata").unwrap();
        let second = enc.seal(b"same payload", b"tls-appdata").unwrap();

        assert_eq!(dec.open(&first, b"tls-appdata").unwrap(), b"same payload");
        assert!(matches!(
            dec.open(&first, b"tls-appdata"),
            Err(SessionError::Aead)
        ));
        assert_eq!(dec.open(&second, b"tls-appdata").unwrap(), b"same payload");
    }

    #[test]
    fn aead_ratchet_changes_ciphertext_for_repeated_plaintext() {
        let key = [7_u8; KEY_LEN];
        let nonce = [9_u8; NONCE_LEN];
        let mut enc = AeadCodec::new(key, nonce);

        let first = enc.seal(b"same payload", b"tls-appdata").unwrap();
        let second = enc.seal(b"same payload", b"tls-appdata").unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn derive_keys_rejects_all_zero_shared_secret() {
        let transcript_hash = [7_u8; 32];
        assert!(matches!(
            derive_client_keys_from_shared(TEST_PSK, &[0_u8; KEY_LEN], &transcript_hash),
            Err(SessionError::DegenerateSharedSecret)
        ));
        assert!(matches!(
            derive_server_keys_from_shared(TEST_PSK, &[0_u8; KEY_LEN], &transcript_hash),
            Err(SessionError::DegenerateSharedSecret)
        ));
    }

    #[test]
    fn derive_rejects_empty_psk() {
        // An empty PSK would make the HKDF salt identical to the all-zero salt and
        // silently drop the PSK binding, so the public entry points reject it at
        // runtime (release included). A non-degenerate shared secret ensures we hit
        // the PSK guard rather than the all-zero shared-secret reject.
        let transcript_hash = [7_u8; 32];
        let shared = [3_u8; KEY_LEN];
        assert!(matches!(
            derive_client_keys_from_shared(b"", &shared, &transcript_hash),
            Err(SessionError::EmptyPsk)
        ));
        assert!(matches!(
            derive_server_keys_from_shared(b"", &shared, &transcript_hash),
            Err(SessionError::EmptyPsk)
        ));
    }

    #[test]
    fn low_order_x25519_public_yields_degenerate_shared_secret_rejected() {
        // The all-zero X25519 public key is a small-order point: x25519-dalek does
        // not reject it, and DH against it yields an all-zero shared secret, which
        // the key-derivation funnel must now reject (L-1).
        let kp = X25519KeyPair::generate();
        let shared = x25519_shared_secret(&kp.private, &[0_u8; KEY_LEN]);
        assert_eq!(
            shared, [0_u8; KEY_LEN],
            "all-zero public is a small-order point"
        );
        let transcript_hash = [9_u8; 32];
        assert!(matches!(
            derive_client_keys_from_shared(TEST_PSK, &shared, &transcript_hash),
            Err(SessionError::DegenerateSharedSecret)
        ));
    }

    fn session_keys_fixture() -> SessionKeys {
        let client = X25519KeyPair::generate();
        let server = X25519KeyPair::generate();
        derive_client_keys(TEST_PSK, &client.private, &server.public, &[7_u8; 32]).unwrap()
    }

    #[test]
    fn session_keys_equality_is_test_only() {
        // `SessionKeys: PartialEq/Eq` exists ONLY under cfg(test) (the derived `==`
        // is variable-time over live secret bytes). This test pins that the
        // test-gated impls still exist so `assert_eq!` keeps working in tests; the
        // complementary check — that equality is UNAVAILABLE in production — is the
        // non-test compile itself (`cargo build` / `cargo clippy`), where any
        // production `==` over `SessionKeys` is now a compile error.
        let keys = session_keys_fixture();
        let same = keys.clone();
        assert_eq!(keys, same);
    }

    #[test]
    fn substream_keys_are_deterministic_and_match_across_ends() {
        // Both ends derive from the SAME `SessionKeys` (they agree on it after the
        // handshake), so a given stream_id must yield identical substream keys on
        // each end — otherwise the substream codecs could never interoperate.
        let keys = session_keys_fixture();
        let a = expand_substream_keys(&keys, 1).unwrap();
        let b = expand_substream_keys(&keys, 1).unwrap();
        assert_eq!(a, b, "same session + same stream_id must be deterministic");
    }

    #[test]
    fn substream_keys_differ_per_stream_id() {
        // Distinct substreams must get independent (key, nonce_base) pairs in BOTH
        // directions, or two concurrent QUIC streams would reuse nonces.
        let keys = session_keys_fixture();
        let s1 = expand_substream_keys(&keys, 1).unwrap();
        let s3 = expand_substream_keys(&keys, 3).unwrap();
        assert_ne!(s1.client_key, s3.client_key);
        assert_ne!(s1.server_key, s3.server_key);
        assert_ne!(s1.client_nonce, s3.client_nonce);
        assert_ne!(s1.server_nonce, s3.server_nonce);
    }

    #[test]
    fn substream_keys_differ_from_session_epoch_keys() {
        // Label domain separation: a substream base must never alias the session's
        // own epoch base (which carries the single-connect relay's records).
        let keys = session_keys_fixture();
        let sub = expand_substream_keys(&keys, 1).unwrap();
        assert_ne!(sub.client_key, keys.client_key);
        assert_ne!(sub.server_key, keys.server_key);
        assert_ne!(sub.client_nonce, keys.client_nonce);
        assert_ne!(sub.server_nonce, keys.server_nonce);
    }

    #[test]
    fn substream_carries_parent_derivation_material_unchanged() {
        // The returned struct mirrors the parent's chain_secret/epoch/transcript so
        // it stays self-consistent (and zeroizes the same); only the four AEAD
        // key/nonce fields are substream-specific.
        let keys = session_keys_fixture();
        let sub = expand_substream_keys(&keys, 42).unwrap();
        assert_eq!(sub.chain_secret, keys.chain_secret);
        assert_eq!(sub.epoch, keys.epoch);
        assert_eq!(sub.transcript_hash, keys.transcript_hash);
        assert_eq!(sub.x25519_shared_secret, keys.x25519_shared_secret);
    }

    #[test]
    fn cross_substream_codecs_cannot_open_each_others_records() {
        // The end-to-end safety property at the AEAD layer: a record sealed under
        // substream 1's client key must NOT open under substream 2's client key.
        let keys = session_keys_fixture();
        let s1 = expand_substream_keys(&keys, 1).unwrap();
        let s2 = expand_substream_keys(&keys, 2).unwrap();
        const AAD: &[u8] = b"ParallaX v1 client appdata";

        let mut seal1 = AeadCodec::new(s1.client_key, s1.client_nonce);
        let mut open1 = AeadCodec::new(s1.client_key, s1.client_nonce);
        let mut open2 = AeadCodec::new(s2.client_key, s2.client_nonce);

        let record = seal1.seal(b"substream-isolation-probe", AAD).unwrap();

        // The matching substream key opens it; a sibling substream's key rejects it.
        assert_eq!(
            open1.open(&record, AAD).unwrap(),
            b"substream-isolation-probe"
        );
        assert!(open2.open(&record, AAD).is_err());
    }

    #[test]
    fn cipher_suite_wire_codec_round_trips_and_rejects_unknown() {
        // The one-byte suite tag rides the tail of a ServerKeyExchange and gates
        // which AEAD family the whole session uses. Pin the wire mapping so a
        // future variant reorder/rename cannot silently flip 0<->1 (a wire-compat
        // and cross-version break), and confirm every non-{0,1} byte is rejected
        // rather than defaulting to a suite.
        for suite in [CipherSuite::ChaCha20Poly1305, CipherSuite::Aes256Gcm] {
            let wire = suite.to_wire();
            assert_eq!(
                CipherSuite::from_wire(wire),
                Some(suite),
                "suite must decode from its own wire tag: {suite:?}"
            );
        }
        // Pin the concrete tag values (not just that they round-trip): these are
        // on the wire and must never move.
        assert_eq!(CipherSuite::ChaCha20Poly1305.to_wire(), 0);
        assert_eq!(CipherSuite::Aes256Gcm.to_wire(), 1);
        // Every other byte in the u8 space must be rejected.
        for byte in 2_u8..=u8::MAX {
            assert_eq!(
                CipherSuite::from_wire(byte),
                None,
                "unknown suite tag {byte} must not decode to any suite"
            );
        }
    }

    #[test]
    fn record_nonce_from_is_injective_in_sequence() {
        // Fast-lane backstop for the counter-nonce scheme whose formal guarantee
        // lives only under `#[cfg(kani)]` (absent from `cargo test`). Within one
        // epoch (a fixed nonce_base) distinct sequence numbers MUST yield distinct
        // nonces, or AEAD security collapses. This also catches a refactor that
        // swaps the XOR for `&=`/`=` or narrows the touched byte range.
        let base = [0xA5_u8; NONCE_LEN];

        // Distinct sequences => distinct nonces across the full u64 range.
        let seqs = [
            0_u64,
            1,
            2,
            255,
            256,
            u32::MAX as u64,
            u64::MAX - 1,
            u64::MAX,
        ];
        let mut seen = std::collections::HashSet::new();
        for &seq in &seqs {
            let nonce = record_nonce_from(&base, seq);
            assert!(
                seen.insert(nonce),
                "sequence {seq} collided with an earlier nonce"
            );
        }

        // Sequence 0 is the identity: it must leave the base untouched.
        assert_eq!(record_nonce_from(&base, 0), base);

        // Only the low 8 bytes are sequence-dependent; the high bytes are the
        // fixed epoch material and must never be perturbed by the counter.
        let nonce_max = record_nonce_from(&base, u64::MAX);
        assert_eq!(
            nonce_max[..NONCE_LEN - 8],
            base[..NONCE_LEN - 8],
            "the counter must not touch the high (epoch) nonce bytes"
        );
        // The low 8 bytes are exactly base XOR the big-endian sequence.
        for (i, b) in nonce_max[NONCE_LEN - 8..].iter().enumerate() {
            assert_eq!(*b, base[NONCE_LEN - 8 + i] ^ 0xFF);
        }
    }
}
