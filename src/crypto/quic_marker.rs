//! 32-byte `ClientHello.random` covert authentication marker for the QUIC
//! origin-splice fork.
//!
//! This is the QUIC analogue of the TCP REALITY ClientHello marker
//! ([`crate::crypto::auth`]). A deployment secret (the PSK) plus an X25519 ECDH
//! between the server's **static** key and the client's **ephemeral** key-share
//! derive a keystream + an HMAC auth key; a freshness-bound tag is hidden in the
//! otherwise-uniformly-random 32-byte `ClientHello.random`. The censor reads SNI
//! and extension *types* off the (publicly decryptable) QUIC Initial but never
//! interprets the random, so the marker is invisible to passive DPI; and it is
//! unforgeable without BOTH secrets (PSK and the server static key), exactly the
//! two-secret property the TCP marker relies on.
//!
//! The fork it drives (in the endpoint driver): a valid + fresh marker on the
//! first Initial routes the flow to local QUIC termination (a real ParallaX
//! client); anything else — no marker, a forged marker, a stale or replayed one —
//! routes to the verbatim origin splice. Because a failed verify reaches only the
//! real origin (no error, no oracle, no feedback), the tag can be shorter than the
//! TCP marker's 128-bit tag without enabling an online forgery search.
//!
//! ## Carrier layout (32 bytes, before the keystream XOR)
//!
//! ```text
//! tag[12] || nonce[12] || timestamp_be[8]
//! ```
//!
//! The **96-bit tag** binds the connection id (DCID) and SNI of this Initial plus
//! the nonce and timestamp, so a captured marker cannot be lifted onto a different
//! Initial, and the timestamp + an Initial-time replay cache (in the caller) bound
//! replay. `seal` (client) and `open` (server) are the inverse of each other.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const TAG_LEN: usize = 12;
const NONCE_LEN: usize = 12;
const TS_LEN: usize = 8;
/// The full `ClientHello.random` carrier length (RFC 8446 / TLS 1.3 random).
pub const MARKER_LEN: usize = TAG_LEN + NONCE_LEN + TS_LEN; // 32

/// Clock-skew tolerance for a marker timestamp in the future (seconds). Matches the
/// replay cache's future-clamp; a client a few seconds ahead of the server is fine.
const FUTURE_SKEW_SECS: u64 = 5;

/// HKDF-Expand info labels (version-pinned). Distinct labels give independent
/// keystream and auth keys from the same PRK.
const KEYSTREAM_INFO: &[u8] = b"ParallaX v1 QUIC marker keystream";
const AUTH_INFO: &[u8] = b"ParallaX v1 QUIC marker auth key";
/// Domain-separation prefix for the HMAC tag input.
const TAG_DOMAIN: &[u8] = b"ParallaX v1 QUIC marker tag";

/// The freshness material recovered from a valid marker: the caller keys an
/// Initial-time replay cache on `(nonce, timestamp)` (per source) so a captured
/// valid marker replayed within its window routes to the splice, not termination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Marker {
    pub nonce: [u8; NONCE_LEN],
    pub timestamp: u64,
}

/// Derive `(keystream, auth_key)` from the PSK (HKDF salt) and the X25519 ECDH
/// shared secret (HKDF IKM). Binding the PSK as the salt — not the IKM — preserves
/// the two-secret property: a leaked server static key alone cannot derive these,
/// because the HKDF PRK is unknown without the PSK (mirrors `crypto::auth`). Do NOT
/// swap salt and IKM.
fn derive(psk: &[u8], ecdh_ss: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let hk = Hkdf::<Sha256>::new(Some(psk), ecdh_ss);
    let mut keystream = Zeroizing::new([0_u8; 32]);
    let mut auth_key = Zeroizing::new([0_u8; 32]);
    hk.expand(KEYSTREAM_INFO, keystream.as_mut())
        .expect("HKDF-Expand of 32 bytes never fails");
    hk.expand(AUTH_INFO, auth_key.as_mut())
        .expect("HKDF-Expand of 32 bytes never fails");
    (keystream, auth_key)
}

/// Compute the 96-bit tag over the version domain, SNI, DCID, nonce, and timestamp.
/// Every field is length-prefixed so distinct `(sni, dcid)` pairs cannot collide.
fn compute_tag(
    auth_key: &[u8; 32],
    sni: &[u8],
    dcid: &[u8],
    nonce: &[u8; NONCE_LEN],
    timestamp: u64,
) -> [u8; TAG_LEN] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(auth_key).expect("HMAC accepts any key length");
    mac.update(TAG_DOMAIN);
    mac.update(&(sni.len() as u16).to_be_bytes());
    mac.update(sni);
    mac.update(&(dcid.len() as u16).to_be_bytes());
    mac.update(dcid);
    mac.update(nonce);
    mac.update(&timestamp.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let mut tag = [0_u8; TAG_LEN];
    tag.copy_from_slice(&digest[..TAG_LEN]);
    tag
}

/// Client side: build the 32-byte `ClientHello.random` carrying the marker.
///
/// `ecdh_ss` is `X25519(client_ephemeral_private, server_static_public)`; `dcid` is
/// the Destination Connection ID of this Initial; `now_unix` is the current Unix
/// time in seconds; `nonce` is a fresh CSPRNG value.
pub fn seal(
    psk: &[u8],
    ecdh_ss: &[u8; 32],
    sni: &[u8],
    dcid: &[u8],
    now_unix: u64,
    nonce: &[u8; NONCE_LEN],
) -> [u8; MARKER_LEN] {
    let (keystream, auth_key) = derive(psk, ecdh_ss);
    let tag = compute_tag(&auth_key, sni, dcid, nonce, now_unix);

    let mut plain = [0_u8; MARKER_LEN];
    plain[..TAG_LEN].copy_from_slice(&tag);
    plain[TAG_LEN..TAG_LEN + NONCE_LEN].copy_from_slice(nonce);
    plain[TAG_LEN + NONCE_LEN..].copy_from_slice(&now_unix.to_be_bytes());

    let mut out = [0_u8; MARKER_LEN];
    for (o, (p, k)) in out.iter_mut().zip(plain.iter().zip(keystream.iter())) {
        *o = p ^ k;
    }
    out
}

/// Server side: verify a `ClientHello.random` as a marker. Returns the freshness
/// material on success, `None` on any failure (no marker, forged, stale, or future).
///
/// `ecdh_ss` is `X25519(server_static_private, client_ephemeral_public)` — the same
/// shared secret the client computed. Constant-work: the HKDF + HMAC + constant-time
/// tag comparison always run, so a failed verify takes the same path as a success
/// (the terminate-vs-splice latency fork is avoided; the caller additionally pads
/// the no-key_share branch with a ballast ECDH).
pub fn open(
    psk: &[u8],
    ecdh_ss: &[u8; 32],
    sni: &[u8],
    dcid: &[u8],
    client_random: &[u8; MARKER_LEN],
    now_unix: u64,
    window_secs: u64,
) -> Option<Marker> {
    let (keystream, auth_key) = derive(psk, ecdh_ss);

    let mut plain = [0_u8; MARKER_LEN];
    for (pl, (c, k)) in plain
        .iter_mut()
        .zip(client_random.iter().zip(keystream.iter()))
    {
        *pl = c ^ k;
    }
    let mut tag = [0_u8; TAG_LEN];
    tag.copy_from_slice(&plain[..TAG_LEN]);
    let mut nonce = [0_u8; NONCE_LEN];
    nonce.copy_from_slice(&plain[TAG_LEN..TAG_LEN + NONCE_LEN]);
    let mut ts_bytes = [0_u8; TS_LEN];
    ts_bytes.copy_from_slice(&plain[TAG_LEN + NONCE_LEN..]);
    let timestamp = u64::from_be_bytes(ts_bytes);

    let expected = compute_tag(&auth_key, sni, dcid, &nonce, timestamp);
    let tag_ok = bool::from(tag.ct_eq(&expected));

    // Freshness: not older than the window, not more than the skew into the future.
    let fresh = timestamp <= now_unix.saturating_add(FUTURE_SKEW_SECS)
        && now_unix <= timestamp.saturating_add(window_secs);

    if tag_ok && fresh {
        Some(Marker { nonce, timestamp })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSK: &[u8] = b"parallax-quic-marker-test-psk-001";
    const SS: [u8; 32] = [7_u8; 32];
    const SNI: &[u8] = b"www.cloudflare.com";
    const DCID: &[u8] = &[0xab, 0xcd, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05];
    const WINDOW: u64 = 604_800;

    fn nonce() -> [u8; NONCE_LEN] {
        [0x11; NONCE_LEN]
    }

    #[test]
    fn seal_then_open_round_trips() {
        let now = 1_900_000_000;
        let cr = seal(PSK, &SS, SNI, DCID, now, &nonce());
        let m = open(PSK, &SS, SNI, DCID, &cr, now, WINDOW).expect("valid marker opens");
        assert_eq!(m.nonce, nonce());
        assert_eq!(m.timestamp, now);
    }

    #[test]
    fn carrier_is_pseudorandom_not_plaintext() {
        // The tag/nonce/ts must be hidden by the keystream: the carrier must not
        // expose the nonce in the clear (would be a distinguisher).
        let now = 1_900_000_000;
        let cr = seal(PSK, &SS, SNI, DCID, now, &nonce());
        assert_ne!(&cr[TAG_LEN..TAG_LEN + NONCE_LEN], &nonce()[..]);
    }

    #[test]
    fn wrong_psk_rejects() {
        let now = 1_900_000_000;
        let cr = seal(PSK, &SS, SNI, DCID, now, &nonce());
        assert!(open(
            b"a-different-psk-entirely--------!",
            &SS,
            SNI,
            DCID,
            &cr,
            now,
            WINDOW
        )
        .is_none());
    }

    #[test]
    fn wrong_ecdh_rejects() {
        let now = 1_900_000_000;
        let cr = seal(PSK, &SS, SNI, DCID, now, &nonce());
        assert!(open(PSK, &[8_u8; 32], SNI, DCID, &cr, now, WINDOW).is_none());
    }

    #[test]
    fn wrong_dcid_or_sni_rejects() {
        let now = 1_900_000_000;
        let cr = seal(PSK, &SS, SNI, DCID, now, &nonce());
        assert!(open(PSK, &SS, b"www.apple.com", DCID, &cr, now, WINDOW).is_none());
        assert!(open(PSK, &SS, SNI, &[0_u8; 8], &cr, now, WINDOW).is_none());
    }

    #[test]
    fn tampered_carrier_rejects() {
        let now = 1_900_000_000;
        let mut cr = seal(PSK, &SS, SNI, DCID, now, &nonce());
        cr[0] ^= 0x01;
        assert!(open(PSK, &SS, SNI, DCID, &cr, now, WINDOW).is_none());
    }

    #[test]
    fn stale_or_future_rejects() {
        let now = 1_900_000_000;
        let cr = seal(PSK, &SS, SNI, DCID, now, &nonce());
        // Verified a full window + 1s later: stale.
        assert!(open(PSK, &SS, SNI, DCID, &cr, now + WINDOW + 1, WINDOW).is_none());
        // Verified well before it was sealed (beyond skew): future.
        assert!(open(PSK, &SS, SNI, DCID, &cr, now - 60, WINDOW).is_none());
        // Within the window: still valid.
        assert!(open(PSK, &SS, SNI, DCID, &cr, now + WINDOW - 1, WINDOW).is_some());
    }

    #[test]
    fn a_random_clienthello_random_is_not_a_marker() {
        // A genuine (non-ParallaX) client's random must (overwhelmingly) fail to
        // verify — i.e. cold Initials route to the splice, not termination.
        let now = 1_900_000_000;
        let not_a_marker = [0x5a_u8; MARKER_LEN];
        assert!(open(PSK, &SS, SNI, DCID, &not_a_marker, now, WINDOW).is_none());
    }
}
