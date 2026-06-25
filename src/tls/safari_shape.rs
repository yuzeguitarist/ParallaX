//! Shared Safari-26 ClientHello shape primitives.
//!
//! This module is the single source of truth for the GREASE machinery and the
//! structurally load-bearing ClientHello byte-builders (cipher list, supported
//! groups, signature algorithms incl. Apple's duplicate `0x0805`, key_share
//! container, supported versions). Two callers consume it:
//!
//! * the handwritten TCP camouflage path in [`super::safari26`], which assembles
//!   a full ClientHello record from these extension bodies, and
//! * the hand-written QUIC TLS engine in [`super::quic`], which assembles the
//!   Safari-26 H3 ClientHello handshake message from the same GREASE rules and the
//!   same exact `signature_algorithms` bytes.
//!
//! Keeping both paths on one builder guarantees the GREASE classes and the kept
//! `0x0805` duplicate stay identical no matter which carrier emits the hello.
//! These builders are rustls-free; the QUIC path is no longer routed through the
//! vendored-rustls fork.

// --- Wire codepoints (RFC-fixed values, shared with the TCP path) ------------

pub(crate) const TLS13: u16 = 0x0304;
pub(crate) const TLS12: u16 = 0x0303;

pub(crate) const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub(crate) const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub(crate) const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

pub(crate) const GROUP_X25519_MLKEM768: u16 = 0x11ec;
pub(crate) const GROUP_X25519: u16 = 0x001d;
pub(crate) const GROUP_SECP256R1: u16 = 0x0017;
pub(crate) const GROUP_SECP384R1: u16 = 0x0018;
pub(crate) const GROUP_SECP521R1: u16 = 0x0019;

pub(crate) const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
pub(crate) const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
pub(crate) const SIG_RSA_PKCS1_SHA256: u16 = 0x0401;
pub(crate) const SIG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
pub(crate) const SIG_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
pub(crate) const SIG_RSA_PKCS1_SHA384: u16 = 0x0501;
pub(crate) const SIG_RSA_PSS_RSAE_SHA512: u16 = 0x0806;
pub(crate) const SIG_RSA_PKCS1_SHA512: u16 = 0x0601;
/// Trailing ecdsa_sha1 in Apple's `signature_algorithms`. Confirmed present on
/// BOTH the TCP and the QUIC/H3 1-RTT path (Safari emits all 10 schemes incl.
/// this trailing 0x0201) — do NOT drop it.
pub(crate) const SIG_ECDSA_SHA1: u16 = 0x0201;

pub(crate) const MLKEM768_PUBLIC_KEY_LEN: usize = 1184;
pub(crate) const X25519_KEY_LEN: usize = 32;

/// Standard GREASE values from RFC 8701.
pub(crate) const BROWSER_GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// GREASE codepoints chosen for one ClientHello: independent values for the
/// cipher, the first (len-0) extension, the supported_groups/key_share/
/// supported_versions lead, and the last (len-1) extension. Only the first and
/// last extension GREASE are forced to differ, and on collision the last is
/// derived by `value ^ 0x1010` — exactly BoringSSL's `ssl_get_grease_value`
/// rule, the engine real Safari runs. Every other surface is drawn freely,
/// matching the value space real Safari occupies.
#[derive(Clone, Copy)]
pub(crate) struct GreaseSet {
    pub(crate) cipher: u16,
    pub(crate) extension: u16,
    pub(crate) group: u16,
    pub(crate) version: u16,
    pub(crate) final_extension: u16,
}

impl GreaseSet {
    pub(crate) fn from_seed(seed: [u8; 5]) -> Self {
        let extension = BROWSER_GREASE_VALUES[seed[1] as usize % BROWSER_GREASE_VALUES.len()];
        let mut final_extension =
            BROWSER_GREASE_VALUES[seed[4] as usize % BROWSER_GREASE_VALUES.len()];
        // Byte-for-byte BoringSSL `ssl_get_grease_value`: the two fake extensions
        // must not share a value, and on collision BoringSSL XORs the value (not
        // the index) with 0x1010 — never a `(idx+1) % 16` increment. The XOR is a
        // closed involution over the RFC 8701 0x?a?a set, so the result is always
        // another valid GREASE value distinct from `extension`.
        if final_extension == extension {
            final_extension ^= 0x1010;
        }
        Self {
            cipher: BROWSER_GREASE_VALUES[seed[0] as usize % BROWSER_GREASE_VALUES.len()],
            extension,
            group: BROWSER_GREASE_VALUES[seed[2] as usize % BROWSER_GREASE_VALUES.len()],
            version: BROWSER_GREASE_VALUES[seed[3] as usize % BROWSER_GREASE_VALUES.len()],
            final_extension,
        }
    }
}

/// The 20-suite Safari-26 cipher list (GREASE-led). Identical for the TCP and H3
/// paths: libquic's `quic_crypto_tls_setup` does NOT prune to pure-1.3 suites, so
/// pruning would itself be a tell.
pub(crate) fn safari_cipher_suites(grease: GreaseSet) -> [u16; 21] {
    [
        grease.cipher,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
        TLS_AES_128_GCM_SHA256,
        0xc02c,
        0xc02b,
        0xcca9,
        0xc030,
        0xc02f,
        0xcca8,
        0xc00a,
        0xc009,
        0xc014,
        0xc013,
        0x009d,
        0x009c,
        0x0035,
        0x002f,
        0xc008,
        0xc012,
        0x000a,
    ]
}

/// Safari-26 QUIC ClientHello cipher list: GREASE + the 3 TLS 1.3 AEAD suites
/// ONLY. QUIC pins TLS 1.3, so the cipher_suites prune to 1.3 — UNLIKE the
/// TCP/H2 path's 21-suite (1.2+1.3) [`safari_cipher_suites`] list. Reusing TCP's
/// full list over QUIC is an instant tell (confirmed 2026-06-22 against real
/// Safari 26.4 H3 wire: the QUIC ClientHello carries exactly GREASE,1302,1303,1301).
pub(crate) fn safari_quic_cipher_suites(grease: GreaseSet) -> [u16; 4] {
    [
        grease.cipher,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
        TLS_AES_128_GCM_SHA256,
    ]
}

/// `supported_groups` extension body: GREASE-led, then X25519MLKEM768, x25519,
/// secp256r1/384/521.
pub(crate) fn supported_groups_extension(grease_group: u16) -> Vec<u8> {
    let groups = [
        grease_group,
        GROUP_X25519_MLKEM768,
        GROUP_X25519,
        GROUP_SECP256R1,
        GROUP_SECP384R1,
        GROUP_SECP521R1,
    ];
    let mut out = Vec::with_capacity(2 + groups.len() * 2);
    push_u16_len_prefixed_u16s(&mut out, &groups);
    out
}

/// `signature_algorithms` extension body. KEEPS Apple's real duplicate `0x0805`
/// (`rsa_pss_rsae_sha384` appears twice) and the trailing ecdsa_sha1 — both are
/// intentional fidelity points, do NOT dedup.
pub(crate) fn signature_algorithms_extension() -> Vec<u8> {
    let schemes = [
        SIG_ECDSA_SECP256R1_SHA256,
        SIG_RSA_PSS_RSAE_SHA256,
        SIG_RSA_PKCS1_SHA256,
        SIG_ECDSA_SECP384R1_SHA384,
        SIG_RSA_PSS_RSAE_SHA384,
        SIG_RSA_PSS_RSAE_SHA384, // duplicate 0x0805 — Apple's table, kept verbatim
        SIG_RSA_PKCS1_SHA384,
        SIG_RSA_PSS_RSAE_SHA512,
        SIG_RSA_PKCS1_SHA512,
        SIG_ECDSA_SHA1,
    ];
    let mut out = Vec::with_capacity(2 + schemes.len() * 2);
    push_u16_len_prefixed_u16s(&mut out, &schemes);
    out
}

/// `key_share` extension body: GREASE entry (single throwaway byte) +
/// X25519MLKEM768 hybrid (1216B) + x25519 (32B).
///
/// `mlkem768_public` MUST be [`MLKEM768_PUBLIC_KEY_LEN`] bytes; the caller checks.
pub(crate) fn key_share_extension(
    grease_group: u16,
    mlkem768_public: &[u8],
    x25519_public: &[u8; 32],
) -> Vec<u8> {
    let hybrid_len = MLKEM768_PUBLIC_KEY_LEN + X25519_KEY_LEN;
    let shares_len = (2 + 2 + 1) + (2 + 2 + hybrid_len) + (2 + 2 + X25519_KEY_LEN);
    let mut shares = Vec::with_capacity(shares_len);
    shares.extend_from_slice(&grease_group.to_be_bytes());
    push_vec_u16(&mut shares, &[0]);

    shares.extend_from_slice(&GROUP_X25519_MLKEM768.to_be_bytes());
    push_u16_len(&mut shares, hybrid_len);
    shares.extend_from_slice(mlkem768_public);
    shares.extend_from_slice(x25519_public);

    shares.extend_from_slice(&GROUP_X25519.to_be_bytes());
    push_vec_u16(&mut shares, x25519_public);

    let mut out = Vec::with_capacity(2 + shares_len);
    push_vec_u16(&mut out, &shares);
    out
}

/// `supported_versions` extension body: GREASE-led, then TLS 1.3, TLS 1.2.
pub(crate) fn supported_versions_extension(grease_version: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(7);
    out.push(6);
    out.extend_from_slice(&grease_version.to_be_bytes());
    out.extend_from_slice(&TLS13.to_be_bytes());
    out.extend_from_slice(&TLS12.to_be_bytes());
    out
}

/// `supported_versions` body for the H3/QUIC path: GREASE-led, then **TLS 1.3
/// only** (no TLS 1.2). QUIC pins min=max=TLS1.3, so Safari's QUIC ClientHello
/// drops 0x0303 — unlike the TCP path's [`supported_versions_extension`], which
/// still offers TLS 1.2.
pub(crate) fn supported_versions_extension_h3(grease_version: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.push(4);
    out.extend_from_slice(&grease_version.to_be_bytes());
    out.extend_from_slice(&TLS13.to_be_bytes());
    out
}

// --- Infallible byte helpers --------------------------------------------------
//
// Every list these write is a small, compile-time-bounded protocol vector, so a
// u16 length can never overflow; the `as u16` casts are sound by construction.

fn push_u16_len_prefixed_u16s(out: &mut Vec<u8>, values: &[u16]) {
    push_u16_len(out, values.len() * 2);
    for value in values {
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn push_vec_u16(out: &mut Vec<u8>, data: &[u8]) {
    push_u16_len(out, data.len());
    out.extend_from_slice(data);
}

fn push_u16_len(out: &mut Vec<u8>, len: usize) {
    debug_assert!(len <= u16::MAX as usize, "TLS vector length fits u16");
    out.extend_from_slice(&(len as u16).to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_grease(value: u16) -> bool {
        value & 0x0f0f == 0x0a0a && (value >> 8) == (value & 0xff)
    }

    fn read_u16(data: &[u8], pos: usize) -> u16 {
        u16::from_be_bytes([data[pos], data[pos + 1]])
    }

    fn grease() -> GreaseSet {
        GreaseSet::from_seed([1, 2, 3, 4, 5])
    }

    #[test]
    fn grease_set_forces_distinct_first_and_last_extension() {
        // The first (len-0) and last (len-1) extension GREASE values must differ
        // for every seed (RFC-8701-style distinct GREASE), including the
        // adversarial seed where both indices collide.
        for a in 0..=u8::MAX {
            for b in 0..=u8::MAX {
                let g = GreaseSet::from_seed([0, a, 0, 0, b]);
                assert_ne!(
                    g.extension, g.final_extension,
                    "first/last GREASE collided for seed bytes {a},{b}"
                );
                assert!(is_grease(g.extension));
                assert!(is_grease(g.final_extension));
            }
        }
    }

    #[test]
    fn grease_collision_resolves_with_boringssl_xor_0x1010() {
        // BoringSSL `ssl_get_grease_value`: on a first/last extension collision the
        // last value is `extension ^ 0x1010`, NOT a `(idx+1) % 16` index bump.
        // Seed bytes 1 and 4 share index 0 here, forcing the collision branch.
        let g = GreaseSet::from_seed([0, 0, 0, 0, 0]);
        assert_eq!(g.extension, BROWSER_GREASE_VALUES[0]);
        assert_eq!(g.final_extension, g.extension ^ 0x1010);
        assert!(is_grease(g.final_extension));
    }

    #[test]
    fn cipher_suites_are_grease_led_and_complete() {
        let suites = safari_cipher_suites(grease());
        assert_eq!(suites.len(), 21, "20 suites + 1 GREASE");
        assert!(is_grease(suites[0]), "slot 0 must be GREASE");
        // The three TLS 1.3 suites follow the GREASE lead, in Safari's order.
        assert_eq!(
            &suites[1..4],
            &[
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_AES_128_GCM_SHA256
            ]
        );
        // No accidental pruning to pure-1.3: a legacy suite must survive.
        assert!(suites.contains(&0x000a), "TLS_RSA_WITH_3DES survives");
    }

    #[test]
    fn signature_algorithms_keeps_the_0x0805_duplicate() {
        let body = signature_algorithms_extension();
        let list_len = read_u16(&body, 0) as usize;
        assert_eq!(list_len + 2, body.len());
        let schemes: Vec<u16> = body[2..].chunks_exact(2).map(|c| read_u16(c, 0)).collect();
        let dups = schemes.iter().filter(|&&s| s == 0x0805).count();
        assert_eq!(dups, 2, "0x0805 must appear exactly twice (Apple's table)");
        assert_eq!(schemes[0], SIG_ECDSA_SECP256R1_SHA256);
        assert_eq!(*schemes.last().unwrap(), SIG_ECDSA_SHA1);
    }

    #[test]
    fn supported_groups_and_versions_are_grease_led() {
        let g = grease();
        let groups = supported_groups_extension(g.group);
        // list-length prefix, then GREASE group first.
        assert_eq!(read_u16(&groups, 0) as usize + 2, groups.len());
        assert_eq!(read_u16(&groups, 2), g.group);
        assert!(is_grease(read_u16(&groups, 2)));
        assert_eq!(read_u16(&groups, 4), GROUP_X25519_MLKEM768);

        let versions = supported_versions_extension(g.version);
        assert_eq!(versions[0] as usize + 1, versions.len());
        assert_eq!(read_u16(&versions, 1), g.version);
        assert!(is_grease(read_u16(&versions, 1)));
        assert_eq!(read_u16(&versions, 3), TLS13);
        assert_eq!(read_u16(&versions, 5), TLS12);

        // The H3/QUIC variant is GREASE + TLS 1.3 ONLY (no TLS 1.2).
        let versions_h3 = supported_versions_extension_h3(g.version);
        assert_eq!(versions_h3[0] as usize + 1, versions_h3.len());
        assert_eq!(versions_h3.len(), 5, "GREASE + 0x0304 only");
        assert_eq!(read_u16(&versions_h3, 1), g.version);
        assert!(is_grease(read_u16(&versions_h3, 1)));
        assert_eq!(read_u16(&versions_h3, 3), TLS13);
        assert!(
            !versions_h3.chunks_exact(2).any(|c| read_u16(c, 0) == TLS12),
            "QUIC supported_versions must NOT offer TLS 1.2"
        );
    }
}
