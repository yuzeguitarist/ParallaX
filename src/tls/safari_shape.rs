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

/// The collision-branch stride in [`GreaseSet::from_seed`] is load-bearing on this
/// length being a power of two: it splits `seed[4]` into a low nibble (pinned to the
/// first-extension index `k = seed[4] % len` by the branch predicate) and a free high
/// nibble (`seed[4] >> 4`) used for the stride. That split equals `% len` vs the
/// complementary free bits ONLY when `len` is a power of two. For a non-power-of-two
/// `len`, `seed[4] % len` is not the low nibble, `seed[4] >> 4` would overlap the
/// pinned bits, and the resolved first->last GREASE delta would re-couple to `k` (a
/// censor-observable correlation, ~17x worse than the modulo skew the split removes).
/// RFC 8701 fixes exactly 16 GREASE values, so this holds by spec — assert it so a
/// future edit to the table cannot silently reintroduce the coupling.
const _: () = assert!(
    BROWSER_GREASE_VALUES.len().is_power_of_two(),
    "GREASE collision-stride nibble split requires a power-of-two table length"
);

/// GREASE codepoints chosen for one ClientHello: independent values for the
/// cipher, the first (len-0) extension, the supported_groups/key_share/
/// supported_versions lead, and the last (len-1) extension. The first and last
/// extension GREASE are drawn INDEPENDENTLY at random and only forced to differ
/// — matching real Safari 26 wire behavior. Measured first/last index deltas
/// across confirmed Safari ClientHellos span {1, 4, 6, 15} (captures
/// `~/Desktop/safari-tcp`), so the last is NOT a fixed derivation of the first:
/// neither a `value ^ 0x1010` (current BoringSSL master) nor a `(idx+1) % 16`
/// relationship holds. Any fixed first->last relationship would itself be a
/// distinguishable tell, so on the rare collision we reshuffle the last index by
/// a per-ClientHello seed-derived (non-constant) stride rather than a fixed
/// transform.
///
/// The collision stride is derived ONLY from seed bits that are free on the
/// collision branch — `seed[5]` and the high nibble of `seed[4]` — never from a
/// bit that already determines another on-wire GREASE value. An earlier version
/// reused `seed[0]` (which also picks the cipher GREASE) for the stride, which
/// made the resolved first->last delta a deterministic function of the cipher
/// GREASE on every colliding ClientHello — an externally observable per-connection
/// correlation that real Safari (independent draws) does not have. The stride
/// spans the full `1..=len-1` range (any non-zero stride is < len so it always
/// lands on a different index; no `| 1` odd-only forcing, which would skew the
/// delta distribution toward odd values). See [`GreaseSet::from_seed`] for why it
/// uses the high nibble of `seed[4]` rather than the whole byte (the low nibble
/// carries the first-extension index `k` on this branch, so feeding it would
/// re-couple the delta to the first-extension GREASE).
#[derive(Clone, Copy)]
pub(crate) struct GreaseSet {
    pub(crate) cipher: u16,
    pub(crate) extension: u16,
    pub(crate) group: u16,
    pub(crate) version: u16,
    pub(crate) final_extension: u16,
}

impl GreaseSet {
    pub(crate) fn from_seed(seed: [u8; 6]) -> Self {
        let len = BROWSER_GREASE_VALUES.len();
        let extension_index = seed[1] as usize % len;
        let mut final_extension_index = seed[4] as usize % len;
        if final_extension_index == extension_index {
            // Independent re-draw, not a fixed first->last transform: advance by a
            // stride so the resolved last GREASE stays uncorrelated with the cipher
            // and first-extension GREASE. The stride is in `1..=len-1` (non-zero and
            // < len), so `(idx + stride) % len` always lands on a different index —
            // keeping the first/last pair indistinguishable from two independent
            // draws, as observed on the wire. On this branch the resolved index delta
            // equals the stride exactly (final = (idx + stride) % len), so the stride
            // distribution IS the observable first->last delta distribution.
            //
            // The stride MUST stay independent of the first-extension GREASE index
            // `k = seed[1] % len`. The branch predicate already pins the LOW nibble
            // of `seed[4]` to `k` (it fired because `seed[4] % len == k`), so the low
            // nibble carries `k` and must NOT feed the stride. Use only the FREE high
            // nibble `seed[4] >> 4` (uniform and independent of `k` on this branch),
            // folded with `seed[5]`. This widens the reduction input beyond a single
            // byte to shrink the `% (len-1)` modulo skew — a bare `seed[5] % 15` over-
            // represents stride 1 (18/256, since 256 = 15·17 + 1) — while keeping the
            // delta exactly k-independent (proven exhaustively in
            // `grease_collision_delta_distribution_is_identical_across_first_ext_index`,
            // which compares the full per-k delta HISTOGRAMS; the set-coverage test
            // `grease_collision_stride_is_independent_of_cipher_grease` cannot detect
            // this coupling, as the buggy whole-byte form also produced all 15 deltas
            // for every k and only their frequencies differed). Folding the WHOLE
            // `seed[4]` byte instead would leak `k` (its low nibble) into the delta;
            // the high nibble alone does not (see the power-of-two assert by
            // `BROWSER_GREASE_VALUES`). Residual skew is a benign per-k-identical
            // frequency wobble (~2.4e-4), not a cross-value correlation.
            let stride = ((((seed[4] >> 4) as usize) << 8 | seed[5] as usize) % (len - 1)) + 1;
            final_extension_index = (final_extension_index + stride) % len;
        }
        Self {
            cipher: BROWSER_GREASE_VALUES[seed[0] as usize % len],
            extension: BROWSER_GREASE_VALUES[extension_index],
            group: BROWSER_GREASE_VALUES[seed[2] as usize % len],
            version: BROWSER_GREASE_VALUES[seed[3] as usize % len],
            final_extension: BROWSER_GREASE_VALUES[final_extension_index],
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
        GreaseSet::from_seed([1, 2, 3, 4, 5, 6])
    }

    #[test]
    fn grease_set_forces_distinct_first_and_last_extension() {
        // The first (len-0) and last (len-1) extension GREASE values must differ
        // for every seed (RFC-8701-style distinct GREASE), including the
        // adversarial seed where both indices collide.
        for a in 0..=u8::MAX {
            for b in 0..=u8::MAX {
                let g = GreaseSet::from_seed([0, a, 0, 0, b, a ^ b]);
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
    fn grease_collision_resolves_without_fixed_first_to_last_relationship() {
        // Real Safari draws the first/last extension GREASE independently and only
        // forces them to differ; measured index deltas span {1,4,6,15}, so the
        // last is NOT a fixed transform of the first. On the collision branch we
        // must therefore avoid pinning a constant relationship: in particular the
        // result must NOT always equal `extension ^ 0x1010` (current BoringSSL
        // master) nor a constant `(idx+1) % 16` bump. Sweep every colliding seed
        // (including the dedicated stride byte `seed[5]`) and assert distinctness
        // plus that no single fixed transform explains all resolutions.
        let mut all_xor = true;
        let mut all_inc = true;
        for stride_byte in 0..=u8::MAX {
            for idx in 0..u8::MAX {
                // Force seed[1] == seed[4] (same index) to hit the collision branch.
                let g = GreaseSet::from_seed([0, idx, 0, 0, idx, stride_byte]);
                assert_ne!(
                    g.extension, g.final_extension,
                    "collision not resolved for stride_byte={stride_byte} idx={idx}"
                );
                assert!(is_grease(g.final_extension));
                if g.final_extension != g.extension ^ 0x1010 {
                    all_xor = false;
                }
                let fi = BROWSER_GREASE_VALUES
                    .iter()
                    .position(|&v| v == g.extension)
                    .unwrap();
                if g.final_extension
                    != BROWSER_GREASE_VALUES[(fi + 1) % BROWSER_GREASE_VALUES.len()]
                {
                    all_inc = false;
                }
            }
        }
        assert!(
            !all_xor,
            "collision resolution must not be a constant ^0x1010"
        );
        assert!(
            !all_inc,
            "collision resolution must not be a constant (idx+1)"
        );
    }

    /// Index of `value` in [`BROWSER_GREASE_VALUES`] (panics if absent — every
    /// GREASE field is by construction one of the 16 table entries).
    fn grease_index(value: u16) -> usize {
        BROWSER_GREASE_VALUES
            .iter()
            .position(|&v| v == value)
            .expect("GREASE value is a table entry")
    }

    /// Resolved first->last extension-GREASE index delta for a forced-collision
    /// seed. `first_byte` is seed[1] (the first-extension index source), and the
    /// branch is forced by setting seed[4] to a value congruent to it mod 16 (the
    /// caller passes the colliding `last_byte`). Returns `(final - first) mod 16`.
    fn collision_delta(cipher: u8, first_byte: u8, last_byte: u8, stride_byte: u8) -> usize {
        let len = BROWSER_GREASE_VALUES.len();
        assert_eq!(
            first_byte as usize % len,
            last_byte as usize % len,
            "caller must force the collision (seed[1] ≡ seed[4] mod 16)"
        );
        let g = GreaseSet::from_seed([cipher, first_byte, 0, 0, last_byte, stride_byte]);
        let first = grease_index(g.extension);
        let last = grease_index(g.final_extension);
        (last + len - first) % len
    }

    /// Regression: the collision-branch stride must come only from seed bits that
    /// drive no other on-wire GREASE value. A prior version derived the stride from
    /// `seed[0]` (which also picks the cipher GREASE), so on every colliding
    /// ClientHello the resolved (first->last) extension-GREASE index delta equaled
    /// `cipher_idx | 1` — an externally observable per-connection correlation real
    /// Safari's independent draws do not have. Holding `seed[0]` (cipher) and the
    /// colliding extension index fixed, varying ONLY the stride source must still
    /// produce every non-zero delta; if the stride were a function of `seed[0]`, the
    /// delta would be pinned to a single value.
    #[test]
    fn grease_collision_stride_is_independent_of_cipher_grease() {
        let len = BROWSER_GREASE_VALUES.len();
        for cipher_seed in 0..=u8::MAX {
            for idx in 0..(len as u8) {
                let mut deltas = std::collections::HashSet::new();
                for stride_byte in 0..=u8::MAX {
                    // seed[1] ≡ seed[4] = idx forces the collision; sweep seed[5].
                    deltas.insert(collision_delta(cipher_seed, idx, idx, stride_byte));
                }
                assert_eq!(
                    deltas.len(),
                    len - 1,
                    "collision delta must span all non-zero strides independent of \
                     cipher seed (cipher_seed={cipher_seed}, idx={idx}); got {deltas:?}"
                );
            }
        }
    }

    /// LOAD-BEARING — do NOT delete as redundant with the set-coverage test above.
    /// This is the SOLE guard of the stride's k-independence: the set-coverage test
    /// `grease_collision_stride_is_independent_of_cipher_grease` only checks that all
    /// 15 deltas appear, which the buggy whole-`seed[4]` stride also satisfied (it
    /// differed only in delta FREQUENCIES). Only this histogram comparison catches a
    /// regression back to a k-coupled stride.
    ///
    /// The strongest anti-tell invariant: on the collision branch the resolved
    /// first->last delta distribution must be IDENTICAL for every first-extension
    /// GREASE index `k` — otherwise a censor who reads the (observable) first-
    /// extension GREASE can predict something about the (observable) last-extension
    /// GREASE, a cross-value correlation real Safari (independent draws) lacks.
    ///
    /// This guards a subtle trap: the branch predicate pins the LOW nibble of
    /// `seed[4]` to `k`, so any stride that consumes the whole `seed[4]` byte leaks
    /// `k` into the delta. The fix uses only `seed[4] >> 4` (free of `k`). We build
    /// the full delta histogram for each `k` by sweeping every free seed bit —
    /// `seed[4]`'s high nibble (16 values) and `seed[5]` (256 values) — and assert
    /// all 16 histograms are bit-for-bit equal. Reverting the stride to consume the
    /// whole `seed[4]` byte makes the histograms differ and reds this test.
    #[test]
    fn grease_collision_delta_distribution_is_identical_across_first_ext_index() {
        let len = BROWSER_GREASE_VALUES.len();
        let histogram_for = |k: u8| -> Vec<u32> {
            let mut hist = vec![0_u32; len];
            for hi in 0..16_u8 {
                // seed[4] ≡ k (mod 16) keeps the collision; its high nibble `hi` is
                // the only free part. seed[4] = hi*16 + k.
                let last_byte = hi.wrapping_mul(16).wrapping_add(k);
                for stride_byte in 0..=u8::MAX {
                    let d = collision_delta(0, k, last_byte, stride_byte);
                    hist[d] += 1;
                }
            }
            hist
        };
        let reference = histogram_for(0);
        // delta 0 must never occur (forced-distinct); every mass sits in 1..=len-1.
        assert_eq!(reference[0], 0, "collision must never yield delta 0");
        for k in 1..(len as u8) {
            assert_eq!(
                histogram_for(k),
                reference,
                "collision delta histogram for first-ext index k={k} differs from \
                 k=0 — the stride leaks the first-extension GREASE index"
            );
        }
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
