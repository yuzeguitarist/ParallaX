//! Shared Safari-26 ClientHello shape primitives.
//!
//! This module is the single source of truth for the GREASE machinery and the
//! structurally load-bearing ClientHello byte-builders (cipher list, supported
//! groups, signature algorithms incl. Apple's duplicate `0x0805`, key_share
//! container, supported versions). Two callers consume it:
//!
//! * the handwritten TCP camouflage path in [`super::safari26`], which assembles
//!   a full ClientHello record from these extension bodies, and
//! * the QUIC/H3 path, which assembles a typed [`SafariChProfile`] (consumed by
//!   the vendored-rustls fork) from the same GREASE rules and the same exact
//!   `signature_algorithms` bytes.
//!
//! Keeping both paths on one builder guarantees the GREASE classes and the kept
//! `0x0805` duplicate stay identical no matter which carrier emits the hello.

use rustls::client::{SafariChProfile, SafariExt};
use rustls::internal::msgs::enums::ExtensionType;
use rustls::CipherSuite;

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
/// Trailing ecdsa_sha1 in Apple's TCP `signature_algorithms`. Capture-gated for
/// the H3 path (the QUIC enumeration may omit it); kept for the TCP fixture.
pub(crate) const SIG_ECDSA_SHA1: u16 = 0x0201;

pub(crate) const MLKEM768_PUBLIC_KEY_LEN: usize = 1184;
pub(crate) const X25519_KEY_LEN: usize = 32;

// Extension codepoints used as raw-extension types in the H3 plan, consumed by
// `safari_h3_ch_profile` (the default QUIC client backend, S6).
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// Standard GREASE values from RFC 8701.
pub(crate) const BROWSER_GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// CAPTURE SWITCH: emit `extended_master_secret` (0x17) and
/// `renegotiation_info` (0xff01) on the H3 path to match the TCP fixture. A real
/// Safari-26 H3 capture may show these are dropped on the pure-1.3 QUIC path; if
/// so, flip this to `false`. Gated on STRUCTURE only — never assert their
/// presence/absence in tests beyond this switch.
pub(crate) const SAFARI_H3_EMIT_LEGACY_EXTS: bool = true;

/// GREASE codepoints chosen for one ClientHello: distinct values for the cipher,
/// the first (len-0) extension, the supported_groups/key_share/supported_versions
/// lead, and the last (len-1) extension.
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
        let mut cipher_index = seed[0] as usize % BROWSER_GREASE_VALUES.len();
        let extension_index = seed[1] as usize % BROWSER_GREASE_VALUES.len();
        if cipher_index == extension_index {
            cipher_index = (cipher_index + 1) % BROWSER_GREASE_VALUES.len();
        }
        let mut final_extension_index = seed[4] as usize % BROWSER_GREASE_VALUES.len();
        if final_extension_index == extension_index {
            final_extension_index = (final_extension_index + 1) % BROWSER_GREASE_VALUES.len();
        }
        Self {
            cipher: BROWSER_GREASE_VALUES[cipher_index],
            extension: BROWSER_GREASE_VALUES[extension_index],
            group: BROWSER_GREASE_VALUES[seed[2] as usize % BROWSER_GREASE_VALUES.len()],
            version: BROWSER_GREASE_VALUES[seed[3] as usize % BROWSER_GREASE_VALUES.len()],
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

// --- QUIC/H3 typed profile ---------------------------------------------------

/// Assemble the exact Safari-26 H3 ClientHello shape as a typed
/// [`SafariChProfile`] for the vendored-rustls fork.
///
/// COLD-START only: `psk_key_exchange_modes` is present (a `Managed` extension),
/// but `pre_shared_key` and `early_data` are absent (`Resumption::disabled()`).
///
/// Structurally-load-bearing extensions whose exact bytes matter — the GREASE
/// pair, the GREASE-led `supported_groups`/`supported_versions`, and the
/// `signature_algorithms` with the kept `0x0805` duplicate — are emitted as
/// [`SafariExt::Raw`] from the shared byte-builders. Extensions rustls encodes
/// byte-faithfully (and which carry live key material / SNI) stay
/// [`SafariExt::Managed`], including `key_share` (GREASE prepend + real shares
/// applied by the fork) and `quic_transport_parameters` (0x39, carrying the
/// hand-encoded ascending blob the QUIC Session substitutes).
pub(crate) fn safari_h3_ch_profile(grease: GreaseSet) -> SafariChProfile {
    let mut plan = Vec::with_capacity(16);

    // Leading GREASE, len 0.
    plan.push(SafariExt::Raw(grease.extension, Vec::new()));
    plan.push(SafariExt::Managed(ExtensionType::ServerName));

    // Capture-gated legacy extensions (match the TCP fixture; see switch above).
    if SAFARI_H3_EMIT_LEGACY_EXTS {
        plan.push(SafariExt::Raw(EXT_EXTENDED_MASTER_SECRET, Vec::new()));
        plan.push(SafariExt::Raw(EXT_RENEGOTIATION_INFO, vec![0x00]));
    }

    plan.push(SafariExt::Raw(
        u16::from(ExtensionType::EllipticCurves),
        supported_groups_extension(grease.group),
    ));
    plan.push(SafariExt::Managed(ExtensionType::ECPointFormats));
    // ALPN = h3 (the profile's `alpn` field drives the body).
    plan.push(SafariExt::Managed(ExtensionType::ALProtocolNegotiation));
    plan.push(SafariExt::Managed(ExtensionType::StatusRequest));
    // signature_algorithms with the kept duplicate 0x0805 — Raw to preserve the
    // dup that a typed `Vec<SignatureScheme>` cannot represent.
    plan.push(SafariExt::Raw(
        u16::from(ExtensionType::SignatureAlgorithms),
        signature_algorithms_extension(),
    ));
    // signed_certificate_timestamp (SCT, 0x12): an empty client-side flag. rustls
    // has NO `ClientExtensions` field for it, so a `Managed` entry would encode to
    // nothing and silently drop from the wire; emit it Raw with the empty body the
    // TCP fixture uses (safari26.rs:760).
    plan.push(SafariExt::Raw(u16::from(ExtensionType::SCT), Vec::new()));
    // key_share: Managed so rustls keeps the real hybrid+x25519 shares (and the
    // fork prepends the GREASE entry); never reconstruct the live key material.
    plan.push(SafariExt::Managed(ExtensionType::KeyShare));
    plan.push(SafariExt::Managed(ExtensionType::PSKKeyExchangeModes));
    plan.push(SafariExt::Raw(
        u16::from(ExtensionType::SupportedVersions),
        supported_versions_extension(grease.version),
    ));
    // quic_transport_parameters (0x39): Managed, carrying the opaque ascending
    // blob the QUIC Session substitutes for quinn's `params.write()`.
    plan.push(SafariExt::Managed(ExtensionType::TransportParameters));
    // compress_certificate (0x1b): the QUIC rustls config leaves
    // `certificate_compression_algorithms` unset, so a `Managed` entry would drop
    // from the wire; emit it Raw with the `[len=2, zlib=0x0001]` body the TCP
    // fixture uses (safari26.rs:772).
    plan.push(SafariExt::Raw(
        u16::from(ExtensionType::CompressCertificate),
        vec![0x02, 0x00, 0x01],
    ));

    // Trailing GREASE, len 1.
    plan.push(SafariExt::Raw(grease.final_extension, vec![0x00]));

    SafariChProfile {
        cipher_suites: safari_cipher_suites(grease)
            .into_iter()
            .map(CipherSuite::Unknown)
            .collect(),
        extension_plan: plan,
        alpn: vec![b"h3".to_vec()],
        key_share_grease_group: grease.group,
    }
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
    }

    #[test]
    fn h3_profile_extension_plan_is_the_static_safari_order() {
        let g = grease();
        let profile = safari_h3_ch_profile(g);

        assert_eq!(profile.alpn, vec![b"h3".to_vec()]);
        assert_eq!(profile.key_share_grease_group, g.group);
        assert_eq!(profile.cipher_suites.len(), 21);

        // Project the plan onto its wire extension-type codepoints.
        let order: Vec<u16> = profile
            .extension_plan
            .iter()
            .map(|ext| match ext {
                SafariExt::Raw(typ, _) => *typ,
                SafariExt::Managed(typ) => u16::from(*typ),
            })
            .collect();

        // First is GREASE (len 0), last is GREASE (len 1), and they differ.
        assert!(is_grease(order[0]));
        assert!(is_grease(*order.last().unwrap()));
        assert_ne!(order[0], *order.last().unwrap());
        match &profile.extension_plan[0] {
            SafariExt::Raw(_, body) => assert!(body.is_empty(), "leading GREASE is len 0"),
            _ => panic!("leading GREASE must be Raw"),
        }
        match profile.extension_plan.last().unwrap() {
            SafariExt::Raw(_, body) => assert_eq!(body, &[0x00], "trailing GREASE is len 1"),
            _ => panic!("trailing GREASE must be Raw"),
        }

        // The static Safari H3 table between the GREASE bookends.
        let expected = [
            0x0000, // server_name
            0x0017, // extended_master_secret (capture switch)
            0xff01, // renegotiation_info (capture switch)
            0x000a, // supported_groups
            0x000b, // ec_point_formats
            0x0010, // ALPN (h3)
            0x0005, // status_request
            0x000d, // signature_algorithms (with dup 0x0805)
            0x0012, // SCT
            0x0033, // key_share
            0x002d, // psk_key_exchange_modes
            0x002b, // supported_versions
            0x0039, // quic_transport_parameters
            0x001b, // compress_certificate
        ];
        assert_eq!(&order[1..order.len() - 1], &expected);

        // Cold-start: no pre_shared_key, no early_data anywhere in the plan.
        assert!(
            !order.contains(&0x0029) && !order.contains(&0x002a),
            "cold-start: pre_shared_key (0x29) and early_data (0x2a) must be absent"
        );
    }

    #[test]
    fn h3_profile_signature_algorithms_carries_the_kept_duplicate() {
        let profile = safari_h3_ch_profile(grease());
        let sig = profile
            .extension_plan
            .iter()
            .find_map(|ext| match ext {
                SafariExt::Raw(0x000d, body) => Some(body.clone()),
                _ => None,
            })
            .expect("signature_algorithms is a Raw extension in the plan");
        assert_eq!(sig, signature_algorithms_extension());
    }
}
