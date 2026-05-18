//! Regression baseline that locks the Safari 17 ParallaX ClientHello against
//! real Safari 26.4 (macOS Tahoe) captures.
//!
//! The fixtures under `tests/fixtures/safari26_*.bin` are raw TLS records
//! taken from `tcpdump -i en0 'tcp port 443'` while Safari 26.4 fetched the
//! corresponding hostname. They are the ground truth that the Safari17
//! profile is calibrated against in `src/tls/stateful.rs`.
//!
//! These tests intentionally use the same loopback rustls server harness as
//! `chrome_parity_baseline.rs` so the parallax ClientHello bytes are the
//! exact ones produced on a real TLS handshake, not a synthetic snapshot.

use parallax::{
    crypto::session::X25519KeyPair,
    tls::{client_hello_builder::BrowserProfile, stateful::StatefulRustlsCamouflageBackend},
};

const TLS12: u16 = 0x0303;
const TLS13: u16 = 0x0304;

const EXT_SNI: u16 = 0x0000;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;

const GROUP_X25519: u16 = 0x001d;
const GROUP_X25519_MLKEM768: u16 = 0x11ec;
const GROUP_SECP256R1: u16 = 0x0017;
const GROUP_SECP384R1: u16 = 0x0018;
const GROUP_SECP521R1: u16 = 0x0019;

const SCSV: u16 = 0x00ff;

/// TLS 1.3 cipher suites in Safari 26.4 ClientHello order.
const SAFARI_TLS13_CIPHER_PREFIX: &[u16] = &[0x1302, 0x1303, 0x1301];

/// Full set of TLS 1.2 / 1.3 cipher suites Safari 26.4 announces that
/// rustls + aws-lc-rs can actually implement, in Apple's wire order.
const SAFARI_RUSTLS_SUPPORTED_CIPHERS: &[u16] = &[
    0x1302, 0x1303, 0x1301, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8,
];

/// Real Safari 26.4 also offers AES_CBC/RSA/3DES legacy ciphers (c00a, c009,
/// c014, c013, 009d, 009c, 0035, 002f, c008, c012, 000a). rustls + aws-lc-rs
/// cannot emit these from the client side; we accept the resulting length
/// difference as a known limitation and verify the rustls-supported prefix.
const SAFARI_LEGACY_CIPHER_TAIL: &[u16] = &[
    0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
];

/// Safari 26.4 supported_groups (without GREASE), in apple.com wire order.
const SAFARI_SUPPORTED_GROUPS: &[u16] = &[
    GROUP_X25519_MLKEM768,
    GROUP_X25519,
    GROUP_SECP256R1,
    GROUP_SECP384R1,
    GROUP_SECP521R1,
];

/// Safari 26.4 signature_algorithms in apple.com wire order. The real Apple
/// list contains a duplicate `rsa_pss_rsae_sha384` and `rsa_pss_pss_sha512`
/// (0x080a); rustls 0.23 dedupes its scheme list and has no enum variant for
/// 0x080a, so the parallax ClientHello drops both entries. See
/// `SAFARI_RUSTLS_SUPPORTED_SIG_ALGS` for the subset we lock down.
const SAFARI_SIGNATURE_ALGORITHMS_REAL: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];

const SAFARI_RUSTLS_SUPPORTED_SIG_ALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];

const SAFARI_APPLE_FIXTURE: &[u8] = include_bytes!("fixtures/safari26_apple_com_clienthello.bin");
const SAFARI_CLOUDFLARE_FIXTURE: &[u8] =
    include_bytes!("fixtures/safari26_cloudflare_com_clienthello.bin");

#[test]
fn safari_fixture_apple_com_matches_known_shape() {
    let fields = parse_client_hello(SAFARI_APPLE_FIXTURE)
        .expect("apple.com Safari fixture is a valid TLS ClientHello");
    assert_real_safari_shape(&fields, "apple.com");
}

#[test]
fn safari_fixture_cloudflare_com_matches_known_shape() {
    let fields = parse_client_hello(SAFARI_CLOUDFLARE_FIXTURE)
        .expect("cloudflare.com Safari fixture is a valid TLS ClientHello");
    assert_real_safari_shape(&fields, "cloudflare.com");
}

#[test]
fn parallax_safari_client_hello_matches_real_safari_shaping_points() {
    let parallax_record = generate_parallax_safari_client_hello();
    let parallax =
        parse_client_hello(&parallax_record).expect("parallax emits a valid ClientHello");
    let safari = parse_client_hello(SAFARI_APPLE_FIXTURE)
        .expect("apple.com Safari fixture is a valid TLS ClientHello");

    assert_parallax_matches_safari(&safari, &parallax);
}

fn assert_real_safari_shape(fields: &ClientHelloFields, host: &str) {
    assert_eq!(
        fields.legacy_version, TLS12,
        "{host}: Safari should pin the legacy ClientHello version to TLS 1.2"
    );
    assert_eq!(
        fields.client_random.len(),
        32,
        "{host}: ClientHello.random is always 32 bytes"
    );
    assert_eq!(
        fields.session_id.len(),
        32,
        "{host}: Safari emits a 32-byte session_id for TLS 1.3 middlebox compatibility"
    );

    // GREASE at index 0 of cipher_suites and at index 0 of supported_groups
    // is the most load-bearing JA3 / JA4 input. If Apple ever drops these,
    // the calibration below must be revisited.
    assert!(
        is_grease(fields.cipher_suites[0]),
        "{host}: Safari prepends GREASE to cipher_suites: {:?}",
        fields.cipher_suites
    );
    assert!(
        is_grease(fields.supported_groups[0]),
        "{host}: Safari prepends GREASE to supported_groups: {:?}",
        fields.supported_groups
    );

    assert_eq!(
        &fields.cipher_suites[1..4],
        SAFARI_TLS13_CIPHER_PREFIX,
        "{host}: Safari TLS 1.3 cipher prefix changed"
    );

    let non_grease_groups = non_grease(&fields.supported_groups);
    assert_eq!(
        non_grease_groups, SAFARI_SUPPORTED_GROUPS,
        "{host}: Safari supported_groups (sans GREASE) changed"
    );

    assert_eq!(
        fields.signature_algorithms, SAFARI_SIGNATURE_ALGORITHMS_REAL,
        "{host}: Safari signature_algorithms changed",
    );

    assert_eq!(
        fields.alpn,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        "{host}: Safari ALPN list changed"
    );

    let non_grease_versions = non_grease(&fields.supported_versions);
    assert_eq!(
        non_grease_versions,
        vec![TLS13, TLS12],
        "{host}: Safari supported_versions (sans GREASE) changed"
    );

    let non_grease_key_share = non_grease_key_share_groups(fields);
    assert_eq!(
        non_grease_key_share,
        vec![GROUP_X25519_MLKEM768, GROUP_X25519],
        "{host}: Safari key_share groups (sans GREASE) changed"
    );

    assert_eq!(
        fields.ec_point_formats,
        vec![0],
        "{host}: Safari should advertise only the uncompressed EC point format"
    );

    // Spot-check the suites that follow the TLS 1.3 prefix to make sure the
    // fixture wasn't truncated or reordered post-capture.
    for suite in SAFARI_RUSTLS_SUPPORTED_CIPHERS {
        assert!(
            fields.cipher_suites.contains(suite),
            "{host}: Safari fixture is missing expected cipher 0x{suite:04x}"
        );
    }
    for suite in SAFARI_LEGACY_CIPHER_TAIL {
        assert!(
            fields.cipher_suites.contains(suite),
            "{host}: Safari fixture is missing expected legacy cipher 0x{suite:04x}"
        );
    }
}

fn assert_parallax_matches_safari(safari: &ClientHelloFields, parallax: &ClientHelloFields) {
    assert_eq!(
        parallax.legacy_version, TLS12,
        "ParallaX should pin the legacy ClientHello version to TLS 1.2"
    );

    // --- Cipher suites ---------------------------------------------------
    //
    // rustls + aws-lc-rs cannot emit the legacy ECDHE-CBC / RSA / 3DES tail
    // Apple ships, but we can (and must) match Apple's order for everything
    // the rustls provider does support. The leading GREASE entry must be
    // identical too. rustls appends SCSV (0x00ff) at the end when TLS 1.2 is
    // enabled; Safari has the renegotiation_info extension (0xff01) instead
    // — that delta is unavoidable while we stay on stock rustls.
    assert!(
        is_grease(parallax.cipher_suites[0]),
        "ParallaX should prepend GREASE to cipher_suites: {:?}",
        parallax.cipher_suites
    );
    let parallax_real_ciphers: Vec<u16> = parallax
        .cipher_suites
        .iter()
        .copied()
        .filter(|c| !is_grease(*c) && *c != SCSV)
        .collect();
    assert_eq!(
        parallax_real_ciphers, SAFARI_RUSTLS_SUPPORTED_CIPHERS,
        "ParallaX cipher_suites diverged from the Safari-supported prefix"
    );
    let safari_real_ciphers: Vec<u16> = safari
        .cipher_suites
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .take(SAFARI_RUSTLS_SUPPORTED_CIPHERS.len())
        .collect();
    assert_eq!(
        safari_real_ciphers, SAFARI_RUSTLS_SUPPORTED_CIPHERS,
        "Safari fixture cipher prefix drifted from the calibrated constant"
    );

    // --- Supported groups ------------------------------------------------
    assert!(
        is_grease(parallax.supported_groups[0]),
        "ParallaX should prepend GREASE to supported_groups: {:?}",
        parallax.supported_groups
    );
    assert_eq!(
        non_grease(&parallax.supported_groups),
        SAFARI_SUPPORTED_GROUPS,
        "ParallaX supported_groups (sans GREASE) must match Safari"
    );
    assert_eq!(
        non_grease(&safari.supported_groups),
        SAFARI_SUPPORTED_GROUPS,
        "Safari fixture supported_groups (sans GREASE) drifted from the calibrated constant"
    );

    // --- Key share groups ------------------------------------------------
    //
    // rustls picks the first hybrid + classical entry for key_share
    // regardless of how many groups are listed before them. Both Chrome and
    // Safari end up offering MLKEM768 + X25519, which is exactly what
    // CoreCrypto does on a fresh handshake.
    let parallax_ks = non_grease_key_share_groups(parallax);
    assert_eq!(
        parallax_ks,
        vec![GROUP_X25519_MLKEM768, GROUP_X25519],
        "ParallaX key_share groups (sans GREASE) must match Safari"
    );
    let safari_ks = non_grease_key_share_groups(safari);
    assert_eq!(
        safari_ks,
        vec![GROUP_X25519_MLKEM768, GROUP_X25519],
        "Safari fixture key_share groups (sans GREASE) drifted"
    );

    // --- Signature algorithms -------------------------------------------
    assert_eq!(
        parallax.signature_algorithms, SAFARI_RUSTLS_SUPPORTED_SIG_ALGS,
        "ParallaX signature_algorithms must match Safari's rustls-supported subset"
    );
    // The Safari fixture is the source of truth for which schemes we drop
    // (the duplicate 0x0805 and 0x080a). Make sure those two entries are
    // still present in the fixture so a future Safari release that fixes
    // this list trips the assertion and we re-calibrate.
    let safari_sig_algs = &safari.signature_algorithms;
    assert_eq!(
        safari_sig_algs.iter().filter(|s| **s == 0x0805).count(),
        2,
        "Safari fixture lost its duplicate rsa_pss_rsae_sha384 entry"
    );

    // --- ALPN ------------------------------------------------------------
    assert_eq!(
        parallax.alpn,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        "ParallaX ALPN must match Safari (h2, http/1.1)"
    );
    assert_eq!(parallax.alpn, safari.alpn, "ALPN lists diverged");

    // --- Supported versions ---------------------------------------------
    assert_eq!(
        non_grease(&parallax.supported_versions),
        vec![TLS13, TLS12],
        "ParallaX supported_versions (sans GREASE) must match Safari"
    );
    assert_eq!(
        non_grease(&safari.supported_versions),
        vec![TLS13, TLS12],
        "Safari fixture supported_versions changed"
    );

    // --- EC point formats -----------------------------------------------
    assert_eq!(
        parallax.ec_point_formats,
        vec![0],
        "ParallaX must advertise only the uncompressed EC point format"
    );
    assert_eq!(
        safari.ec_point_formats,
        vec![0],
        "Safari fixture changed its EC point format list"
    );

    // --- Extension presence ---------------------------------------------
    //
    // Extension *order* differs between rustls and CoreCrypto and is not
    // something we can shape without forking rustls. Lock down the set of
    // extension types instead so we notice if rustls ever drops or adds
    // one. The Safari-only extensions we know we cannot emit are listed in
    // SAFARI_ONLY_EXTENSIONS below.
    const SAFARI_ONLY_EXTENSIONS: &[u16] = &[
        0xff01, // renegotiation_info; rustls uses SCSV instead
        0x0012, // signed_certificate_timestamp
        0x001b, // compress_certificate
    ];
    for ext in SAFARI_ONLY_EXTENSIONS {
        assert!(
            safari.extensions.contains(ext),
            "Safari fixture lost expected extension 0x{ext:04x}"
        );
        assert!(
            !parallax.extensions.contains(ext),
            "ParallaX unexpectedly grew extension 0x{ext:04x} (rustls support changed?)"
        );
    }

    let required_shared_extensions = [
        EXT_SNI,
        EXT_SUPPORTED_GROUPS,
        EXT_EC_POINT_FORMATS,
        EXT_ALPN,
        EXT_SIGNATURE_ALGORITHMS,
        EXT_KEY_SHARE,
        EXT_SUPPORTED_VERSIONS,
    ];
    for ext in required_shared_extensions {
        assert!(
            parallax.extensions.contains(&ext),
            "ParallaX is missing extension 0x{ext:04x}"
        );
        assert!(
            safari.extensions.contains(&ext),
            "Safari fixture is missing extension 0x{ext:04x}"
        );
    }
}

/// Drive rustls just far enough to materialise the ClientHello bytes. We
/// deliberately do not run a full handshake here: the integration tests in
/// `chrome_parity_baseline.rs` that do drive a loopback handshake are all
/// `#[ignore]` because `StatefulRustlsSession::complete` also writes the
/// HTTP/2 connection preface, which requires a real h2 peer. For fingerprint
/// regression we only need the wire-level ClientHello.
fn generate_parallax_safari_client_hello() -> Vec<u8> {
    let server = X25519KeyPair::generate();
    let psk = b"0123456789abcdef0123456789abcdef";
    let session = StatefulRustlsCamouflageBackend
        .start(
            "apple.com".to_owned(),
            psk,
            &server.public,
            BrowserProfile::Safari17,
        )
        .expect("start stateful ParallaX TLS camouflage");
    session.client_hello_bytes().to_vec()
}

#[derive(Debug, Default)]
struct ClientHelloFields {
    legacy_version: u16,
    client_random: Vec<u8>,
    session_id: Vec<u8>,
    cipher_suites: Vec<u16>,
    extensions: Vec<u16>,
    supported_groups: Vec<u16>,
    supported_versions: Vec<u16>,
    signature_algorithms: Vec<u16>,
    alpn: Vec<Vec<u8>>,
    key_shares: Vec<KeyShare>,
    ec_point_formats: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct KeyShare {
    group: u16,
    #[allow(dead_code)] // Retained for diagnostic logging.
    len: usize,
}

fn parse_client_hello(record: &[u8]) -> Result<ClientHelloFields, String> {
    let mut cursor = Cursor::new(record);
    let content_type = cursor.u8()?;
    if content_type != 0x16 {
        return Err(format!("not a TLS handshake record: 0x{content_type:02x}"));
    }
    let _record_version = cursor.u16()?;
    let record_len = cursor.u16()? as usize;
    let record_body = cursor.bytes(record_len)?;

    let mut cursor = Cursor::new(record_body);
    let handshake_type = cursor.u8()?;
    if handshake_type != 0x01 {
        return Err(format!(
            "not a ClientHello handshake: 0x{handshake_type:02x}"
        ));
    }
    let handshake_len = cursor.u24()? as usize;
    let handshake_end = cursor.pos + handshake_len;
    if handshake_end > record_body.len() {
        return Err("handshake length overruns record".to_string());
    }

    let legacy_version = cursor.u16()?;
    let client_random = cursor.bytes(32)?.to_vec();
    let session_id_len = cursor.u8()? as usize;
    let session_id = cursor.bytes(session_id_len)?.to_vec();

    let cipher_suites = parse_u16_vector(&mut cursor)?;
    let _compression = parse_u8_vector(&mut cursor)?;

    let extensions_len = cursor.u16()? as usize;
    let extensions_end = cursor.pos + extensions_len;
    if extensions_end > handshake_end {
        return Err("extensions overrun handshake body".to_string());
    }

    let mut fields = ClientHelloFields {
        legacy_version,
        client_random,
        session_id,
        cipher_suites,
        ..ClientHelloFields::default()
    };

    while cursor.pos < extensions_end {
        let ext_type = cursor.u16()?;
        let ext_len = cursor.u16()? as usize;
        let ext_data = cursor.bytes(ext_len)?;
        fields.extensions.push(ext_type);
        match ext_type {
            EXT_SUPPORTED_GROUPS => {
                let mut inner = Cursor::new(ext_data);
                fields.supported_groups = parse_u16_vector(&mut inner)?;
            }
            EXT_SUPPORTED_VERSIONS => {
                let mut inner = Cursor::new(ext_data);
                fields.supported_versions = parse_u16_vector_u8_len(&mut inner)?;
            }
            EXT_SIGNATURE_ALGORITHMS => {
                let mut inner = Cursor::new(ext_data);
                fields.signature_algorithms = parse_u16_vector(&mut inner)?;
            }
            EXT_ALPN => {
                fields.alpn = parse_alpn(ext_data)?;
            }
            EXT_KEY_SHARE => {
                fields.key_shares = parse_key_shares(ext_data)?;
            }
            EXT_EC_POINT_FORMATS => {
                let mut inner = Cursor::new(ext_data);
                fields.ec_point_formats = parse_u8_vector(&mut inner)?;
            }
            _ => {}
        }
    }

    Ok(fields)
}

fn parse_u16_vector(cursor: &mut Cursor<'_>) -> Result<Vec<u16>, String> {
    let len = cursor.u16()? as usize;
    let body = cursor.bytes(len)?;
    let mut out = Vec::with_capacity(len / 2);
    for chunk in body.chunks_exact(2) {
        out.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    Ok(out)
}

fn parse_u16_vector_u8_len(cursor: &mut Cursor<'_>) -> Result<Vec<u16>, String> {
    let len = cursor.u8()? as usize;
    let body = cursor.bytes(len)?;
    let mut out = Vec::with_capacity(len / 2);
    for chunk in body.chunks_exact(2) {
        out.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    Ok(out)
}

fn parse_u8_vector(cursor: &mut Cursor<'_>) -> Result<Vec<u8>, String> {
    let len = cursor.u8()? as usize;
    Ok(cursor.bytes(len)?.to_vec())
}

fn parse_alpn(data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut cursor = Cursor::new(data);
    let total = cursor.u16()? as usize;
    let body = cursor.bytes(total)?;
    let mut out = Vec::new();
    let mut inner = Cursor::new(body);
    while inner.pos < body.len() {
        let len = inner.u8()? as usize;
        out.push(inner.bytes(len)?.to_vec());
    }
    Ok(out)
}

fn parse_key_shares(data: &[u8]) -> Result<Vec<KeyShare>, String> {
    let mut cursor = Cursor::new(data);
    let total = cursor.u16()? as usize;
    let body = cursor.bytes(total)?;
    let mut shares = Vec::new();
    let mut inner = Cursor::new(body);
    while inner.pos < body.len() {
        let group = inner.u16()?;
        let len = inner.u16()? as usize;
        inner.skip(len)?;
        shares.push(KeyShare { group, len });
    }
    Ok(shares)
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn u8(&mut self) -> Result<u8, String> {
        if self.pos >= self.data.len() {
            return Err("cursor: out of bytes".to_string());
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, String> {
        let hi = self.u8()?;
        let lo = self.u8()?;
        Ok(u16::from_be_bytes([hi, lo]))
    }

    fn u24(&mut self) -> Result<u32, String> {
        let a = self.u8()?;
        let b = self.u8()?;
        let c = self.u8()?;
        Ok(((a as u32) << 16) | ((b as u32) << 8) | (c as u32))
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], String> {
        if self.pos + len > self.data.len() {
            return Err(format!(
                "cursor: requested {len} bytes but only {} remain",
                self.data.len() - self.pos
            ));
        }
        let out = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }

    fn skip(&mut self, len: usize) -> Result<(), String> {
        let _ = self.bytes(len)?;
        Ok(())
    }
}

fn is_grease(value: u16) -> bool {
    let high = (value >> 8) as u8;
    let low = value as u8;
    high == low && (low & 0x0f) == 0x0a
}

fn non_grease(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .collect()
}

fn non_grease_key_share_groups(fields: &ClientHelloFields) -> Vec<u16> {
    fields
        .key_shares
        .iter()
        .map(|share| share.group)
        .filter(|group| !is_grease(*group))
        .collect()
}
