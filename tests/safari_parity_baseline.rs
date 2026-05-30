//! Regression baseline that locks the Safari 26 ParallaX ClientHello against
//! real Safari 26.4 (macOS Tahoe) captures.
//!
//! The fixtures under `tests/fixtures/safari26_*.bin` are raw TLS records
//! taken from `tcpdump -i en0 'tcp port 443'` while Safari 26.4 fetched the
//! corresponding hostname. They are the ground truth that the Safari26
//! profile is calibrated against in `src/tls/safari26.rs`.
//!
//! These tests drive the Safari 26 handwritten TLS backend directly so the
//! ParallaX ClientHello bytes are the exact ones produced by the maintained
//! TLS camouflage path, not a synthetic snapshot.

use parallax::{crypto::session::X25519KeyPair, tls::safari26::Safari26TlsCamouflage};

const TLS12: u16 = 0x0303;
const TLS13: u16 = 0x0304;

const EXT_SNI: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SCT: u16 = 0x0012;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

const GROUP_X25519: u16 = 0x001d;
const GROUP_X25519_MLKEM768: u16 = 0x11ec;
const GROUP_SECP256R1: u16 = 0x0017;
const GROUP_SECP384R1: u16 = 0x0018;
const GROUP_SECP521R1: u16 = 0x0019;

/// TLS 1.3 cipher suites in Safari 26.4 ClientHello order.
const SAFARI_TLS13_CIPHER_PREFIX: &[u16] = &[0x1302, 0x1303, 0x1301];

/// Full Safari 26.4 cipher suite list without the leading GREASE value.
const SAFARI_CIPHERS: &[u16] = &[
    0x1302, 0x1303, 0x1301, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a, 0xc009, 0xc014,
    0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
];

/// Safari 26.4 supported_groups (without GREASE), in apple.com wire order.
const SAFARI_SUPPORTED_GROUPS: &[u16] = &[
    GROUP_X25519_MLKEM768,
    GROUP_X25519,
    GROUP_SECP256R1,
    GROUP_SECP384R1,
    GROUP_SECP521R1,
];

/// Safari 26.4 signature_algorithms in apple.com wire order, including the
/// duplicated `rsa_pss_rsae_sha384` (0x0805) entry Apple emits twice.
const SAFARI_SIGNATURE_ALGORITHMS_REAL: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];

const SAFARI_EXTENSION_ORDER_WITHOUT_GREASE: &[u16] = &[
    EXT_SNI,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_RENEGOTIATION_INFO,
    EXT_SUPPORTED_GROUPS,
    EXT_EC_POINT_FORMATS,
    EXT_ALPN,
    EXT_STATUS_REQUEST,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_SCT,
    EXT_KEY_SHARE,
    EXT_PSK_KEY_EXCHANGE_MODES,
    EXT_SUPPORTED_VERSIONS,
    EXT_COMPRESS_CERTIFICATE,
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

#[test]
fn parallax_safari_client_hello_matches_apple_fixture_after_dynamic_normalization() {
    let parallax_record = generate_parallax_safari_client_hello();
    let safari = normalize_dynamic_client_hello_bytes(SAFARI_APPLE_FIXTURE)
        .expect("normalize Safari apple.com fixture");
    let parallax = normalize_dynamic_client_hello_bytes(&parallax_record)
        .expect("normalize ParallaX ClientHello");

    assert_eq!(
        parallax.len(),
        safari.len(),
        "normalized ClientHello lengths must match before byte comparison"
    );
    if parallax != safari {
        panic!(
            "ParallaX normalized ClientHello is not byte-for-byte Safari: {}",
            first_diff(&safari, &parallax)
        );
    }
}

fn assert_real_safari_shape(fields: &ClientHelloFields, host: &str) {
    assert_eq!(
        fields.record_version, 0x0301,
        "{host}: Safari ClientHello record version should be TLS 1.0 compatibility"
    );
    assert_eq!(
        fields.record_len + 5,
        fields.wire_len,
        "{host}: TLS record length must cover the whole fixture"
    );
    assert_eq!(
        fields.handshake_len + 4,
        fields.record_len,
        "{host}: ClientHello handshake length must fill the TLS record"
    );
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
    assert_eq!(
        fields.compression_methods,
        vec![0],
        "{host}: Safari should advertise only null compression"
    );
    assert_eq!(
        fields.sni.as_deref(),
        Some(host),
        "{host}: Safari SNI extension should carry the target host"
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
    assert!(is_grease(fields.extensions[0]));
    assert!(is_grease(*fields.extensions.last().unwrap()));
    assert_ne!(
        fields.cipher_suites[0], fields.extensions[0],
        "{host}: Safari uses a separate GREASE surface for cipher_suites and extensions"
    );
    assert_eq!(
        extension_payload(fields, fields.extensions[0]),
        Some(&[][..]),
        "{host}: Safari's opening GREASE extension is zero-length"
    );
    assert_eq!(
        extension_payload(fields, *fields.extensions.last().unwrap()),
        Some(&[0][..]),
        "{host}: Safari's closing GREASE extension carries a single zero byte"
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
        key_share_lengths(fields),
        vec![
            (fields.supported_groups[0], 1),
            (GROUP_X25519_MLKEM768, 1216),
            (GROUP_X25519, 32)
        ],
        "{host}: Safari key_share GREASE/hybrid/X25519 lengths changed"
    );

    assert_eq!(
        fields.ec_point_formats,
        vec![0],
        "{host}: Safari should advertise only the uncompressed EC point format"
    );

    assert_eq!(
        non_grease(&fields.cipher_suites),
        SAFARI_CIPHERS,
        "{host}: Safari cipher list changed"
    );
    assert_eq!(
        non_grease(&fields.extensions),
        SAFARI_EXTENSION_ORDER_WITHOUT_GREASE,
        "{host}: Safari extension order changed"
    );
    assert_safari_extension_payloads(fields, host);
}

fn assert_parallax_matches_safari(safari: &ClientHelloFields, parallax: &ClientHelloFields) {
    assert_eq!(
        parallax.record_version, safari.record_version,
        "ParallaX record-layer compatibility version must match Safari"
    );
    assert_eq!(
        parallax.wire_len, safari.wire_len,
        "ParallaX ClientHello wire length must match the apple.com Safari fixture"
    );
    assert_eq!(
        parallax.record_len, safari.record_len,
        "ParallaX TLS record payload length must match the apple.com Safari fixture"
    );
    assert_eq!(
        parallax.handshake_len, safari.handshake_len,
        "ParallaX ClientHello handshake length must match the apple.com Safari fixture"
    );
    assert_eq!(
        parallax.legacy_version, TLS12,
        "ParallaX should pin the legacy ClientHello version to TLS 1.2"
    );
    assert_eq!(
        parallax.compression_methods,
        vec![0],
        "ParallaX must match Safari's null-only compression_methods"
    );
    assert_eq!(
        parallax.sni.as_deref(),
        Some("apple.com"),
        "ParallaX SNI extension must carry the target host"
    );

    // --- Cipher suites ---------------------------------------------------
    //
    assert!(
        is_grease(parallax.cipher_suites[0]),
        "ParallaX should prepend GREASE to cipher_suites: {:?}",
        parallax.cipher_suites
    );
    assert_eq!(
        non_grease(&parallax.cipher_suites),
        SAFARI_CIPHERS,
        "ParallaX cipher_suites must match Safari 26.4"
    );
    assert_eq!(
        non_grease(&safari.cipher_suites),
        SAFARI_CIPHERS,
        "Safari fixture cipher list drifted from the calibrated constant"
    );
    assert_ne!(
        parallax.cipher_suites[0], parallax.extensions[0],
        "ParallaX must not reuse the cipher-suite GREASE value as the opening GREASE extension"
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
    // Safari offers the hybrid ML-KEM/X25519 share and the standalone X25519
    // component on fresh handshakes.
    let parallax_ks = non_grease_key_share_groups(parallax);
    assert_eq!(
        parallax_ks,
        vec![GROUP_X25519_MLKEM768, GROUP_X25519],
        "ParallaX key_share groups (sans GREASE) must match Safari"
    );
    assert_eq!(
        parallax.key_shares[0].group, parallax.supported_groups[0],
        "ParallaX key_share GREASE group must match the supported_groups GREASE value"
    );
    assert_eq!(
        key_share_lengths(parallax),
        vec![
            (parallax.supported_groups[0], 1),
            (GROUP_X25519_MLKEM768, 1216),
            (GROUP_X25519, 32),
        ],
        "ParallaX key_share GREASE/hybrid/X25519 lengths must match Safari"
    );
    let safari_ks = non_grease_key_share_groups(safari);
    assert_eq!(
        safari_ks,
        vec![GROUP_X25519_MLKEM768, GROUP_X25519],
        "Safari fixture key_share groups (sans GREASE) drifted"
    );

    // --- Signature algorithms -------------------------------------------
    //
    // Apple emits `rsa_pss_rsae_sha384` (0x0805) twice; the handwritten
    // Safari path reproduces the duplicate verbatim.
    assert_eq!(
        parallax.signature_algorithms, SAFARI_SIGNATURE_ALGORITHMS_REAL,
        "ParallaX signature_algorithms must match Safari 26.4 exactly \
         (including the duplicate 0x0805)"
    );
    assert_eq!(
        parallax.signature_algorithms, safari.signature_algorithms,
        "ParallaX signature_algorithms must equal the apple.com fixture byte-for-byte"
    );
    assert_eq!(
        safari
            .signature_algorithms
            .iter()
            .filter(|s| **s == 0x0805)
            .count(),
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

    // --- Extension order -------------------------------------------------
    //
    // GREASE values are allowed to vary per connection. Everything else must
    // follow the Safari/CoreCrypto order byte-for-byte.
    assert!(is_grease(parallax.extensions[0]));
    assert!(is_grease(*parallax.extensions.last().unwrap()));
    assert_eq!(
        non_grease(&parallax.extensions),
        SAFARI_EXTENSION_ORDER_WITHOUT_GREASE,
        "ParallaX extension order must match Safari 26.4"
    );
    assert_eq!(
        non_grease(&safari.extensions),
        SAFARI_EXTENSION_ORDER_WITHOUT_GREASE,
        "Safari fixture extension order drifted"
    );
    assert_safari_extension_payloads(parallax, "apple.com");
    assert_eq!(
        extension_payload(parallax, parallax.extensions[0]),
        Some(&[][..]),
        "ParallaX opening GREASE extension must be zero-length like Safari"
    );
    assert_eq!(
        extension_payload(parallax, *parallax.extensions.last().unwrap()),
        Some(&[0][..]),
        "ParallaX closing GREASE extension must carry Safari's single zero byte"
    );
}

/// Drive the Safari backend just far enough to materialise the ClientHello
/// bytes. We deliberately do not run a full handshake here because
/// `Safari26TlsSession::complete` also writes the HTTP/2 connection
/// preface, which requires a real h2 peer. For fingerprint regression we only
/// need the wire-level ClientHello.
fn generate_parallax_safari_client_hello() -> Vec<u8> {
    let server = X25519KeyPair::generate();
    let psk = b"0123456789abcdef0123456789abcdef";
    let session = Safari26TlsCamouflage
        .start("apple.com".to_owned(), psk, &server.public)
        .expect("start Safari 26 ParallaX TLS camouflage");
    session.client_hello_bytes().to_vec()
}

#[derive(Debug, Default)]
struct ClientHelloFields {
    wire_len: usize,
    record_version: u16,
    record_len: usize,
    handshake_len: usize,
    legacy_version: u16,
    client_random: Vec<u8>,
    session_id: Vec<u8>,
    compression_methods: Vec<u8>,
    cipher_suites: Vec<u16>,
    extensions: Vec<u16>,
    extension_payloads: Vec<(u16, Vec<u8>)>,
    sni: Option<String>,
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
    let record_version = cursor.u16()?;
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
    let compression_methods = parse_u8_vector(&mut cursor)?;

    let extensions_len = cursor.u16()? as usize;
    let extensions_end = cursor.pos + extensions_len;
    if extensions_end > handshake_end {
        return Err("extensions overrun handshake body".to_string());
    }

    let mut fields = ClientHelloFields {
        wire_len: record.len(),
        record_version,
        record_len,
        handshake_len,
        legacy_version,
        client_random,
        session_id,
        compression_methods,
        cipher_suites,
        ..ClientHelloFields::default()
    };

    while cursor.pos < extensions_end {
        let ext_type = cursor.u16()?;
        let ext_len = cursor.u16()? as usize;
        let ext_data = cursor.bytes(ext_len)?;
        fields.extensions.push(ext_type);
        fields
            .extension_payloads
            .push((ext_type, ext_data.to_vec()));
        match ext_type {
            EXT_SNI => {
                fields.sni = Some(parse_sni(ext_data)?);
            }
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

fn assert_safari_extension_payloads(fields: &ClientHelloFields, host: &str) {
    assert_eq!(
        extension_payload(fields, EXT_EXTENDED_MASTER_SECRET),
        Some(&[][..]),
        "{host}: extended_master_secret should be empty"
    );
    assert_eq!(
        extension_payload(fields, EXT_RENEGOTIATION_INFO),
        Some(&[0][..]),
        "{host}: renegotiation_info should be a zero-length renegotiated_connection vector"
    );
    assert_eq!(
        extension_payload(fields, EXT_EC_POINT_FORMATS),
        Some(&[1, 0][..]),
        "{host}: ec_point_formats payload changed"
    );
    assert_eq!(
        extension_payload(fields, EXT_ALPN),
        Some(&[0, 12, 2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'][..]),
        "{host}: ALPN payload changed"
    );
    assert_eq!(
        extension_payload(fields, EXT_STATUS_REQUEST),
        Some(&[1, 0, 0, 0, 0][..]),
        "{host}: status_request payload changed"
    );
    assert_eq!(
        extension_payload(fields, EXT_SCT),
        Some(&[][..]),
        "{host}: signed_certificate_timestamp extension should be empty"
    );
    assert_eq!(
        extension_payload(fields, EXT_PSK_KEY_EXCHANGE_MODES),
        Some(&[1, 1][..]),
        "{host}: psk_key_exchange_modes payload changed"
    );
    assert_eq!(
        extension_payload(fields, EXT_COMPRESS_CERTIFICATE),
        Some(&[2, 0, 1][..]),
        "{host}: compress_certificate should advertise zlib only"
    );
}

fn extension_payload(fields: &ClientHelloFields, ext_type: u16) -> Option<&[u8]> {
    fields
        .extension_payloads
        .iter()
        .find(|(candidate, _)| *candidate == ext_type)
        .map(|(_, payload)| payload.as_slice())
}

fn key_share_lengths(fields: &ClientHelloFields) -> Vec<(u16, usize)> {
    fields
        .key_shares
        .iter()
        .map(|share| (share.group, share.len))
        .collect()
}

fn parse_sni(data: &[u8]) -> Result<String, String> {
    let mut cursor = Cursor::new(data);
    let list_len = cursor.u16()? as usize;
    let list = cursor.bytes(list_len)?;
    let mut names = Cursor::new(list);
    let name_type = names.u8()?;
    if name_type != 0 {
        return Err(format!("unsupported SNI name type {name_type}"));
    }
    let name_len = names.u16()? as usize;
    let name = names.bytes(name_len)?;
    std::str::from_utf8(name)
        .map(str::to_owned)
        .map_err(|err| err.to_string())
}

fn normalize_dynamic_client_hello_bytes(record: &[u8]) -> Result<Vec<u8>, String> {
    const NORMALIZED_GREASE: u16 = 0x0a0a;

    let mut out = record.to_vec();
    let mut pos = 0;
    let content_type = read_u8(&out, &mut pos)?;
    if content_type != 0x16 {
        return Err(format!("not a TLS handshake record: 0x{content_type:02x}"));
    }
    pos += 2; // record-layer compatibility version
    let record_len = read_u16(&out, &mut pos)? as usize;
    if pos + record_len != out.len() {
        return Err("TLS record length does not cover the whole record".to_string());
    }

    let handshake_type = read_u8(&out, &mut pos)?;
    if handshake_type != 0x01 {
        return Err(format!(
            "not a ClientHello handshake: 0x{handshake_type:02x}"
        ));
    }
    let handshake_len = read_u24(&out, &mut pos)? as usize;
    let handshake_end = pos + handshake_len;
    if handshake_end > out.len() {
        return Err("ClientHello handshake length overruns record".to_string());
    }

    pos += 2; // legacy_version
    fill_range(&mut out, pos, 32, 0x52)?;
    pos += 32;
    let session_id_len = read_u8(&out, &mut pos)? as usize;
    fill_range(&mut out, pos, session_id_len, 0x53)?;
    pos += session_id_len;

    let cipher_len = read_u16(&out, &mut pos)? as usize;
    normalize_grease_u16s(&mut out, pos, pos + cipher_len, NORMALIZED_GREASE)?;
    pos += cipher_len;

    let compression_len = read_u8(&out, &mut pos)? as usize;
    pos += compression_len;

    let extensions_len = read_u16(&out, &mut pos)? as usize;
    let extensions_end = pos + extensions_len;
    if extensions_end > handshake_end {
        return Err("extensions overrun ClientHello".to_string());
    }

    while pos < extensions_end {
        let ext_type_pos = pos;
        let ext_type = read_u16(&out, &mut pos)?;
        let ext_len = read_u16(&out, &mut pos)? as usize;
        let ext_data_start = pos;
        let ext_data_end = pos + ext_len;
        if ext_data_end > extensions_end {
            return Err("extension length overruns ClientHello".to_string());
        }

        if is_grease(ext_type) {
            write_u16(&mut out, ext_type_pos, NORMALIZED_GREASE)?;
        }

        match ext_type {
            EXT_SUPPORTED_GROUPS => {
                let mut inner = ext_data_start;
                let groups_len = read_u16(&out, &mut inner)? as usize;
                normalize_grease_u16s(&mut out, inner, inner + groups_len, NORMALIZED_GREASE)?;
            }
            EXT_SUPPORTED_VERSIONS => {
                let mut inner = ext_data_start;
                let versions_len = read_u8(&out, &mut inner)? as usize;
                normalize_grease_u16s(&mut out, inner, inner + versions_len, NORMALIZED_GREASE)?;
            }
            EXT_KEY_SHARE => {
                normalize_key_share_extension(&mut out, ext_data_start, ext_data_end)?;
            }
            _ => {}
        }

        pos = ext_data_end;
    }

    Ok(out)
}

fn normalize_key_share_extension(out: &mut [u8], start: usize, end: usize) -> Result<(), String> {
    const NORMALIZED_GREASE: u16 = 0x0a0a;

    let mut pos = start;
    let shares_len = read_u16(out, &mut pos)? as usize;
    let shares_end = pos + shares_len;
    if shares_end != end {
        return Err("key_share vector length does not match extension length".to_string());
    }

    while pos < shares_end {
        let group_pos = pos;
        let group = read_u16(out, &mut pos)?;
        let share_len = read_u16(out, &mut pos)? as usize;
        let share_start = pos;
        let share_end = pos + share_len;
        if share_end > shares_end {
            return Err("key_share entry overruns extension".to_string());
        }

        if is_grease(group) {
            write_u16(out, group_pos, NORMALIZED_GREASE)?;
        } else if group == GROUP_X25519_MLKEM768 {
            fill_range(out, share_start, share_len, 0x4b)?;
        } else if group == GROUP_X25519 {
            fill_range(out, share_start, share_len, 0x58)?;
        }
        pos = share_end;
    }
    Ok(())
}

fn normalize_grease_u16s(
    out: &mut [u8],
    start: usize,
    end: usize,
    normalized: u16,
) -> Result<(), String> {
    if end > out.len() || (end - start) % 2 != 0 {
        return Err("invalid u16 vector range".to_string());
    }
    for pos in (start..end).step_by(2) {
        let value = u16::from_be_bytes([out[pos], out[pos + 1]]);
        if is_grease(value) {
            write_u16(out, pos, normalized)?;
        }
    }
    Ok(())
}

fn fill_range(out: &mut [u8], start: usize, len: usize, value: u8) -> Result<(), String> {
    let end = start + len;
    if end > out.len() {
        return Err("range overruns record".to_string());
    }
    out[start..end].fill(value);
    Ok(())
}

fn read_u8(input: &[u8], pos: &mut usize) -> Result<u8, String> {
    if *pos >= input.len() {
        return Err("cursor: out of bytes".to_string());
    }
    let value = input[*pos];
    *pos += 1;
    Ok(value)
}

fn read_u16(input: &[u8], pos: &mut usize) -> Result<u16, String> {
    if *pos + 2 > input.len() {
        return Err("cursor: out of bytes".to_string());
    }
    let value = u16::from_be_bytes([input[*pos], input[*pos + 1]]);
    *pos += 2;
    Ok(value)
}

fn read_u24(input: &[u8], pos: &mut usize) -> Result<u32, String> {
    if *pos + 3 > input.len() {
        return Err("cursor: out of bytes".to_string());
    }
    let value =
        ((input[*pos] as u32) << 16) | ((input[*pos + 1] as u32) << 8) | input[*pos + 2] as u32;
    *pos += 3;
    Ok(value)
}

fn write_u16(out: &mut [u8], pos: usize, value: u16) -> Result<(), String> {
    if pos + 2 > out.len() {
        return Err("cursor: out of bytes".to_string());
    }
    out[pos..pos + 2].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn first_diff(expected: &[u8], actual: &[u8]) -> String {
    let Some(index) = expected
        .iter()
        .zip(actual.iter())
        .position(|(left, right)| left != right)
    else {
        return format!(
            "length differs: expected {} bytes, actual {} bytes",
            expected.len(),
            actual.len()
        );
    };
    let start = index.saturating_sub(8);
    let end = (index + 9).min(expected.len()).min(actual.len());
    format!(
        "first diff at byte {index}: expected 0x{:02x}, actual 0x{:02x}; expected[{}..{}]={}; actual[{}..{}]={}",
        expected[index],
        actual[index],
        start,
        end,
        hex_window(&expected[start..end]),
        start,
        end,
        hex_window(&actual[start..end])
    )
}

fn hex_window(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
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
