//! Safari-26 H3 ClientHello assembly for the hand-written QUIC TLS client.
//!
//! Emits the handshake message (`type 0x01 || u24 len || body`) carried in the
//! Initial CRYPTO stream — NOT a TLS record (QUIC has no record layer). The wire
//! shape (cipher list, extension order, GREASE bookends, the kept `0x0805`
//! signature-algorithm duplicate, the X25519MLKEM768 hybrid key_share) comes from
//! the shared [`crate::tls::safari_shape`] byte builders, so this path and the TCP
//! camouflage path stay byte-identical by construction.
//!
//! Cold-start only: no `pre_shared_key` / `early_data` (resumption disabled), so
//! the trailing GREASE is the last extension. The `legacy_session_id` is EMPTY —
//! QUIC has no middlebox-compat CCS mode, so (like real browsers and the rustls
//! baseline this replaces) the QUIC ClientHello carries a zero-length session id,
//! unlike the TCP path's 32-byte id.

use crate::tls::safari_shape::{
    key_share_extension, safari_quic_cipher_suites, signature_algorithms_extension,
    supported_groups_extension, supported_versions_extension_h3, GreaseSet,
    MLKEM768_PUBLIC_KEY_LEN,
};

use super::schedule::psk_binder;
use super::suite::CipherSuite;
use super::QuicTlsError;

const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS12_LEGACY_VERSION: u16 = 0x0303;

// Extension codepoints, in Safari-26 H3 wire order.
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x0012;
const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;
/// `early_data` (RFC 8446 §4.2.10): empty in a 0-RTT ClientHello. Sent right after
/// `psk_key_exchange_modes`, matching the Safari 26.4 0-RTT wire order.
const EXT_EARLY_DATA: u16 = 0x002a;
/// `pre_shared_key` (RFC 8446 §4.2.11): MUST be the last extension, after the
/// trailing GREASE, carrying the ticket identity + the PSK binder.
const EXT_PRE_SHARED_KEY: u16 = 0x0029;

/// The resumption inputs that turn a cold-start ClientHello into a 0-RTT one: the
/// opaque ticket (sent as the PSK identity), its `obfuscated_ticket_age`, and the
/// binder finished key + suite used to compute the PSK binder (RFC 8446 §4.2.11.2).
pub(crate) struct ResumptionParams<'a> {
    pub ticket: &'a [u8],
    pub obfuscated_ticket_age: u32,
    pub binder_finished_key: &'a [u8],
    pub suite: CipherSuite,
}

/// Everything the ClientHello builder needs from the live handshake.
pub(crate) struct ClientHelloParams<'a> {
    pub server_name: &'a str,
    /// Offered ALPN protocols (`[b"h3"]` for the QUIC carrier).
    pub alpn_protocols: &'a [Vec<u8>],
    /// The client's X25519 public key (the classical half of the hybrid + the
    /// standalone X25519 key_share).
    pub x25519_public: &'a [u8; 32],
    /// The client's ML-KEM-768 encapsulation (public) key (1184 bytes).
    pub mlkem768_public: &'a [u8],
    /// The opaque QUIC transport-parameters blob for extension `0x39`.
    pub transport_params: &'a [u8],
    /// Per-ClientHello GREASE selection.
    pub grease: GreaseSet,
    /// The 32-byte client random.
    pub random: &'a [u8; 32],
    /// `Some` for a 0-RTT resumption ClientHello (adds `early_data` + a trailing
    /// `pre_shared_key`); `None` for a cold-start ClientHello.
    pub resumption: Option<ResumptionParams<'a>>,
}

/// Build the Safari-26 H3 ClientHello handshake message.
pub(crate) fn build_client_hello(params: &ClientHelloParams) -> Result<Vec<u8>, QuicTlsError> {
    if params.mlkem768_public.len() != MLKEM768_PUBLIC_KEY_LEN {
        return Err(QuicTlsError::Crypto("ML-KEM-768 public key length".into()));
    }

    let mut body = Vec::with_capacity(1536);
    body.extend_from_slice(&TLS12_LEGACY_VERSION.to_be_bytes());
    body.extend_from_slice(params.random);
    // legacy_session_id: EMPTY in QUIC (no CCS middlebox-compat mode).
    body.push(0);

    // cipher_suites: GREASE + the 3 TLS 1.3 AEADs ONLY (QUIC prunes to 1.3, NOT
    // the TCP path's 21-suite 1.2+1.3 list) + null compression.
    push_u16_prefixed_u16s(&mut body, &safari_quic_cipher_suites(params.grease));
    body.push(1);
    body.push(0);

    // extensions, in the fixed Safari-26 H3 order with GREASE bookends.
    let mut ext = Vec::with_capacity(1410);
    push_ext(&mut ext, params.grease.extension, &[])?;
    push_ext(
        &mut ext,
        EXT_SERVER_NAME,
        &server_name_extension(params.server_name)?,
    )?;
    push_ext(
        &mut ext,
        EXT_SUPPORTED_GROUPS,
        &supported_groups_extension(params.grease.group),
    )?;
    push_ext(&mut ext, EXT_ALPN, &alpn_extension(params.alpn_protocols)?)?;
    push_ext(&mut ext, EXT_STATUS_REQUEST, &[1, 0, 0, 0, 0])?;
    push_ext(
        &mut ext,
        EXT_SIGNATURE_ALGORITHMS,
        &signature_algorithms_extension(),
    )?;
    push_ext(&mut ext, EXT_SIGNED_CERTIFICATE_TIMESTAMP, &[])?;
    push_ext(
        &mut ext,
        EXT_KEY_SHARE,
        &key_share_extension(
            params.grease.group,
            params.mlkem768_public,
            params.x25519_public,
        ),
    )?;
    push_ext(&mut ext, EXT_PSK_KEY_EXCHANGE_MODES, &[1, 1])?;
    // 0-RTT resumption: `early_data` sits right after psk_key_exchange_modes and
    // before supported_versions (the Safari 26.4 0-RTT wire order); empty body.
    if params.resumption.is_some() {
        push_ext(&mut ext, EXT_EARLY_DATA, &[])?;
    }
    push_ext(
        &mut ext,
        EXT_SUPPORTED_VERSIONS,
        &supported_versions_extension_h3(params.grease.version),
    )?;
    push_ext(
        &mut ext,
        EXT_QUIC_TRANSPORT_PARAMETERS,
        params.transport_params,
    )?;
    push_ext(&mut ext, EXT_COMPRESS_CERTIFICATE, &[2, 0, 1])?;
    push_ext(&mut ext, params.grease.final_extension, &[0])?;
    // `pre_shared_key` MUST be the LAST extension (RFC 8446 §4.2.11) — after the
    // trailing GREASE — with a zero-filled binder placeholder patched in below.
    if let Some(r) = params.resumption.as_ref() {
        push_ext(
            &mut ext,
            EXT_PRE_SHARED_KEY,
            &pre_shared_key_placeholder(r)?,
        )?;
    }

    push_u16_vec(&mut body, &ext)?;

    // Wrap as a handshake message (type + u24 length).
    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(HANDSHAKE_CLIENT_HELLO);
    push_u24(&mut msg, body.len())?;
    msg.extend_from_slice(&body);

    // Two-pass binder (RFC 8446 §4.2.11.2): HMAC over the message truncated to
    // exclude the binders list, then patch the binder into the placeholder. All
    // length fields above are already set as if the binder were present.
    if let Some(r) = params.resumption.as_ref() {
        let binder_len = r.suite.hash_len();
        // binders field on the wire = binders_len(2) + binder_len(1) + binder bytes.
        let binders_field_len = 2 + 1 + binder_len;
        let truncated = &msg[..msg.len() - binders_field_len];
        let transcript_hash = r.suite.digest(truncated);
        let binder = psk_binder(r.suite, r.binder_finished_key, &transcript_hash)?;
        let start = msg.len() - binder_len;
        msg[start..].copy_from_slice(&binder);
    }
    Ok(msg)
}

/// `server_name` extension body: a single host_name SNI entry.
fn server_name_extension(sni: &str) -> Result<Vec<u8>, QuicTlsError> {
    let name = sni.as_bytes();
    let name_len = u16::try_from(name.len())
        .map_err(|_| QuicTlsError::InvalidServerName("SNI too long".into()))?;
    let list_len = name_len
        .checked_add(3)
        .ok_or_else(|| QuicTlsError::InvalidServerName("SNI too long".into()))?;
    let mut out = Vec::with_capacity(2 + list_len as usize);
    out.extend_from_slice(&list_len.to_be_bytes());
    out.push(0); // host_name
    out.extend_from_slice(&name_len.to_be_bytes());
    out.extend_from_slice(name);
    Ok(out)
}

/// ALPN extension body from the offered protocol list.
fn alpn_extension(protocols: &[Vec<u8>]) -> Result<Vec<u8>, QuicTlsError> {
    let mut list = Vec::new();
    for proto in protocols {
        let len = u8::try_from(proto.len())
            .map_err(|_| QuicTlsError::Crypto("ALPN protocol too long".into()))?;
        list.push(len);
        list.extend_from_slice(proto);
    }
    let mut out = Vec::with_capacity(2 + list.len());
    push_u16_vec(&mut out, &list)?;
    Ok(out)
}

/// `pre_shared_key` extension body with a single identity and a zero-filled binder
/// placeholder (RFC 8446 §4.2.11): `identities<...>` (one `(ticket,
/// obfuscated_ticket_age)`) then `binders<...>` (one hash-length entry). The binder
/// bytes — the trailing `hash_len` bytes of the whole ClientHello — are patched by
/// the caller after the truncated-transcript hash.
fn pre_shared_key_placeholder(r: &ResumptionParams) -> Result<Vec<u8>, QuicTlsError> {
    let binder_len = r.suite.hash_len();
    let mut identities = Vec::with_capacity(2 + r.ticket.len() + 4);
    push_u16_vec(&mut identities, r.ticket)?; // identity_len(2) || ticket
    identities.extend_from_slice(&r.obfuscated_ticket_age.to_be_bytes());
    let mut binders = Vec::with_capacity(1 + binder_len);
    binders.push(binder_len as u8); // PskBinderEntry length prefix
    binders.resize(1 + binder_len, 0); // zero placeholder
    let mut out = Vec::with_capacity(2 + identities.len() + 2 + binders.len());
    push_u16_vec(&mut out, &identities)?; // identities_len(2) || identities
    push_u16_vec(&mut out, &binders)?; // binders_len(2) || binders
    Ok(out)
}

fn push_ext(out: &mut Vec<u8>, ext_type: u16, body: &[u8]) -> Result<(), QuicTlsError> {
    out.extend_from_slice(&ext_type.to_be_bytes());
    // Extension bodies are small in practice, but a pathological SNI could push
    // the server_name body past u16::MAX; error rather than emit a truncated
    // (malformed) length via an unchecked `as u16` cast.
    push_u16_vec(out, body)
}

fn push_u16_prefixed_u16s(out: &mut Vec<u8>, values: &[u16]) {
    out.extend_from_slice(&((values.len() * 2) as u16).to_be_bytes());
    for v in values {
        out.extend_from_slice(&v.to_be_bytes());
    }
}

fn push_u16_vec(out: &mut Vec<u8>, data: &[u8]) -> Result<(), QuicTlsError> {
    let len = u16::try_from(data.len())
        .map_err(|_| QuicTlsError::Crypto("TLS u16 vector too large".into()))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

fn push_u24(out: &mut Vec<u8>, len: usize) -> Result<(), QuicTlsError> {
    if len > 0x00ff_ffff {
        return Err(QuicTlsError::Crypto("handshake message too large".into()));
    }
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_grease(value: u16) -> bool {
        value & 0x0f0f == 0x0a0a && (value >> 8) == (value & 0xff)
    }

    fn read_u16(b: &[u8], pos: usize) -> u16 {
        u16::from_be_bytes([b[pos], b[pos + 1]])
    }

    /// (cipher_suites, session_id_len, ordered (ext_type, body) pairs).
    type ParsedClientHello = (Vec<u16>, usize, Vec<(u16, Vec<u8>)>);

    /// Parse the ClientHello handshake message into its structural fields.
    fn parse(msg: &[u8]) -> ParsedClientHello {
        assert_eq!(msg[0], HANDSHAKE_CLIENT_HELLO, "ClientHello type");
        let body_len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | (msg[3] as usize);
        let body = &msg[4..4 + body_len];
        let mut p = 0;
        assert_eq!(read_u16(body, p), TLS12_LEGACY_VERSION, "legacy_version");
        p += 2 + 32; // version + random
        let sid_len = body[p] as usize;
        p += 1 + sid_len;
        let cs_len = read_u16(body, p) as usize;
        p += 2;
        let ciphers: Vec<u16> = body[p..p + cs_len]
            .chunks_exact(2)
            .map(|c| read_u16(c, 0))
            .collect();
        p += cs_len;
        let comp_len = body[p] as usize;
        p += 1 + comp_len;
        let ext_total = read_u16(body, p) as usize;
        p += 2;
        let exts = &body[p..p + ext_total];
        let mut order = Vec::new();
        let mut q = 0;
        while q + 4 <= exts.len() {
            let typ = read_u16(exts, q);
            let len = read_u16(exts, q + 2) as usize;
            q += 4;
            order.push((typ, exts[q..q + len].to_vec()));
            q += len;
        }
        (ciphers, sid_len, order)
    }

    fn sample_client_hello() -> Vec<u8> {
        let grease = GreaseSet::from_seed([1, 2, 3, 4, 5, 6]);
        let x25519 = [0x11_u8; 32];
        let mlkem = vec![0x22_u8; MLKEM768_PUBLIC_KEY_LEN];
        let tp = vec![0x04, 0x04, 0x80, 0x10, 0x00, 0x00];
        let random = [0x33_u8; 32];
        build_client_hello(&ClientHelloParams {
            server_name: "example.com",
            alpn_protocols: &[b"h3".to_vec()],
            x25519_public: &x25519,
            mlkem768_public: &mlkem,
            transport_params: &tp,
            grease,
            random: &random,
            resumption: None,
        })
        .unwrap()
    }

    #[test]
    fn clienthello_matches_safari26_h3_structure() {
        let msg = sample_client_hello();
        let (ciphers, sid_len, order) = parse(&msg);

        // QUIC ClientHello carries an EMPTY legacy_session_id (no CCS compat).
        assert_eq!(sid_len, 0, "QUIC legacy_session_id must be empty");

        // 4 cipher suites: GREASE + the 3 TLS 1.3 AEADs ONLY. QUIC pins TLS 1.3
        // so it prunes to 1.3 — unlike the TCP path's 21-suite 1.2+1.3 list.
        assert_eq!(ciphers.len(), 4);
        assert!(is_grease(ciphers[0]));
        assert_eq!(&ciphers[1..4], &[0x1302, 0x1303, 0x1301]);
        assert!(
            !ciphers.contains(&0x000a),
            "no TLS 1.2 legacy suite (QUIC is 1.3-only)"
        );

        let types: Vec<u16> = order.iter().map(|(t, _)| *t).collect();
        // Bookend GREASE: first len 0, last len 1, distinct.
        assert!(is_grease(types[0]));
        assert!(is_grease(*types.last().unwrap()));
        assert_ne!(types[0], *types.last().unwrap());
        assert!(order[0].1.is_empty(), "leading GREASE len 0");
        assert_eq!(order.last().unwrap().1, vec![0x00], "trailing GREASE len 1");

        // Static Safari-26 H3 table between the GREASE bookends.
        assert_eq!(
            &types[1..types.len() - 1],
            &[
                0x0000, // server_name
                0x000a, // supported_groups
                0x0010, // ALPN
                0x0005, // status_request
                0x000d, // signature_algorithms
                0x0012, // SCT
                0x0033, // key_share
                0x002d, // psk_key_exchange_modes
                0x002b, // supported_versions
                0x0039, // quic_transport_parameters
                0x001b, // compress_certificate
            ]
        );

        // QUIC drops EMS / renegotiation_info; cold-start drops PSK / early_data.
        for absent in [0x0017, 0xff01, 0x0029, 0x002a] {
            assert!(
                !types.contains(&absent),
                "extension {absent:#06x} must be absent"
            );
        }

        // supported_versions = GREASE + 0x0304 only (no TLS 1.2).
        let sv = &order.iter().find(|(t, _)| *t == 0x002b).unwrap().1;
        let sv_versions: Vec<u16> = sv[1..].chunks_exact(2).map(|c| read_u16(c, 0)).collect();
        assert_eq!(sv_versions.len(), 2);
        assert!(is_grease(sv_versions[0]));
        assert_eq!(sv_versions[1], 0x0304);
        assert!(!sv_versions.contains(&0x0303));

        // ALPN carries h3; transport_parameters carries our blob.
        let alpn = &order.iter().find(|(t, _)| *t == 0x0010).unwrap().1;
        assert!(alpn.windows(2).any(|w| w == b"h3"));
        let tp = &order.iter().find(|(t, _)| *t == 0x0039).unwrap().1;
        assert_eq!(tp, &vec![0x04, 0x04, 0x80, 0x10, 0x00, 0x00]);

        // signature_algorithms keeps Apple's duplicated 0x0805.
        let sigs = &order.iter().find(|(t, _)| *t == 0x000d).unwrap().1;
        let schemes: Vec<u16> = sigs[2..].chunks_exact(2).map(|c| read_u16(c, 0)).collect();
        assert_eq!(schemes.iter().filter(|&&s| s == 0x0805).count(), 2);
    }

    #[test]
    fn resumption_clienthello_adds_early_data_and_trailing_psk_with_valid_binder() {
        use crate::tls::quic::schedule::{binder_finished_key, early_secret_from_psk, psk_binder};

        let grease = GreaseSet::from_seed([9, 8, 7, 6, 5, 4]);
        let x25519 = [0x11_u8; 32];
        let mlkem = vec![0x22_u8; MLKEM768_PUBLIC_KEY_LEN];
        let tp = vec![0x04, 0x04, 0x80, 0x10, 0x00, 0x00];
        let random = [0x44_u8; 32];
        let suite = CipherSuite::Aes128GcmSha256;
        let psk = [0x5a_u8; 32];
        let early = early_secret_from_psk(suite, &psk);
        let fk = binder_finished_key(suite, &early).unwrap();
        let ticket = vec![0xab_u8; 160];

        let msg = build_client_hello(&ClientHelloParams {
            server_name: "example.com",
            alpn_protocols: &[b"h3".to_vec()],
            x25519_public: &x25519,
            mlkem768_public: &mlkem,
            transport_params: &tp,
            grease,
            random: &random,
            resumption: Some(ResumptionParams {
                ticket: &ticket,
                obfuscated_ticket_age: 0x0102_0304,
                binder_finished_key: &fk,
                suite,
            }),
        })
        .unwrap();

        let (ciphers, sid_len, order) = parse(&msg);
        assert_eq!(sid_len, 0);
        assert_eq!(ciphers.len(), 4);
        let types: Vec<u16> = order.iter().map(|(t, _)| *t).collect();
        // 15 extensions = the 13 cold-start slots + early_data + pre_shared_key.
        assert_eq!(types.len(), 15);
        // early_data (0x2a) immediately follows psk_key_exchange_modes (0x2d).
        let psk_modes_idx = types.iter().position(|&t| t == 0x002d).unwrap();
        assert_eq!(
            types[psk_modes_idx + 1],
            0x002a,
            "early_data follows psk_key_exchange_modes"
        );
        // pre_shared_key (0x29) is the absolute last extension (RFC 8446 §4.2.11).
        assert_eq!(*types.last().unwrap(), 0x0029, "pre_shared_key is last");
        // early_data body is empty in a ClientHello.
        assert!(order
            .iter()
            .find(|(t, _)| *t == 0x002a)
            .unwrap()
            .1
            .is_empty());

        // The embedded binder must verify: recompute over the message truncated
        // before the binders list and compare to the trailing binder bytes.
        let binder_len = suite.hash_len();
        let truncated = &msg[..msg.len() - (2 + 1 + binder_len)];
        let expected = psk_binder(suite, &fk, &suite.digest(truncated)).unwrap();
        assert_eq!(
            &msg[msg.len() - binder_len..],
            &expected[..],
            "embedded PSK binder verifies"
        );

        // The pre_shared_key extension carries our ticket + obfuscated_ticket_age.
        let psk_ext = &order.iter().find(|(t, _)| *t == 0x0029).unwrap().1;
        let id_len = read_u16(psk_ext, 2) as usize;
        assert_eq!(id_len, ticket.len(), "identity is the ticket");
        assert_eq!(&psk_ext[4..4 + id_len], &ticket[..]);
        let age = u32::from_be_bytes([
            psk_ext[4 + id_len],
            psk_ext[5 + id_len],
            psk_ext[6 + id_len],
            psk_ext[7 + id_len],
        ]);
        assert_eq!(age, 0x0102_0304);
    }
}
