//! Regression baseline locking the Safari 26.4 QUIC (H3) ClientHello structure
//! against a real public-internet capture (server-side keylog decrypt, 2026-06).
//!
//! The fixture `tests/fixtures/safari26_h3_clienthello.bin` is the reassembled
//! ClientHello handshake message from a real Safari 26.4 H3 connection, REDACTED
//! so it carries no per-machine or identifying data: the per-connection
//! `client_random` and the `key_share` ephemeral public keys are zeroed, and the
//! SNI host_name is replaced with `example.com`. Everything that is a stable
//! Safari fingerprint — cipher list, extension order, supported groups, key_share
//! group set + lengths, QUIC transport parameters — is kept verbatim.
//!
//! This catches drift in any of those, e.g. accidentally reusing the TCP path's
//! 21-suite (1.2+1.3) cipher list over QUIC, or re-adding `ec_point_formats`.

const CH: &[u8] = include_bytes!("fixtures/safari26_h3_clienthello.bin");

fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0x00ff)
}

fn u16be(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

/// QUIC/RFC 9000 variable-length integer.
fn varint(b: &[u8], i: usize) -> (u64, usize) {
    let len = 1usize << (b[i] >> 6);
    let mut v = (b[i] & 0x3f) as u64;
    for k in 1..len {
        v = (v << 8) | b[i + k] as u64;
    }
    (v, i + len)
}

struct ParsedCh {
    legacy_version: u16,
    session_id_len: usize,
    ciphers: Vec<u16>,
    ext_types: Vec<u16>,
    key_share: Vec<(u16, usize)>,
    transport_params: Vec<(u64, Vec<u8>)>,
}

fn parse() -> ParsedCh {
    assert_eq!(CH[0], 0x01, "handshake type must be ClientHello");
    let declared = ((CH[1] as usize) << 16) | ((CH[2] as usize) << 8) | CH[3] as usize;
    assert_eq!(
        declared + 4,
        CH.len(),
        "declared handshake length matches the body"
    );

    let mut p = 4;
    let legacy_version = u16be(CH, p);
    p += 2 + 32; // legacy_version + random
    let session_id_len = CH[p] as usize;
    p += 1 + session_id_len;

    let cs_len = u16be(CH, p) as usize;
    p += 2;
    let ciphers = (0..cs_len / 2).map(|i| u16be(CH, p + i * 2)).collect();
    p += cs_len;

    let comp_len = CH[p] as usize;
    p += 1 + comp_len;

    let ext_total = u16be(CH, p) as usize;
    p += 2;
    let end = p + ext_total;
    let mut ext_types = Vec::new();
    let mut key_share = Vec::new();
    let mut transport_params = Vec::new();
    while p < end {
        let et = u16be(CH, p);
        let el = u16be(CH, p + 2) as usize;
        let data = &CH[p + 4..p + 4 + el];
        ext_types.push(et);
        if et == 0x0033 {
            // key_share: client_shares_len(2) then [group(2) ke_len(2) ke]*
            let mut q = 2;
            while q + 4 <= data.len() {
                let group = u16be(data, q);
                let ke_len = u16be(data, q + 2) as usize;
                key_share.push((group, ke_len));
                q += 4 + ke_len;
            }
        }
        if et == 0x0039 {
            // quic_transport_parameters: [id(varint) len(varint) value]*
            let mut q = 0;
            while q < data.len() {
                let (id, n) = varint(data, q);
                let (vlen, n2) = varint(data, n);
                let val = data[n2..n2 + vlen as usize].to_vec();
                transport_params.push((id, val));
                q = n2 + vlen as usize;
            }
        }
        p += 4 + el;
    }

    ParsedCh {
        legacy_version,
        session_id_len,
        ciphers,
        ext_types,
        key_share,
        transport_params,
    }
}

#[test]
fn safari_h3_clienthello_ciphers_pruned_to_tls13() {
    let ch = parse();
    // QUIC pins TLS 1.3, so the cipher_suites prune to GREASE + exactly the 3
    // 1.3 AEAD suites — NOT the TCP/H2 path's 21-suite 1.2+1.3 list.
    assert_eq!(ch.ciphers.len(), 4, "got {:?}", ch.ciphers);
    assert!(is_grease(ch.ciphers[0]), "cipher slot 0 must be GREASE");
    assert_eq!(&ch.ciphers[1..4], &[0x1302, 0x1303, 0x1301]);
    assert!(
        !ch.ciphers.contains(&0x000a),
        "no TLS 1.2 legacy suite (QUIC is 1.3-only)"
    );
}

#[test]
fn safari_h3_clienthello_extension_order_drops_ec_point() {
    let ch = parse();
    assert_eq!(ch.ext_types.len(), 13, "got {:?}", ch.ext_types);
    assert!(
        is_grease(ch.ext_types[0]) && is_grease(*ch.ext_types.last().unwrap()),
        "GREASE bookends"
    );
    let middle: Vec<u16> = ch.ext_types[1..ch.ext_types.len() - 1].to_vec();
    assert_eq!(
        middle,
        vec![
            0x0000, // server_name
            0x000a, // supported_groups
            0x0010, // ALPN
            0x0005, // status_request
            0x000d, // signature_algorithms
            0x0012, // signed_certificate_timestamp
            0x0033, // key_share
            0x002d, // psk_key_exchange_modes
            0x002b, // supported_versions
            0x0039, // quic_transport_parameters
            0x001b, // compress_certificate
        ],
    );
    // Pure-1.3 QUIC path drops these; cold-start drops PSK/early_data.
    for absent in [0x000b, 0x0017, 0xff01, 0x0029, 0x002a] {
        assert!(
            !ch.ext_types.contains(&absent),
            "extension {absent:#06x} must be absent"
        );
    }
}

#[test]
fn safari_h3_clienthello_key_share_two_real_shares() {
    let ch = parse();
    // GREASE throwaway (len 1) + X25519MLKEM768 (1216) + x25519 (32).
    assert_eq!(ch.key_share.len(), 3, "got {:?}", ch.key_share);
    assert!(
        is_grease(ch.key_share[0].0),
        "first key_share entry is GREASE"
    );
    assert_eq!(ch.key_share[1], (0x11ec, 1216), "X25519MLKEM768 hybrid");
    assert_eq!(ch.key_share[2], (0x001d, 32), "standalone x25519");
}

#[test]
fn safari_h3_clienthello_session_id_empty_and_tls13() {
    let ch = parse();
    assert_eq!(ch.legacy_version, 0x0303);
    assert_eq!(
        ch.session_id_len, 0,
        "QUIC ClientHello carries an empty legacy_session_id (no CCS compat)"
    );
}

#[test]
fn safari_h3_clienthello_transport_params_match_safari() {
    let ch = parse();
    let raw = |id: u64| {
        ch.transport_params
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, v)| v.clone())
    };
    let val = |id: u64| varint(&raw(id).expect("param present"), 0).0;

    assert_eq!(val(0x04), 16 * 1024 * 1024, "initial_max_data = 16 MiB");
    assert_eq!(val(0x05), 2 * 1024 * 1024, "stream_data_bidi_local = 2 MiB");
    assert_eq!(
        val(0x06),
        2 * 1024 * 1024,
        "stream_data_bidi_remote = 2 MiB"
    );
    assert_eq!(val(0x07), 2 * 1024 * 1024, "stream_data_uni = 2 MiB");
    assert_eq!(val(0x09), 8, "initial_max_streams_uni = 8");
    assert_eq!(val(0x0e), 64, "active_connection_id_limit = 64");
    assert_eq!(
        raw(0x0f)
            .expect("initial_source_connection_id present")
            .len(),
        0,
        "zero-length source connection id"
    );
    // Safari/CFNetwork omits these from the wire entirely.
    for omitted in [0x01u64, 0x03, 0x08, 0x20] {
        assert!(
            raw(omitted).is_none(),
            "transport parameter {omitted:#x} must be omitted"
        );
    }
}
