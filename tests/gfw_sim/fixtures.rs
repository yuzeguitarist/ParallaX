//! Test-only wire fixtures for the GFW simulator.
//!
//! These helpers deliberately live under `tests/` so the production TLS stack
//! stays focused on the real Safari 26 camouflage path.

use rand::{rngs::StdRng, RngCore, SeedableRng};

const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const TLS12_LEGACY_VERSION: u16 = 0x0303;
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;
const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca9;
const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca8;
const GROUP_X25519: u16 = 0x001d;
const GROUP_SECP256R1: u16 = 0x0017;
const GROUP_SECP384R1: u16 = 0x0018;

pub fn synthetic_tls13_client_hello(sni: &str, seed: u64) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut client_random = [0_u8; 32];
    let mut x25519_key_share = [0_u8; 32];
    rng.fill_bytes(&mut client_random);
    rng.fill_bytes(&mut x25519_key_share);

    let mut body = Vec::with_capacity(512);
    body.extend_from_slice(&TLS12_LEGACY_VERSION.to_be_bytes());
    body.extend_from_slice(&client_random);
    body.push(32);
    body.extend_from_slice(&[0_u8; 32]);
    push_cipher_suites(&mut body);
    body.push(1);
    body.push(0);

    let mut extensions = Vec::with_capacity(256);
    push_sni(&mut extensions, sni.as_bytes());
    push_supported_groups(&mut extensions);
    push_signature_algorithms(&mut extensions);
    push_alpn(&mut extensions, &[b"h2".as_slice(), b"http/1.1".as_slice()]);
    push_supported_versions(&mut extensions);
    push_key_share(&mut extensions, &x25519_key_share);

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::with_capacity(4 + body.len());
    handshake.push(HANDSHAKE_CLIENT_HELLO);
    push_u24(&mut handshake, body.len() as u32);
    handshake.extend_from_slice(&body);

    let mut record = Vec::with_capacity(5 + handshake.len());
    record.push(parallax::tls::record::TLS_CONTENT_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn push_cipher_suites(out: &mut Vec<u8>) {
    let suites = [
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];
    out.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for suite in suites {
        out.extend_from_slice(&suite.to_be_bytes());
    }
}

fn push_sni(out: &mut Vec<u8>, sni: &[u8]) {
    extension_header(out, EXT_SERVER_NAME, 5 + sni.len());
    out.extend_from_slice(&((1 + 2 + sni.len()) as u16).to_be_bytes());
    out.push(0);
    out.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    out.extend_from_slice(sni);
}

fn push_supported_groups(out: &mut Vec<u8>) {
    let groups = [GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1];
    extension_header(out, EXT_SUPPORTED_GROUPS, 2 + groups.len() * 2);
    out.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
    for group in groups {
        out.extend_from_slice(&group.to_be_bytes());
    }
}

fn push_signature_algorithms(out: &mut Vec<u8>) {
    let schemes = [
        0x0403_u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    extension_header(out, EXT_SIGNATURE_ALGORITHMS, 2 + schemes.len() * 2);
    out.extend_from_slice(&((schemes.len() * 2) as u16).to_be_bytes());
    for scheme in schemes {
        out.extend_from_slice(&scheme.to_be_bytes());
    }
}

fn push_alpn(out: &mut Vec<u8>, protocols: &[&[u8]]) {
    let list_len: usize = protocols.iter().map(|p| p.len() + 1).sum();
    extension_header(out, EXT_ALPN, 2 + list_len);
    out.extend_from_slice(&(list_len as u16).to_be_bytes());
    for protocol in protocols {
        out.push(protocol.len() as u8);
        out.extend_from_slice(protocol);
    }
}

fn push_supported_versions(out: &mut Vec<u8>) {
    extension(out, EXT_SUPPORTED_VERSIONS, &[2, 0x03, 0x04]);
}

fn push_key_share(out: &mut Vec<u8>, x25519_key_share: &[u8; 32]) {
    let share_len = 2 + 2 + x25519_key_share.len();
    extension_header(out, EXT_KEY_SHARE, 2 + share_len);
    out.extend_from_slice(&(share_len as u16).to_be_bytes());
    out.extend_from_slice(&GROUP_X25519.to_be_bytes());
    out.extend_from_slice(&(x25519_key_share.len() as u16).to_be_bytes());
    out.extend_from_slice(x25519_key_share);
}

fn extension(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    extension_header(out, ext_type, data.len());
    out.extend_from_slice(data);
}

fn extension_header(out: &mut Vec<u8>, ext_type: u16, data_len: usize) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(data_len as u16).to_be_bytes());
}

fn push_u24(out: &mut Vec<u8>, value: u32) {
    out.push(((value >> 16) & 0xff) as u8);
    out.push(((value >> 8) & 0xff) as u8);
    out.push((value & 0xff) as u8);
}
