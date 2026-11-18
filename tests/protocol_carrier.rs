//! Carrier codecs checked against literal RFC layouts and independent emitters.
//! Hello parsing here tests the extraction API, not the full TLS validator.
//! SOCKS fixtures use short in-memory reads/writes and never open a socket.

#[macro_use]
#[path = "support/property.rs"]
mod property;

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::task::{Context, Poll};

use parallax::client::socks::{accept_connect, SocksRequest};
use parallax::fingerprint::http2::{Http2Fingerprint, Http2FrameHeader, Http2Setting};
use parallax::fingerprint::http3::{self, Http3Error};
use parallax::tls::client_hello::parse_client_hello;
use parallax::tls::server_hello::parse_server_hello;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct ShortIo {
    input: Vec<u8>,
    position: usize,
    output: Vec<u8>,
    read_size: usize,
    write_size: usize,
}

impl AsyncRead for ShortIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let count = out
            .remaining()
            .min(self.read_size)
            .min(self.input.len() - self.position);
        out.put_slice(&self.input[self.position..self.position + count]);
        self.position += count;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ShortIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let count = input.len().min(self.write_size);
        self.output.extend_from_slice(&input[..count]);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// RFC 1928 slice oracle. This does not call the async production parser or its
// framing helpers. Failed parses need not consume the same prefix, but must
// return the same success/failure and method/success response bytes.
fn socks_oracle(input: &[u8]) -> (Option<(SocksRequest, usize)>, Vec<u8>) {
    let mut reply = Vec::new();
    let parsed = (|| {
        if *input.first()? != 5 {
            return None;
        }
        let count = usize::from(*input.get(1)?);
        if count == 0 {
            return None;
        }
        let methods = input.get(2..2 + count)?;
        if !methods.contains(&0) {
            reply.extend_from_slice(&[5, 255]);
            return None;
        }
        reply.extend_from_slice(&[5, 0]);
        let start = 2 + count;
        let request = input.get(start..)?;
        if request.get(..3)? != [5, 1, 0] {
            return None;
        }
        let (host, port_at) = match *request.get(3)? {
            1 => {
                let bytes: [u8; 4] = request.get(4..8)?.try_into().ok()?;
                (Ipv4Addr::from(bytes).to_string(), 8)
            }
            4 => {
                let bytes: [u8; 16] = request.get(4..20)?.try_into().ok()?;
                (Ipv6Addr::from(bytes).to_string(), 20)
            }
            3 => {
                let len = usize::from(*request.get(4)?);
                if len == 0 {
                    return None;
                }
                let host = std::str::from_utf8(request.get(5..5 + len)?)
                    .ok()?
                    .to_owned();
                (host, 5 + len)
            }
            _ => return None,
        };
        let port_bytes: [u8; 2] = request.get(port_at..port_at + 2)?.try_into().ok()?;
        let port = u16::from_be_bytes(port_bytes);
        if port == 0 {
            return None;
        }
        reply.extend_from_slice(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        Some((SocksRequest { host, port }, start + port_at + 2))
    })();
    (parsed, reply)
}

fn check_socks(
    runtime: &tokio::runtime::Runtime,
    input: &[u8],
    read_size: usize,
    write_size: usize,
) -> Result<(), String> {
    let (expected, reply) = socks_oracle(input);
    let mut stream = ShortIo {
        input: input.to_vec(),
        position: 0,
        output: Vec::new(),
        read_size,
        write_size,
    };
    let actual = runtime.block_on(accept_connect(&mut stream));
    prop_assert_eq!(
        actual.as_ref().ok(),
        expected.as_ref().map(|(request, _)| request)
    );
    prop_assert_eq!(stream.output, reply);
    if let Some((_, consumed)) = expected {
        prop_assert_eq!(stream.position, consumed);
        prop_assert_eq!(&stream.input[stream.position..], &input[consumed..]);
    }
    Ok(())
}

fn socks_message(address: &[u8], port: u16) -> Vec<u8> {
    let mut wire = vec![5, 3, 2, 0, 128, 5, 1, 0];
    wire.extend_from_slice(address);
    wire.extend_from_slice(&port.to_be_bytes());
    wire
}

#[test]
fn generated_socks_formats_preserve_payload_under_short_reads_and_every_eof() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    property::check("carrier-socks-addresses", |case| {
        let mut ipv4 = vec![1];
        ipv4.extend_from_slice(&case.array::<4>(0));
        let mut ipv6 = vec![4];
        ipv6.extend_from_slice(&case.array::<16>(4));
        let host: Vec<u8> = case
            .payload(255)
            .iter()
            .map(|byte| b'a' + byte % 26)
            .collect();
        let host = if host.is_empty() { b"x".to_vec() } else { host };
        let mut domain = vec![3, host.len() as u8];
        domain.extend_from_slice(&host);
        for address in [&ipv4, &ipv6, &domain] {
            let wire = socks_message(address, (case.a as u16).max(1));
            for end in 0..wire.len() {
                check_socks(&runtime, &wire[..end], 1, 1)?;
            }
            let mut with_payload = wire;
            with_payload.extend_from_slice(case.payload(128));
            check_socks(
                &runtime,
                &with_payload,
                1 + case.b as usize % 17,
                1 + case.c as usize % 7,
            )?;
        }
        Ok(())
    });
}

#[test]
fn socks_discriminants_and_invalid_domains_match_the_literal_oracle() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let seed = socks_message(&[1, 93, 184, 216, 34], 443);
    // Greeting version, request version, command, reserved byte and address type.
    for at in [0, 5, 6, 7, 8] {
        for value in 0..=255 {
            let mut wire = seed.clone();
            wire[at] = value;
            check_socks(&runtime, &wire, 2, 1).unwrap();
        }
    }
    for methods in [
        vec![],
        vec![1],
        vec![2, 128, 255],
        vec![255, 0],
        vec![0; 255],
    ] {
        let mut wire = vec![5, methods.len() as u8];
        wire.extend_from_slice(&methods);
        wire.extend_from_slice(&seed[5..]);
        check_socks(&runtime, &wire, 1, 2).unwrap();
    }
    for address in [vec![3, 0], vec![3, 1, 255], vec![3, 2, 0xc3, 0x28]] {
        check_socks(&runtime, &socks_message(&address, 443), 1, 1).unwrap();
    }
    check_socks(&runtime, &socks_message(&[1, 1, 2, 3, 4], 0), 1, 1).unwrap();
}

fn extension(out: &mut Vec<u8>, id: u16, data: &[u8]) {
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

fn hello_record(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut wire = vec![0x16, 3, 3];
    wire.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    wire.push(kind);
    wire.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    wire.extend_from_slice(body);
    wire
}

// The independent fixture records every length location it creates, so malformed
// length checks do not recover locations using the production Hello parser.
fn client_hello(case: &property::Case) -> (Vec<u8>, String, Vec<(usize, usize)>) {
    let random = case.array::<32>(0);
    let session = case.payload(case.a as usize % 33);
    let host: String = case
        .payload(63)
        .iter()
        .map(|byte| char::from(b'a' + byte % 26))
        .collect();
    let host = if host.is_empty() {
        "x".to_owned()
    } else {
        host
    };
    let mut body = vec![3, 3];
    body.extend_from_slice(&random);
    let mut lengths = vec![(3, 2), (6, 3), (9 + body.len(), 1)];
    body.push(session.len() as u8);
    body.extend_from_slice(session);
    lengths.push((9 + body.len(), 2));
    body.extend_from_slice(&2_u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 1]);
    lengths.push((9 + body.len(), 1));
    body.extend_from_slice(&[1, 0]);
    lengths.push((9 + body.len(), 2));
    let base = 9 + body.len() + 2;
    let mut extensions = Vec::new();
    extension(&mut extensions, 0xaaaa, case.payload(16));
    let sni_at = base + extensions.len();
    let mut sni = Vec::new();
    sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni.extend_from_slice(host.as_bytes());
    extension(&mut extensions, 0, &sni);
    lengths.extend([(sni_at + 2, 2), (sni_at + 4, 2), (sni_at + 7, 2)]);
    let version_at = base + extensions.len();
    extension(&mut extensions, 43, &[2, 3, 4]);
    lengths.extend([(version_at + 2, 2), (version_at + 4, 1)]);
    let key_at = base + extensions.len();
    let mut shares = vec![0, 43, 0x2a, 0x2a, 0, 3, 1, 2, 3, 0, 29, 0, 32];
    shares.extend_from_slice(&case.array::<32>(32));
    extension(&mut extensions, 51, &shares);
    lengths.extend([
        (key_at + 2, 2),
        (key_at + 4, 2),
        (key_at + 8, 2),
        (key_at + 15, 2),
    ]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    (hello_record(1, &body), host, lengths)
}

#[test]
fn generated_client_hello_extracts_fields_and_rejects_nested_length_overruns() {
    property::check("carrier-client-hello", |case| {
        let (wire, host, lengths) = client_hello(case);
        let parsed = parse_client_hello(&wire).unwrap();
        prop_assert_eq!(parsed.record_len, wire.len());
        prop_assert_eq!(parsed.client_random, case.array::<32>(0));
        prop_assert_eq!(
            &wire[parsed.session_id_range],
            case.payload(case.a as usize % 33)
        );
        prop_assert_eq!(parsed.sni.as_deref(), Some(host.as_str()));
        prop_assert!(parsed.tls13_supported);
        prop_assert_eq!(parsed.x25519_key_share, Some(case.array::<32>(32)));
        for end in 0..wire.len() {
            prop_assert!(parse_client_hello(&wire[..end]).is_err());
        }
        for (offset, width) in lengths {
            let mut invalid = wire.clone();
            invalid[offset..offset + width].fill(255);
            prop_assert!(parse_client_hello(&invalid).is_err());
        }
        let mut concatenated = wire.clone();
        concatenated.extend_from_slice(&[0x14, 3, 3, 0, 1, 1]);
        prop_assert_eq!(
            parse_client_hello(&concatenated).unwrap().record_len,
            wire.len()
        );
        Ok(())
    });
}

#[test]
fn generated_server_hello_extracts_prefix_and_rejects_nested_length_overruns() {
    property::check("carrier-server-hello", |case| {
        let session = case.payload(case.a as usize % 33);
        let mut body = vec![3, 3];
        body.extend_from_slice(&case.array::<32>(0));
        body.push(session.len() as u8);
        body.extend_from_slice(session);
        body.extend_from_slice(&[0x13, 1, 0]);
        let ext_at = 9 + body.len();
        let mut extensions = Vec::new();
        extension(&mut extensions, 0xaaaa, case.payload(16));
        let version_at = ext_at + 2 + extensions.len();
        extension(&mut extensions, 43, &[3, 4]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let wire = hello_record(2, &body);
        let parsed = parse_server_hello(&wire).unwrap();
        prop_assert_eq!(parsed.random, case.array::<32>(0));
        prop_assert_eq!(&wire[parsed.session_id_range], session);
        prop_assert!(parsed.tls13_selected);
        for end in 0..wire.len() {
            prop_assert!(parse_server_hello(&wire[..end]).is_err());
        }
        for (offset, width) in [(3, 2), (6, 3), (43, 1), (ext_at, 2), (version_at + 2, 2)] {
            let mut invalid = wire.clone();
            invalid[offset..offset + width].fill(255);
            prop_assert!(parse_server_hello(&invalid).is_err());
        }
        let mut concatenated = wire.clone();
        concatenated.extend_from_slice(&[0x14, 3, 3, 0, 1, 1]);
        prop_assert_eq!(
            parse_server_hello(&concatenated).unwrap().record_len,
            wire.len()
        );
        Ok(())
    });
}

#[test]
fn generated_http2_headers_settings_and_prefaces_match_wire_layout() {
    property::check("carrier-http2", |case| {
        let payload = case.payload(256);
        let raw_id = case.a as u32;
        let mut wire = Vec::new();
        wire.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
        wire.extend_from_slice(&[case.b as u8, case.c as u8]);
        wire.extend_from_slice(&raw_id.to_be_bytes());
        wire.extend_from_slice(payload);
        wire.extend_from_slice(case.payload(8));
        let (header, used) = Http2FrameHeader::parse_complete(&wire).unwrap();
        prop_assert_eq!(
            (
                header.len,
                header.frame_type,
                header.flags,
                header.stream_id,
                used
            ),
            (
                payload.len(),
                case.b as u8,
                case.c as u8,
                raw_id & 0x7fff_ffff,
                9 + payload.len()
            )
        );
        prop_assert_eq!(
            header.is_settings(),
            case.b as u8 == 4 && raw_id & 0x7fff_ffff == 0
        );
        prop_assert_eq!(
            header.is_settings_ack(),
            header.is_settings() && payload.is_empty() && case.c & 1 != 0
        );
        for end in 0..9 + payload.len() {
            prop_assert!(Http2FrameHeader::parse_complete(&wire[..end]).is_none());
        }
        // Exercise all three length octets without allocating the declared
        // payload. A parser dropping the high octet must not accept the prefix.
        for declared in [
            0,
            1,
            255,
            256,
            65535,
            65536,
            0xffffff,
            (case.a & 0xffffff) as usize,
        ] {
            let mut advertised = wire.clone();
            advertised[..3].copy_from_slice(&(declared as u32).to_be_bytes()[1..]);
            let actual = Http2FrameHeader::parse_complete(&advertised);
            prop_assert_eq!(actual.is_some(), declared <= advertised.len() - 9);
            if let Some((header, used)) = actual {
                prop_assert_eq!((header.len, used), (declared, 9 + declared));
            }
        }
        let settings = vec![
            Http2Setting {
                id: case.a as u16,
                value: case.b as u32,
            },
            Http2Setting {
                id: case.b as u16,
                value: case.c as u32,
            },
        ];
        let fingerprint = Http2Fingerprint {
            settings,
            initial_window_update: Some(case.c as u32),
        };
        let mut expected = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        expected.extend_from_slice(&[0, 0, 12, 4, 0, 0, 0, 0, 0]);
        for setting in &fingerprint.settings {
            expected.extend_from_slice(&setting.id.to_be_bytes());
            expected.extend_from_slice(&setting.value.to_be_bytes());
        }
        expected.extend_from_slice(&[0, 0, 4, 8, 0, 0, 0, 0, 0]);
        expected.extend_from_slice(&((case.c as u32) & 0x7fff_ffff).to_be_bytes());
        prop_assert_eq!(fingerprint.connection_preface().unwrap(), expected);
        prop_assert_eq!(
            Http2Fingerprint::settings_ack_frame().unwrap(),
            vec![0, 0, 0, 4, 1, 0, 0, 0, 0]
        );
        Ok(())
    });
}

fn varint(value: u64, width: usize) -> Vec<u8> {
    assert!(value < 1_u64 << 62);
    assert!(matches!(width, 1 | 2 | 4 | 8));
    assert!(u128::from(value) < 1_u128 << (8 * width - 2));
    let mut bytes = value.to_be_bytes()[8 - width..].to_vec();
    bytes[0] |= match width {
        1 => 0,
        2 => 64,
        4 => 128,
        _ => 192,
    };
    bytes
}

fn minimum_width(value: u64) -> usize {
    [1, 2, 4, 8]
        .into_iter()
        .find(|width| u128::from(value) < 1_u128 << (8 * width - 2))
        .unwrap()
}

fn read_varint(input: &[u8]) -> Option<(u64, usize)> {
    let width = match input.first()? / 64 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let bytes = input.get(..width)?;
    let number = bytes
        .iter()
        .fold(0_u64, |value, byte| value * 256 + u64::from(*byte));
    Some((number & ((1_u64 << (8 * width - 2)) - 1), width))
}

fn h3_oracle(input: &[u8]) -> Result<(u64, &[u8], usize), Http3Error> {
    let (kind, a) = read_varint(input).ok_or(Http3Error::Truncated)?;
    let (length, b) = read_varint(&input[a..]).ok_or(Http3Error::Truncated)?;
    if length > 1 << 20 {
        return Err(Http3Error::FrameTooLarge);
    }
    let total = a + b + usize::try_from(length).unwrap();
    Ok((
        kind,
        input.get(a + b..total).ok_or(Http3Error::Truncated)?,
        total,
    ))
}

fn check_h3(input: &[u8]) -> Result<(), String> {
    let actual = http3::decode_frame(input)
        .map(|(header, payload, used)| (header.frame_type, payload, used));
    prop_assert_eq!(actual, h3_oracle(input));
    Ok(())
}

#[test]
fn generated_http3_varints_frames_and_advertised_lengths_match_independent_oracle() {
    property::check("carrier-http3-framing", |case| {
        let kind = case.a & ((1_u64 << 62) - 1);
        let payload = case.payload(256);
        let mut canonical = varint(kind, minimum_width(kind));
        canonical.extend_from_slice(&varint(
            payload.len() as u64,
            minimum_width(payload.len() as u64),
        ));
        canonical.extend_from_slice(payload);
        prop_assert_eq!(http3::encode_frame(kind, payload).unwrap(), canonical);
        prop_assert_eq!(
            http3::encode_stream_type(kind),
            varint(kind, minimum_width(kind))
        );
        for width in [1, 2, 4, 8] {
            if width < minimum_width(kind) {
                continue;
            }
            let mut encoded = varint(kind, width);
            prop_assert_eq!(http3::read_stream_type(&encoded), Some((kind, width)));
            encoded.extend_from_slice(&varint(payload.len() as u64, 8));
            encoded.extend_from_slice(payload);
            for end in 0..encoded.len() {
                check_h3(&encoded[..end])?;
            }
            encoded.extend_from_slice(case.payload(8));
            check_h3(&encoded)?;
        }
        for length in [
            0,
            1,
            63,
            64,
            16383,
            16384,
            1 << 20,
            (1 << 20) + 1,
            u32::MAX as u64 + 1,
            (1_u64 << 62) - 1,
        ] {
            let mut hostile = vec![0];
            hostile.extend_from_slice(&varint(length, minimum_width(length)));
            hostile.extend_from_slice(case.payload(8));
            check_h3(&hostile)?;
        }
        Ok(())
    });
}

fn settings_oracle(mut input: &[u8]) -> Option<Vec<http3::Http3Setting>> {
    let mut settings = Vec::new();
    while !input.is_empty() {
        let (id, a) = read_varint(input)?;
        let (value, b) = read_varint(&input[a..])?;
        settings.push(http3::Http3Setting { id, value });
        input = &input[a + b..];
    }
    Some(settings)
}

#[test]
fn generated_http3_settings_parser_and_shape_checks_match_independent_values() {
    property::check("carrier-http3-settings", |case| {
        let seed = case.array::<8>(0);
        let id = 33 + 31 * u64::from(u32::from_be_bytes(seed[..4].try_into().unwrap()));
        let value = u64::from(u32::from_be_bytes(seed[4..].try_into().unwrap()));
        let expected = [
            http3::Http3Setting {
                id: 1,
                value: 16383,
            },
            http3::Http3Setting { id: 7, value: 100 },
            http3::Http3Setting { id, value },
        ];
        let grease = http3::grease_setting_from_seed(seed);
        prop_assert_eq!((grease.id, grease.value), (id, value));
        let mut wire = Vec::new();
        for setting in expected {
            wire.extend_from_slice(&varint(setting.id, 8));
            wire.extend_from_slice(&varint(setting.value, 8));
        }
        for end in 0..=wire.len() {
            prop_assert_eq!(
                http3::parse_settings_payload(&wire[..end]).ok(),
                settings_oracle(&wire[..end])
            );
        }
        let parsed = http3::parse_settings_payload(&wire).unwrap();
        prop_assert_eq!(parsed.as_slice(), expected.as_slice());
        prop_assert!(http3::is_safari26_settings(&parsed));
        for order in [[0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
            prop_assert!(!http3::is_safari26_settings(
                &order.map(|index| expected[index])
            ));
        }
        for setting in &expected {
            let mut duplicate = parsed.clone();
            duplicate.push(*setting);
            prop_assert!(!http3::is_safari26_settings(&duplicate));
        }
        for at in 0..2 {
            let mut invalid = expected;
            invalid[at].value ^= 1;
            prop_assert!(!http3::is_safari26_settings(&invalid));
        }
        Ok(())
    });
}

// Independent RFC 7541 prefix-integer emitter, used only for non-Huffman QPACK
// fixtures. No production QPACK encoder/decoder builds these oracle bytes.
fn qpack_integer(out: &mut Vec<u8>, value: usize, bits: u8, pattern: u8) {
    let limit = (1_usize << bits) - 1;
    out.push(pattern | value.min(limit) as u8);
    if value >= limit {
        let mut remaining = value - limit;
        while remaining >= 128 {
            out.push((remaining % 128) as u8 + 128);
            remaining /= 128;
        }
        out.push(remaining as u8);
    }
}

fn qpack_literal(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    qpack_integer(out, name.len(), 3, 0x20);
    out.extend_from_slice(name);
    qpack_integer(out, value.len(), 7, 0);
    out.extend_from_slice(value);
}

#[test]
fn generated_qpack_literal_and_name_reference_decoding_uses_independent_wire() {
    property::check("carrier-qpack", |case| {
        let name: Vec<u8> = case
            .payload(63)
            .iter()
            .map(|byte| b'a' + byte % 26)
            .collect();
        let name = if name.is_empty() { b"x".to_vec() } else { name };
        let value: Vec<u8> = case
            .payload(256)
            .iter()
            .map(|byte| b' ' + byte % 95)
            .collect();
        let expected = vec![(
            String::from_utf8(name.clone()).unwrap(),
            String::from_utf8(value.clone()).unwrap(),
        )];
        let mut wire = vec![0, 0];
        qpack_literal(&mut wire, &name, &value);
        prop_assert_eq!(
            http3::decode_field_section(&wire).unwrap(),
            expected.clone()
        );
        for end in 0..wire.len() {
            if end == 2 {
                continue;
            } // An empty, complete field section is legal.
            prop_assert!(http3::decode_field_section(&wire[..end]).is_err());
        }
        let mut duplicate = wire.clone();
        duplicate.extend_from_slice(&wire[2..]);
        let mut duplicated_fields = expected.clone();
        duplicated_fields.extend(expected);
        prop_assert_eq!(
            http3::decode_field_section(&duplicate).unwrap(),
            duplicated_fields
        );
        // Static name index zero is :authority; raw value length uses a 7-bit
        // prefix and spans continuation lengths as generated values grow.
        let mut reference = vec![0, 0, 0x50];
        qpack_integer(&mut reference, value.len(), 7, 0);
        reference.extend_from_slice(&value);
        prop_assert_eq!(
            http3::decode_field_section(&reference).unwrap(),
            vec![(":authority".to_owned(), String::from_utf8(value).unwrap())]
        );
        for first in [
            0x80 | (case.a as u8 & 63),
            0x40 | (case.b as u8 & 15),
            case.c as u8 & 31,
        ] {
            prop_assert_eq!(
                http3::decode_field_section(&[0, 0, first]),
                Err(Http3Error::QpackDynamicUnsupported)
            );
        }
        prop_assert_eq!(
            http3::decode_field_section(&[1 + (case.a % 254) as u8, 0]),
            Err(Http3Error::QpackDynamicUnsupported)
        );
        let mut oversize = vec![0, 0];
        qpack_integer(&mut oversize, (1 << 20) + 1, 3, 0x20);
        prop_assert_eq!(
            http3::decode_field_section(&oversize),
            Err(Http3Error::FrameTooLarge)
        );
        Ok(())
    });
}

#[test]
fn qpack_static_indices_and_malformed_strings_fail_without_aliasing() {
    for (index, name, value) in [
        (0, ":authority", ""),
        (1, ":path", "/"),
        (17, ":method", "GET"),
        (23, ":scheme", "https"),
        (25, ":status", "200"),
    ] {
        let mut wire = vec![0, 0];
        qpack_integer(&mut wire, index, 6, 0xc0);
        assert_eq!(
            http3::decode_field_section(&wire).unwrap(),
            vec![(name.to_owned(), value.to_owned())]
        );
    }
    for index in [99, 255, 16384, usize::MAX] {
        let mut wire = vec![0, 0];
        qpack_integer(&mut wire, index, 6, 0xc0);
        assert_eq!(
            http3::decode_field_section(&wire),
            Err(Http3Error::QpackBadStaticIndex(index as u64))
        );
    }
    for (wire, expected) in [
        (vec![0, 0, 0x21, 255, 0], Http3Error::QpackTruncated),
        (vec![0, 0, 0x21, b'x', 1, 255], Http3Error::QpackTruncated),
        (
            vec![0, 0, 0x21, b'x', 0x81, 0xff],
            Http3Error::QpackBadHuffman,
        ),
        (
            vec![0, 0, 0x21, b'x', 0x84, 0xff, 0xff, 0xff, 0xfc],
            Http3Error::QpackBadHuffman,
        ),
    ] {
        assert_eq!(http3::decode_field_section(&wire), Err(expected));
    }
}
