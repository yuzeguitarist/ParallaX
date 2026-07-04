#![no_main]
use libfuzzer_sys::fuzz_target;
use parallax::protocol::command::{
    ConnectRequest, FramedChunk, FramedReassembler, PqRekeyRequest, ServerIdentityChunk,
    ServerIdentityProof, ServerKeyExchange, SpeedTestAck, SpeedTestRequest, UdpDecline, UdpOffer,
    UdpProbeAck, UdpRequest,
};

// All protocol/command.rs wire codecs. Every decoder enforces canonical strict
// length, so decode->encode->decode must be value-stable AND encode-idempotent.
// A fired assert means a non-canonical codec (a real bug), not a false positive.
//
// rt_eq! covers codecs whose encode() returns Result; rt_eq_vec! covers those
// returning Vec<u8> directly (SpeedTestAck + the TUDP-negotiation codecs). The
// UDP codecs (UdpOffer/UdpProbeAck/UdpRequest/UdpDecline) were added with PR#19
// but had been LEFT OUT of this selector — their decode/encode sat at 0% fuzz
// coverage. Wiring them in here closes that blind spot; the fuzzer grows their
// corpus from zero.
macro_rules! rt_eq {
    ($t:ty, $b:expr) => {{
        if let Ok(v1) = <$t>::decode($b) {
            let e1 = v1.encode().expect("decoded value must re-encode");
            let v2 = <$t>::decode(&e1).expect("our own encoding must decode");
            assert_eq!(
                v1, v2,
                concat!(stringify!($t), " roundtrip not value-stable")
            );
            let e2 = v2.encode().expect("re-encode must succeed");
            assert_eq!(e1, e2, concat!(stringify!($t), " encode not idempotent"));
        }
    }};
}
macro_rules! rt_eq_vec {
    ($t:ty, $b:expr) => {{
        if let Ok(v1) = <$t>::decode($b) {
            let e1 = v1.encode();
            let v2 = <$t>::decode(&e1).expect("our own encoding must decode");
            assert_eq!(
                v1, v2,
                concat!(stringify!($t), " roundtrip not value-stable")
            );
            assert_eq!(
                e1,
                v2.encode(),
                concat!(stringify!($t), " encode not idempotent")
            );
        }
    }};
}

// ServerKeyExchange's canonical wire form carries a trailing cipher-suite tag
// (the bare encode() is crate-internal and tag-less), so it round-trips through
// the tagged encoder/decoder rather than the generic rt_eq! that assumes
// encode()/decode() are inverses. Value AND suite must be stable, and the tagged
// encoding must be idempotent.
fn rt_ske(b: &[u8]) {
    if let Ok((_, suite1)) = ServerKeyExchange::decode_ref_with_suite(b) {
        let v1 = ServerKeyExchange::decode(b).expect("decode_ref_with_suite Ok implies decode Ok");
        let e1 = v1
            .encode_with_suite(suite1)
            .expect("decoded value must re-encode");
        let v2 = ServerKeyExchange::decode(&e1).expect("our own encoding must decode");
        let (_, suite2) =
            ServerKeyExchange::decode_ref_with_suite(&e1).expect("our own encoding must decode");
        assert_eq!(suite1, suite2, "ServerKeyExchange suite not stable");
        assert_eq!(v1, v2, "ServerKeyExchange roundtrip not value-stable");
        let e2 = v2
            .encode_with_suite(suite2)
            .expect("re-encode must succeed");
        assert_eq!(e1, e2, "ServerKeyExchange encode not idempotent");
    }
}

// FramedChunk carries the SAME `magic | total_len | offset | len | bytes`
// offset codec as ServerIdentityChunk, but only ever exposes a borrowed
// `decode_ref` + a payload-tiling `encode_all` (no owned decode()/encode()
// pair), so it does not fit rt_eq!. It was therefore absent from this selector
// even though it decodes untrusted bytes on the PQ-handshake path. Cover it: a
// decoded chunk's payload, re-tiled into a fresh single-record frame, must
// reassemble byte-for-byte through the reassembler that consumes it on the wire.
fn rt_framed(b: &[u8]) {
    let Ok(chunk) = FramedChunk::decode_ref(b) else {
        return;
    };
    let payload = chunk.bytes.to_vec();
    // A decoded chunk always carries a non-empty payload (the codec rejects
    // len==0), so encode_all yields at least one record.
    let reencoded = FramedChunk::encode_all(&payload, payload.len())
        .expect("a decoded chunk payload must re-tile");
    let mut reassembler = FramedReassembler::default();
    let mut assembled = None;
    for record in &reencoded {
        // decode_ref -> encode_all -> decode_ref must be value-stable.
        let d = FramedChunk::decode_ref(record).expect("our own FramedChunk record must decode");
        assert_eq!(d.total_len as usize, payload.len(), "re-tiled total mismatch");
        if let Some(done) = reassembler
            .push(record, payload.len())
            .expect("our own FramedChunk record must reassemble")
        {
            assembled = Some(done);
        }
    }
    assert_eq!(
        assembled.expect("re-tiled frame must fully reassemble"),
        payload,
        "FramedChunk decode -> re-tile -> reassemble is not lossless"
    );
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (sel, body) = (data[0], &data[1..]);
    match sel % 12 {
        0 => rt_eq!(ConnectRequest, body),
        1 => rt_eq!(PqRekeyRequest, body),
        2 => rt_ske(body),
        3 => rt_eq!(ServerIdentityProof, body),
        4 => rt_eq!(ServerIdentityChunk, body),
        5 => rt_eq!(SpeedTestRequest, body),
        6 => rt_eq!(UdpOffer, body),
        7 => rt_eq_vec!(SpeedTestAck, body),
        8 => rt_eq_vec!(UdpProbeAck, body),
        9 => rt_eq_vec!(UdpRequest, body),
        10 => rt_framed(body),
        _ => rt_eq_vec!(UdpDecline, body),
    }
});
