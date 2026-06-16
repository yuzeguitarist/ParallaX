#![no_main]
use libfuzzer_sys::fuzz_target;
use parallax::protocol::command::{
    ConnectRequest, PqRekeyRequest, ServerIdentityChunk, ServerIdentityProof, ServerKeyExchange,
    SpeedTestAck, SpeedTestRequest, UdpDecline, UdpOffer, UdpProbeAck, UdpRequest,
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

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (sel, body) = (data[0], &data[1..]);
    match sel % 11 {
        0 => rt_eq!(ConnectRequest, body),
        1 => rt_eq!(PqRekeyRequest, body),
        2 => rt_eq!(ServerKeyExchange, body),
        3 => rt_eq!(ServerIdentityProof, body),
        4 => rt_eq!(ServerIdentityChunk, body),
        5 => rt_eq!(SpeedTestRequest, body),
        6 => rt_eq!(UdpOffer, body),
        7 => rt_eq_vec!(SpeedTestAck, body),
        8 => rt_eq_vec!(UdpProbeAck, body),
        9 => rt_eq_vec!(UdpRequest, body),
        _ => rt_eq_vec!(UdpDecline, body),
    }
});
