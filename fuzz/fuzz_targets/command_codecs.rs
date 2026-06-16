#![no_main]
use libfuzzer_sys::fuzz_target;
use parallax::protocol::command::{
    ConnectRequest, PqRekeyRequest, ServerKeyExchange, ServerIdentityProof,
    ServerIdentityChunk, SpeedTestRequest, SpeedTestAck,
};

// All 7 protocol/command.rs codecs. Every decoder enforces canonical strict
// length, so decode->encode->decode must be value-stable AND encode-idempotent.
// A fired assert means a non-canonical codec (a real bug), not a false positive.
macro_rules! rt_eq {
    ($t:ty, $b:expr) => {{
        if let Ok(v1) = <$t>::decode($b) {
            let e1 = v1.encode().expect("decoded value must re-encode");
            let v2 = <$t>::decode(&e1).expect("our own encoding must decode");
            assert_eq!(v1, v2, concat!(stringify!($t), " roundtrip not value-stable"));
            let e2 = v2.encode().expect("re-encode must succeed");
            assert_eq!(e1, e2, concat!(stringify!($t), " encode not idempotent"));
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (sel, body) = (data[0], &data[1..]);
    match sel % 7 {
        0 => rt_eq!(ConnectRequest, body),
        1 => rt_eq!(PqRekeyRequest, body),
        2 => rt_eq!(ServerKeyExchange, body),
        3 => rt_eq!(ServerIdentityProof, body),
        4 => rt_eq!(ServerIdentityChunk, body),
        5 => rt_eq!(SpeedTestRequest, body),
        _ => {
            // SpeedTestAck::encode returns Vec<u8>, not Result.
            if let Ok(v1) = SpeedTestAck::decode(body) {
                let e1 = v1.encode();
                let v2 = SpeedTestAck::decode(&e1).expect("SpeedTestAck encoding must decode");
                assert_eq!(v1, v2, "SpeedTestAck roundtrip not value-stable");
                assert_eq!(e1, v2.encode(), "SpeedTestAck encode not idempotent");
            }
        }
    }
});
