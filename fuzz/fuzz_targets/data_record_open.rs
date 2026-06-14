#![no_main]
use libfuzzer_sys::fuzz_target;
use parallax::crypto::session::{AeadCodec, KEY_LEN, NONCE_LEN};
use parallax::protocol::data::{DataRecordCodec, CLIENT_TO_SERVER_AAD};
use parallax::traffic::PaddingProfile;
use rand::{rngs::StdRng, SeedableRng};

// Build a fresh codec each call: open_concat_records poisons the AEAD on error,
// and seal/open need independent seq counters that both start at 0.
fn codec() -> DataRecordCodec {
    let key = [7u8; KEY_LEN];
    let nonce = [9u8; NONCE_LEN];
    let padding = PaddingProfile::new(0, 16).expect("valid padding profile");
    DataRecordCodec::new(AeadCodec::new(key, nonce), padding, CLIENT_TO_SERVER_AAD)
}

fuzz_target!(|data: &[u8]| {
    // (a) attacker-controlled bytes through every open path (AEAD auth will
    //     reject; hunting panics in TLS-record parse / padding removal / zeroize).
    let _ = codec().open(data);
    {
        let mut buf = data.to_vec();
        let _ = codec().open_in_place(&mut buf);
    }
    {
        let mut buf = data.to_vec();
        let mut out = Vec::new();
        let _ = codec().open_concat_records(&mut buf, &mut out);
    }

    // (b) genuine seal -> open roundtrip on the success path. Cap plaintext so a
    //     single record suffices; assert the opened plaintext matches.
    let pt = if data.len() > 4096 { &data[..4096] } else { data };
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    if let Ok(record) = codec().seal(pt, &mut rng) {
        let opened = codec().open(&record).expect("sealed record must open");
        assert_eq!(opened, pt, "seal/open roundtrip mismatch");
    }
});
