#![no_main]
use libfuzzer_sys::fuzz_target;
use parallax::fingerprint::http3::parse_settings_payload;

// parse_settings_payload walks an attacker-controlled HTTP/3 SETTINGS payload
// (RFC 9114 §7.2.4: a sequence of varint id/value pairs) on the QUIC fast-plane
// control stream. It must fail-closed (Err) or return a bounded list — never
// panic, hang, or over-produce. No public SETTINGS-payload encoder exists (the
// builder only emits Safari's fixed set), so this is a decode-only no-panic +
// bounded-output check rather than a round-trip.
fuzz_target!(|data: &[u8]| {
    if let Ok(settings) = parse_settings_payload(data) {
        // Each setting consumes >= 2 bytes (two varints, >= 1 byte each), so the
        // count can never exceed the input length — a regression that looped or
        // double-counted a pair would trip this.
        assert!(
            settings.len() <= data.len(),
            "more settings than input bytes"
        );
    }
});
