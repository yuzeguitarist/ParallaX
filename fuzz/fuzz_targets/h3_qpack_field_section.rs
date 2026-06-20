#![no_main]
use libfuzzer_sys::fuzz_target;
use parallax::fingerprint::http3::{decode_field_section, encode_field_section};

// decode_field_section decodes an attacker-controlled QPACK encoded field section
// (RFC 9204 §4) — static-table index lookups + Huffman string decoding — on the
// QUIC fast-plane H3 façade. Beyond "does not panic", this asserts a value-stable
// decode->encode->decode round-trip: re-encoding the decoded fields and decoding
// again must yield the identical (name, value) list, even though the re-encode
// may pick a different representation (indexed vs. literal, Huffman vs. raw).
fuzz_target!(|data: &[u8]| {
    if let Ok(fields) = decode_field_section(data) {
        let reenc = encode_field_section(&fields);
        let again =
            decode_field_section(&reenc).expect("a freshly encoded field section must decode");
        assert_eq!(again, fields, "decode->encode->decode is not value-stable");
    }
});
