#![no_main]
use libfuzzer_sys::fuzz_target;
use parallax::transport::udp::fuzz::{decode_envelope_prefix, encode_envelope_into};

// TUDP envelope wire format (PR#19, src/transport/udp/envelope.rs). decode_prefix
// parses attacker-controlled UDP datagram bytes — seq(u64 BE) + record_len(u16 BE)
// + record — possibly several envelopes concatenated in one datagram.
//
// Property: walking all concatenated envelopes never panics; and for each decoded
// envelope, re-encoding (seq, record) then re-decoding yields the SAME seq +
// record bytes and a consumed length covering exactly that one envelope — a real
// codec-symmetry check, not a restatement of the parser's own arithmetic.
fuzz_target!(|data: &[u8]| {
    let mut off = 0usize;
    while off < data.len() {
        let (seq, record, consumed) = match decode_envelope_prefix(&data[off..]) {
            Ok(v) => v,
            Err(_) => break,
        };
        // decode guarantees record_end <= input.len(), so these indices are in bounds.
        let rec = &data[off + record.start..off + record.end];

        let mut buf = Vec::new();
        encode_envelope_into(seq, rec, &mut buf).expect("a decoded record must re-encode");
        let (seq2, record2, consumed2) =
            decode_envelope_prefix(&buf).expect("our own envelope must decode");
        assert_eq!(seq2, seq, "seq not stable across roundtrip");
        assert_eq!(&buf[record2.clone()], rec, "record bytes not stable across roundtrip");
        assert_eq!(consumed2, buf.len(), "consumed must cover exactly one envelope");

        if consumed == 0 {
            break; // defensive: consumed is always >= header, the loop must advance
        }
        off += consumed;
    }
});
