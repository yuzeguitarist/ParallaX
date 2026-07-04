#![no_main]
use libfuzzer_sys::fuzz_target;
use parallax::transport::udp::quic::packet::{
    first_packet_space, long_packet_len, peek_long_cids, Header,
};

// The QUIC packet-header parsers (RFC 9000 §17) run on attacker-controlled
// datagram bytes BEFORE header protection is removed and before anything is
// authenticated: the server calls `peek_long_cids` on the client's first Initial
// to derive keys, `first_packet_space` / `long_packet_len` to classify and walk
// coalesced packets, and `Header::decode` on the unmasked header. None of these
// may panic on arbitrary input, and each carries structural invariants worth
// pinning.
//
// `Header::decode` reconstructs the FULL packet number from its truncated wire
// form, so it needs a `largest_pn` and the endpoint's local CID length; we sweep
// a few representative values of each from the fuzz input so the target explores
// both header forms (long, and short with several DCID lengths).
fuzz_target!(|data: &[u8]| {
    // `first_packet_space` reads only the (plaintext) first byte — must never
    // panic and must agree with the long/short header form.
    let space = first_packet_space(data);

    // `long_packet_len`: if it returns a coalescing boundary, that boundary MUST
    // lie within the datagram (else walking coalesced packets would index past
    // the buffer). This is the invariant its `checked_add` + `<= buf.len()` guard
    // promises.
    if let Some(total) = long_packet_len(data) {
        assert!(
            total <= data.len(),
            "long_packet_len boundary past datagram"
        );
        assert!(total >= 1, "a packet cannot have zero on-wire length");
    }

    // `peek_long_cids` must not panic; on success both CIDs are legal QUIC CID
    // lengths (0..=20, enforced by the packet Cursor's `cid()`).
    if let Ok((dcid, scid)) = peek_long_cids(data) {
        assert!(dcid.len() <= 20, "dcid length exceeds RFC 9000 max");
        assert!(scid.len() <= 20, "scid length exceeds RFC 9000 max");
    }

    // `Header::decode` for the long-header form (local_cid_len is irrelevant to a
    // long header, whose DCID is length-prefixed on the wire).
    let largest_pn = seed_u64(data);
    if let Ok((header, aad_len)) = Header::decode(data, 0, largest_pn) {
        assert!(aad_len <= data.len(), "AAD length past the buffer");
        // A decoded header re-encodes. `Header::encode` returns the packet-number
        // OFFSET (the AAD length), not the total bytes written, so the re-encoded
        // buffer runs `pn_offset + pn_len` bytes: the header up to the PN, then the
        // `pn_len`-byte truncated packet number. Pin exactly that relationship.
        let mut out = Vec::new();
        let pn_offset = header.encode(&mut out);
        assert!(pn_offset <= out.len(), "encode pn_offset past the buffer");
        assert_eq!(
            out.len(),
            pn_offset + header.pn_len(),
            "re-encoded header length must be pn_offset + pn_len"
        );
    }

    // Short-header form: sweep a few plausible local DCID lengths (the Safari
    // client issues zero-length CIDs; the relay may issue longer ones).
    for local_cid_len in [0usize, 4, 8, 20] {
        // Must never panic regardless of how short/hostile the buffer is.
        let _ = Header::decode(data, local_cid_len, largest_pn);
    }

    // `space` classification must be consistent with a successful long-CID peek:
    // if we could peek long CIDs, the packet is a long header, so the space (when
    // Some) is one of the long spaces, never OneRtt.
    if peek_long_cids(data).is_ok() {
        use parallax::transport::udp::quic::packet::PacketSpace;
        assert!(
            !matches!(space, Some(PacketSpace::OneRtt)),
            "a long-header packet must not classify as OneRtt"
        );
    }
});

/// Derive a `largest_pn` from the tail of the input so the fuzzer can steer PN
/// reconstruction without a structured-input crate.
fn seed_u64(data: &[u8]) -> u64 {
    let mut v = 0u64;
    for &b in data.iter().rev().take(8) {
        v = (v << 8) | u64::from(b);
    }
    v
}
