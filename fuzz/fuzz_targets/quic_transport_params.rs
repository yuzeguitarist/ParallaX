#![no_main]
use libfuzzer_sys::fuzz_target;
use parallax::transport::udp::quic::transport_params::TransportParameters;

// `TransportParameters::read` parses a peer's transport-parameters blob (RFC 9000
// §18) carried in the TLS `quic_transport_parameters` extension. On the server
// this is attacker-controlled input handled pre-authentication (before the
// exporter-bound token is verified), so it must never panic on arbitrary bytes
// and must enforce its documented range checks.
//
// Beyond "never panics", this asserts:
//   * a successfully parsed blob's enforced fields obey the RFC ranges the parser
//     promises (active_connection_id_limit >= 2, max_streams <= 2^60, SCID <= 20
//     bytes), and
//   * re-encoding then re-reading the SERVER form of a decoded value is stable
//     (a decode -> encode -> decode fixed point on the recognized fields).
fuzz_target!(|data: &[u8]| {
    let Ok(tp) = TransportParameters::read(data) else {
        return;
    };

    // Range invariants the parser enforces on the recognized ids (RFC 9000 §18.2).
    assert!(
        tp.active_connection_id_limit >= 2,
        "active_connection_id_limit below the RFC minimum survived parse"
    );
    assert!(
        tp.initial_max_streams_bidi <= (1u64 << 60),
        "max_streams_bidi above 2^60 survived parse"
    );
    assert!(
        tp.initial_max_streams_uni <= (1u64 << 60),
        "max_streams_uni above 2^60 survived parse"
    );
    assert!(
        tp.initial_src_cid.len() <= 20,
        "initial_source_connection_id longer than a legal CID survived parse"
    );

    // Fixed-point property: encode the recognized values back out (server form,
    // which serializes EVERY field this parser reads) and re-read them. The second
    // read must recover the WHOLE struct byte-for-byte — the encoder emits each id
    // at most once and in ascending order, so it round-trips through `read`
    // cleanly. A full-struct equality (rather than a hand-picked subset of fields)
    // keeps this invariant aligned with what `read`/`encode_server` actually
    // handle, so an encode/decode regression on any field — including the
    // per-stream-data and bidi-streams limits — cannot slip through.
    let reencoded = tp.encode_server();
    let tp2 = TransportParameters::read(&reencoded)
        .expect("our own encode_server output must re-read without error");
    assert_eq!(
        tp2, tp,
        "transport parameters not stable across encode_server -> read"
    );
});
