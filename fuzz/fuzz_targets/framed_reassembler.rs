#![no_main]
use libfuzzer_sys::fuzz_target;
use parallax::protocol::command::{FramedChunk, FramedReassembler};

// The stateful `FramedChunk` reassembly path — the piece of the offset-chunk
// codec that `command_codecs` does NOT reach. That target is decode-first and
// single-record: it only ever sees inputs the decoder already accepts, and it
// never drives `FramedReassembler`, the multi-chunk state machine that walks
// untrusted, possibly out-of-order / inconsistent-total / oversized chunk
// sequences (`src/protocol/command.rs`, `FramedReassembler::push`). This target
// closes that blind spot from BOTH directions.
//
// The `cap` and per-chunk sizing are taken from the fuzz input so the corpus
// explores the memory-DoS bound and the tiling arithmetic, not one fixed shape.
//
// Byte layout of `data`:
//   [0]      mode selector
//   [1..3]   cap (u16 big-endian); 0 is bumped to 1 so a frame can exist
//   [3]      chunk_len seed (mode 0 only)
//   [4..]    body (payload in mode 0, raw chunk stream in mode 1)

fn split_header(data: &[u8]) -> Option<(u8, usize, &[u8])> {
    if data.len() < 4 {
        return None;
    }
    let mode = data[0];
    let cap = (u16::from_be_bytes([data[1], data[2]]) as usize).max(1);
    Some((mode, cap, &data[3..]))
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, cap, rest)) = split_header(data) else {
        return;
    };

    if mode & 1 == 0 {
        // ── Mode 0: structured encode -> reassemble roundtrip ──────────────
        // Tile an arbitrary payload into chunks, then reassemble. A payload the
        // encoder accepts MUST reassemble back to the exact same bytes through a
        // cap that admits it. The reassembler is size-agnostic, so any positive
        // chunk_len tiles the same payload; feeding those chunks back must be a
        // lossless identity.
        let (chunk_len_byte, payload) = rest.split_first().unwrap_or((&1, &[]));
        // Map the seed byte to a positive chunk length; +1 avoids a zero length
        // (which `encode_all` rejects) and keeps small payloads multi-chunk.
        let chunk_len = (*chunk_len_byte as usize) + 1;

        let Ok(chunks) = FramedChunk::encode_all(payload, chunk_len) else {
            return;
        };
        // `encode_all` only succeeds for a non-empty payload, so total_len >= 1.
        // Use a cap that is guaranteed to admit this payload so the roundtrip is
        // an identity: reassembly must not be starved by an artificially small
        // cap here (the cap boundary is exercised in mode 1).
        let roundtrip_cap = cap.max(payload.len());

        let mut reassembler = FramedReassembler::default();
        let mut assembled: Option<Vec<u8>> = None;
        for chunk in &chunks {
            match reassembler.push(chunk, roundtrip_cap) {
                Ok(Some(done)) => {
                    assert!(
                        assembled.is_none(),
                        "reassembler yielded a payload more than once for one frame"
                    );
                    assembled = Some(done);
                }
                Ok(None) => {}
                Err(err) => panic!("our own encode_all chunks must reassemble, got {err:?}"),
            }
        }
        let assembled = assembled.expect("a non-empty payload must fully reassemble");
        assert_eq!(
            assembled, payload,
            "encode_all -> FramedReassembler is not a lossless identity"
        );
    } else {
        // ── Mode 1: adversarial chunk stream ───────────────────────────────
        // Chop the body into attacker-controlled, length-prefixed records and
        // feed each straight into `push` with the fuzzed cap. The contract:
        // `push` NEVER panics on hostile bytes, and any payload it yields is
        // exactly `total_len` bytes and within the cap. A crafted offset/len/
        // total that slipped a bound would surface as an over-length assembly
        // or an out-of-bounds panic here.
        let mut reassembler = FramedReassembler::default();
        let mut cursor = rest;
        // Bound the record count so one input can't spin forever; the fuzzer
        // still reaches deep sequences across the corpus.
        for _ in 0..64 {
            if cursor.len() < 2 {
                break;
            }
            let len = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
            let body = &cursor[2..];
            let take = len.min(body.len());
            let (chunk, next) = body.split_at(take);
            cursor = next;

            match reassembler.push(chunk, cap) {
                Ok(Some(payload)) => {
                    assert!(
                        !payload.is_empty() && payload.len() <= cap,
                        "reassembled payload violates cap: len={}, cap={cap}",
                        payload.len()
                    );
                    // A completed frame resets the reassembler (see the
                    // expected-total latch clear in `push`); it is reusable, so
                    // keep feeding the remaining stream into the same instance.
                }
                Ok(None) | Err(_) => {}
            }

            if take < len {
                // The declared record ran past the available bytes: the stream
                // is exhausted, stop rather than feed empty trailing chunks.
                break;
            }
        }
    }
});
