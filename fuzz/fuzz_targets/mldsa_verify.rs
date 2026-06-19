#![no_main]
use libfuzzer_sys::fuzz_target;
use parallax::crypto::mldsa::{self, PUBLICKEY_BYTES, SIG_BYTES};

// crypto::mldsa::verify on attacker-controlled bytes. ParallaX verifies a peer's
// ML-DSA-87 server-identity signature over network-supplied (pk, sig, msg, ctx),
// so verify MUST treat every byte as hostile and return an Err — never panic,
// never index out of bounds, never overflow — regardless of input. (Verify is
// documented as public-input-only, so this guards safety, not constant-time.)
//
// The first byte selects a slicing mode so the fuzzer can reach BOTH the cheap
// length-rejects AND the inner verify_ctx math: mode 0/1 coerce the pk and sig to
// their exact accepted sizes (2592 / 4627) so unpack_sig, the norm checks, the
// NTT, and the challenge recompute all execute on malformed-but-correct-length
// inputs; the default mode passes raw, arbitrarily-sized slices (the common
// length-mismatch path). The return value is intentionally ignored — only the
// absence of a panic is asserted (implicitly, by libFuzzer).
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (mode, body) = (data[0], &data[1..]);

    // Split the body into (a, b, msg, ctx) at two length-prefix bytes, so the
    // fuzzer can independently grow each field. ctx is clamped to <= 255 sometimes
    // and left arbitrary otherwise (both the in-range and over-long branches).
    let alen = body.first().copied().unwrap_or(0) as usize;
    let rest = body.get(1..).unwrap_or(&[]);
    let blen = rest.first().copied().unwrap_or(0) as usize;
    let rest = rest.get(1..).unwrap_or(&[]);

    let a = &rest[..alen.min(rest.len())];
    let rest = rest.get(alen.min(rest.len())..).unwrap_or(&[]);
    let b = &rest[..blen.min(rest.len())];
    let rest = rest.get(blen.min(rest.len())..).unwrap_or(&[]);

    // Remaining bytes: split in half into msg / ctx.
    let mid = rest.len() / 2;
    let (msg, ctx) = rest.split_at(mid);

    match mode % 3 {
        0 => {
            // Coerce a -> exact pk length, b -> exact sig length (drives the inner
            // verify_ctx unpack + arithmetic on hostile, correctly-sized buffers).
            let pk = coerce(a, PUBLICKEY_BYTES);
            let sig = coerce(b, SIG_BYTES);
            let _ = mldsa::verify(&pk, &sig, msg, ctx);
        }
        1 => {
            // Exact-length pk/sig but a deliberately over-long ctx (> 255) to drive
            // the ContextTooLong reject without panicking.
            let pk = coerce(a, PUBLICKEY_BYTES);
            let sig = coerce(b, SIG_BYTES);
            let long_ctx = vec![0u8; 256];
            let _ = mldsa::verify(&pk, &sig, msg, &long_ctx);
        }
        _ => {
            // Raw, arbitrarily-sized slices: the common length-mismatch reject.
            let _ = mldsa::verify(a, b, msg, ctx);
        }
    }
});

/// Resize `src` to exactly `n` bytes: truncate if longer, zero-pad if shorter.
fn coerce(src: &[u8], n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    let take = src.len().min(n);
    out[..take].copy_from_slice(&src[..take]);
    out
}
