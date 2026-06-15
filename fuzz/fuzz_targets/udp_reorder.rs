#![no_main]
use libfuzzer_sys::fuzz_target;

// TUDP reorder buffer (PR#19, src/transport/udp/reorder.rs). Drives a bounded
// ReorderBuffer with an attacker-derived stream of insert(seq, record) / pop ops
// and asserts the HARD memory bounds (max_records / max_bytes) always hold — the
// anti-exhaustion guarantee a lossy or malicious peer must never be able to
// break (withholding a low seq while flooding high ones must not blow memory).
// The driver lives in the crate's #[cfg(fuzzing)] module because ReorderBuffer
// is pub(crate); config caps keep the buffer itself from being told to hold GiB.
fuzz_target!(|data: &[u8]| {
    parallax::transport::udp::fuzz::reorder_drive(data);
});
