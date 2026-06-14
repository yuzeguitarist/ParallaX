#![no_main]
use libfuzzer_sys::fuzz_target;
use parallax::crypto::replay::ReplayCache;
use std::io::Write;

// Replay-journal parsing. The server reads this file at startup; corruption or a
// partial write must never panic (only Err). Both the plain and the
// authenticated journals are parsed; the authenticated path also walks the HMAC
// hash-chain verifier.
fuzz_target!(|data: &[u8]| {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("plx_fuzz_replay_{}.journal", std::process::id()));
    if std::fs::File::create(&path)
        .and_then(|mut f| f.write_all(data))
        .is_err()
    {
        return;
    }
    let _ = ReplayCache::load_or_create(&path, 8192);
    let _ = ReplayCache::load_or_create_authenticated(&path, 8192, &[0u8; 32]);
    let _ = std::fs::remove_file(&path);
});
