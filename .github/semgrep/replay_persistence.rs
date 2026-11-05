mod good {
    // ok: parallax-replay-copy-and-wipe
    fn cache_mac_key_from_digest(digest: &mut [u8]) -> CacheMacKey {
        let mut key = CacheMacKey([0_u8; 32]);
        key.0.copy_from_slice(digest);
        digest.zeroize();
        key
    }
}
mod missing_wipe {
    // ruleid: parallax-replay-copy-and-wipe
    fn cache_mac_key_from_digest(digest: &mut [u8]) -> CacheMacKey {
        let mut key = CacheMacKey([0_u8; 32]);
        key.0.copy_from_slice(digest);
        key
    }
}
mod partial_wipe {
    // ruleid: parallax-replay-copy-and-wipe
    fn cache_mac_key_from_digest(digest: &mut [u8]) -> CacheMacKey {
        let mut key = CacheMacKey([0_u8; 32]);
        key.0.copy_from_slice(digest);
        digest[..1].zeroize();
        key
    }
}
fn fsync_parent_dir(path: &Path) -> io::Result<()> {
    let directory = fs::File::open(path)?;
    // ruleid: parallax-replay-no-ignored-directory-sync
    let _ = directory.sync_all();
    Ok(())
}
fn compact_authenticated_journal(path: &Path) -> io::Result<()> {
    // ruleid: parallax-replay-no-ignored-compaction-sync
    let _ = fsync_parent_dir(path);
    Ok(())
}
