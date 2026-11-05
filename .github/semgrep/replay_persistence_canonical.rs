// Reviewed complete AST scopes. Changes require review plus full-source mutations.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct CacheMacKey([u8; 32]);

impl ReplayCache {
    fn compact_authenticated_journal(
        &mut self,
        path: &Path,
        mac_key: &CacheMacKey,
    ) -> Result<(), ReplayCacheError> {
        let (raw, journal) = serialize_authenticated_journal(&self.order, mac_key);
        self.auth_journal = None;
        let tmp = cache_tmp_path(path);
        write_cache_file(&tmp, raw.as_bytes())?;
        fs::rename(tmp, path)?;
        fsync_parent_dir(
            path,
            #[cfg(all(test, unix))]
            self.fail_directory_sync.take(),
        )?;
        self.auth_journal = Some(journal);
        Ok(())
    }
}

#[cfg(unix)]
fn fsync_parent_dir(
    path: &Path,
    #[cfg(test)] failure: Option<DirectorySyncFailure>,
) -> io::Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = parent.unwrap_or_else(|| Path::new("."));
    let open = || -> io::Result<fs::File> {
        #[cfg(test)]
        if matches!(failure, Some(DirectorySyncFailure::Open)) {
            return Err(io::Error::other("injected directory-open failure"));
        }
        fs::File::open(dir)
    };
    let dir_file = open()?;
    #[cfg(test)]
    if matches!(failure, Some(DirectorySyncFailure::Sync)) {
        return Err(io::Error::other("injected directory-sync failure"));
    }
    dir_file.sync_all()
}

#[cfg(not(unix))]
fn fsync_parent_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn cache_mac_key(key_material: &[u8]) -> CacheMacKey {
    let mut mac = HmacSha256::new_from_slice(key_material).expect("HMAC accepts any key length");
    mac.update(CACHE_KEY_LABEL);
    let mut digest = mac.finalize().into_bytes();
    cache_mac_key_from_digest(&mut digest)
}

fn cache_mac_key_from_digest(digest: &mut [u8]) -> CacheMacKey {
    let mut key = CacheMacKey([0_u8; 32]);
    key.0.copy_from_slice(digest);
    digest.zeroize();
    key
}
