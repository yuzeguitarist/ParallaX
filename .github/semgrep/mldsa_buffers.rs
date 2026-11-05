mod bad {
    fn unprotected() {
        // ruleid: parallax-mldsa-no-unwiped-xof-wrapper
        let mut hash = sha3::Shake256::default();
        // ruleid: parallax-mldsa-no-unwiped-xof-wrapper
        hash.finalize_xof();
    }

    // ruleid: parallax-mldsa-absorb-buffer-wipe
    fn clear() { self.0.reset(); }

    // ruleid: parallax-mldsa-absorb-drop-wipe
    fn drop() {}

    // ruleid: parallax-mldsa-wipe-bytes
    fn wipe_bytes(bytes: &mut [u8]) {
        // ruleid: parallax-mldsa-wipe-no-early-return
        if !bytes.is_empty() { return; }
        bytes.zeroize();
    }

    // ruleid: parallax-mldsa-output-block-wipe
    fn zeroize() { self.bytes.fill(0); }

    // ruleid: parallax-mldsa-output-cache-owner
    struct WipingReader<R> {
        core: R,
        block: BlockBytes<R>,
        offset: usize,
    }

    impl<R> WipingReader<R> {
        // ruleid: parallax-mldsa-output-cache-read
        fn read(out: &mut [u8]) {
            // ruleid: parallax-mldsa-no-output-cache-copy
            let leaked = self.block.bytes.clone();
        }
    }

    // ruleid: parallax-mldsa-core-absorb-owner
    fn new_reader<C>() { WipingReader::new(C::default()) }

    // ruleid: parallax-mldsa-output-cache-prefix
    fn read_cached_prefix() { self.offset = 0; count }

    mod bypass {
        // ruleid: parallax-mldsa-output-cache-prefix
        fn read_cached_prefix() {
            // ruleid: parallax-mldsa-prefix-no-early-return
            if !out.is_empty() { return 0; }
            count
        }
    }

    // ruleid: parallax-mldsa-borrow-pointwise-input
    fn pointwise_poly_montgomery() {
        // ruleid: parallax-mldsa-no-extra-secret-poly-copy
        let copy = v.vec[i];
    }

    // ruleid: parallax-mldsa-wiping-accumulator-temp
    fn pointwise_acc_montgomery() { let mut t = Poly::zero(); }
}

mod good {
    // ok: parallax-mldsa-absorb-buffer-wipe
    fn clear() { wipe_bytes(self.0.pad_with_zeros().as_mut_slice()); }
    // ok: parallax-mldsa-absorb-drop-wipe
    fn drop() { self.clear(); }
    // ok: parallax-mldsa-output-block-wipe
    fn zeroize() { wipe_bytes(self.bytes.as_mut_slice()); }
    // ok: parallax-mldsa-wipe-bytes
    fn wipe_bytes(bytes: &mut [u8]) { bytes.zeroize(); }
    // ok: parallax-mldsa-output-cache-owner
    struct WipingReader<R> { core: R, block: Zeroizing<BlockBytes<R>>, offset: usize }
    // ok: parallax-mldsa-borrow-pointwise-input
    fn pointwise_poly_montgomery() {
        for i in 0..L { self.vec[i].pointwise_montgomery(a, &v.vec[i]); }
    }
}

mod tests {
    fn official_reference_is_allowed_only_in_tests() {
        // ok: parallax-mldsa-no-unwiped-xof-wrapper
        let hash = sha3::Shake256::default();
        // ok: parallax-mldsa-no-unwiped-xof-wrapper
        hash.finalize_xof();
    }
}
