// These syntactic fixtures are parsed by Semgrep, not compiled as Rust.

// ruleid: parallax-owned-signing-key-copy
fn copied_key(sk: &[u8]) -> Result<[u8; SECRETKEYBYTES], KeyError> {
    Ok(core::array::from_fn(|i| sk[i]))
}

// ruleid: parallax-owned-signing-key-copy
fn bare_copied_key(sk: &[u8]) -> [u8; SECRETKEYBYTES] {
    core::array::from_fn(|i| sk[i])
}

// ok: parallax-owned-signing-key-copy
fn borrowed_key(sk: &[u8]) -> Result<&[u8; SECRETKEYBYTES], KeyError> {
    sk.try_into().map_err(|_| KeyError)
}

// ok: parallax-owned-signing-key-copy
fn zeroizing_key(sk: &[u8]) -> Zeroizing<[u8; SECRETKEYBYTES]> {
    Zeroizing::new(core::array::from_fn(|i| sk[i]))
}

// ruleid: parallax-by-value-array-wipe
fn copied_wipe(mut key: [u8; SECRETKEYBYTES]) {
    key.zeroize();
}

// ok: parallax-by-value-array-wipe
fn borrowed_wipe(key: &mut [u8; SECRETKEYBYTES]) {
    key.zeroize();
}

impl DataRecordCodec {
    fn guarded(&mut self, plaintext: &mut [u8]) -> Result<(), Error> {
        self.ensure_seal_budget(1)?;
        check_padded_len(plaintext.len())?;
        // ok: parallax-record-seal-guard
        self.aead.seal_in_place_detached(plaintext, self.aad)?;
        Ok(())
    }

    fn missing_guard(&mut self, plaintext: &mut [u8]) -> Result<(), Error> {
        check_padded_len(plaintext.len())?;
        // ruleid: parallax-record-seal-guard
        self.aead.seal_in_place_detached(plaintext, self.aad)?;
        Ok(())
    }

    fn late_guard(&mut self, plaintext: &mut [u8]) -> Result<(), Error> {
        // ruleid: parallax-record-seal-guard
        self.aead.seal_in_place_detached(plaintext, self.aad)?;
        self.ensure_seal_budget(1)?;
        check_padded_len(plaintext.len())?;
        Ok(())
    }

    fn ignored_guard(&mut self, plaintext: &mut [u8]) -> Result<(), Error> {
        let _ = self.ensure_seal_budget(1);
        check_padded_len(plaintext.len())?;
        // ruleid: parallax-record-seal-guard
        self.aead.seal_in_place_detached(plaintext, self.aad)?;
        Ok(())
    }

    fn false_branch_guard(&mut self, plaintext: &mut [u8]) -> Result<(), Error> {
        if false {
            self.ensure_seal_budget(1)?;
            check_padded_len(plaintext.len())?;
        }
        // ruleid: parallax-record-seal-guard
        self.aead.seal_in_place_detached(plaintext, self.aad)?;
        Ok(())
    }

    fn wrong_buffer_guard(&mut self, plaintext: &mut [u8]) -> Result<(), Error> {
        self.ensure_seal_budget(1)?;
        check_padded_len(other.len())?;
        // ruleid: parallax-record-seal-guard
        self.aead.seal_in_place_detached(plaintext, self.aad)?;
        Ok(())
    }

    fn wrong_direction_aad(&mut self, plaintext: &mut [u8]) -> Result<(), Error> {
        self.ensure_seal_budget(1)?;
        check_padded_len(plaintext.len())?;
        // ruleid: parallax-record-seal-direction-binding
        self.aead.seal_in_place_detached(plaintext, other_aad)?;
        Ok(())
    }

    fn allocating_primitive_bypass(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        // ruleid: parallax-record-allocating-seal-bypass
        self.aead.seal(plaintext, self.aad)?;
        Ok(())
    }

    fn aliased_allocating_bypass(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        let codec = &mut self.aead;
        // ruleid: parallax-record-allocating-seal-bypass
        codec.seal(plaintext, self.aad)?;
        Ok(())
    }

    fn qualified_allocating_bypass(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        // ruleid: parallax-record-allocating-seal-bypass
        AeadCodec::seal(&mut self.aead, plaintext, self.aad)?;
        Ok(())
    }

    fn own_record_seal(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        // ok: parallax-record-allocating-seal-bypass
        self.seal(plaintext, rng)?;
        Ok(())
    }

    fn seal_records_into_parallel(&mut self) -> Result<(), Error> {
        validate_record_lens(record_lens, plaintext.len())?;
        let record_count = record_lens.len();
        self.ensure_seal_budget(record_count)?;
        if record_count == 0 { return Ok(()); }
        let base = self.aead.reserve_sequence(record_count as u64)?;
        // ok: parallax-reserve-before-seal-dispatch
        let segments = parallel::dispatch_blocking(|| pool.run_ordered(jobs));
        Ok(())
    }

    fn seal_records_into_parallel(&mut self) -> Result<(), Error> {
        validate_record_lens(record_lens, plaintext.len())?;
        let record_count = record_lens.len();
        self.ensure_seal_budget(record_count)?;
        if record_count == 0 { return Ok(()); }
        // ruleid: parallax-reserve-before-seal-dispatch
        let segments = parallel::dispatch_blocking(|| pool.run_ordered(jobs));
        let base = self.aead.reserve_sequence(record_count as u64)?;
        Ok(())
    }

    fn seal_records_into_parallel(&mut self) -> Result<(), Error> {
        validate_record_lens(record_lens, plaintext.len())?;
        let record_count = record_lens.len();
        let _ = self.ensure_seal_budget(record_count);
        if record_count == 0 { return Ok(()); }
        let base = self.aead.reserve_sequence(record_count as u64)?;
        // ruleid: parallax-reserve-before-seal-dispatch
        let segments = parallel::dispatch_blocking(|| pool.run_ordered(jobs));
        Ok(())
    }

    fn seal_records_into_parallel(&mut self) -> Result<(), Error> {
        validate_record_lens(record_lens, plaintext.len())?;
        let record_count = record_lens.len();
        if false {
            self.ensure_seal_budget(record_count)?;
        }
        if record_count == 0 { return Ok(()); }
        let base = self.aead.reserve_sequence(record_count as u64)?;
        // ruleid: parallax-reserve-before-seal-dispatch
        let segments = parallel::dispatch_blocking(|| pool.run_ordered(jobs));
        Ok(())
    }

    fn seal_records_into_parallel(&mut self) -> Result<(), Error> {
        match segment {
            Ok(value) => sealed.push(value),
            Err(err) => {
                self.aead.poison();
                // ok: parallax-poison-failed-seal-worker
                return Err(err);
            }
        }
        Ok(())
    }

    fn seal_records_into_parallel(&mut self) -> Result<(), Error> {
        match segment {
            Ok(value) => sealed.push(value),
            Err(err) => {
                // ruleid: parallax-poison-failed-seal-worker
                return Err(err);
            }
        }
        Ok(())
    }
}

fn seal_worker_payload(plaintext: &mut [u8]) -> Result<(), Error> {
    check_padded_len(plaintext.len())?;
    // ok: parallax-worker-seal-length-guard
    session::seal_in_place_detached_with(cipher, nonce, seq, plaintext, aad)?;
    Ok(())
}

fn seal_worker_payload(plaintext: &mut [u8]) -> Result<(), Error> {
    // ruleid: parallax-worker-seal-length-guard
    session::seal_in_place_detached_with(cipher, nonce, seq, plaintext, aad)?;
    check_padded_len(plaintext.len())?;
    Ok(())
}

fn seal_worker_payload(plaintext: &mut [u8]) -> Result<(), Error> {
    check_padded_len(other.len())?;
    // ruleid: parallax-worker-seal-length-guard
    session::seal_in_place_detached_with(cipher, nonce, seq, plaintext, aad)?;
    Ok(())
}

fn arbitrary_unreserved_helper(plaintext: &mut [u8]) -> Result<(), Error> {
    check_padded_len(plaintext.len())?;
    // ruleid: parallax-raw-worker-seal-boundary
    session::seal_in_place_detached_with(cipher, nonce, seq, plaintext, aad)?;
    Ok(())
}

fn unqualified_primitive_bypass(plaintext: &mut [u8]) -> Result<(), Error> {
    check_padded_len(plaintext.len())?;
    // ruleid: parallax-raw-worker-seal-boundary
    seal_in_place_detached_with(cipher, nonce, seq, plaintext, aad)?;
    Ok(())
}

fn primitive_function_pointer_bypass(plaintext: &mut [u8]) -> Result<(), Error> {
    // ruleid: parallax-raw-worker-seal-boundary
    let raw = session::seal_in_place_detached_with;
    raw(cipher, nonce, seq, plaintext, aad)?;
    Ok(())
}

mod imported_primitive {
    use crate::crypto::session::seal_in_place_detached_with as raw_seal;

    fn aliased_primitive_bypass(plaintext: &mut [u8]) -> Result<(), Error> {
        check_padded_len(plaintext.len())?;
        // ruleid: parallax-raw-worker-seal-boundary
        raw_seal(cipher, nonce, seq, plaintext, aad)?;
        Ok(())
    }
}

fn seal_one_record_into() {
    // ok: parallax-worker-seal-boundary
    seal_worker_payload(cipher, nonce, seq, plaintext, aad);
}

fn bypass_builder() {
    // ruleid: parallax-worker-seal-boundary
    seal_worker_payload(cipher, nonce, seq, plaintext, aad);
}

fn seal_records_segment() {
    // ok: parallax-record-worker-boundary
    seal_one_record_into(cipher, nonce, seq, plaintext, aad);
}

fn bypass_reservation() {
    // ruleid: parallax-record-worker-boundary
    seal_one_record_into(cipher, nonce, seq, plaintext, aad);
}

// ok: parallax-exact-padding-capacity
fn exact_padded_record_capacity(payload_len: usize, total_pad: usize) -> Result<usize, Error> {
    if total_pad > u16::MAX as usize { return Err(record::TlsRecordError::PayloadTooLarge(total_pad).into()); }
    let tls_len = payload_len.checked_add(total_pad).and_then(|len| len.checked_add(PADDING_LEN_FIELD + AEAD_TAG_LEN)).ok_or(record::TlsRecordError::PayloadTooLarge(usize::MAX))?;
    if tls_len > OUTER_TLS_RECORD_LIMIT { return Err(record::TlsRecordError::PayloadTooLarge(tls_len).into()); }
    tls_len.checked_add(record::TLS_HEADER_LEN).ok_or(DataRecordError::InvalidExactPadding)
}
// ruleid: parallax-exact-padding-capacity
fn exact_padded_record_capacity(payload_len: usize, total_pad: usize) -> Result<usize, Error> { Ok(payload_len + total_pad + 23) }
// ok: parallax-exact-padding-whole-window
fn validate_exact_padded_record_lens(record_lens: &[usize], pad_lens: &[usize], plaintext_len: usize) -> Result<usize, Error> {
    validate_record_lens(record_lens, plaintext_len)?;
    if record_lens.len() != pad_lens.len() { return Err(DataRecordError::InvalidExactPadding); }
    record_lens.iter().zip(pad_lens).try_fold(0usize, |total, (&len, &pad)| {
        total.checked_add(exact_padded_record_capacity(len, pad)?).ok_or(DataRecordError::InvalidExactPadding)
    })
}
// ruleid: parallax-exact-padding-whole-window
fn validate_exact_padded_record_lens(record_lens: &[usize], pad_lens: &[usize], plaintext_len: usize) -> Result<usize, Error> { Ok(0) }
impl DataRecordCodec {
    // ok: parallax-exact-padding-batch-preflight
    fn seal_records_into_exact_padded(&mut self) -> Result<(), Error> {
        let reserve = validate_exact_padded_record_lens(record_lens, pad_lens, plaintext.len())?;
        self.ensure_seal_budget(record_lens.len())?;
        out.len().checked_add(reserve).ok_or(DataRecordError::InvalidExactPadding)?;
        out.reserve(reserve);
        let start = out.len();
        let mut offset = 0;
        for (&len, &pad) in record_lens.iter().zip(pad_lens) {
            if let Err(err) = self.seal_into_exact_padded(&plaintext[offset..offset + len], pad, rng, out) {
                self.aead.poison();
                out[start..].zeroize();
                out.truncate(start);
                return Err(err);
            }
            offset += len;
        }
        Ok(())
    }
    // ruleid: parallax-exact-padding-batch-preflight
    fn seal_records_into_exact_padded(&mut self) -> Result<(), Error> {
        self.seal_into_exact_padded(&plaintext[..1], 0, rng, out)?;
        let reserve = validate_exact_padded_record_lens(record_lens, pad_lens, plaintext.len())?;
        self.ensure_seal_budget(record_lens.len())?;
        out.len().checked_add(reserve).ok_or(DataRecordError::InvalidExactPadding)?;
        out.reserve(reserve);
        let start = out.len();
        let mut offset = 0;
        for (&len, &pad) in record_lens.iter().zip(pad_lens) {
            if let Err(err) = self.seal_into_exact_padded(&plaintext[offset..offset + len], pad, rng, out) {
                self.aead.poison();
                out[start..].zeroize();
                out.truncate(start);
                return Err(err);
            }
            offset += len;
        }
        Ok(())
    }
}
