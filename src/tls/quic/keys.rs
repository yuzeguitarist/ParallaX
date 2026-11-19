//! QUIC packet protection (AEAD) and header protection (RFC 9001 §5.3 / §5.4),
//! plus the per-direction / per-space key aggregates the engine and transport
//! pass around.
//!
//! These are ParallaX-owned types with inherent methods used directly by the
//! hand-written transport's packet/header protection; the engine names no quinn
//! type. AEAD uses AWS-LC (`aws-lc-rs`, already the TLS provider's backend);
//! header-protection masks use a raw single-block AES-ECB (`aes`) or a ChaCha20
//! keystream (`chacha20`).

use aes::{Aes128Enc, Aes256Enc};
use aws_lc_rs::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};
use chacha20::ChaCha20;
use chacha20poly1305::aead::KeyInit;
use cipher::generic_array::GenericArray;
use cipher::{BlockEncrypt, KeyIvInit, StreamCipher, StreamCipherSeek};
use zeroize::{Zeroize, Zeroizing};

use super::suite::CipherSuite;
use super::QuicTlsError;

/// AEAD tag length for every supported suite (RFC 9001 §5.3).
pub const AEAD_TAG_LEN: usize = 16;
/// QUIC AEAD nonce / IV length (RFC 9001 §5.3).
const IV_LEN: usize = 12;
/// Header-protection sample length for every supported suite (RFC 9001 §5.4.2).
const SAMPLE_LEN: usize = 16;
/// Header-protection mask length actually consumed (1 first-byte + up to 4 PN).
const MASK_LEN: usize = 5;

/// A generic local/remote pair (mirrors quinn-proto's `crypto::KeyPair`).
pub struct KeyPair<T> {
    /// Key that protects outbound packets.
    pub local: T,
    /// Key that unprotects inbound packets.
    pub remote: T,
}

/// One direction's full protection key set for a packet-number space.
pub struct DirectionalKeys {
    pub packet: PacketKey,
    pub header: HeaderProtectionKey,
}

impl DirectionalKeys {
    /// Derive `quic key`/`quic iv`/`quic hp` from a traffic `secret` (RFC 9001
    /// §5.1). The same secret feeds both the packet AEAD and the header
    /// protection.
    pub(crate) fn from_secret(suite: CipherSuite, secret: &[u8]) -> Result<Self, QuicTlsError> {
        Ok(Self {
            packet: PacketKey::from_secret(suite, secret)?,
            header: HeaderProtectionKey::from_secret(suite, secret)?,
        })
    }
}

/// Both directions' keys for one packet-number space (Initial / Handshake / 1-RTT).
pub struct Keys {
    pub local: DirectionalKeys,
    pub remote: DirectionalKeys,
}

/// Packet-protection AEAD key for one direction of one packet-number space.
///
/// Holds the `quic iv` and an AWS-LC AEAD context keyed with `quic key`, built
/// once per key so the key schedule is not re-expanded per packet; AWS-LC
/// cleanses the context on drop. The QUIC packet number is supplied per call
/// and folded into the nonce as `iv XOR pad(pn)`.
pub struct PacketKey {
    suite: CipherSuite,
    aead: LessSafeKey,
    iv: [u8; IV_LEN],
    /// Raw key for the RustCrypto differential reference in tests.
    #[cfg(test)]
    key: Zeroizing<Vec<u8>>,
}

impl PacketKey {
    pub(crate) fn from_secret(suite: CipherSuite, secret: &[u8]) -> Result<Self, QuicTlsError> {
        let key =
            Zeroizing::new(suite.hkdf_expand_label(secret, "quic key", &[], suite.key_len())?);
        let iv_vec = Zeroizing::new(suite.hkdf_expand_label(secret, "quic iv", &[], IV_LEN)?);
        let mut iv = [0_u8; IV_LEN];
        iv.copy_from_slice(&iv_vec);
        let algorithm = match suite {
            CipherSuite::Aes128GcmSha256 => &AES_128_GCM,
            CipherSuite::Aes256GcmSha384 => &AES_256_GCM,
            CipherSuite::ChaCha20Poly1305Sha256 => &CHACHA20_POLY1305,
        };
        let aead = UnboundKey::new(algorithm, &key)
            .map(LessSafeKey::new)
            .map_err(|_| QuicTlsError::Crypto("invalid packet key".into()))?;
        Ok(Self {
            suite,
            aead,
            iv,
            #[cfg(test)]
            key,
        })
    }

    /// AEAD tag length (always 16).
    pub fn tag_len(&self) -> usize {
        AEAD_TAG_LEN
    }

    /// RFC 9001 §6.6 confidentiality limit (max packets before a forced key
    /// update): 2^23 for AES-GCM, effectively unlimited for ChaCha20-Poly1305.
    pub fn confidentiality_limit(&self) -> u64 {
        match self.suite {
            CipherSuite::Aes128GcmSha256 | CipherSuite::Aes256GcmSha384 => 1 << 23,
            CipherSuite::ChaCha20Poly1305Sha256 => u64::MAX,
        }
    }

    /// RFC 9001 §6.6 integrity limit (max forged packets tolerated): 2^52 for
    /// AES-GCM, 2^36 for ChaCha20-Poly1305.
    pub fn integrity_limit(&self) -> u64 {
        match self.suite {
            CipherSuite::Aes128GcmSha256 | CipherSuite::Aes256GcmSha384 => 1 << 52,
            CipherSuite::ChaCha20Poly1305Sha256 => 1 << 36,
        }
    }

    /// Nonce = `iv XOR pad(pn)` (RFC 9001 §5.3): the 64-bit packet number is
    /// written big-endian into the low 8 bytes of the 12-byte IV.
    fn nonce(&self, packet_number: u64) -> [u8; IV_LEN] {
        let mut nonce = self.iv;
        let pn = packet_number.to_be_bytes();
        for (dst, src) in nonce[IV_LEN - 8..].iter_mut().zip(pn) {
            *dst ^= src;
        }
        nonce
    }

    /// Seal in place. `buf` is `[plaintext .. | AEAD_TAG_LEN reserved]`; on return
    /// the plaintext region is ciphertext and the trailing region holds the tag.
    /// `header` is the unprotected packet header (the AEAD AAD).
    pub fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        buf: &mut [u8],
    ) -> Result<(), QuicTlsError> {
        if buf.len() < AEAD_TAG_LEN {
            return Err(QuicTlsError::Crypto(
                "packet buffer shorter than tag".into(),
            ));
        }
        let split = buf.len() - AEAD_TAG_LEN;
        let (plaintext, tag_out) = buf.split_at_mut(split);
        let nonce = Nonce::assume_unique_for_key(self.nonce(packet_number));
        let tag = self
            .aead
            .seal_in_place_separate_tag(nonce, Aad::from(header), plaintext)
            .map_err(|_| QuicTlsError::Crypto("AEAD seal failed".into()))?;
        tag_out.copy_from_slice(tag.as_ref());
        Ok(())
    }

    /// Open in place. `buf` is `[ciphertext | AEAD_TAG_LEN tag]`; on success the
    /// returned slice is the decrypted plaintext (the leading region of `buf`).
    pub fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        buf: &'a mut [u8],
    ) -> Result<&'a [u8], QuicTlsError> {
        if buf.len() < AEAD_TAG_LEN {
            return Err(QuicTlsError::alert(
                super::ALERT_BAD_RECORD_MAC,
                "packet shorter than AEAD tag",
            ));
        }
        let nonce = Nonce::assume_unique_for_key(self.nonce(packet_number));
        self.aead
            .open_in_place(nonce, Aad::from(header), buf)
            .map(|plaintext| &*plaintext)
            .map_err(|_| QuicTlsError::alert(super::ALERT_BAD_RECORD_MAC, "AEAD open failed"))
    }
}

impl Drop for PacketKey {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

/// Header-protection key for one direction of one packet-number space.
///
/// Holds the raw `quic hp` key; the mask cipher is built per packet. AES suites
/// use a single 16-byte ECB block; ChaCha20 uses a keystream block seeded from
/// the sample (RFC 9001 §5.4.3 / §5.4.4). The header-protection key is NOT rotated
/// on a 1-RTT key update (RFC 9001 §6).
pub struct HeaderProtectionKey {
    suite: CipherSuite,
    key: Zeroizing<Vec<u8>>,
}

impl HeaderProtectionKey {
    pub(crate) fn from_secret(suite: CipherSuite, secret: &[u8]) -> Result<Self, QuicTlsError> {
        let key =
            Zeroizing::new(suite.hkdf_expand_label(secret, "quic hp", &[], suite.key_len())?);
        Ok(Self { suite, key })
    }

    /// Header-protection sample length (16 for every supported suite).
    pub fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }

    /// Compute the 5-byte header-protection mask from the 16-byte `sample`.
    fn mask(&self, sample: &[u8]) -> [u8; MASK_LEN] {
        let mut mask = [0_u8; MASK_LEN];
        match self.suite {
            CipherSuite::Aes128GcmSha256 => {
                let cipher = Aes128Enc::new(GenericArray::from_slice(&self.key));
                let mut block = *GenericArray::from_slice(sample);
                cipher.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..MASK_LEN]);
            }
            CipherSuite::Aes256GcmSha384 => {
                let cipher = Aes256Enc::new(GenericArray::from_slice(&self.key));
                let mut block = *GenericArray::from_slice(sample);
                cipher.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..MASK_LEN]);
            }
            CipherSuite::ChaCha20Poly1305Sha256 => {
                // RFC 9001 §5.4.4: counter = sample[0..4] little-endian,
                // nonce = sample[4..16]; mask = first 5 keystream bytes.
                let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
                let nonce = GenericArray::from_slice(&sample[4..16]);
                let mut cipher = ChaCha20::new(GenericArray::from_slice(&self.key), nonce);
                // Seek to block `counter` (64 bytes/block) within the keystream.
                cipher.seek(u64::from(counter) * 64);
                cipher.apply_keystream(&mut mask);
            }
        }
        mask
    }

    /// Apply header protection to an outbound packet (RFC 9001 §5.4.1). `pn_offset`
    /// is the byte offset of the packet-number field; the packet number must still
    /// be plaintext.
    pub fn encrypt_header(&self, pn_offset: usize, packet: &mut [u8]) -> Result<(), QuicTlsError> {
        let (first_mask, pn_mask, first_bits) = self.header_mask(pn_offset, packet)?;
        // PN length is read from the (still-plaintext) first byte before masking.
        let pn_len = ((packet[0] & 0x03) as usize) + 1;
        packet[0] ^= first_mask & first_bits;
        for i in 0..pn_len {
            packet[pn_offset + i] ^= pn_mask[i];
        }
        Ok(())
    }

    /// Remove header protection from an inbound packet (RFC 9001 §5.4.1).
    /// Unmasks the first byte first to recover the packet-number length, then
    /// unmasks exactly that many packet-number bytes.
    pub fn decrypt_header(&self, pn_offset: usize, packet: &mut [u8]) -> Result<(), QuicTlsError> {
        let (first_mask, pn_mask, first_bits) = self.header_mask(pn_offset, packet)?;
        packet[0] ^= first_mask & first_bits;
        let pn_len = ((packet[0] & 0x03) as usize) + 1;
        for i in 0..pn_len {
            packet[pn_offset + i] ^= pn_mask[i];
        }
        Ok(())
    }

    /// Shared mask derivation for encrypt/decrypt: returns
    /// `(first_byte_mask, pn_mask[..4], first_byte_bit_mask)`. The first-byte bit
    /// mask is 0x0f for long headers and 0x1f for short headers (RFC 9001 §5.4.1).
    fn header_mask(
        &self,
        pn_offset: usize,
        packet: &[u8],
    ) -> Result<(u8, [u8; 4], u8), QuicTlsError> {
        let sample_start = pn_offset + 4;
        let sample_end = sample_start + SAMPLE_LEN;
        if sample_end > packet.len() {
            return Err(QuicTlsError::alert(
                super::ALERT_DECODE_ERROR,
                "packet too short for header-protection sample",
            ));
        }
        let mask = self.mask(&packet[sample_start..sample_end]);
        let first_bits = if packet[0] & 0x80 != 0 { 0x0f } else { 0x1f };
        let pn_mask = [mask[1], mask[2], mask[3], mask[4]];
        Ok((mask[0], pn_mask, first_bits))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::AeadInPlace;
    use chacha20poly1305::ChaCha20Poly1305;

    // Keep the original full AES types independent of the production aliases.
    fn legacy_encrypt(
        key: &PacketKey,
        packet_number: u64,
        header: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, QuicTlsError> {
        if buf.len() < AEAD_TAG_LEN {
            return Err(QuicTlsError::Crypto(
                "packet buffer shorter than tag".into(),
            ));
        }
        let split = buf.len() - AEAD_TAG_LEN;
        let (plaintext, tag_out) = buf.split_at_mut(split);
        let nonce = GenericArray::from_slice(&key.nonce(packet_number)[..]).to_owned();
        let aead_err = || QuicTlsError::Crypto("AEAD seal failed".into());
        let tag = match key.suite {
            CipherSuite::Aes128GcmSha256 => aes_gcm::Aes128Gcm::new_from_slice(&key.key)
                .map_err(|_| aead_err())?
                .encrypt_in_place_detached(&nonce, header, plaintext)
                .map_err(|_| aead_err())?,
            CipherSuite::Aes256GcmSha384 => aes_gcm::Aes256Gcm::new_from_slice(&key.key)
                .map_err(|_| aead_err())?
                .encrypt_in_place_detached(&nonce, header, plaintext)
                .map_err(|_| aead_err())?,
            CipherSuite::ChaCha20Poly1305Sha256 => ChaCha20Poly1305::new_from_slice(&key.key)
                .map_err(|_| aead_err())?
                .encrypt_in_place_detached(&nonce, header, plaintext)
                .map_err(|_| aead_err())?,
        };
        tag_out.copy_from_slice(&tag);
        Ok(split)
    }

    fn current_encrypt(
        key: &PacketKey,
        packet_number: u64,
        header: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, QuicTlsError> {
        key.encrypt_in_place(packet_number, header, buf)?;
        Ok(buf.len() - AEAD_TAG_LEN)
    }

    fn legacy_decrypt(
        key: &PacketKey,
        packet_number: u64,
        header: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, QuicTlsError> {
        if buf.len() < AEAD_TAG_LEN {
            return Err(QuicTlsError::alert(
                super::super::ALERT_BAD_RECORD_MAC,
                "packet shorter than AEAD tag",
            ));
        }
        let pt_len = buf.len() - AEAD_TAG_LEN;
        let nonce = GenericArray::from_slice(&key.nonce(packet_number)[..]).to_owned();
        let aead_err =
            || QuicTlsError::alert(super::super::ALERT_BAD_RECORD_MAC, "AEAD open failed");
        let (ciphertext, tag) = buf.split_at_mut(pt_len);
        let tag = GenericArray::from_slice(tag);
        match key.suite {
            CipherSuite::Aes128GcmSha256 => aes_gcm::Aes128Gcm::new_from_slice(&key.key)
                .map_err(|_| aead_err())?
                .decrypt_in_place_detached(&nonce, header, ciphertext, tag)
                .map_err(|_| aead_err())?,
            CipherSuite::Aes256GcmSha384 => aes_gcm::Aes256Gcm::new_from_slice(&key.key)
                .map_err(|_| aead_err())?
                .decrypt_in_place_detached(&nonce, header, ciphertext, tag)
                .map_err(|_| aead_err())?,
            CipherSuite::ChaCha20Poly1305Sha256 => ChaCha20Poly1305::new_from_slice(&key.key)
                .map_err(|_| aead_err())?
                .decrypt_in_place_detached(&nonce, header, ciphertext, tag)
                .map_err(|_| aead_err())?,
        }
        Ok(pt_len)
    }

    fn current_decrypt(
        key: &PacketKey,
        packet_number: u64,
        header: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, QuicTlsError> {
        key.decrypt_in_place(packet_number, header, buf)
            .map(|plaintext| plaintext.len())
    }

    fn legacy_mask(key: &HeaderProtectionKey, sample: &[u8]) -> [u8; MASK_LEN] {
        let mut mask = [0; MASK_LEN];
        match key.suite {
            CipherSuite::Aes128GcmSha256 => {
                let cipher = aes::Aes128::new(GenericArray::from_slice(&key.key));
                let mut block = *GenericArray::from_slice(sample);
                cipher.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..MASK_LEN]);
            }
            CipherSuite::Aes256GcmSha384 => {
                let cipher = aes::Aes256::new(GenericArray::from_slice(&key.key));
                let mut block = *GenericArray::from_slice(sample);
                cipher.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..MASK_LEN]);
            }
            CipherSuite::ChaCha20Poly1305Sha256 => {
                let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
                let nonce = GenericArray::from_slice(&sample[4..16]);
                let mut cipher = ChaCha20::new(GenericArray::from_slice(&key.key), nonce);
                cipher.seek(u64::from(counter) * 64);
                cipher.apply_keystream(&mut mask);
            }
        }
        mask
    }

    #[test]
    fn packet_protection_matches_full_aes_bytes_errors_and_failed_buffers() {
        let header = b"\xc3header-bytes";
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let secret = vec![0x42; suite.hash_len()];
            let key = PacketKey::from_secret(suite, &secret).unwrap();
            for packet_number in [0, 1, u32::MAX as u64, 1 << 32, u64::MAX] {
                for len in [0, 1, 64, 1200, 16384] {
                    let plaintext: Vec<_> = (0..len).map(|index| index as u8).collect();
                    for aad in [header.as_slice(), &[]] {
                        let mut actual = plaintext.clone();
                        actual.resize(len + AEAD_TAG_LEN, 0);
                        let mut expected = actual.clone();
                        let result = current_encrypt(&key, packet_number, aad, &mut actual);
                        let reference = legacy_encrypt(&key, packet_number, aad, &mut expected);
                        assert_eq!(format!("{result:?}"), format!("{reference:?}"));
                        assert_eq!(actual, expected);
                        assert_eq!(result.unwrap(), len);
                        let sealed = actual.clone();
                        let result = current_decrypt(&key, packet_number, aad, &mut actual);
                        let reference = legacy_decrypt(&key, packet_number, aad, &mut expected);
                        assert_eq!(format!("{result:?}"), format!("{reference:?}"));
                        assert_eq!(actual, expected);
                        assert_eq!(&actual[..result.unwrap()], plaintext);

                        for failure in 0..3 {
                            let mut actual = sealed.clone();
                            let mut expected = sealed.clone();
                            let (pn, bad_aad) = match failure {
                                0 => {
                                    *actual.last_mut().unwrap() ^= 1;
                                    *expected.last_mut().unwrap() ^= 1;
                                    (packet_number, aad)
                                }
                                1 => (packet_number, b"different header".as_slice()),
                                _ => (packet_number ^ 1, aad),
                            };
                            let result = current_decrypt(&key, pn, bad_aad, &mut actual);
                            let reference = legacy_decrypt(&key, pn, bad_aad, &mut expected);
                            assert!(result.is_err());
                            assert_eq!(format!("{result:?}"), format!("{reference:?}"));
                            // AWS-LC clears the rejected plaintext region; the tag
                            // and everything outside the packet stay untouched.
                            assert_eq!(actual[len..], expected[len..]);
                        }
                    }
                }
            }
            for len in 0..AEAD_TAG_LEN {
                for (current, legacy) in [
                    (
                        current_encrypt as PacketOperation,
                        legacy_encrypt as PacketOperation,
                    ),
                    (
                        current_decrypt as PacketOperation,
                        legacy_decrypt as PacketOperation,
                    ),
                ] {
                    let mut actual = vec![0x5a; len];
                    let mut expected = actual.clone();
                    let result = current(&key, 7, header, &mut actual);
                    let reference = legacy(&key, 7, header, &mut expected);
                    assert!(result.is_err());
                    assert_eq!(format!("{result:?}"), format!("{reference:?}"));
                    assert_eq!(actual, expected);
                }
            }
            let hp = HeaderProtectionKey::from_secret(suite, &secret).unwrap();
            for seed in 0..64u8 {
                let sample: [u8; SAMPLE_LEN] =
                    std::array::from_fn(|index| seed.wrapping_add((index * 17) as u8));
                assert_eq!(hp.mask(&sample), legacy_mask(&hp, &sample));
            }
        }
    }

    type PacketOperation = fn(&PacketKey, u64, &[u8], &mut [u8]) -> Result<usize, QuicTlsError>;

    /// Same-process controls for per-packet cipher construction and protection.
    /// Run in release mode with --ignored --nocapture.
    #[test]
    #[ignore = "key protection timing benchmark; run manually in release mode"]
    fn packet_key_protection_benchmark() {
        use std::{hint::black_box, time::Instant};

        const ITERATIONS: u64 = if cfg!(debug_assertions) { 32 } else { 10_000 };
        const SAMPLES: usize = 7;
        let header = b"\xc3header-bytes";
        let packet_number = 0x1_0000_ffff;
        let report = |suite: CipherSuite, name: &str, mut samples: Vec<f64>| {
            samples.sort_by(f64::total_cmp);
            eprintln!(
                "packet key {suite:?}, {name}: ns/op samples={samples:?}, median={:.0}",
                samples[SAMPLES / 2],
            );
        };
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let secret = vec![0x42; suite.hash_len()];
            let key = PacketKey::from_secret(suite, &secret).unwrap();
            for len in [64, 1200] {
                for open in [false, true] {
                    let mut fixture = vec![0x5a; len + AEAD_TAG_LEN];
                    if open {
                        legacy_encrypt(&key, packet_number, header, &mut fixture).unwrap();
                    }
                    let operations: [PacketOperation; 2] = if open {
                        [current_decrypt, legacy_decrypt]
                    } else {
                        [current_encrypt, legacy_encrypt]
                    };
                    let mut scratch = fixture.clone();
                    let mut samples = [Vec::with_capacity(SAMPLES), Vec::with_capacity(SAMPLES)];
                    for sample in 0..=SAMPLES {
                        let order = if sample % 2 == 0 { [0, 1] } else { [1, 0] };
                        for index in order {
                            let start = Instant::now();
                            for _ in 0..ITERATIONS {
                                scratch.copy_from_slice(&fixture);
                                black_box(
                                    black_box(operations[index])(
                                        &key,
                                        packet_number,
                                        header,
                                        &mut scratch,
                                    )
                                    .unwrap(),
                                );
                            }
                            let elapsed = start.elapsed().as_secs_f64() * 1e9 / ITERATIONS as f64;
                            if sample != 0 {
                                samples[index].push(elapsed);
                            }
                        }
                    }
                    let name = format!("{}-{len}", if open { "open" } else { "seal" });
                    report(suite, &name, std::mem::take(&mut samples[0]));
                    report(
                        suite,
                        &format!("{name}-legacy"),
                        std::mem::take(&mut samples[1]),
                    );
                }
            }
            type MaskOperation = fn(&HeaderProtectionKey, &[u8]) -> [u8; MASK_LEN];
            let hp = HeaderProtectionKey::from_secret(suite, &secret).unwrap();
            let masks: [MaskOperation; 2] = [HeaderProtectionKey::mask, legacy_mask];
            let mut samples = [Vec::with_capacity(SAMPLES), Vec::with_capacity(SAMPLES)];
            let mut sample_bytes = [0x5a; SAMPLE_LEN];
            for sample in 0..=SAMPLES {
                let order = if sample % 2 == 0 { [0, 1] } else { [1, 0] };
                for index in order {
                    let start = Instant::now();
                    for counter in 0..ITERATIONS {
                        sample_bytes[..4].copy_from_slice(&(counter as u32).to_le_bytes());
                        black_box(black_box(masks[index])(&hp, &sample_bytes));
                    }
                    let elapsed = start.elapsed().as_secs_f64() * 1e9 / ITERATIONS as f64;
                    if sample != 0 {
                        samples[index].push(elapsed);
                    }
                }
            }
            report(suite, "hp", std::mem::take(&mut samples[0]));
            report(suite, "hp-legacy", std::mem::take(&mut samples[1]));
        }
    }

    // RFC 9001 Appendix A.2/A.3 client Initial vectors. DCID 8394c8f03e515708.
    const CLIENT_KEY: &str = "1f369613dd76d5467730efcbe3b1a22d";
    const CLIENT_IV: &str = "fa044b2f42a3fd3b46fb255c";
    const CLIENT_HP: &str = "9f50449e04a0e810283a1e9933adedd2";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn client_initial_keys() -> (PacketKey, HeaderProtectionKey) {
        let suite = CipherSuite::Aes128GcmSha256;
        // RFC 9001 §5.2 QUIC v1 Initial salt.
        let salt = unhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
        let dcid = unhex("8394c8f03e515708");
        let initial_secret = suite.hkdf_extract(&salt, &dcid);
        let client_secret = suite
            .hkdf_expand_label(&initial_secret, "client in", &[], 32)
            .unwrap();
        (
            PacketKey::from_secret(suite, &client_secret).unwrap(),
            HeaderProtectionKey::from_secret(suite, &client_secret).unwrap(),
        )
    }

    #[test]
    fn initial_packet_key_iv_match_rfc9001() {
        let (pk, hp) = client_initial_keys();
        assert_eq!(pk.key.to_vec(), unhex(CLIENT_KEY));
        assert_eq!(pk.iv.to_vec(), unhex(CLIENT_IV));
        assert_eq!(hp.key.to_vec(), unhex(CLIENT_HP));
    }

    #[test]
    fn nonce_xors_packet_number_right_aligned() {
        let (pk, _) = client_initial_keys();
        // RFC 9001 Appendix A.2 uses packet number 2; nonce = iv XOR 0x..0002.
        let nonce = pk.nonce(2);
        let mut expected = unhex(CLIENT_IV);
        expected[IV_LEN - 1] ^= 2;
        assert_eq!(nonce.to_vec(), expected);
    }

    #[test]
    fn aead_seal_open_roundtrip_all_suites() {
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let secret = vec![0x42_u8; suite.hash_len()];
            let pk = PacketKey::from_secret(suite, &secret).unwrap();
            let header = b"\xc3header-bytes";
            let plaintext = b"the quick brown fox";
            let mut buf = Vec::from(&plaintext[..]);
            buf.extend_from_slice(&[0_u8; AEAD_TAG_LEN]);
            pk.encrypt_in_place(7, header, &mut buf).unwrap();
            assert_ne!(
                &buf[..plaintext.len()],
                &plaintext[..],
                "ciphertext differs"
            );
            let pt = pk.decrypt_in_place(7, header, &mut buf).unwrap();
            assert_eq!(pt, &plaintext[..]);
        }
    }

    #[test]
    fn aead_open_rejects_tampered_tag() {
        let suite = CipherSuite::Aes128GcmSha256;
        let secret = vec![0x11_u8; 32];
        let pk = PacketKey::from_secret(suite, &secret).unwrap();
        let mut buf = Vec::from(&b"payload"[..]);
        buf.extend_from_slice(&[0_u8; AEAD_TAG_LEN]);
        pk.encrypt_in_place(1, b"hdr", &mut buf).unwrap();
        let last = buf.len() - 1;
        buf[last] ^= 0x01;
        assert!(pk.decrypt_in_place(1, b"hdr", &mut buf).is_err());
    }

    #[test]
    fn header_protect_unprotect_roundtrip_long_header() {
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let secret = vec![0x7e_u8; suite.hash_len()];
            let hp = HeaderProtectionKey::from_secret(suite, &secret).unwrap();
            // Long header (first byte high bit set), 4-byte PN at offset 5,
            // followed by >=16 bytes of "ciphertext" to sample.
            let mut packet = vec![0xc3_u8, 0, 0, 0, 0, 1, 2, 3, 4];
            packet.extend_from_slice(&[0xaa_u8; 20]);
            let original = packet.clone();
            hp.encrypt_header(5, &mut packet).unwrap();
            assert_ne!(packet, original, "header protection changed the bytes");
            hp.decrypt_header(5, &mut packet).unwrap();
            assert_eq!(packet, original, "unprotect inverts protect");
        }
    }
}
