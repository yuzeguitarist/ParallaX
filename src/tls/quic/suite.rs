//! TLS 1.3 cipher suites and the HKDF/hash primitives the QUIC key schedule is
//! built from.
//!
//! These mirror the proven `TlsCipherSuite` helpers in [`crate::tls::safari26`]
//! (the TCP camouflage path) but are kept independent so the QUIC engine owns its
//! key schedule outright — the Phase-2 north star is a self-contained,
//! transport-agnostic core. The "tls13 " HKDF-Expand-Label prefix (RFC 8446 §7.1)
//! and the SHA-256/384 split are identical to the TCP path by construction.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

use super::QuicTlsError;

/// Wire codepoint for `TLS_AES_128_GCM_SHA256` (the QUIC v1 Initial suite).
pub(crate) const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
/// Wire codepoint for `TLS_AES_256_GCM_SHA384`.
pub(crate) const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
/// Wire codepoint for `TLS_CHACHA20_POLY1305_SHA256`.
pub(crate) const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// The three TLS 1.3 cipher suites a QUIC endpoint can negotiate (RFC 9001 pins
/// the Initial suite to `Aes128GcmSha256`; the handshake/1-RTT suite is whatever
/// the ServerHello selects from the Safari cipher list).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    /// Map a wire cipher-suite codepoint to the supported suite, or reject.
    pub(crate) fn from_u16(value: u16) -> Result<Self, QuicTlsError> {
        match value {
            TLS_AES_128_GCM_SHA256 => Ok(Self::Aes128GcmSha256),
            TLS_AES_256_GCM_SHA384 => Ok(Self::Aes256GcmSha384),
            TLS_CHACHA20_POLY1305_SHA256 => Ok(Self::ChaCha20Poly1305Sha256),
            _ => Err(QuicTlsError::alert(
                super::ALERT_ILLEGAL_PARAMETER,
                format!("server selected unsupported cipher suite {value:#06x}"),
            )),
        }
    }

    /// The wire codepoint for this suite (inverse of [`Self::from_u16`]).
    pub(crate) fn to_u16(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => TLS_AES_128_GCM_SHA256,
            Self::Aes256GcmSha384 => TLS_AES_256_GCM_SHA384,
            Self::ChaCha20Poly1305Sha256 => TLS_CHACHA20_POLY1305_SHA256,
        }
    }

    /// Output length of the suite hash (and of every derived secret): 32 for
    /// SHA-256 suites, 48 for SHA-384.
    pub(crate) fn hash_len(self) -> usize {
        match self {
            Self::Aes256GcmSha384 => 48,
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => 32,
        }
    }

    /// AEAD key length: 16 for AES-128-GCM, 32 for AES-256-GCM and
    /// ChaCha20-Poly1305. This is also the AES header-protection key length; the
    /// ChaCha20 header-protection key is the full 32-byte ChaCha key.
    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::ChaCha20Poly1305Sha256 => 32,
        }
    }

    /// Suite hash of `data` (one-shot), SHA-256 or SHA-384.
    pub(crate) fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Aes256GcmSha384 => Sha384::digest(data).to_vec(),
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => Sha256::digest(data).to_vec(),
        }
    }

    /// HMAC of `data` under `key`, with the suite hash (used for Finished
    /// verify_data).
    pub(crate) fn hmac(self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, QuicTlsError> {
        match self {
            Self::Aes256GcmSha384 => {
                let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key)
                    .map_err(|_| QuicTlsError::Crypto("HMAC-SHA384 key".into()))?;
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => {
                let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
                    .map_err(|_| QuicTlsError::Crypto("HMAC-SHA256 key".into()))?;
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
        }
    }

    /// HKDF-Extract (RFC 5869) under the suite hash.
    pub(crate) fn hkdf_extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match self {
            Self::Aes256GcmSha384 => {
                let (prk, _) = Hkdf::<Sha384>::extract(Some(salt), ikm);
                prk.to_vec()
            }
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => {
                let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
                prk.to_vec()
            }
        }
    }

    /// HKDF-Expand-Label (RFC 8446 §7.1): the universal TLS-1.3/QUIC key-schedule
    /// primitive. `label` is the bare label (e.g. `"quic key"`); the `"tls13 "`
    /// prefix is prepended here, so the wire label is `"tls13 quic key"`.
    pub(crate) fn hkdf_expand_label(
        self,
        secret: &[u8],
        label: &str,
        context: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, QuicTlsError> {
        // The wire encoding packs `full_label_len`, `context.len()`, and `len`
        // into u8/u16 fields. Every internal caller uses short constant labels and
        // bounded contexts (hashes ≤48 B), so these never overflow in practice —
        // but a raw `as u8`/`as u16` would SILENTLY TRUNCATE an over-long input and
        // derive a subtly wrong key. Fail closed instead: reject anything that does
        // not fit the RFC 8446 §7.1 wire fields rather than truncating in release.
        let full_label_len = 6 + label.len();
        if full_label_len > u8::MAX as usize {
            return Err(QuicTlsError::Crypto(
                "HKDF-Expand-Label label exceeds the u8 wire length".into(),
            ));
        }
        if context.len() > u8::MAX as usize {
            return Err(QuicTlsError::Crypto(
                "HKDF-Expand-Label context exceeds the u8 wire length".into(),
            ));
        }
        if len > u16::MAX as usize {
            return Err(QuicTlsError::Crypto(
                "HKDF-Expand-Label output exceeds the u16 wire length".into(),
            ));
        }
        let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1 + context.len());
        info.extend_from_slice(&(len as u16).to_be_bytes());
        info.push(full_label_len as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label.as_bytes());
        info.push(context.len() as u8);
        info.extend_from_slice(context);

        let mut out = vec![0_u8; len];
        let expand = |res: Result<(), hkdf::InvalidLength>| {
            res.map_err(|_| QuicTlsError::Crypto("HKDF-Expand-Label length".into()))
        };
        match self {
            Self::Aes256GcmSha384 => expand(
                Hkdf::<Sha384>::from_prk(secret)
                    .map_err(|_| QuicTlsError::Crypto("HKDF PRK length".into()))?
                    .expand(&info, &mut out),
            )?,
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => expand(
                Hkdf::<Sha256>::from_prk(secret)
                    .map_err(|_| QuicTlsError::Crypto("HKDF PRK length".into()))?
                    .expand(&info, &mut out),
            )?,
        }
        Ok(out)
    }

    /// Derive-Secret (RFC 8446): HKDF-Expand-Label keyed by `secret`, with
    /// `transcript_hash` as the context and the suite hash length as the output.
    /// `transcript_hash` is the already-computed running transcript hash snapshot.
    pub(crate) fn derive_secret(
        self,
        secret: &[u8],
        label: &str,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>, QuicTlsError> {
        self.hkdf_expand_label(secret, label, transcript_hash, self.hash_len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_params_match_rfc8446() {
        assert_eq!(CipherSuite::Aes128GcmSha256.hash_len(), 32);
        assert_eq!(CipherSuite::Aes128GcmSha256.key_len(), 16);
        assert_eq!(CipherSuite::Aes256GcmSha384.hash_len(), 48);
        assert_eq!(CipherSuite::Aes256GcmSha384.key_len(), 32);
        assert_eq!(CipherSuite::ChaCha20Poly1305Sha256.hash_len(), 32);
        assert_eq!(CipherSuite::ChaCha20Poly1305Sha256.key_len(), 32);
    }

    #[test]
    fn from_u16_rejects_non_tls13_suite() {
        assert!(CipherSuite::from_u16(0x1301).is_ok());
        assert!(CipherSuite::from_u16(0x1302).is_ok());
        assert!(CipherSuite::from_u16(0x1303).is_ok());
        assert!(CipherSuite::from_u16(0xc02f).is_err());
    }

    #[test]
    fn to_u16_is_inverse_of_from_u16() {
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            assert_eq!(CipherSuite::from_u16(suite.to_u16()).unwrap(), suite);
        }
        assert_eq!(CipherSuite::Aes128GcmSha256.to_u16(), 0x1301);
        assert_eq!(CipherSuite::Aes256GcmSha384.to_u16(), 0x1302);
        assert_eq!(CipherSuite::ChaCha20Poly1305Sha256.to_u16(), 0x1303);
    }

    #[test]
    fn sha384_digest_and_hmac_known_answers() {
        let suite = CipherSuite::Aes256GcmSha384;
        // SHA-384("") known digest (FIPS 180-4 / NIST example).
        let empty = suite.digest(&[]);
        let empty_hex: String = empty.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            empty_hex,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
             274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(empty.len(), 48);
        // RFC 4231 HMAC-SHA-384 test case 1: key=0x0b x20, data="Hi There".
        let mac = suite.hmac(&[0x0b; 20], b"Hi There").unwrap();
        let mac_hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            mac_hex,
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
             faea9ea9076ede7f4af152e8b2fa9cb6"
        );
    }

    #[test]
    fn hkdf_expand_label_rejects_over_long_inputs_instead_of_truncating() {
        // The wire fields are u8 (full label), u8 (context), u16 (output). Inputs
        // that would overflow those must fail closed rather than silently truncate
        // via `as u8`/`as u16` and derive a wrong key. `full_label_len = 6 + label`,
        // so a 250-byte label overflows the u8 (6 + 250 = 256).
        let suite = CipherSuite::Aes128GcmSha256;
        // Throwaway PRK from a runtime RNG (the length guard is independent of its
        // value). A fixed test salt would trip CodeQL's
        // `rust/hard-coded-cryptographic-value` query (a false positive on a test
        // fixture); an OsRng-filled salt is not a hard-coded value.
        use rand::RngCore as _;
        let mut salt = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let prk = suite.hkdf_extract(&salt, &salt);

        assert!(matches!(
            suite.hkdf_expand_label(&prk, &"x".repeat(250), &[], 16),
            Err(QuicTlsError::Crypto(_))
        ));
        assert!(matches!(
            suite.hkdf_expand_label(&prk, "key", &[0_u8; 256], 16),
            Err(QuicTlsError::Crypto(_))
        ));
        assert!(matches!(
            suite.hkdf_expand_label(&prk, "key", &[], u16::MAX as usize + 1),
            Err(QuicTlsError::Crypto(_))
        ));

        // The boundary values that DO fit the wire fields still succeed (the guard
        // rejects only genuine overflow, not the largest legal input): a 249-byte
        // label (6 + 249 = 255) and a 255-byte context.
        assert!(suite
            .hkdf_expand_label(&prk, &"x".repeat(249), &[0_u8; 255], 16)
            .is_ok());
    }

    #[test]
    fn hkdf_expand_label_matches_rfc8448_empty_hash_derive() {
        // RFC 8448 §3: Early Secret = HKDF-Extract(0, 0) for SHA-256,
        // then derived = Derive-Secret(Early, "derived", "") which is well-known:
        //   early  = 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a
        //   derived= 6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba
        let suite = CipherSuite::Aes128GcmSha256;
        let zeros = [0_u8; 32];
        let early = suite.hkdf_extract(&zeros, &zeros);
        let early_hex: String = early.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            early_hex,
            "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
        );
        let empty_hash = suite.digest(&[]);
        let derived = suite.derive_secret(&early, "derived", &empty_hash).unwrap();
        let derived_hex: String = derived.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            derived_hex,
            "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"
        );
    }
}
