use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const HYBRID_REKEY_IKM_FIXED_LEN: usize = 7 + 32 + 11 + 32 + 5 + 4;
const HYBRID_REKEY_IKM_STACK_LEN: usize = 128;

#[derive(Debug, Error)]
pub enum PqError {
    #[error("invalid ML-KEM public key")]
    InvalidPublicKey,
    #[error("invalid ML-KEM secret key")]
    InvalidSecretKey,
    #[error("invalid ML-KEM ciphertext")]
    InvalidCiphertext,
    /// Retained for symmetry with the sibling crypto error enums; pq.rs currently uses only the infallible Hkdf::extract, so this is not constructed here.
    #[error("HKDF expansion failed")]
    Hkdf,
    #[error("degenerate (all-zero) X25519 shared secret")]
    DegenerateSharedSecret,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemKeyPair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MlKemEncapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: [u8; 32],
}

// Hand-written redacting Debug so the ML-KEM shared secret can never reach a log
// or panic message, mirroring the redacting impls on X25519KeyPair / SessionKeys
// in crypto/session.rs. The ciphertext is public wire material.
impl std::fmt::Debug for MlKemEncapsulation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlKemEncapsulation")
            .field("ciphertext", &self.ciphertext)
            .field("shared_secret", &"<redacted>")
            .finish()
    }
}

/// FIPS 203 ML-KEM-1024 serialized sizes (bytes). Exposed so config/probe can
/// validate stored key lengths without depending on the KEM backend crate; the
/// fn form mirrors the previous pqcrypto API so call sites only change the path.
pub fn public_key_bytes() -> usize {
    1568
}
pub fn secret_key_bytes() -> usize {
    3168
}
pub fn ciphertext_bytes() -> usize {
    1568
}

pub fn keypair() -> MlKemKeyPair {
    let dk = DecapsulationKey::generate(&ML_KEM_1024).expect("ML-KEM-1024 key generation");
    let ek = dk
        .encapsulation_key()
        .expect("ML-KEM-1024 encapsulation-key derivation");
    MlKemKeyPair {
        public: ek
            .key_bytes()
            .expect("serialize ML-KEM-1024 encapsulation key")
            .as_ref()
            .to_vec(),
        secret: dk
            .key_bytes()
            .expect("serialize ML-KEM-1024 decapsulation key")
            .as_ref()
            .to_vec(),
    }
}

pub fn encapsulate(public_key: &[u8]) -> Result<MlKemEncapsulation, PqError> {
    let public =
        EncapsulationKey::new(&ML_KEM_1024, public_key).map_err(|_| PqError::InvalidPublicKey)?;
    let (ciphertext, shared_secret) = public
        .encapsulate()
        .map_err(|_| PqError::InvalidPublicKey)?;
    Ok(MlKemEncapsulation {
        ciphertext: ciphertext.as_ref().to_vec(),
        shared_secret: shared_secret_32(shared_secret.as_ref())?,
    })
}

pub fn decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<[u8; 32], PqError> {
    let secret =
        DecapsulationKey::new(&ML_KEM_1024, secret_key).map_err(|_| PqError::InvalidSecretKey)?;
    let shared_secret = secret
        .decapsulate(Ciphertext::from(ciphertext))
        .map_err(|_| PqError::InvalidCiphertext)?;
    shared_secret_32(shared_secret.as_ref())
}

pub fn hybrid_rekey(
    old_chain_secret: &[u8; 32],
    x25519_shared_secret: &[u8; 32],
    pq_shared_secret: &[u8; 32],
) -> Result<[u8; 32], PqError> {
    hybrid_sandwich_rekey(
        old_chain_secret,
        x25519_shared_secret,
        pq_shared_secret,
        &[],
    )
}

pub fn hybrid_sandwich_rekey(
    old_chain_secret: &[u8; 32],
    x25519_shared_secret: &[u8; 32],
    pq_shared_secret: &[u8; 32],
    symmetric_secret: &[u8],
) -> Result<[u8; 32], PqError> {
    // Reject a degenerate (all-zero) X25519 contribution, mirroring the initial
    // handshake check in crypto/session.rs. The peer's ephemeral public is
    // attacker-controllable on the rekey path; a small-order point can force the
    // X25519 shared secret to zero, silently dropping that layer's contributory
    // guarantee. Compared in constant time (subtle) for consistency with the
    // session.rs check — the same constant-time-secret-handling hygiene.
    if bool::from(x25519_shared_secret.ct_eq(&[0_u8; 32])) {
        return Err(PqError::DegenerateSharedSecret);
    }
    let mut chain_secret = [0_u8; 32];
    let ikm_len = HYBRID_REKEY_IKM_FIXED_LEN + symmetric_secret.len();
    if ikm_len <= HYBRID_REKEY_IKM_STACK_LEN {
        let mut ikm = [0_u8; HYBRID_REKEY_IKM_STACK_LEN];
        let used = write_hybrid_rekey_ikm(
            &mut ikm,
            x25519_shared_secret,
            pq_shared_secret,
            symmetric_secret,
        );
        let (mut prk, _) = Hkdf::<Sha256>::extract(Some(old_chain_secret), &ikm[..used]);
        chain_secret.copy_from_slice(&prk);
        prk.zeroize();
        ikm[..used].zeroize();
    } else {
        let mut ikm = Vec::with_capacity(ikm_len);
        write_hybrid_rekey_ikm_vec(
            &mut ikm,
            x25519_shared_secret,
            pq_shared_secret,
            symmetric_secret,
        );
        let (mut prk, _) = Hkdf::<Sha256>::extract(Some(old_chain_secret), &ikm);
        chain_secret.copy_from_slice(&prk);
        prk.zeroize();
        ikm.zeroize();
    }
    Ok(chain_secret)
}
fn write_hybrid_rekey_ikm(
    out: &mut [u8; HYBRID_REKEY_IKM_STACK_LEN],
    x25519_shared_secret: &[u8; 32],
    pq_shared_secret: &[u8; 32],
    symmetric_secret: &[u8],
) -> usize {
    let mut offset = 0;
    write_ikm_bytes(out, &mut offset, b"x25519:");
    write_ikm_bytes(out, &mut offset, x25519_shared_secret);
    write_ikm_bytes(out, &mut offset, b"|mlkem1024:");
    write_ikm_bytes(out, &mut offset, pq_shared_secret);
    write_ikm_bytes(out, &mut offset, b"|psk:");
    write_ikm_bytes(
        out,
        &mut offset,
        &(symmetric_secret.len() as u32).to_be_bytes(),
    );
    write_ikm_bytes(out, &mut offset, symmetric_secret);
    offset
}

fn write_ikm_bytes(out: &mut [u8; HYBRID_REKEY_IKM_STACK_LEN], offset: &mut usize, bytes: &[u8]) {
    let end = *offset + bytes.len();
    out[*offset..end].copy_from_slice(bytes);
    *offset = end;
}

fn write_hybrid_rekey_ikm_vec(
    out: &mut Vec<u8>,
    x25519_shared_secret: &[u8; 32],
    pq_shared_secret: &[u8; 32],
    symmetric_secret: &[u8],
) {
    out.extend_from_slice(b"x25519:");
    out.extend_from_slice(x25519_shared_secret);
    out.extend_from_slice(b"|mlkem1024:");
    out.extend_from_slice(pq_shared_secret);
    out.extend_from_slice(b"|psk:");
    out.extend_from_slice(&(symmetric_secret.len() as u32).to_be_bytes());
    out.extend_from_slice(symmetric_secret);
}
fn shared_secret_32(shared_secret: &[u8]) -> Result<[u8; 32], PqError> {
    if shared_secret.len() != 32 {
        return Err(PqError::InvalidCiphertext);
    }
    let mut out = [0_u8; 32];
    out.copy_from_slice(shared_secret);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem_round_trip() {
        let keys = keypair();
        let enc = encapsulate(&keys.public).unwrap();
        let dec = decapsulate(&enc.ciphertext, &keys.secret).unwrap();
        assert_eq!(enc.shared_secret, dec);
        assert_eq!(keys.public.len(), public_key_bytes());
        assert_eq!(keys.secret.len(), secret_key_bytes());
        assert_eq!(enc.ciphertext.len(), ciphertext_bytes());
    }

    #[test]
    fn hybrid_rekey_changes_key_material() {
        let chain_secret = hybrid_rekey(&[1; 32], &[2; 32], &[3; 32]).unwrap();
        assert_ne!(chain_secret, [1; 32]);
    }

    #[test]
    fn hybrid_rekey_binds_old_chain_x25519_and_mlkem_secrets() {
        let baseline = hybrid_rekey(&[1; 32], &[2; 32], &[3; 32]).unwrap();
        assert_ne!(
            baseline,
            hybrid_rekey(&[9; 32], &[2; 32], &[3; 32]).unwrap()
        );
        assert_ne!(
            baseline,
            hybrid_rekey(&[1; 32], &[9; 32], &[3; 32]).unwrap()
        );
        assert_ne!(
            baseline,
            hybrid_rekey(&[1; 32], &[2; 32], &[9; 32]).unwrap()
        );
    }

    #[test]
    fn hybrid_sandwich_rekey_binds_symmetric_secret() {
        let baseline = hybrid_sandwich_rekey(&[1; 32], &[2; 32], &[3; 32], b"psk-a").unwrap();
        assert_ne!(
            baseline,
            hybrid_sandwich_rekey(&[1; 32], &[2; 32], &[3; 32], b"psk-b").unwrap()
        );
        assert_ne!(
            baseline,
            hybrid_rekey(&[1; 32], &[2; 32], &[3; 32]).unwrap()
        );
    }

    #[test]
    fn hybrid_rekey_rejects_degenerate_x25519_shared_secret() {
        // A small-order peer ephemeral can force the X25519 shared secret to all
        // zero; the rekey combiner must reject it on both the PSK and non-PSK
        // paths rather than silently dropping the X25519 contribution.
        assert!(matches!(
            hybrid_rekey(&[1; 32], &[0; 32], &[3; 32]),
            Err(PqError::DegenerateSharedSecret)
        ));
        assert!(matches!(
            hybrid_sandwich_rekey(&[1; 32], &[0; 32], &[3; 32], b"psk"),
            Err(PqError::DegenerateSharedSecret)
        ));
        // A non-degenerate X25519 secret still rekeys successfully.
        assert!(hybrid_rekey(&[1; 32], &[2; 32], &[3; 32]).is_ok());
    }

    #[test]
    fn hybrid_sandwich_rekey_uses_heap_path_for_large_symmetric_secrets() {
        let small = hybrid_sandwich_rekey(&[1; 32], &[2; 32], &[3; 32], b"small").unwrap();
        let big_secret = vec![0xAB; HYBRID_REKEY_IKM_STACK_LEN];
        let big = hybrid_sandwich_rekey(&[1; 32], &[2; 32], &[3; 32], &big_secret).unwrap();
        assert_ne!(small, big);

        // Heap and stack paths must produce identical output for the same inputs.
        let psk = b"boundary-psk-input-for-hashing";
        let stack = hybrid_sandwich_rekey(&[7; 32], &[8; 32], &[9; 32], psk).unwrap();
        let heap = {
            let mut ikm = Vec::new();
            write_hybrid_rekey_ikm_vec(&mut ikm, &[8; 32], &[9; 32], psk);
            let (prk, _) = Hkdf::<Sha256>::extract(Some(&[7_u8; 32]), &ikm);
            let mut out = [0_u8; 32];
            out.copy_from_slice(&prk);
            out
        };
        assert_eq!(stack, heap);
    }

    #[test]
    fn hybrid_rekey_ikm_fixed_len_matches_written_prefix() {
        // HYBRID_REKEY_IKM_FIXED_LEN is the byte length the IKM writer emits BEFORE
        // the variable-length symmetric secret: it must equal the sum of the fixed
        // framing the writer actually produces ("x25519:" + 32 + "|mlkem1024:" + 32
        // + "|psk:" + 4-byte length prefix). It drives the stack-vs-heap branch in
        // hybrid_sandwich_rekey, so if the constant under-counts, a symmetric secret
        // sized to the boundary is mis-routed to the fixed stack buffer and the
        // writer overruns it (panic). Pin the constant directly against the writer.
        let mut ikm = [0_u8; HYBRID_REKEY_IKM_STACK_LEN];
        let written = write_hybrid_rekey_ikm(&mut ikm, &[1; 32], &[2; 32], b"");
        assert_eq!(
            written, HYBRID_REKEY_IKM_FIXED_LEN,
            "fixed-len constant must equal the writer's fixed prefix length"
        );
        // Independent recomputation of the framing so a wrong constant is caught
        // even if the writer itself were changed in lockstep.
        let expected = b"x25519:".len() + 32 + b"|mlkem1024:".len() + 32 + b"|psk:".len() + 4;
        assert_eq!(HYBRID_REKEY_IKM_FIXED_LEN, expected);
    }

    #[test]
    fn hybrid_sandwich_rekey_is_correct_across_the_stack_heap_boundary() {
        // The stack path uses a fixed [u8; HYBRID_REKEY_IKM_STACK_LEN] buffer and is
        // taken when HYBRID_REKEY_IKM_FIXED_LEN + symmetric.len() <= STACK_LEN. Sweep
        // symmetric-secret lengths straddling that exact boundary: every length must
        // round-trip to the SAME value an independent heap computation produces, and
        // must not panic. If the fixed-len constant is under-counted (e.g. a `+`
        // turned into `-`), a boundary length is wrongly routed to the stack buffer
        // and write_hybrid_rekey_ikm overruns it -> panic -> this test fails.
        // Largest sym_len still on the stack path (stack iff sym_len <= this); the
        // first heap length is boundary + 1. The sweep below straddles both sides.
        let boundary = HYBRID_REKEY_IKM_STACK_LEN - HYBRID_REKEY_IKM_FIXED_LEN; // max stack len
        for sym_len in (boundary.saturating_sub(3))..=(boundary + 3) {
            let sym = vec![0x5A_u8; sym_len];
            let got = hybrid_sandwich_rekey(&[7; 32], &[8; 32], &[9; 32], &sym).unwrap();

            // Independent reference via the explicit heap writer + HKDF-Extract.
            let mut ikm = Vec::new();
            write_hybrid_rekey_ikm_vec(&mut ikm, &[8; 32], &[9; 32], &sym);
            let (prk, _) = Hkdf::<Sha256>::extract(Some(&[7_u8; 32]), &ikm);
            let mut want = [0_u8; 32];
            want.copy_from_slice(&prk);

            assert_eq!(
                got, want,
                "rekey output must match the reference at symmetric len {sym_len}"
            );
        }
    }

    #[test]
    fn encapsulate_rejects_malformed_public_key() {
        let err = encapsulate(&[0_u8; 4]).unwrap_err();
        assert!(matches!(err, PqError::InvalidPublicKey));
    }

    #[test]
    fn decapsulate_rejects_malformed_ciphertext() {
        let keys = keypair();
        let err = decapsulate(&[0_u8; 4], &keys.secret).unwrap_err();
        assert!(matches!(err, PqError::InvalidCiphertext));
    }

    #[test]
    fn decapsulate_rejects_malformed_secret_key() {
        let keys = keypair();
        let enc = encapsulate(&keys.public).unwrap();
        let err = decapsulate(&enc.ciphertext, &[0_u8; 4]).unwrap_err();
        assert!(matches!(err, PqError::InvalidSecretKey));
    }

    #[test]
    fn shared_secret_32_rejects_wrong_length() {
        let err = shared_secret_32(&[0_u8; 31]).unwrap_err();
        assert!(matches!(err, PqError::InvalidCiphertext));
        let err = shared_secret_32(&[0_u8; 33]).unwrap_err();
        assert!(matches!(err, PqError::InvalidCiphertext));

        let ok = shared_secret_32(&[1_u8; 32]).unwrap();
        assert_eq!(ok, [1_u8; 32]);
    }

    #[test]
    fn pq_error_messages_are_stable() {
        assert_eq!(
            PqError::InvalidPublicKey.to_string(),
            "invalid ML-KEM public key"
        );
        assert_eq!(
            PqError::InvalidSecretKey.to_string(),
            "invalid ML-KEM secret key"
        );
        assert_eq!(
            PqError::InvalidCiphertext.to_string(),
            "invalid ML-KEM ciphertext"
        );
        assert_eq!(PqError::Hkdf.to_string(), "HKDF expansion failed");
        assert_eq!(
            PqError::DegenerateSharedSecret.to_string(),
            "degenerate (all-zero) X25519 shared secret"
        );
    }
}
