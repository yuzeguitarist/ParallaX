# Hand-Rolled ML-DSA-87 (FIPS 204)

> Navigation: [Index](README.md) | [Cryptographic Subsystems](Cryptographic-Subsystems.md) | [Post-Quantum Cryptography (ML-KEM & ML-DSA)](<Post-Quantum-Cryptography-(ML-KEM-&-ML-DSA).md>)

## Purpose

ParallaX's pinned server-identity signature is ML-DSA-87 (FIPS 204). The
implementation lives in `src/crypto/mldsa/` as a pure-Rust, hand-rolled port of the
PQClean `ml-dsa-87/clean` C reference — the same code `pqcrypto-mldsa 0.1.2`
wrapped. This page documents the implementation and the de-vendoring decision; for
how the signature is *used* in the handshake (identity proof, rekey binding) see
[Post-Quantum Cryptography (ML-KEM & ML-DSA)](<Post-Quantum-Cryptography-(ML-KEM-&-ML-DSA).md>).

## Why hand-rolled

The two post-quantum primitives now sit on different backends:

| Primitive | Backend | Code |
|---|---|---|
| ML-KEM-1024 (FIPS 203) | `aws-lc-rs` | `src/crypto/pq.rs` |
| ML-DSA-87 (FIPS 204) | Hand-rolled, pure Rust | `src/crypto/mldsa/` |

`pqcrypto-mldsa` and `pqcrypto-traits` were removed from the runtime dependency
tree. They remain in **`[dev-dependencies]` only**, kept deliberately as a
differential-test oracle so every hand-rolled operation can be cross-checked
byte-for-byte against the original C-backed implementation (`tests/mldsa_differential.rs`).
Do not delete the `pqcrypto` dev-dependency — it is the oracle, not dead weight.

## Module layout

The Rust layout mirrors the PQClean C translation units 1:1, so each Rust function
diffs against exactly one C function:

| Module | Owns |
|---|---|
| `params.rs` | FIPS 204 ML-DSA-87 constants (compile-time checked against the reference). |
| `fips202.rs` | SHAKE128/256 sponge (one-shot + incremental), via the `sha3` crate's constant-time Keccak-f1600. The only module delegating to external crypto. |
| `ntt.rs` | Number-theoretic transform for polynomial multiplication mod `Q`. |
| `reduce.rs` | Montgomery / Barrett modular reduction. |
| `rounding.rs` | High/low coefficient decomposition for commitment and rejection. |
| `poly.rs` | Single-polynomial operations over `Z_q[X]/(X^256+1)`. |
| `polyvec.rs` | Vectors of polynomials (`Polyvecl` length `L`, `Polyveck` length `K`), matrix expand, pointwise multiply. |
| `packing.rs` | Bit-packed serialization of keys and signatures. |
| `sign.rs` | FIPS 204 KeyGen / Sign / Verify with context. |
| `mod.rs` | The byte-oriented public API mirroring the retired `pqcrypto` surface. |

## Parameters (ML-DSA-87)

| Constant | Value |
|---|---|
| `N` (polynomial degree) | 256 |
| `Q` (modulus) | 8 380 417 (`2^23 − 2^13 + 1`) |
| `K` (rows) | 8 |
| `L` (columns) | 7 |
| `ETA` | 2 |
| `TAU` | 60 |
| `BETA` | 120 |
| `GAMMA1` | `2^19` |
| `GAMMA2` | `(Q − 1) / 32` |
| `OMEGA` | 75 |
| Public-key bytes (`PUBLICKEY_BYTES`) | 2592 |
| Secret-key bytes (`SECRETKEY_BYTES`) | 4896 |
| Signature bytes (`SIG_BYTES`) | 4627 |

## Public API (`src/crypto/mldsa/mod.rs`)

- `keypair() -> (Vec<u8>, Vec<u8>)` — returns `(public, secret)`.
- `sign(secret_key, msg, ctx) -> Result<Vec<u8>, MlDsaError>`.
- `verify(public_key, sig, msg, ctx) -> Result<(), MlDsaError>`.
- `public_key_bytes()`, `secret_key_bytes()`, `signature_bytes()` — size helpers
  mirroring the retired `pqcrypto_mldsa::mldsa87` API so call sites only changed
  their import path.
- `MlDsaError`: `InvalidSecretKeyLength`, `InvalidPublicKeyLength`,
  `InvalidSignatureLength`, `ContextTooLong`, `VerificationFailed`.

`src/crypto/identity.rs` is the sole caller: it maps the `MlDsaError` surface onto
its own identity-proof error type and calls `keypair`/`sign`/`verify` directly.

## Constant-time and zeroization

- The **signing path** (which touches the secret key) is constant-time; the verify
  path operates on public data.
- Secret-key material is held in fixed-size stack arrays that are zeroized before
  return; only the returned `Vec` carries plaintext, and the on-stack copies are
  scrubbed via `Zeroizing` / explicit zeroize.

## Validation

- **Differential oracle:** `tests/mldsa_differential.rs` cross-checks against the
  `pqcrypto` dev-dependency.
- **ACVP KATs:** `tests/mldsa_acvp.rs` validates against NIST ACVP vectors; a
  test-only `sign_deterministic` seam supplies the ACVP sigGen randomness.
- **Self-tests / round-trips:** unit tests in `mod.rs` cover keygen sizes, sign /
  verify round-trip, empty-message support, and every error variant.

## Drift risks

The 1:1 mapping to PQClean is intentional — keep it so the differential test stays
meaningful. If you change a module, re-run `tests/mldsa_differential.rs` and
`tests/mldsa_acvp.rs`. If the dev-only `pqcrypto` oracle is ever removed, update
this page and [Cryptographic Subsystems](Cryptographic-Subsystems.md) together.
