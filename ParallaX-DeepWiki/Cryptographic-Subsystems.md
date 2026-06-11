# Cryptographic Subsystems

> Navigation: [Index](README.md) | [ClientHello Auth](<ClientHello-Authentication-(PSK-+-X25519).md>) | [PQ & Identity](<Post-Quantum-Cryptography-(ML-KEM-&-ML-DSA).md>)

## Map

| Subsystem | Code | Purpose |
|---|---|---|
| ClientHello authentication | `src/crypto/auth.rs` | Hide authentication material in ClientHello entropy fields. |
| X25519/session keys | `src/crypto/session.rs` | Derive initial directional AEAD keys and nonce bases. |
| AEAD transport | `src/crypto/session.rs`, `src/protocol/data.rs` | Seal/open framed data records. |
| Parallel AEAD pool | `src/crypto/parallel.rs` | Process-wide worker pool that fans bulk seal/open across cores. |
| ML-KEM-1024 | `src/crypto/pq.rs` | Post-quantum shared secret for rekeying. |
| ML-DSA-87 | `src/crypto/identity.rs` | Server identity proof pinned by client config. |
| Replay cache | `src/crypto/replay.rs` | Reject captured/replayed authenticated handshakes. |
| Process hardening | `src/process_hardening.rs` | Best-effort key memory protection and dump suppression. |

## Handshake phases

1. **ClientHello authentication.** PSK and X25519 material are bound into
   `ClientHello.random` and compatibility `SessionID`.
2. **Initial session keys.** The client and server derive matching directional
   AEAD keys from the X25519 shared secret and transcript hash.
3. **PQ rekey.** The client sends ML-KEM public key plus fresh X25519 public
   key. The server encapsulates and both sides compute a hybrid sandwich chain
   secret.
4. **Server identity proof.** The server signs transcript/key material with
   ML-DSA-87. The client verifies the pinned public key from config.
5. **Data relay.** Application bytes are sealed into TLS ApplicationData-shaped
   records with padding/timing behavior from config.

## Design intent

- **No custom visible auth extension.** The public wire shape remains a TLS
  ClientHello and subsequent TLS records.
- **No CA dependency for ParallaX identity.** The TLS fallback path uses WebPKI
  for the camouflage origin, while ParallaX server identity is pinned through
  ML-DSA config.
- **Replay-aware first record.** Captured authenticated ClientHellos are not
  reusable across restarts when the replay cache persists.
- **Best-effort secret hygiene.** Secrets are zeroized where practical and
  protected with `mlock`/`MADV_DONTDUMP` on supported Unix systems.

## Related pages

- [ClientHello Authentication (PSK + X25519)](<ClientHello-Authentication-(PSK-+-X25519).md>)
- [Session Key Derivation & AEAD Transport](Session-Key-Derivation-&-AEAD-Transport.md)
- [Post-Quantum Cryptography (ML-KEM & ML-DSA)](<Post-Quantum-Cryptography-(ML-KEM-&-ML-DSA).md>)
- [Replay Protection](Replay-Protection.md)
