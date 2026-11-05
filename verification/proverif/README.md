# Symbolic authenticated rekey / identity slice

This model checks the client-side acceptance of the pinned server identity and
the associated PQ-rekey messages. It is a protocol slice, not a verification of
the whole proxy, TLS implementation, traffic camouflage or computational hybrid
construction. The verifier is [ProVerif 2.05](https://bblanche.gitlabpages.inria.fr/proverif/),
using symbolic perfect cryptography and an active Dolev-Yao network attacker.

Run the fail-closed checker:

```sh
python3 -B -m unittest discover -s verification/proverif -p 'test_*.py'
python3 -B verification/proverif/run.py --proverif /path/to/proverif
```

Each run gets a fresh artifact directory under `target/proverif/`, containing
the exact models, complete proof/attack traces and `verification.json`. The
report records source-region hashes, model hashes, verifier version and binary
hash. The dedicated CI workflow downloads the official source archive, checks
its pinned SHA-256 and builds with `./build -nointeract`; the runner's version
check and recorded binary hash alone are not a source-attestation mechanism.

## Properties and non-vacuity

The baseline must prove all three security queries:

1. **Injective pinned-server correspondence.** Every honest client acceptance
   matches a preceding server signing event with the same verification key,
   static server X25519 pin, initial transcript, complete client request,
   complete server response (including the selected suite), and epoch.
2. **Injective derived-key agreement.** The accepted client-direction key and
   that same complete context match a server key-derivation event. Keys are
   independently computed by the two roles through DH and KEM equations and
   the modeled sandwich/epoch KDFs.
3. **Application-secret secrecy.** A private application message sent after
   the identity check remains unknown to the attacker under the assumptions
   below. This is ordinary symbolic secrecy, not a computational advantage bound
   or an observational-equivalence claim.

A fourth reachability query must refute `not event(acceptance_reached)`: the
model must exhibit an accepting execution. An unreachable client is a failure,
not a successful authentication proof. Missing, duplicate, unknown, unproved or
unexpected query results also fail the runner.
The result parser requires the exact secret and reachability terms, both
correspondence event names, all six context fields (seven with the derived key),
and identical variables in the same positions on both sides. Only consistent
numeric suffixes added to the declared variables by ProVerif are accepted.

Both client and server roles are replicated without a session limit. The public
network permits interception, modification, injection and replay. Injectivity
depends on fresh client ephemeral material and fresh transcript identifiers and
on one accepting transition per modeled client session; this does not verify
the implementation's replay cache, persistence, timestamp window or restart
behavior.

## Deliberately strong attacker and explicit assumptions

- The epoch-0 transport and root, plus the PSK, are exposed. The model gives the
  attacker the PQ messages and identity signatures in plaintext. It therefore
  does not obtain identity correspondence merely by assuming an already secure
  carrier. Actual epoch-0 record protection and post-rekey encryption of the
  identity proof are omitted defenses. Mutated-model attacks are not by
  themselves executable attacks against the complete production protocol.
- The client's configured ML-DSA verification key and static X25519 pin are
  trusted. The server signing key is uncompromised and is not reused in an
  unmodeled signing service. Honest ephemeral exponents, KEM secrets and
  encapsulation randomness are fresh and unexposed.
- Each initial transcript has a consistent epoch-0 root on the two honest
  sides, modeled as a public deterministic function of that context. The model
  assumes this initial-state agreement; it does not establish ClientHello auth,
  TLS certificate validation or the initial key schedule. Fresh transcript
  names abstract a collision-free hash containing fresh ClientHello material.
- Server initial context/epoch and hardware suite selection are overapproximated
  by attacker-controlled public inputs. `next_epoch` is an abstract stage label,
  not a model of `u64` arithmetic or saturation. Production currently performs
  one initial PQ rekey from epoch zero to one; no ongoing ratchet or PCS theorem
  follows from the model's arbitrary symbolic context labels.
- DH has the usual symbolic commutativity equation. ML-KEM uses ideal public
  encapsulation/decapsulation equations. Invalid KEM ciphertext behavior,
  subgroup/low-order arithmetic and implicit rejection are not modeled.
- Signatures are ideal unforgeable, context-bound signatures. Hash bindings are
  collision-free one-way constructors. The sandwich and epoch KDFs are ideal
  one-way constructors on their full inputs. The model does not prove ML-DSA,
  ML-KEM, X25519, SHA-256, HKDF, AEAD, constant-time code, memory erasure or a
  computational guarantee when one hybrid component is broken.
- Only the client-direction secret-release path is modeled. Individual-client
  authentication is not claimed with the PSK exposed. Existing-session state
  compromise, signing-key compromise, component-compromise variants, forward
  secrecy after later disclosure, and post-compromise recovery remain separate
  work. No anonymity, availability or traffic-indistinguishability result is
  claimed.

## Mapping to production ownership

| Model term / transition | Owning source and meaning |
| --- | --- |
| `request(client_dh, client_kem)` | `ClientDataSession::build_pq_rekey_record` generates fresh X25519 and ML-KEM keys; the PX1Q bytes are retained by `PendingPqRekey`. |
| `response(server_dh, ciphertext, selected)` | `ServerKeyExchange::encode_with_suite` appends the negotiated suite byte; `decode_ref_with_suite` includes it in the canonical accepted payload. |
| `binding(request, response)` | `crypto::identity::pq_rekey_binding` hashes the domain label, 32-bit request length, complete request, 32-bit response length and complete response. `PendingPqRekey::identity_binding` and the server use those original encoded bytes. |
| `identity_message(label, epoch, transcript, static_pin, binding)` | `crypto::identity::identity_message` emits the fixed label, epoch, transcript hash, configured static X25519 public key and binding, in that order. The parameter name `server_x25519_public_key` does **not** mean the new ephemeral key at the runtime callsite; the ephemeral server key is covered through the response binding. |
| `checked_identity(signature, identity_public, context)` | `verify_server_identity_payload_blocking` pins the configured identity key, reconstructs the message from the session context and stored binding, then calls `identity::verify_server_identity` with the fixed ML-DSA context. |
| `sandwich_chain(old, dh, pq, psk)` | `crypto::pq::hybrid_sandwich_rekey` uses the old chain as HKDF-Extract salt; its input writer domain-separates X25519, ML-KEM-1024 and the length-prefixed PSK. |
| `client_key(chain, epoch, transcript)` | `crypto::session::expand_epoch_keys` applies the client-direction label, epoch and transcript. The suite selects the record cipher; it is authenticated in the response but is not added to this KDF in the model or production. |
| Client acceptance and secret release | `establish_authenticated_data_session_inner` finishes PQ application and verifies the identity before returning the usable session. The model's application ciphertext abstracts later data records, not their sizes, counters or framing. |

Relevant sources are [identity.rs](../../src/crypto/identity.rs),
[pq.rs](../../src/crypto/pq.rs), [session.rs](../../src/crypto/session.rs),
[handshake/client.rs](../../src/handshake/client.rs),
[handshake/server.rs](../../src/handshake/server.rs),
[client/runtime.rs](../../src/client/runtime.rs),
[transcript.rs](../../src/handshake/transcript.rs) and
[command.rs](../../src/protocol/command.rs).

`source_contracts.json` fingerprints only the reviewed mapped functions and
call regions, not entire files. A change blocks the checker until the source,
model and mapping are reviewed and the fingerprints are updated deliberately.
The extractor follows the repository's formatted function boundaries; these
fingerprints are review triggers, **not a semantic refinement proof** or an
automatic Rust-to-ProVerif translation.
The covered KDF regions include both stack and heap IKM writers, plus the epoch
HKDF expansion and info writer. Regression checks delete actual source writes
in temporary copies and require the corresponding review trigger to fail.

## Required attack controls

The runner derives five weakened models without altering event arguments or
query declarations:

| Mutation | Required detected outcome |
| --- | --- |
| Erase the request/response binding in both reconstructed identity messages | Authentication counterexample and application-secret disclosure |
| Erase the initial transcript from the signed/reconstructed message | Authentication counterexample |
| Erase the epoch from the signed/reconstructed message | Authentication counterexample |
| Omit only the response's selected suite from the hash binding | Authentication counterexample |
| Remove the expected-message equality check after signature verification | Authentication counterexample and application-secret disclosure |

All variants must retain a reachable client acceptance and produce conclusive
results. The full generated weakened models and actual attack traces are saved;
syntactic query rewrites or a verifier's inability to prove a result do not
count as detected attacks.
