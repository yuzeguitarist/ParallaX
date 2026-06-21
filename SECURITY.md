# Security Policy

ParallaX is a censorship-resistance proxy. People may rely on it in adversarial
network environments, so a security issue here can have real-world consequences
for the operators and users running it. Reports are taken seriously and
responsible disclosure is appreciated.

## Supported Versions

ParallaX is pre-1.0 and under active development. Security fixes land on `main`
and in the latest tagged release only; there are no long-term support branches.

| Version           | Supported         |
| ----------------- | ----------------- |
| `main` (latest)   | Yes               |
| Latest `v0.x` tag | Yes (best-effort) |
| Older releases    | No                |

Run the latest release (or current `main`) to receive security fixes.

## Reporting a Vulnerability

**Please do not open a public issue, pull request, or discussion for a security
vulnerability.** Public disclosure before a fix exists can put users at risk.

Use GitHub's private vulnerability reporting instead:

1. Open the
   [**Report a vulnerability**](https://github.com/yuzeguitarist/ParallaX/security/advisories/new)
   form on this repository's Security tab.
2. Submit a private advisory describing the issue.

This opens a channel visible only to the maintainers. If private reporting is
unavailable to you, open a minimal public issue that says only *"security report,
please enable contact"* — with no technical details — and we will follow up
privately.

### What to include

- A description of the issue and its impact.
- The version or commit (`git rev-parse HEAD`) you tested.
- Steps to reproduce, ideally a minimal proof of concept.
- Any relevant configuration, with keys and secrets redacted.

## Scope

Because ParallaX is a traffic-camouflage tool, **distinguishability is itself a
security property**: a reliable way to fingerprint, classify, or actively probe
ParallaX traffic apart from the browser/TLS profile it imitates is in scope — not
only classic memory-safety or cryptographic bugs.

In scope:

- The TLS / ClientHello camouflage and its distinguishability from a real Safari
  client (`src/tls/`, `src/fingerprint/`).
- The handshake, authentication, and replay protection (`src/handshake/`).
- The cryptographic core — hand-rolled ML-DSA-87 (`src/crypto/mldsa`), the AEAD
  data plane, KEM integration, key handling, and any side channel.
- The experimental UDP/QUIC fast plane (`src/transport/udp/`), even though it is
  off by default (`[udp].enabled = false`): its masquerading-H3 QUIC ClientHello
  and distinguishability, the exporter-bound probe-token authentication, and the
  QUIC data-plane crypto are all in scope.
- The GFW simulator's detection / distinguishing logic (`tests/gfw_sim/`): a flaw
  that makes ParallaX's censorship-resistance validation unsound — for example
  failing to flag traffic a real censor could — is treated as security-relevant.
- Memory safety and the `unsafe` / FFI surfaces.
- Bypasses of ParallaX's process hardening and key-in-memory protections under a
  local attacker or a partially-compromised host — leaking keys or plaintext via
  core dumps, debugger / ptrace attach, swap, or memory scraping
  (`src/process_hardening.rs`, `src/runtime_guard.rs`: `mlock`, `MADV_DONTDUMP`,
  `RLIMIT_CORE`, `PT_DENY_ATTACH`). These are in scope even when they assume local
  access or an already-compromised endpoint.
- The GitHub Actions CI/CD configuration (`.github/workflows/`): workflow script /
  template injection, excessive `GITHUB_TOKEN` permissions or secret exposure, and
  supply-chain risk from third-party actions — especially the workflows that
  process untrusted PR content (`claude-*.yml`).
- Software supply-chain integrity: the Rust dependency tree (`Cargo.toml`,
  `Cargo.lock`) and the integrity of released binaries — for example a malicious
  or compromised dependency, or a tampered release artifact. (Known advisories in
  dependencies are already gated by cargo-deny / OSV; this covers supply-chain
  risk beyond published advisories.)
- Anything that can deanonymize or actively probe a user of the proxy.

Out of scope:

- Purely documentation and research notes with no executable attack surface.

## Secret handling & config threat model

A ParallaX deployment rests on a few long-lived secrets. Treating the config
file as a single artifact that is safe to share is the most common way to lose a
deployment, so the file format separates **public parameters** from **secrets**
and lets the secrets live outside the config.

### Which config fields are public vs secret

| Field | Sensitivity | If leaked |
| --- | --- | --- |
| `crypto.psk` | **SECRET** (shared by client and server) | client/server impersonation; the *client* config alone is a bearer credential |
| `server.private_key` | **SECRET** (X25519 static private) | server impersonation, session decryption |
| `server.identity_secret_key` | **SECRET** (ML-DSA-87 signing key) | forge the server identity signature |
| `client.server_public_key`, `client.server_identity_public_key` | Public | none — verification material |
| `listen` / `server_addr` / `fallback_addr` / `sni` / `authorized_sni` / `traffic.*` / `udp.*` / `replay_cache_*` / timeouts | Public parameters | none |

### Keeping secrets out of the config file

Each of the three secret fields accepts **either** an inline base64 string
(back-compat, discouraged) **or** an indirection so the config file itself is not
a credential:

```toml
psk = "base64=="                              # inline — file IS a credential
psk = { file = "parallax.secrets.toml#psk" } # 0600 sidecar file (default for `plx init`)
psk = { env = "PARALLAX_PSK" }               # environment / systemd LoadCredential
psk = { sealed = "parallax.secrets.enc#psk" }# machine-bound, encrypted at rest
```

- `plx init` writes **referenced** secrets (0600 sidecar files) by default;
  `--inline-secrets` restores the legacy all-in-one file.
- `plx check` warns when any secret is still inline.
- `plx seal` encrypts the secrets into a machine-bound bundle (see below) and
  rewrites the config to reference it.

### What sealing protects against

`plx seal` derives a per-secret key (HKDF-SHA256) from a host-local keyfile
(`/var/lib/parallax/host.key`, mode `0600`) and encrypts each secret with
XChaCha20-Poly1305 (the logical field name is bound as AAD). The sealed bundle
and the config that references it are then **safe to back up, commit, or paste**:
without the host keyfile they decrypt to nothing on any other machine.

**Protects against** the realistic leakage mistakes this issue targets: pasting a
config into an issue/chat/log, committing it to git, a stray backup or upload, or
a wrong-permissions copy.

**Does NOT protect against** (consistent with the in-memory hardening above and
the stated non-goal): a root/kernel compromise, an attacker who can read the host
keyfile *and* the sealed bundle on the same host, live process-memory scraping,
or leakage of the plaintext secret/sidecar files themselves. It is not a
TEE/HSM/TPM and does not claim root-compromise resistance.

### Operational guidance

- Never commit `host.key` (the decryption key — it defeats the whole scheme) or
  plaintext secret/sidecar files (`*.secrets.toml`). These are git-ignored by
  default.
- A **sealed** bundle (`*.secrets.enc`) is safe to commit or back up: without the
  host keyfile it decrypts to nothing. Keeping it out of version control anyway is
  reasonable defense-in-depth, so it is git-ignored by default too — remove that
  ignore rule deliberately if you want to track it.
- Prefer `env`/systemd credentials or `plx seal` over inline secrets in
  production.
- Rotate on suspected leak: regenerate the keypair/identity and PSK and
  redistribute. The PSK is shared, so PSK rotation is a coordinated two-sided op.
- Redact secrets when filing issues (see *What to include* above).

## Disclosure process

- We aim to acknowledge a report within a few days. This is a small project, so
  please allow for best-effort timing.
- We will work with you on a fix and agree on a coordinated disclosure date
  before any public details are shared.
- With your consent, we are glad to credit you in the advisory and release notes.
