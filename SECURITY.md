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

## Disclosure process

- We aim to acknowledge a report within a few days. This is a small project, so
  please allow for best-effort timing.
- We will work with you on a fix and agree on a coordinated disclosure date
  before any public details are shared.
- With your consent, we are glad to credit you in the advisory and release notes.
