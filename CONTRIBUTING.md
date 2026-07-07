# Contributing to ParallaX

Thanks for your interest in ParallaX. It is a censorship-resistance proxy that
people may run in adversarial network environments, so this project values
**correctness, camouflage fidelity, and security over feature velocity**. A
small, well-verified change that keeps the traffic indistinguishable from a real
browser is worth more here than a large one that adds surface area.

Please read this guide before opening an issue or a pull request.

## Ground rules first

- **Security and distinguishability issues are private.** Do **not** open a
  public issue or PR for a vulnerability, and note that *a reliable way to
  fingerprint, classify, or actively probe ParallaX apart from the Safari/TLS
  profile it imitates is itself a security issue*. Report these privately — see
  [`SECURITY.md`](./SECURITY.md).
- **Be kind.** Participation is governed by our
  [Code of Conduct](./CODE_OF_CONDUCT.md).
- **Know the license.** ParallaX is under the
  [PolyForm Noncommercial License 1.0.0](./LICENSE) with supplemental
  [AI/ML usage restrictions](./AI_USAGE.md). See
  [Licensing of contributions](#licensing-of-contributions) below — by
  contributing you accept those terms for your contribution.
- **Follow the engineering guidelines.** [`AGENTS.md`](./AGENTS.md) (think before
  coding, simplicity first, surgical changes, goal-driven verification) applies
  to human and AI-assisted contributions alike.

## Ways to contribute

- **Report a (non-security) bug** — use the bug report form.
- **Propose a change** — use the feature request form, but read
  [Scope and product boundary](#scope-and-product-boundary) first; ParallaX has a
  deliberately narrow product path.
- **Improve documentation** — the README, `SPEC.md`, and the
  [`ParallaX-DeepWiki/`](./ParallaX-DeepWiki/) knowledge base.
- **Strengthen validation** — new GFW-simulator scenarios, distinguisher tests,
  parity fixtures, or censorship-measurement notes are especially welcome.

## Development setup

- **Toolchain:** a **recent stable** Rust. The `rust-version = "1.80"` in
  `Cargo.toml` is nominal — the pinned `Cargo.lock` pulls crates that need
  Cargo's `edition2024` feature, so you need **Cargo ≥ 1.85** (`rustup default
  stable`). Do not pin to 1.80/1.83.
- No `openssl-sys` / system OpenSSL dependency.
- **Always build and test with `--locked`**, exactly as CI does.

```bash
cargo build --locked --release
```

## Verification

Run these before pushing — they mirror the required CI checks (`lint`, `test`,
`gfw-sim`):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked --no-fail-fast
```

Loopback relay tests are `#[ignore]`d because they bind local TCP sockets; run
them separately and serially:

```bash
cargo test --locked -- --ignored --test-threads=1
```

Run the GFW simulator directly:

```bash
cargo test --locked --test gfw_simulator
```

Notes:

- If you add a `tests/*.rs` integration target, it must also be added to the
  explicit test list in `.github/workflows/ci-pr.yml` — cargo only runs the
  targets named there, so a new file will otherwise silently never run in CI.
  (`ci_test_allowlist_complete` guards against exactly this.)
- Heavier gates (Miri, Kani, dudect, mutants, fuzz, cargo-deny/OSV/geiger,
  CodeQL/semgrep/zizmor) run in CI. You do not need to run all of them locally;
  the three commands above plus the loopback/gfw-sim runs are the practical local
  bar.

## Scope and product boundary

The current product path is intentionally narrow: local SOCKS5 ingress, a
TCP/TLS Safari-shaped camouflage transport, ClientHello-embedded authentication,
fallback passthrough, and a post-quantum-rekeyed AEAD data plane. The UDP/QUIC
fast plane is **experimental and off by default** (`[udp].enabled = false`); the
TCP path must stay byte-identical whether or not it is enabled.

Before proposing a feature, ask whether it fits that boundary. Changes that add
speculative configurability, or that widen the gap between ParallaX traffic and a
real browser, are unlikely to be accepted. When in doubt, open a feature request
to discuss the design before writing code.

## Guardrails for camouflage- and crypto-touching changes

Changes under `src/tls/`, `src/fingerprint/`, `src/handshake/`, and
`src/crypto/` get extra scrutiny, because a regression there can be a *security*
regression (see [`SECURITY.md`](./SECURITY.md)):

- **Keep the camouflage exact.** The Safari-26 profile, parity fixtures under
  `tests/fixtures/`, and the GFW simulator must stay green. If your change alters
  wire bytes, explain why the new bytes still match the imitated browser, and
  update fixtures deliberately (not to "make the test pass").
- **Preserve failure behavior.** The server relays malformed / unauthenticated /
  unauthorized / partial-probe traffic to the fallback origin instead of emitting
  a proxy-shaped rejection. Do not introduce a new externally observable
  branch (distinct close code, response shape, or timing fork) on a failure path.
- **Do not hand-modify crypto casually.** Constant-time behavior, nonce
  uniqueness, key zeroization, and the ML-KEM / ML-DSA / hybrid-rekey paths are
  load-bearing and are gated by dedicated proofs and tests.

## Secret hygiene

- **Never** commit or paste real key material — PSKs, X25519/ML-DSA private keys,
  `host.key`, or `*.secrets.toml`. These are git-ignored by default; keep it that
  way. Redact secrets from any config, log, or capture you attach to an issue or
  PR (see the public-vs-secret table in [`SECURITY.md`](./SECURITY.md)).
- Use freshly generated throwaway keys in examples and tests.

## Pull request workflow

1. **Fork** the repository and create a topic branch from `main`. (Human
   contributors work from forks; fork PRs run with a read-only token. The
   `claude/*`-branch rule in `AGENTS.md` applies only to the in-repo automation
   bot, not to you.)
2. **Keep the PR surgical** — one logical change, minimal diff, matching the
   surrounding style. Every changed line should trace to the stated goal.
3. **Write clear commits.** History uses Conventional-Commits-style, scoped,
   imperative subjects (e.g. `fix(client): stop mux starving new connections`).
   Match that.
4. **Fill in the PR template** and link the issue it addresses.
5. **Make CI green** — `lint`, `test`, and `gfw-sim` are required checks.
6. Expect review focused on scope, camouflage fidelity, and security. Camouflage-
   and crypto-touching PRs may also draw automated review workflows.

## Licensing of contributions

ParallaX is **noncommercial** software. Unless stated otherwise in writing, your
contribution is offered under the same
[PolyForm Noncommercial License 1.0.0](./LICENSE) and the supplemental
[AI/ML usage restrictions](./AI_USAGE.md) that govern the rest of the project
(inbound = outbound). By opening a pull request you confirm that:

- you have the right to submit the work under that license; and
- you are not introducing code, data, or text you are not licensed to
  contribute — including material that would conflict with the noncommercial or
  AI/ML terms.

## Questions

For usage and deployment questions, start with the
[Getting Started & CLI Reference](./ParallaX-DeepWiki/Getting-Started-&-CLI-Reference.md)
and the [DeepWiki knowledge base](./ParallaX-DeepWiki/README.md) before opening
an issue.
