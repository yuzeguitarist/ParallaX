<!--
Thanks for contributing to ParallaX. Please read CONTRIBUTING.md first.

Do NOT open a PR for a security or distinguishability issue — report it
privately (see SECURITY.md). Keep this PR surgical: one logical change, minimal
diff. Delete sections that do not apply.
-->

## Summary

<!-- What does this change do, and why? -->

## Related issue

<!-- e.g. Closes #123. For a feature, link the discussion issue. -->

## Type of change

- [ ] Bug fix
- [ ] Feature / enhancement
- [ ] Documentation
- [ ] Refactor / internal (no behavior change)
- [ ] Build / CI / tooling

## Verification

<!-- Paste results or check what you ran. These mirror the required CI checks. -->

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --locked -- -D warnings`
- [ ] `cargo test --locked --no-fail-fast`
- [ ] `cargo test --locked -- --ignored --test-threads=1` (loopback relay tests)
- [ ] `cargo test --locked --test gfw_simulator`
- [ ] Added any new `tests/*.rs` target to the explicit list in `.github/workflows/ci-pr.yml`

## Camouflage & security impact

- [ ] This change does **not** touch `src/tls/`, `src/fingerprint/`,
      `src/handshake/`, or `src/crypto/`.
- [ ] If it does: the Safari-26 profile and `tests/fixtures/` parity tests still
      pass, and any changed wire bytes still match the imitated browser (explain
      below).
- [ ] It does **not** introduce a new externally observable branch (distinct
      close code, response shape, or timing fork) on any failure/fallback path.
- [ ] The default TCP path stays byte-identical (the UDP/QUIC plane stays off by
      default).

<!-- If you touched camouflage/crypto, explain why it stays indistinguishable: -->

## Scope & hygiene

- [ ] The diff is surgical — every changed line traces to the stated goal; no
      unrelated refactors or reformatting.
- [ ] No secrets in the diff, tests, or logs (PSKs, private keys, `host.key`,
      `*.secrets.toml`); examples use throwaway keys.
- [ ] I have read
      [CONTRIBUTING.md](https://github.com/yuzeguitarist/ParallaX/blob/main/CONTRIBUTING.md)
      and agree my contribution is offered under the project's
      [PolyForm Noncommercial License 1.0.0](https://github.com/yuzeguitarist/ParallaX/blob/main/LICENSE)
      and [AI/ML usage restrictions](https://github.com/yuzeguitarist/ParallaX/blob/main/AI_USAGE.md).
