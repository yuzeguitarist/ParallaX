# untrusted 0.9.0: bounded source review

Date: 2026-11-05. Reviewer: OpenAI ChatGPT (AI-assisted source review, not an independent human auditor). Decision: **safe-to-run only** for ordinary Cargo compilation and tests. No safe-to-deploy certification is asserted.

## Source identity and scope

Registry archive SHA-256: `8ecb6da28b8a351d773b68d5825ac39017e680750f980f3a1a85cd8dd28a47c1`, matching ParallaX's locked 0.9.0 checksum. Packaged VCS metadata identifies commit `89c8b8415f692d3803d183fc5fbf9ec08a6adcf4`. This covers 0.9.0 only, not the separate 0.7.1 dependency.

Read all four compiled Rust sources, normalized and original Cargo manifests, upstream integration tests, and optional developer shell scripts. The crate has no dependencies, build script, procedural macros, or feature variants. It uses `#![no_std]` and `core` only. Cargo does not execute the optional `mk/` scripts. Those scripts explicitly install cross-compilation tooling and use privileged package managers when manually invoked; this review does not recommend running them.

| Compiled source | SHA-256 |
| --- | --- |
| src/lib.rs | 860cdbec448f82196aa2242ad52945dfc60f29fcfbc28d244877fca0c0331fcc |
| src/input.rs | aaa007b7051f03b32f6c71fa8164780435e637bb2242df7792942b699d2d9cbd |
| src/reader.rs | 3826d4de44a970ed42e3f7dead6f4b51b60ccf02c03b9ac7140c80a9e57b104d |
| src/no_panic.rs | bf39e1314721d8350a09aa19628b64a2393b3b489906f1591a722bd47f4351e6 |

## Reasoning

The compiled library wraps borrowed byte slices and a forward cursor. There are no unsafe blocks, filesystem or network capabilities, allocation, subprocesses, global state, or hidden initialization. `read_bytes` checks integer addition and slice bounds before committing its cursor update. `read_byte` increments only after a successful bounds-checked lookup. `read_all` and `read_all_optional` enforce complete consumption after a successful callback. Debug output deliberately omits input bytes and cursor position. The test suite uses deterministic in-memory inputs and formatted strings.

This evidence supports the cargo-vet safe-to-run criterion: ordinary compilation and tests cannot access unrelated files or external endpoints through crate code. It does not establish the security of callers, certificate parsing, constant-time behavior, or native cryptography.

Deployment review is deliberately left open. `read_partial` relies on its callback preserving the reader's identity and monotonic cursor, yet the callback receives `&mut Reader` and can replace it with a new reader. Its final `unwrap` deserves caller-specific review before asserting a broad panic-free deployment guarantee. Caller-provided callbacks may themselves panic. This is a bounded review observation, not a claim of an exploitable ParallaX vulnerability.

## Validation

Ran `cargo test --locked -p untrusted@0.9.0`: all 13 upstream integration tests passed, with zero failing unit/doc tests. These tests support normal API behavior; they do not substitute for a production security audit.

Criteria reference: <https://mozilla.github.io/cargo-vet/built-in-criteria.html>. Source: <https://github.com/briansmith/untrusted/tree/89c8b8415f692d3803d183fc5fbf9ec08a6adcf4>.
