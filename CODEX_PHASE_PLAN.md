# ParallaX Phase 1-15 Speed/Performance Plan

Working rule: every phase must preserve existing functionality, usability,
security, camouflage behavior, and operator UX. Each phase needs code evidence,
full tests, release benchmark comparison, and a commit before moving on.

Baseline captured before Phase 1 on `codex/parallax-phase-1-15-speed`:

- `cargo test --locked`: pass; 259 lib tests, 78 GFWSIM tests, 6 Safari H2
  tests, 4 Safari TLS tests, 4 loopback tests ignored.
- `cargo run --locked --release -- bench --json`: pass; 57 standard cases.
- Current high-cost anchors include `hkdf.session_keys`,
  `server.decide_inbound`, `client.speed_upload_seal_1mb`,
  `client.speed_download_open_1mb`, and 1 MiB record pipeline cases.

## Phase 1: Baseline discipline and first hot-path proof

1. Re-run the full local test gate before touching code.
2. Capture release benchmark numbers and rank the slowest CPU paths by
   `ns_per_op`, `total_elapsed_ns`, and MiB/sec relevance.
3. Inspect the real relay path before accepting synthetic benchmark
   conclusions.
4. Select only a small, provable hot-path improvement with no feature loss.
5. Add or adjust regression coverage for the exact changed behavior.
6. Re-run full tests and release benchmark after the change.
7. Commit Phase 1 with the measured before/after evidence in the commit
   message.

## Phase 2: Real TCP relay throughput path

1. Inspect client/server relay loops for unnecessary copies, allocations, and
   flush boundaries.
2. Preserve half-close correctness and existing error propagation.
3. Verify kernel splice/fast relay paths remain gated by platform support.
4. Avoid fixed socket-buffer regressions; prefer kernel autotuning unless
   evidence proves otherwise.
5. Benchmark record relay cases and run GFWSIM after every relay change.
6. Commit only if real relay semantics and full tests remain green.

## Phase 3: Multiplexed session and stream scheduling

1. Measure current mux frame batching and session prewarm behavior.
2. Reduce per-frame overhead without increasing head-of-line blocking.
3. Keep stream-count limits and backpressure visible rather than hidden.
4. Ensure errors fail fast instead of silently dropping streams.
5. Cover multi-target and large-payload mux behavior with tests.
6. Commit after full tests and release benchmark show no regression.

## Phase 4: Data-record seal/open hot path

1. Inspect `DataRecordCodec` seal/open paths for avoidable metadata rebuilds.
2. Reuse buffers only where ownership is clear and plaintext lifetime stays
   minimal.
3. Prefer in-place open and payload-range paths where wire format is unchanged.
4. Keep nonce advancement failure semantics exactly intact.
5. Benchmark 1 KiB, 64 KiB, and 1 MiB record pipeline cases.
6. Add tests for any changed buffer reuse or nonce behavior.
7. Commit after full verification.

## Phase 5: Handshake crypto and key schedule

1. Separate expensive mandatory crypto from repeated derivation work.
2. Reuse already-computed X25519 shared material where current protocol allows.
3. Keep ML-KEM, ML-DSA, replay protection, and PSK binding enabled.
4. Avoid weakening transcript binding or server identity verification.
5. Benchmark `hkdf.*`, PQ rekey, and identity verification cases.
6. Add tests proving derived keys and transcript bindings are unchanged.
7. Commit after full verification.

## Phase 6: TLS camouflage construction and parsing

1. Inspect Safari 26 ClientHello construction for repeat allocations.
2. Preserve byte-shape parity fixtures and authenticated ClientHello fields.
3. Cache only static template material that cannot leak per-session secrets.
4. Keep parser behavior strict for malformed inputs and honest errors.
5. Benchmark `safari26.clienthello_start`, parse, and auth verification.
6. Run Safari parity tests and GFWSIM after changes.
7. Commit after full verification.

## Phase 7: Server inbound decision and fallback boundary

1. Profile `server.decide_inbound` and first-record handling.
2. Reduce duplicate ClientHello parsing or auth recovery when safe.
3. Preserve fallback camouflage for unauthorized or malformed traffic.
4. Keep active-prober resistance and residual camouflage behavior intact.
5. Add tests for authenticated, fallback, unauthorized, and malformed paths.
6. Run GFWSIM as a hard gate.
7. Commit after full verification.

## Phase 8: Client SOCKS and connect startup latency

1. Inspect SOCKS negotiation, initial payload capture, and connect-record
   build cost.
2. Reduce startup allocations without changing SOCKS semantics.
3. Preserve loopback listener restrictions and config validation.
4. Keep initial-payload timeout behavior explicit and tested.
5. Benchmark `client.connect_record_1k` and related command decode cases.
6. Add tests for connect target and initial-payload edge cases.
7. Commit after full verification.

## Phase 9: Kernel-aware TCP tuning without unsafe regressions

1. Review current TCP_NODELAY, QUICKACK, socket option, and connect racing
   behavior.
2. Compare WireGuard/Hysteria-style throughput assumptions against ParallaX's
   TCP/TLS product path.
3. Avoid hard-coded buffer sizes unless benchmarked on relevant paths.
4. Keep connect failures explicit and race losers cleaned up correctly.
5. Add tests for address racing and platform-gated tuning.
6. Run full tests and release benchmark after any transport change.
7. Commit after full verification.

## Phase 10: Async runtime task and allocation pressure

1. Count spawned tasks per connection/session and identify avoidable churn.
2. Reduce channel/frame allocations only when backpressure remains correct.
3. Keep cancellation and half-close semantics deterministic.
4. Avoid global pools unless measured benefit outweighs complexity.
5. Add tests around clean shutdown and concurrent stream behavior.
6. Benchmark relay and mux cases after changes.
7. Commit after full verification.

## Phase 11: Flow control, batching, and flush policy

1. Inspect every explicit flush and write boundary on hot paths.
2. Batch records where latency and correctness are not harmed.
3. Keep small interactive traffic responsive; do not optimize only bulk
   transfer.
4. Preserve visible errors on short writes, EOF, and protocol mismatch.
5. Compare benchmark bulk throughput and small-record latency cases.
6. Add tests for batched frame decode and partial read/write behavior.
7. Commit after full verification.

## Phase 12: Speed evidence and real-world measurement loop

1. Keep `plx speed` aligned with the real configured client/server path.
2. Add evidence fields only if they clarify real throughput bottlenecks.
3. Avoid changing the speed protocol unless server/client compatibility is
   tested.
4. Preserve JSON/text schema compatibility unless a version bump is justified.
5. Run release benchmark and targeted speed-report tests after changes.
6. Record before/after numbers in commit messages.
7. Commit after full verification.

## Phase 13: Anti-censorship and security invariant audit

1. Re-check that optimizations do not weaken GFW simulator resistance.
2. Preserve replay cache semantics, secret handling, and no-dump hardening.
3. Verify malformed input fails fast or falls back exactly as intended.
4. Keep browser-like TLS/H2 camouflage parity fixtures green.
5. Add tests for any changed security-sensitive branch.
6. Run full tests, GFWSIM, and Safari parity tests.
7. Commit after full verification.

## Phase 14: External protocol and research cross-check

1. Review WireGuard's minimal data path ideas without copying incompatible UDP
   assumptions into ParallaX's TCP/TLS path.
2. Review Hysteria's congestion/QUIC lessons and adopt only product-fit
   principles.
3. Review VLESS/Xray-style transport overhead tradeoffs for TCP/TLS proxying.
4. Check recent network performance research for batching, congestion, and
   latency-throughput tradeoffs.
5. Convert each useful idea into a concrete ParallaX hypothesis and benchmark.
6. Reject ideas that reduce security, camouflage, compatibility, or UX.
7. Commit only measured, code-backed improvements.

## Phase 15: Final integration, benchmark story, and operator docs

1. Re-run full tests from a clean tree.
2. Re-run standard release benchmark and compare against the initial baseline.
3. Verify no dead code, unused imports, or accidental feature loss remain.
4. Check `git diff --check` and inspect the complete phase-by-phase diff.
5. Update docs only after code/test iterations are stable.
6. Produce a plain-language final performance report with risks and evidence.
7. Commit final docs/report if changed and leave the branch ready to merge.
