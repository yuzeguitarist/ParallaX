# AGENTS.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

## 5. Respect Scoped Stop Instructions

When the user says not to keep doing something, not to continue optimizing, or not to keep changing an area, apply that stop instruction only to the specific area or activity the user named. Do not broaden it into a global stop for the whole task. For example, "don't keep editing docs" means stop touching docs, while continuing the requested code work. Do not revert existing changes unless the user explicitly asks for a rollback. If the scope is unclear, ask or choose the narrowest reasonable scope instead of stopping unrelated work.

## 6. Use Patch Tools for File Edits

When changing source code, configuration, documentation, or any repository file content, use the dedicated patch/edit tool instead of writing file changes through shell scripts, inline Python, sed/perl replacement commands, heredocs, or shell redirection. Terminal commands are acceptable for inspection, tests, benchmarks, formatting checks, and git operations, but content edits must go through the patch/edit tool unless the user explicitly authorizes another method.

## Cursor Cloud specific instructions

Single-binary Rust proxy (`parallax` / `plx` alias). No databases or external services to run.

- **Toolchain:** Despite `rust-version = "1.80"` in `Cargo.toml`, the pinned `Cargo.lock` includes crates that need Cargo's `edition2024` feature (e.g. `clap_lex 1.1.0`), so builds require recent **stable** Rust (Cargo ≥ 1.85), matching CI's `dtolnay/rust-toolchain@stable`. The update script runs `rustup default stable`; do not pin to 1.80/1.83.
- **Always pass `--locked`** for build/clippy/test, as CI does.
- **Standard commands** are already documented: build/install in `README.md` "Build"; lint/test in `README.md` "Verification" (`cargo fmt --all -- --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked --no-fail-fast`); ignored loopback tests run serially with `-- --ignored --test-threads=1`; `cargo test --test gfw_simulator`. CI jobs are in `.github/workflows/`.
- **Running the proxy end-to-end needs outbound internet.** For an authenticated session the server splices the camouflage TLS handshake through to the real `fallback_addr` origin (e.g. `cloudflare.com:443`) and the client verifies that origin's cert against `sni`, so a fully local run still requires the fallback host to be reachable.
- **Local loopback run:** `plx init <domain> --server-addr 127.0.0.1:8443 --server-listen 127.0.0.1:8443` writes paired configs with matching keys. Two gotchas: the generated server `replay_cache_path` is `/var/lib/parallax/...` (not writable in the VM — point it at a writable path), and config files must be mode `0600` (`init` sets this; `plx check` enforces it). With `data_target` unset the server relays to the client's SOCKS5-requested target, so `curl --socks5-hostname 127.0.0.1:1080 <url>` proxies normally.
