#!/usr/bin/env bash
# Apple embedding contract checks (EMBEDDING.md section 8).
#
# 1. The library builds for every Apple target the embedder ships.
# 2. The embedding modules call no process-global API (EMBEDDING.md section 3).
# 3. The embed contract tests pass, including the loopback ones.
#
# Usage: scripts/check-apple.sh [--no-loopback]
set -euo pipefail

cd "$(dirname "$0")/.."

run_loopback=1
if [[ "${1:-}" == "--no-loopback" ]]; then
  run_loopback=0
fi

export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-26.0}"

targets=(aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin)
installed="$(rustup target list --installed 2>/dev/null || true)"
for target in "${targets[@]}"; do
  if ! grep -qx "$target" <<<"$installed"; then
    echo "error: Rust target $target is not installed (rustup target add $target)" >&2
    exit 1
  fi
  echo "==> cargo check --lib --target $target (iOS deployment target $IPHONEOS_DEPLOYMENT_TARGET)"
  cargo check --locked --lib --target "$target"
done

echo "==> embedding guard: no process-global effects in the embedding modules"
guard_files=(src/embed.rs src/client/local.rs)
forbidden='std::env|env::var|set_var|std::fs|fs::|File::|OpenOptions|setrlimit|getrlimit|prctl|tracing_subscriber|process::exit|signal::|harden_current_process|install_late_seccomp|RuntimeGuard|bump_nofile_soft_limit|configure_socket_buffers|configure_udp_socket_buffers|TcpListener|UdpSocket::bind'
if grep -nE "$forbidden" "${guard_files[@]}"; then
  echo "error: the embedding modules must not touch process-global state (EMBEDDING.md section 3)" >&2
  exit 1
fi

echo "==> embed contract tests"
cargo test --locked --test embed_contract
if [[ "$run_loopback" == 1 ]]; then
  cargo test --locked --test embed_contract -- --ignored --test-threads=1
fi

echo "Apple embedding contract: OK"
