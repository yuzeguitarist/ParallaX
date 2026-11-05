#!/usr/bin/env python3
"""Execute ParallaX under ASan, TSan or LSan on native Linux x86_64.

Bad canaries are isolated executables, never application dependencies. A failed
process without the expected sanitizer diagnostic is not a successful detection.
Reports record selected build flags, never the complete process environment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NIGHTLY = "nightly-2026-06-17"
TARGET = "x86_64-unknown-linux-gnu"
TSAN_SOURCE = "ec9ab9d68bf7a0e86b2ddf3c0e6e3c4620e02961"
TSAN_PATCH = "09910aa044808dfbfe1e0f96b5e39260789212fb"
DIAGNOSTICS = {
    "address": "AddressSanitizer: heap-use-after-free",
    "thread": "ThreadSanitizer: data race",
    "leak": "LeakSanitizer: detected memory leaks",
}
SUITES = (
    ("library", ["--lib"], []),
    ("linux-fd-lifetimes", ["--lib", "transport::tcp::"], []),
    ("protocol-oracles", ["--test", "security_protocol_differential"], []),
    ("fault-injection", ["--test", "security_fault_injection"], []),
    ("plaintext-reallocation", ["--test", "security_plaintext_allocation"], []),
    ("mldsa-oracle", ["--test", "mldsa_differential"], []),
    ("mldsa-vectors", ["--test", "mldsa_acvp"], []),
    ("production-cert-tunnel", ["--test", "e2e_tunnel_roundtrip"], ["--ignored"]),
    ("origin-splice", ["--test", "splice_equivalence"], ["--ignored"]),
    ("socket-chaos", ["--test", "chaos_liveness"], ["--ignored"]),
)


def expected_detection(kind: str, returncode: int, output: str) -> bool:
    return returncode != 0 and DIAGNOSTICS[kind] in output


def listed_tests(output: str) -> list[str]:
    return re.findall(r"^([A-Za-z_][A-Za-z0-9_:]*): test$", output, flags=re.MULTILINE)


def runtime_link_arguments(report: dict, directory: Path) -> tuple[list[str], list[str]]:
    """Bind the explicitly linked detector to the pinned, freshly built inputs."""
    if (not isinstance(report, dict)
            or report.get("schema") != 1 or report.get("status") != "passed"
            or report.get("source_commit") != TSAN_SOURCE
            or report.get("patch_commit") != TSAN_PATCH):
        raise RuntimeError("Unexpected TSan runtime source or incomplete build")
    paths = []
    for key in ("archive", "dynamic_list"):
        item = report.get(key, {})
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise RuntimeError(f"Invalid TSan runtime artifact record: {key}")
        path = Path(item["path"]).resolve()
        if (not path.is_relative_to(directory.resolve()) or not path.is_file()
                or path.stat().st_size == 0
                or hashlib.sha256(path.read_bytes()).hexdigest() != item.get("sha256")):
            raise RuntimeError(f"Invalid TSan runtime artifact: {key}")
        paths.append(str(path))
    # Match rustc/Clang's normal sanitizer placement. Loading libc before these
    # weak interceptor aliases can bind them to versioned libc symbols; another
    # late -lc does not repair that binding under GNU ld.
    runtime = ["-Wl,--whole-archive", paths[0], "-Wl,--no-whole-archive",
               f"-Wl,--dynamic-list={paths[1]}"]
    dependencies = ["-Wl,--no-as-needed",
            # rustc uses -nodefaultlibs. Clang's -pthread driver option cannot
            # supply the library, and libc must be revisited after this archive
            # for its versioned interceptors and libc_nonshared atfork symbol.
                    "-lpthread", "-lrt", "-lm", "-ldl", "-lresolv", "-lc", "-Wl,--as-needed"]
    return runtime, dependencies


def epoll_control_completed(result: subprocess.CompletedProcess[str], mode: str) -> bool:
    return (result.returncode == 0
            and f"sanitizer-epoll-publication-control-complete: {mode}" in result.stdout
            and "ThreadSanitizer:" not in result.stdout)


def completed_counts(output: str, selected: int, *, allow_ignored: bool = False) -> dict[str, int]:
    summaries = re.findall(
        r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", output)
    passed, failed, ignored = [sum(int(row[i]) for row in summaries) for i in range(3)]
    if not passed or failed or passed + ignored != selected or (ignored and not allow_ignored):
        raise RuntimeError("Incomplete sanitizer test execution")
    return {"passed": passed, "failed": failed, "ignored": ignored}


def configured_environment(kind: str, target_dir: Path) -> dict[str, str]:
    # Build/test dependencies must not inherit compiler wrappers, arbitrary
    # Cargo overrides, loader injection, or application/service credentials.
    # Preserve tool/cache locations and the proxy/CA settings required by the
    # host's network path; flags and compilers are configured below.
    inherited = {
        "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "TMP", "TEMP",
        "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM",
        "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
        "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_DIST_SERVER", "RUSTUP_UPDATE_ROOT",
        "RUSTUP_MAX_RETRIES", "CARGO_NET_RETRY", "CARGO_NET_OFFLINE",
        "CARGO_HTTP_TIMEOUT", "CARGO_HTTP_MULTIPLEXING", "CARGO_HTTP_PROXY",
        "CARGO_HTTP_CAINFO", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "all_proxy", "no_proxy",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE",
        "GIT_SSL_CAINFO", "GIT_SSL_CAPATH",
    }
    env = {key: value for key, value in os.environ.items() if key in inherited}
    rustflags = f"-Zsanitizer={kind} -Cforce-frame-pointers=yes -Cdebuginfo=2"
    native_flags = f"-fsanitize={kind} -fno-omit-frame-pointer -g"
    env.update({
        "RUSTFLAGS": rustflags,
        "RUSTDOCFLAGS": rustflags,
        "CC_x86_64_unknown_linux_gnu": "clang",
        "CXX_x86_64_unknown_linux_gnu": "clang++",
        "CFLAGS_x86_64_unknown_linux_gnu": native_flags,
        "CXXFLAGS_x86_64_unknown_linux_gnu": native_flags,
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": "clang",
        "CARGO_TARGET_DIR": str(target_dir),
        "CARGO_INCREMENTAL": "0",
        "CARGO_BUILD_JOBS": "4",
        "RUST_TEST_THREADS": "1",
        "RUST_MIN_STACK": "8388608",
        "RUST_BACKTRACE": "1",
        "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1:symbolize=1",
        "TSAN_OPTIONS": "halt_on_error=1:exitcode=66:symbolize=1",
        "LSAN_OPTIONS": "exitcode=23:symbolize=1",
        # LSan's helper must inspect threads. Normal CI separately exercises
        # hardening with these documented operator switches left unset.
        "PARALLAX_DISABLE_SECCOMP": "1",
        "PARALLAX_DISABLE_ANTI_DEBUG": "1",
    })
    return env


class Runner:
    def __init__(self, kind: str, nightly: str, canaries_only: bool):
        self.kind = kind
        self.nightly = nightly
        self.output = ROOT / "target/security/sanitizers" / kind
        self.build = ROOT / "target/security/sanitizer-build" / kind
        self.output.mkdir(parents=True, exist_ok=True)
        self.env = configured_environment(kind, self.build)
        self.runtime_pre_link_args: list[str] = []
        self.runtime_link_args: list[str] = []
        self.report = {
            "schema_version": 1, "status": "running", "sanitizer": kind,
            "mode": "canaries-only" if canaries_only else "application-and-canaries",
            "nightly": nightly, "target": TARGET,
            "std_instrumentation_requested": True,
            "commands": [], "tests": {}, "native_archives": [],
            "scope_limits": [
                "Only executed paths are checked; this is not a memory-safety proof.",
                "Handwritten assembly and OS/SDK libraries are not compiler-instrumented.",
                "TSan does not model atomic fences or assembly synchronization.",
                "Reachable process-global caches are not reported as leaks by LSan.",
                "Seccomp/anti-debug behavior is checked in the normal lane.",
            ],
        }

    def run(self, label: str, argv: list[str], *, allow_failure: bool = False,
            timeout: int = 1800) -> subprocess.CompletedProcess[str]:
        print(f"[{self.kind}] {label}: {' '.join(argv)}", flush=True)
        log = self.output / f"{label}.log"
        with log.open("w", encoding="utf-8") as stream:
            process = subprocess.Popen(argv, cwd=ROOT, env=self.env, text=True,
                                       stdout=stream, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            try:
                returncode = process.wait(timeout=timeout)
            except BaseException as error:
                if label == "tsan-runtime-build":
                    # The builder owns separate compiler process groups. Let
                    # its SIGTERM handler reap those before killing its group.
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        pass
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                if isinstance(error, subprocess.TimeoutExpired):
                    raise RuntimeError(f"{label} exceeded {timeout}s; see {log}") from error
                raise
        output = log.read_text(encoding="utf-8", errors="replace")
        self.report["commands"].append({"label": label, "argv": argv,
                                        "exit_code": returncode, "log": log.name})
        if returncode and not allow_failure:
            print(output[-10000:], file=sys.stderr)
            raise RuntimeError(f"{label} exited {returncode}; see {log}")
        return subprocess.CompletedProcess(argv, returncode, output, None)

    def cargo(self) -> list[str]:
        return ["cargo", f"+{self.nightly}", "test", "--locked", "-Zbuild-std",
                "--target", TARGET]

    def prepare_thread_runtime(self) -> None:
        """Reproduce the bundled detector defect, then require the fixed control.

        The duplicate-fd program is race-free. Its old-runtime report documents
        a compatibility defect and never counts as a successful race canary.
        All application code remains instrumented; no reports are suppressed.
        """
        if self.kind != "thread":
            return
        if self.nightly != NIGHTLY:
            raise RuntimeError("The TSan runtime backport requires the pinned nightly")
        original_build = self.build
        self.build = original_build.parent / "thread-bundled-control"
        self.env = configured_environment(self.kind, self.build)
        build = ["cargo", f"+{self.nightly}", "build", "--locked", "-Zbuild-std",
                 "--target", TARGET, "--manifest-path", "verification/sanitizers/Cargo.toml",
                 "--bin", "epoll_publication"]
        self.run("bundled-epoll-build", build)
        binary = self.build / TARGET / "debug/epoll_publication"
        same = self.run("bundled-epoll-same-fd", [str(binary), "same-fd"], timeout=60)
        if not epoll_control_completed(same, "same-fd"):
            raise RuntimeError("Bundled TSan failed the same-fd compatibility control")
        duplicate = self.run("bundled-epoll-duplicate-fd", [str(binary), "duplicate-fd"],
                             allow_failure=True, timeout=60)
        if not (duplicate.returncode == 66
                and DIAGNOSTICS["thread"] in duplicate.stdout
                and "epoll_publication.rs" in duplicate.stdout):
            raise RuntimeError("Pinned bundled TSan defect was not reproduced; reassess the backport")
        self.report["bundled_runtime_compatibility"] = {
            "same_fd": "passed", "duplicate_fd": "known-detector-defect-reproduced",
            "upstream_fix": "https://github.com/llvm/llvm-project/pull/221064",
        }
        self.save()
        self.run("tsan-runtime-build", [sys.executable, "scripts/security/tsan_runtime.py"],
                 timeout=1800)
        runtime_directory = ROOT / "target/security/tsan-runtime"
        runtime = json.loads((runtime_directory / "report.json").read_text(encoding="utf-8"))
        self.runtime_pre_link_args, self.runtime_link_args = runtime_link_arguments(
            runtime, runtime_directory)
        self.report["thread_runtime"] = runtime
        self.build = original_build
        self.env = configured_environment(self.kind, self.build)
        rustflags = shlex.split(self.env["RUSTFLAGS"]) + ["-Zexternal-clangrt"]
        rustflags += [f"-Zpre-link-arg={value}" for value in self.runtime_pre_link_args]
        rustflags += [f"-Clink-arg={value}" for value in self.runtime_link_args]
        # Cargo's encoded form preserves paths containing spaces exactly.
        self.env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(rustflags)
        self.env["RUSTFLAGS"] = shlex.join(rustflags)
        self.env["RUSTDOCFLAGS"] = shlex.join(rustflags)
        self.run("patched-epoll-build", build)
        binary = self.build / TARGET / "debug/epoll_publication"
        for mode in ("same-fd", "duplicate-fd"):
            result = self.run(f"patched-epoll-{mode}", [str(binary), mode], timeout=60)
            if not epoll_control_completed(result, mode):
                raise RuntimeError(f"Patched TSan failed the {mode} compatibility control")
        self.report["patched_runtime_compatibility"] = "same-fd-and-duplicate-fd-passed"
        self.save()

    def canaries(self) -> None:
        self.run("rust-canary-build", ["cargo", f"+{self.nightly}", "build", "--locked",
                 "-Zbuild-std", "--target", TARGET, "--manifest-path",
                 "verification/sanitizers/Cargo.toml"])
        rust = self.build / TARGET / "debug/parallax-sanitizer-canaries"
        native = self.output / "native-canary"
        native_link = (["-fno-sanitize-link-runtime"]
                       + self.runtime_pre_link_args + self.runtime_link_args
                       if self.runtime_link_args else [])
        self.run("native-canary-build", ["clang", f"-fsanitize={self.kind}",
                 "-fno-omit-frame-pointer", "-g", "-O1", "-pthread",
                 "verification/sanitizers/native.c", "-o", str(native)] + native_link)
        for name, binary in (("rust", rust), ("native", native)):
            good = self.run(f"{name}-good", [str(binary), "good"], timeout=60)
            if "sanitizer-good-control-complete" not in good.stdout:
                raise RuntimeError(f"{name} positive control did not finish")
            bad = self.run(f"{name}-bad", [str(binary), self.kind],
                           allow_failure=True, timeout=60)
            if not expected_detection(self.kind, bad.returncode, bad.stdout):
                raise RuntimeError(f"{name} bad canary lacked required {self.kind} "
                                   f"diagnostic (exit={bad.returncode})")
        self.report["canaries"] = "rust-and-native-positive-and-negative-passed"

    def native_inventory(self) -> None:
        native_build = self.build / TARGET / "debug/build"
        archives = sorted(native_build.glob("*/out/**/*.a"))
        if not archives:
            raise RuntimeError("No target native archives; application was not built")
        seen: set[str] = set()
        instrumented: set[str] = set()
        symbol = {"address": "__asan_", "thread": "__tsan_", "leak": "__lsan_"}[self.kind]
        for archive in archives:
            parent = archive.relative_to(native_build).parts[0]
            dependency = next((name for name in ("aws-lc-sys", "ring", "pqcrypto-mldsa")
                               if parent.startswith(name + "-")), None)
            if dependency is None:
                continue
            seen.add(dependency)
            result = subprocess.run(["nm", "-u", str(archive)], cwd=ROOT,
                                    text=True, capture_output=True, check=False, timeout=60)
            if result.returncode:
                raise RuntimeError(f"Cannot inspect native archive {archive}")
            references = result.stdout.count(symbol)
            if references:
                instrumented.add(dependency)
            self.report["native_archives"].append({
                "dependency": dependency,
                "path": str(archive.relative_to(self.build)),
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "sanitizer_symbol_references": references,
            })
        expected = {"aws-lc-sys", "ring", "pqcrypto-mldsa"}
        if expected - seen:
            raise RuntimeError(f"Missing native build evidence: {sorted(expected - seen)}")
        # LSan uses allocation interception, not per-access compiler probes.
        if self.kind != "leak" and expected - instrumented:
            raise RuntimeError(f"Native archives lack {symbol}: "
                               f"{sorted(expected - instrumented)}")
        self.report["native_instrumentation"] = (
            "allocation-interception" if self.kind == "leak" else
            "sanitizer-symbols-observed-for-each-native-dependency; assembly-excluded")

    def application(self) -> None:
        failures = []
        for label, selection, runtime in SUITES:
            command = self.cargo() + selection + ["--"] + runtime
            listing = self.run(label + "-list", command + ["--list"])
            names = listed_tests(listing.stdout)
            if not names:
                raise RuntimeError(f"Empty sanitizer test selection: {label}")
            entry = {"listed": names, "status": "running"}
            self.report["tests"][label] = entry
            self.save()
            try:
                execution = self.run(label, command + ["--test-threads=1"])
                entry.update(completed_counts(execution.stdout, len(names),
                                              allow_ignored=label == "library"))
                entry["status"] = "passed"
            except RuntimeError as error:
                # Retain failures and collect evidence from other compiled
                # targets. Any failure still makes the overall run fail.
                entry.update({"status": "failed", "error": str(error)})
                failures.append(label)
            finally:
                self.save()
        self.native_inventory()
        if failures:
            raise RuntimeError(f"Sanitizer workload(s) failed: {', '.join(failures)}")

    def save(self) -> None:
        (self.output / "report.json").write_text(
            json.dumps(self.report, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=DIAGNOSTICS)
    parser.add_argument("--nightly", default=NIGHTLY)
    parser.add_argument("--canaries-only", action="store_true")
    parser.add_argument("--plan", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"nightly-\d{4}-\d{2}-\d{2}", args.nightly):
        parser.error("use an explicit dated nightly")
    if args.kind == "thread" and args.nightly != NIGHTLY:
        parser.error("thread mode requires the nightly paired with its pinned runtime backport")
    if args.plan:
        print(json.dumps({"kind": args.kind, "nightly": args.nightly, "target": TARGET,
                          "suites": SUITES, "canaries_only": args.canaries_only}, indent=2))
        return 0
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("native x86_64 Linux required; use the GitHub Actions lane")
    for executable in ("cargo", "rustc", "clang", "clang++", "nm"):
        if not shutil.which(executable):
            parser.error(f"missing required executable: {executable}")
    runner = Runner(args.kind, args.nightly, args.canaries_only)
    try:
        runner.report["source_commit"] = runner.run(
            "source", ["git", "rev-parse", "HEAD"]).stdout.strip()
        dirty = runner.run("source-status", ["git", "status", "--porcelain"])
        runner.report["working_tree_dirty"] = bool(dirty.stdout.strip())
        runner.report["rustc"] = runner.run(
            "rustc", ["rustc", f"+{args.nightly}", "-vV"]).stdout.strip()
        runner.report["clang"] = runner.run("clang", ["clang", "--version"]).stdout.strip()
        runner.prepare_thread_runtime()
        runner.report["build_flags"] = {key: runner.env[key] for key in (
            "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CFLAGS_x86_64_unknown_linux_gnu",
            "CXXFLAGS_x86_64_unknown_linux_gnu", "CARGO_INCREMENTAL",
            "ASAN_OPTIONS", "TSAN_OPTIONS", "LSAN_OPTIONS") if key in runner.env}
        runner.canaries()
        if not args.canaries_only:
            runner.application()
        runner.report["status"] = "passed"
        print(f"{args.kind}: passed; report: {runner.output / 'report.json'}")
        return 0
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        runner.report["status"] = "failed"
        runner.report["error"] = str(error)
        print(str(error), file=sys.stderr)
        return 1
    finally:
        runner.save()


if __name__ == "__main__":
    sys.exit(main())
