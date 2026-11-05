#!/usr/bin/env python3
"""Build ParallaX's source-pinned Linux x86_64 TSan runtime.

The runtime is Rust nightly-2026-06-17's LLVM source with exactly LLVM commit
09910aa044808dfbfe1e0f96b5e39260789212fb applied. No detector suppression or
instrumentation change is involved. Requires Python 3.10+, CMake 3.20+, Ninja,
Git, Clang/Clang++, nm and an installed LLVM development CMake package.
Process ownership requires Linux /proc, pidfds and child-subreaper support.

Usage: python3 scripts/security/tsan_runtime.py
Output: target/security/tsan-runtime/{report.json,*.log,*.a,*.a.syms}
Only report.json with schema=1 and status="passed" describes usable artifacts.
Sources and intermediate build files are temporary; every invocation rebuilds.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
TOOL = "parallax-tsan-runtime"
NIGHTLY = "nightly-2026-06-17"
TARGET = "x86_64-unknown-linux-gnu"
SOURCE_COMMIT = "ec9ab9d68bf7a0e86b2ddf3c0e6e3c4620e02961"
PATCH_COMMIT = "09910aa044808dfbfe1e0f96b5e39260789212fb"
SOURCE_URL = f"https://github.com/rust-lang/llvm-project/archive/{SOURCE_COMMIT}.tar.gz"
PATCH_URL = f"https://github.com/llvm/llvm-project/commit/{PATCH_COMMIT}.patch"
SOURCE_SHA256 = "a2267d295f69a8450cae462158d57f5599bef79b4c2940111c9390d47660d4fd"
PATCH_SHA256 = "53863c9ed7f2bb7ab790bc54c31bffa43ea480f6ff8cff75150010cac5252c51"
PATCH_PATHS = (
    "compiler-rt/lib/tsan/rtl/tsan_interceptors_posix.cpp",
    "compiler-rt/test/tsan/Linux/fd_fcntl_dupfd_cloexec_norace.cpp",
)
SOURCE_PREFIXES = ("compiler-rt/", "cmake/", "llvm/cmake/", "llvm/include/")
SOURCE_FILES = ("llvm/CMakeLists.txt", "LICENSE.TXT")
OFF_COMPONENTS = ("BUILTINS", "LIBFUZZER", "PROFILE", "XRAY", "CTX_PROFILE", "MEMPROF", "ORC", "GWP_ASAN")
REQUIRED_SYMBOLS = frozenset(("__tsan_init", "__interceptor_fcntl", "__interceptor_fcntl64"))
ALLOWED_DOWNLOAD_HOSTS = frozenset(("github.com", "codeload.github.com", "patch-diff.githubusercontent.com"))
MAX_SOURCE_BYTES = 1024 * 1024 * 1024
MAX_EXTRACT_BYTES = 2 * MAX_SOURCE_BYTES
# Linux __WALL: include clone children regardless of their exit signal.
LINUX_WAIT_ALL = 0x40000000


class BuildError(RuntimeError):
    pass


class Termination:
    """Defer asynchronous cancellation until command ownership is registered."""

    signals = (signal.SIGTERM, signal.SIGINT)

    def __init__(self):
        self.deferred = 0
        self.pending = None

    def handle(self, signum, _frame) -> None:
        self.pending = signum
        if not self.deferred:
            self.check()

    def check(self) -> None:
        if self.pending is not None:
            signum, self.pending = self.pending, None
            # Once cancellation is delivered, let the registered cleanup
            # finish without a second signal interrupting its finally block.
            for number in self.signals:
                signal.signal(number, signal.SIG_IGN)
            raise BuildError(f"runtime build terminated by signal {signum}")

    @contextlib.contextmanager
    def defer(self):
        self.deferred += 1
        try:
            yield
        finally:
            self.deferred -= 1
            if not self.deferred:
                self.check()


TERMINATION = Termination()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def regular_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise BuildError(f"expected a regular file, not a link: {path}")


def verify_hash(path: Path, expected: str) -> dict:
    regular_file(path)
    actual = sha256_file(path)
    if actual != expected:
        raise BuildError(f"SHA-256 mismatch for {path.name}: expected {expected}, got {actual}")
    return {"sha256": actual, "bytes": path.stat().st_size}


def clean_environment(environment: dict[str, str]) -> dict[str, str]:
    # The caller is normally a sanitizer job. Its instrumentation must not be
    # inherited by the compiler-rt runtime build itself.
    prefixes = (
        "CFLAGS", "CXXFLAGS", "CPPFLAGS", "ASFLAGS", "ASMFLAGS", "LDFLAGS", "CMAKE_", "GIT_",
        "CCACHE_", "SCCACHE_", "CCC_", "DYLD_", "LD_", "LLVM_",
    )
    names = {
        "CC", "CXX", "CPP", "AS", "AR", "RANLIB", "LD", "NM", "STRIP",
        "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH",
        "LIBRARY_PATH", "COMPILER_PATH", "GCC_EXEC_PREFIX", "SDKROOT",
        "MACOSX_DEPLOYMENT_TARGET", "PYTHONPATH", "PYTHONHOME", "BASH_ENV", "ENV",
        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
        "ASAN_OPTIONS", "TSAN_OPTIONS", "LSAN_OPTIONS", "MSAN_OPTIONS", "UBSAN_OPTIONS",
    }
    result = {key: value for key, value in environment.items()
              if key not in names and not key.startswith(prefixes)}
    result.update({"LC_ALL": "C", "LANG": "C", "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": os.devnull})
    return result


def check_download_url(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS
            or parsed.username is not None or parsed.password is not None
            or parsed.port not in (None, 443)):
        raise BuildError(f"unexpected download location: {url}")


class PinnedRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        check_download_url(new_url)
        return super().redirect_request(request, fp, code, message, headers, new_url)


def acquire(url: str, destination: Path, expected: str, limit: int,
            local_file: Path | None = None) -> dict:
    if local_file is not None:
        verify_hash(local_file, expected)
        shutil.copyfile(local_file, destination)
        final_url = None
    else:
        check_download_url(url)
        opener = urllib.request.build_opener(PinnedRedirects())
        request = urllib.request.Request(url, headers={"User-Agent": f"{TOOL}/1"})
        started = time.monotonic()
        size = 0
        with opener.open(request, timeout=60) as response, destination.open("xb") as output:
            final_url = response.geturl()
            check_download_url(final_url)
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                size += len(chunk)
                if size > limit or time.monotonic() - started > 900:
                    raise BuildError("pinned input exceeded its download size/time bound")
                output.write(chunk)
    if destination.stat().st_size > limit:
        raise BuildError("pinned input exceeded its size bound")
    result = verify_hash(destination, expected)
    result.update({"url": url, "final_url": final_url,
                   "local_file": str(local_file) if local_file is not None else None})
    return result


def source_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (path.is_absolute() or ".." in path.parts or "\\" in name
            or any(ord(char) < 32 for char in name)
            or not path.parts or path.parts[0] != f"llvm-project-{SOURCE_COMMIT}"):
        raise BuildError(f"unsafe or unexpected archive member: {name!r}")
    return PurePosixPath(*path.parts[1:])


def extract_sources(archive: Path, destination: Path) -> None:
    destination.mkdir()
    total = 0
    seen = set()
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            relative = source_path(member.name)
            name = relative.as_posix()
            if name not in SOURCE_FILES and not name.startswith(SOURCE_PREFIXES):
                continue
            if not member.isdir() and not member.isfile():
                raise BuildError(f"links and special source members are forbidden: {name}")
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if name in seen:
                raise BuildError(f"duplicate source member: {name}")
            seen.add(name)
            total += member.size
            if member.size < 0 or total > MAX_EXTRACT_BYTES:
                raise BuildError("source archive exceeded its extraction bound")
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = source.extractfile(member)
            if stream is None:
                raise BuildError(f"missing source file data: {name}")
            with stream, target.open("xb") as output:
                shutil.copyfileobj(stream, output)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
    for name in ("compiler-rt/CMakeLists.txt", "llvm/CMakeLists.txt",
                 "compiler-rt/lib/tsan/rtl/tsan_interceptors_posix.cpp"):
        regular_file(destination / name)


def source_state(directory: Path) -> dict[str, str]:
    result = {}
    for parent, directories, files in os.walk(directory, followlinks=False):
        directories[:] = sorted(name for name in directories if name != ".git")
        for name in directories:
            if (Path(parent) / name).is_symlink():
                raise BuildError("unexpected symlink in build sources")
        for name in sorted(files):
            path = Path(parent) / name
            regular_file(path)
            relative = path.relative_to(directory).as_posix()
            result[relative] = f"{stat.S_IMODE(path.stat().st_mode):o}:{sha256_file(path)}"
    return result


def state_digest(state: dict[str, str]) -> str:
    encoded = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def verify_patch(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    if not text.startswith(f"From {PATCH_COMMIT} Mon Sep 17 00:00:00 2001\n"):
        raise BuildError("patch does not identify the pinned upstream commit")
    changes = re.findall(r"^diff --git a/(\S+) b/(\S+)$", text, re.MULTILINE)
    if sorted(changes) != sorted((name, name) for name in PATCH_PATHS):
        raise BuildError("patch touches files outside the exact upstream fix")


def check_patch_changes(before: dict[str, str], after: dict[str, str]) -> None:
    changed = sorted(name for name in before.keys() | after.keys()
                     if before.get(name) != after.get(name))
    if changed != sorted(PATCH_PATHS):
        raise BuildError(f"patch changed unexpected sources: {changed}")


def write_report(output: Path, report: dict) -> None:
    destination = output / "report.json"
    if destination.is_symlink():
        raise BuildError("refusing to overwrite a symlink report")
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=output,
                                     prefix=".report-", delete=False) as stream:
        temporary = Path(stream.name)
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)


def process_identity(pid: int) -> dict | None:
    try:
        data = (Path("/proc") / str(pid) / "stat").read_bytes()
    except (FileNotFoundError, ProcessLookupError):
        return None
    except PermissionError as error:
        raise BuildError(f"cannot inspect process {pid} during cleanup") from error
    # comm is parenthesized and can itself contain spaces or ')' characters.
    head, separator, tail = data.rpartition(b") ")
    fields = tail.split()
    try:
        if not separator or int(head.split(b" (", 1)[0]) != pid or len(fields) < 20:
            raise ValueError("invalid process stat record")
        return {"pid": pid, "ppid": int(fields[1]), "pgid": int(fields[2]),
                "sid": int(fields[3]), "start_ticks": int(fields[19])}
    except (ValueError, IndexError) as error:
        raise BuildError(f"malformed process identity for {pid}") from error


def direct_children(deadline: float | None = None) -> list[dict]:
    children = []
    with os.scandir("/proc") as entries:
        for entry in entries:
            if deadline is not None and time.monotonic() >= deadline:
                raise BuildError("process census exceeded the cleanup deadline")
            if entry.name.isascii() and entry.name.isdigit():
                identity = process_identity(int(entry.name))
                if identity is not None and identity["ppid"] == os.getpid():
                    children.append(identity)
    return children


def prepare_process_tracking() -> None:
    # This is a standalone Linux builder, not a process supervisor embedded in
    # another application. No existing children/reaper may share its ownership.
    if sys.platform != "linux" or not all(hasattr(os, name) for name in
            ("pidfd_open", "waitid", "WNOWAIT")) or not hasattr(signal, "pidfd_send_signal"):
        raise BuildError("runtime commands require Linux /proc, pidfds and waitid(WNOWAIT)")
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise BuildError("runtime builder requires the default SIGCHLD disposition")
    try:
        os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT | LINUX_WAIT_ALL)
    except ChildProcessError:
        pass
    else:
        raise BuildError("runtime builder must not own pre-existing child processes")
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                     ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    # Linux PR_SET_CHILD_SUBREAPER / PR_GET_CHILD_SUBREAPER. Keep this ownership
    # for the standalone builder's lifetime, including failed cleanup.
    enabled = ctypes.c_int()
    if (prctl(36, 1, 0, 0, 0) != 0
            or prctl(37, ctypes.addressof(enabled), 0, 0, 0) != 0):
        raise OSError(ctypes.get_errno(), "cannot establish Linux child subreaper")
    if enabled.value != 1 or process_identity(os.getpid()) is None:
        raise BuildError("cannot verify Linux child ownership")
    descriptor = os.pidfd_open(os.getpid(), 0)
    try:
        signal.pidfd_send_signal(descriptor, 0)
    finally:
        os.close(descriptor)


def kill_adopted_child(observed: dict) -> None:
    try:
        descriptor = os.pidfd_open(observed["pid"], 0)
    except ProcessLookupError:
        return
    try:
        # Opening the pidfd before re-reading identity binds a signal to that
        # process even if its numeric PID is recycled before signal delivery.
        current = process_identity(observed["pid"])
        if current is None or current["ppid"] != os.getpid():
            return
        if current["start_ticks"] != observed["start_ticks"]:
            return
        if current["sid"] == os.getsid(0) or current["pid"] == os.getpid():
            raise BuildError("refusing to signal a process in the caller's session")
        try:
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        except ProcessLookupError:
            pass
    finally:
        os.close(descriptor)


class Commands:
    def __init__(self, output: Path, environment: dict[str, str], report: dict):
        self.output = output
        self.environment = environment
        self.report = report
        self.safe_to_clean = True

    def wait(self, process: subprocess.Popen, timeout: int) -> None:
        deadline = time.monotonic() + timeout
        while True:
            TERMINATION.check()
            # Do not reap yet: the reserved direct child cannot have its PID
            # reused before cleanup has taken responsibility for its children.
            try:
                exited = os.waitid(os.P_PID, process.pid,
                                   os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError as error:
                raise BuildError("command leader was reaped outside the runtime builder") from error
            if exited is not None:
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(process.args, timeout)
            time.sleep(min(0.1, remaining))

    def finish_session(self, process: subprocess.Popen, leader_fd: int | None, record: dict) -> None:
        if process.pid in (os.getpid(), os.getsid(0)):
            raise BuildError("refusing to signal the runtime builder's session")
        deadline = time.monotonic() + 5
        try:
            if leader_fd is None:
                # Only the unreaped direct child uses this fallback if pidfd
                # acquisition itself failed. Its PID is still reserved.
                os.kill(process.pid, signal.SIGKILL)
            else:
                signal.pidfd_send_signal(leader_fd, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=max(0.01, deadline - time.monotonic()))
        record["reaped_descendants"] = []
        # Ninja can use different PGIDs, and descendants can fork during a
        # /proc census. Subreaper adoption plus kernel ECHILD is the completion
        # proof; an empty snapshot alone is never sufficient. After reaping the
        # leader, do not use its potentially reusable numeric SID for ownership.
        while True:
            for child in direct_children(deadline):
                if time.monotonic() >= deadline:
                    raise BuildError("command descendant cleanup exceeded its deadline")
                kill_adopted_child(child)
            while True:
                if time.monotonic() >= deadline:
                    raise BuildError("could not confirm all owned command descendants exited")
                try:
                    pid, _status = os.waitpid(-1, os.WNOHANG | LINUX_WAIT_ALL)
                except ChildProcessError:
                    self.safe_to_clean = True
                    record["cleanup_complete"] = True
                    record["cleanup_proof"] = "linux-subreaper-ECHILD"
                    return
                if pid == 0:
                    break
                record["reaped_descendants"].append(pid)
            if time.monotonic() >= deadline:
                raise BuildError("could not confirm all owned command descendants exited")
            time.sleep(0.02)

    def run(self, command: list[str], label: str, cwd: Path,
            timeout: int = 1800) -> str:
        prepare_process_tracking()
        log = self.output / f"{label}.log"
        if log.is_symlink():
            raise BuildError(f"refusing to overwrite a symlink log: {log}")
        record = {"argv": command, "cwd": str(cwd), "log": str(log)}
        self.report["commands"].append(record)
        print(f"{TOOL}: {label}", flush=True)
        with log.open("w", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
            with TERMINATION.defer():
                process = None
                leader_fd = None
                try:
                    process = subprocess.Popen(command, cwd=cwd, env=self.environment,
                                               stdout=stream, stderr=subprocess.STDOUT,
                                               start_new_session=True)
                    self.safe_to_clean = False
                    record["process_group"] = process.pid
                    record["session_id"] = process.pid
                    record["cleanup_complete"] = False
                    leader_fd = os.pidfd_open(process.pid, 0)
                    identity = process_identity(process.pid)
                    if (identity is None or identity["sid"] != process.pid
                            or identity["ppid"] != os.getpid()):
                        raise BuildError("command leader identity does not match its owned session")
                    record["leader_start_ticks"] = identity["start_ticks"]
                    self.wait(process, timeout)
                finally:
                    if process is not None:
                        try:
                            self.finish_session(process, leader_fd, record)
                        finally:
                            if leader_fd is not None:
                                os.close(leader_fd)
                            record["returncode"] = process.returncode
        text = log.read_text(encoding="utf-8", errors="replace")
        if process.returncode:
            raise BuildError(f"{label} failed ({process.returncode}); see {log}\n{text[-4000:]}")
        return text


@contextlib.contextmanager
def work_directory(output: Path, commands: Commands):
    work = Path(tempfile.mkdtemp(prefix=".work-", dir=output))
    try:
        yield work
    finally:
        if commands.safe_to_clean:
            shutil.rmtree(work)
        else:
            # Fail closed if a process could still be using its sources. A
            # retained path is diagnostic evidence, never a usable runtime.
            commands.report["retained_work_directory"] = str(work)


def executable(name: str) -> Path:
    found = shutil.which(name)
    if found is None:
        raise BuildError(f"required executable is unavailable: {name}")
    # Preserve clang++'s invocation name: resolving that symlink can change
    # driver language/link mode even though its binary is the same as clang.
    return Path(os.path.abspath(found))


def cmake_arguments(source: Path, build: Path, tools: dict[str, Path],
                    llvm_cmake: Path) -> list[str]:
    arguments = [
        str(tools["cmake"]), "-S", str(source / "compiler-rt"), "-B", str(build),
        "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
        f"-DCMAKE_MAKE_PROGRAM={tools['ninja']}",
        f"-DCMAKE_C_COMPILER={tools['clang']}",
        f"-DCMAKE_CXX_COMPILER={tools['clangxx']}",
        f"-DCMAKE_ASM_COMPILER={tools['clang']}",
        f"-DCMAKE_C_COMPILER_TARGET={TARGET}",
        f"-DCMAKE_CXX_COMPILER_TARGET={TARGET}",
        f"-DCMAKE_ASM_COMPILER_TARGET={TARGET}",
        f"-DLLVM_CMAKE_DIR={llvm_cmake}",
        f"-DPython3_EXECUTABLE={sys.executable}",
        "-DLLVM_ENABLE_PER_TARGET_RUNTIME_DIR=OFF",
        "-DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON",
        "-DCOMPILER_RT_BUILD_SANITIZERS=ON",
        "-DCOMPILER_RT_SANITIZERS_TO_BUILD=tsan",
        "-DCOMPILER_RT_USE_LIBCXX=OFF",
        "-DCOMPILER_RT_INCLUDE_TESTS=OFF",
    ]
    arguments.extend(f"-DCOMPILER_RT_BUILD_{name}=OFF" for name in OFF_COMPONENTS)
    arguments.extend(f"-D{name}=" for name in (
        "CMAKE_C_FLAGS", "CMAKE_CXX_FLAGS", "CMAKE_ASM_FLAGS",
        "CMAKE_EXE_LINKER_FLAGS", "CMAKE_SHARED_LINKER_FLAGS",
        "CMAKE_MODULE_LINKER_FLAGS", "CMAKE_STATIC_LINKER_FLAGS",
        "CMAKE_C_COMPILER_LAUNCHER", "CMAKE_CXX_COMPILER_LAUNCHER",
    ))
    return arguments


def validate_cache(path: Path) -> None:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"([^#/:][^:]*):[^=]+=(.*)$", line)
        if match:
            values[match.group(1)] = match.group(2)
    required = {
        "CMAKE_BUILD_TYPE": "Release", "CMAKE_C_COMPILER_TARGET": TARGET,
        "CMAKE_CXX_COMPILER_TARGET": TARGET, "COMPILER_RT_DEFAULT_TARGET_ONLY": "ON",
        "COMPILER_RT_BUILD_SANITIZERS": "ON", "COMPILER_RT_SANITIZERS_TO_BUILD": "tsan",
        "LLVM_ENABLE_PER_TARGET_RUNTIME_DIR": "OFF",
        "CMAKE_C_FLAGS": "", "CMAKE_CXX_FLAGS": "", "CMAKE_ASM_FLAGS": "",
    }
    required.update({f"COMPILER_RT_BUILD_{name}": "OFF" for name in OFF_COMPONENTS})
    for name, expected in required.items():
        if values.get(name) != expected:
            raise BuildError(f"CMake configuration mismatch: {name}={values.get(name)!r}")


def validate_runtime(archive: Path, dynamic_list: Path, nm_output: str) -> None:
    regular_file(archive)
    regular_file(dynamic_list)
    with archive.open("rb") as stream:
        if stream.read(8) != b"!<arch>\n":
            raise BuildError("runtime is not a self-contained static archive")
    defined = {line.split()[-1] for line in nm_output.splitlines() if line.split()}
    missing = REQUIRED_SYMBOLS - defined
    if missing:
        raise BuildError(f"patched runtime is missing definitions: {sorted(missing)}")
    symbols = dynamic_list.read_text(encoding="utf-8").strip()
    exports = set(re.findall(r"^\s*([A-Za-z_][A-Za-z_0-9]*)\s*;\s*$", symbols, re.MULTILINE))
    if (not symbols.startswith("{") or not symbols.endswith("};")
            or not REQUIRED_SYMBOLS.issubset(exports)):
        raise BuildError("runtime dynamic list is missing sanitizer exports")


def publish_artifact(source: Path, output: Path) -> dict:
    destination = output / source.name
    if destination.is_symlink():
        raise BuildError(f"refusing to overwrite a symlink artifact: {destination}")
    with tempfile.NamedTemporaryFile(dir=output, prefix=".artifact-", delete=False) as stream:
        temporary = Path(stream.name)
        with source.open("rb") as incoming:
            shutil.copyfileobj(incoming, stream)
    temporary.chmod(0o644)
    os.replace(temporary, destination)
    return {"path": str(destination), "sha256": sha256_file(destination)}


def prepare_output(path: Path) -> Path:
    if path.is_symlink():
        raise BuildError("output directory must not be a symlink")
    output = path.resolve()
    if output.exists() and any(output.iterdir()):
        previous = output / "report.json"
        regular_file(previous)
        data = json.loads(previous.read_text(encoding="utf-8"))
        if data.get("tool") != TOOL or data.get("schema") != 1:
            raise BuildError("refusing to use a nonempty directory not owned by this builder")
    output.mkdir(parents=True, exist_ok=True)
    return output


def build_runtime(args) -> dict:
    if sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        raise BuildError("this runtime builder requires native Linux x86_64")
    import fcntl

    output = prepare_output(args.output)
    lock_path = output / ".build.lock"
    if lock_path.is_symlink():
        raise BuildError("build lock must not be a symlink")
    with lock_path.open("a") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise BuildError("another runtime build owns this output directory") from error
        report = {"schema": 1, "tool": TOOL, "status": "running", "nightly": NIGHTLY,
                  "source_commit": SOURCE_COMMIT, "patch_commit": PATCH_COMMIT,
                  "target": TARGET, "commands": []}
        # Invalidate any previous successful report before acquisition or build.
        write_report(output, report)
        try:
            environment = clean_environment(dict(os.environ))
            commands = Commands(output, environment, report)
            tools = {name: executable(value) for name, value in {
                "cmake": "cmake", "ninja": "ninja", "git": "git", "nm": "nm",
                "clang": args.clang, "clangxx": args.clangxx,
            }.items()}
            llvm_cmake = args.llvm_cmake_dir.resolve()
            regular_file(llvm_cmake / "LLVMConfig.cmake")
            report["tools"] = {}
            for name, tool in tools.items():
                version = commands.run([str(tool), "--version"], f"{name}-version", output, 30)
                if name in ("clang", "clangxx") and "clang version" not in version.lower():
                    raise BuildError(f"{name} must be a Clang driver")
                report["tools"][name] = {"path": str(tool), "realpath": str(tool.resolve()),
                                         "sha256": sha256_file(tool), "version": version}
            report["llvm_config"] = {"path": str(llvm_cmake / "LLVMConfig.cmake"),
                                     "sha256": sha256_file(llvm_cmake / "LLVMConfig.cmake")}
            report["removed_environment_names"] = sorted(set(os.environ) - set(environment))
            with work_directory(output, commands) as work:
                archive = work / "llvm-project.tar.gz"
                patch = work / "upstream.patch"
                print(f"{TOOL}: acquiring pinned source and patch", flush=True)
                report["source_archive"] = acquire(SOURCE_URL, archive, SOURCE_SHA256,
                                                    MAX_SOURCE_BYTES, args.source_archive)
                report["patch"] = acquire(PATCH_URL, patch, PATCH_SHA256,
                                           2 * 1024 * 1024, args.patch_file)
                verify_patch(patch)
                source = work / "source"
                extract_sources(archive, source)
                before = source_state(source)
                template = work / "empty-git-template"
                template.mkdir()
                commands.run([str(tools["git"]), "init", "--quiet", f"--template={template}"],
                             "source-git-init", source, 60)
                commands.run([str(tools["git"]), "apply", "--check", "--whitespace=error-all", str(patch)],
                             "patch-check", source, 60)
                commands.run([str(tools["git"]), "apply", "--whitespace=error-all", str(patch)],
                             "patch-apply", source, 60)
                after = source_state(source)
                check_patch_changes(before, after)
                report["sources"] = {"selected_prefixes": list(SOURCE_PREFIXES),
                                     "selected_files": list(SOURCE_FILES),
                                     "before_sha256": state_digest(before),
                                     "patched_sha256": state_digest(after),
                                     "changed_paths": list(PATCH_PATHS)}
                build = work / "build"
                commands.run(cmake_arguments(source, build, tools, llvm_cmake),
                             "configure", work, 600)
                validate_cache(build / "CMakeCache.txt")
                commands.run([str(tools["cmake"]), "--build", str(build), "--parallel", str(args.jobs),
                              "--target", "clang_rt.tsan-x86_64", "clang_rt.tsan-x86_64-symbols"],
                             "build", work)
                runtime = build / "lib/linux/libclang_rt.tsan-x86_64.a"
                dynamic_list = runtime.with_name(runtime.name + ".syms")
                regular_file(runtime)
                symbols = commands.run([str(tools["nm"]), "-g", "--defined-only", str(runtime)],
                                       "runtime-symbols", work, 120)
                validate_runtime(runtime, dynamic_list, symbols)
                if source_state(source) != after:
                    raise BuildError("compiler-rt build unexpectedly modified its source tree")
                report["archive"] = publish_artifact(runtime, output)
                report["dynamic_list"] = publish_artifact(dynamic_list, output)
            report["status"] = "passed"
            write_report(output, report)
            return report
        except (BuildError, OSError, ValueError, tarfile.TarError,
                subprocess.SubprocessError, urllib.error.URLError) as error:
            report["status"] = "failed"
            report["error"] = str(error)
            write_report(output, report)
            raise BuildError(str(error)) from error


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, default=ROOT / "target/security/tsan-runtime")
    parser.add_argument("--nightly", choices=(NIGHTLY,), default=NIGHTLY)
    parser.add_argument("--llvm-cmake-dir", type=Path,
                        default=Path(os.environ.get("LLVM_CMAKE_DIR", "/usr/lib/llvm-18/lib/cmake/llvm")))
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--clangxx", default="clang++")
    parser.add_argument("--jobs", type=int, default=min(os.cpu_count() or 1, 8))
    parser.add_argument("--source-archive", type=Path,
                        help="optional local cache; must match the fixed archive SHA-256")
    parser.add_argument("--patch-file", type=Path,
                        help="optional local cache; must match the fixed patch SHA-256")
    args = parser.parse_args(argv)
    if not 1 <= args.jobs <= 64:
        parser.error("--jobs must be between 1 and 64")
    return args


def main(argv=None) -> int:
    previous = {number: signal.getsignal(number) for number in TERMINATION.signals}
    try:
        for number in TERMINATION.signals:
            signal.signal(number, TERMINATION.handle)
        try:
            report = build_runtime(arguments(argv))
        except (BuildError, OSError, ValueError) as error:
            print(f"{TOOL}: {error}", file=sys.stderr)
            return 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    print(json.dumps({"report": str(Path(report["archive"]["path"]).parent / "report.json"),
                      "archive": report["archive"], "dynamic_list": report["dynamic_list"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
