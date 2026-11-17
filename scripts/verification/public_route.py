#!/usr/bin/env python3
"""Verify ClientChosen public-address routing inside disposable Linux namespaces.

Only the namespace's loopback interface is enabled; these globally routable
address shapes never reach the Internet or modify the host's interfaces.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
ADDRESSES = ("8.8.8.8", "2001:4860:4860::8888")
TEST = "binary_tcp_socks_pq_identity_roundtrip"


def check_result(output: str, address: str) -> None:
    witnesses = re.findall(r"^PUBLIC_ROUTE_VERIFIED ([^\r\n]+)$", output, re.MULTILINE)
    if witnesses != [address]:
        raise ValueError("missing or ambiguous public-route execution witness")
    summaries = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", output)
    if summaries != [("1", "0", "0")]:
        raise ValueError("public-route test did not execute exactly once")


def inside(binary: Path, address: str) -> None:
    # Refuse direct invocation on an ordinary host before changing any interface.
    links = json.loads(subprocess.check_output(["ip", "-json", "link", "show"], text=True))
    own_namespace = os.stat("/proc/self/ns/net")
    host_namespace = os.stat("/proc/1/ns/net")
    isolated = (own_namespace.st_dev, own_namespace.st_ino) != (host_namespace.st_dev, host_namespace.st_ino)
    if not isolated or [link["ifname"] for link in links] != ["lo"] or os.geteuid() != 0:
        raise ValueError("requires a fresh root-owned network namespace distinct from PID 1 with only loopback")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    prefix = "128" if ":" in address else "32"
    command = ["ip", "address", "add", f"{address}/{prefix}", "dev", "lo"]
    if ":" in address:
        command.append("nodad")
    subprocess.run(command, check=True)
    env = dict(os.environ, PARALLAX_TEST_PUBLIC_TARGET=address)
    process = subprocess.Popen([str(binary), TEST, "--exact", "--ignored", "--nocapture"],
                               cwd=ROOT, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, start_new_session=True)
    try:
        output, _ = process.communicate(timeout=90)
    except BaseException:
        # This supervisor runs inside the namespace and owns this exact test group.
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise
    print(output, end="")
    if process.returncode:
        raise ValueError(f"public-route test exited {process.returncode}")
    check_result(output, address)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--address", choices=ADDRESSES, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if sys.platform != "linux":
            raise ValueError("Linux network namespaces are required; no host-interface fallback")
        if args.inside:
            if args.address is None:
                raise ValueError("inside mode requires an address")
            inside(args.inside.resolve(), args.address)
            return 0
        artifact = ROOT / "target/security/public-route"
        artifact.mkdir(parents=True, exist_ok=True)
        report = {"schema_version": 1, "status": "running", "cases": [],
                  "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()}
        try:
            build = subprocess.run(["cargo", "test", "--locked", "--test", "protocol_e2e",
                                    "--no-run", "--message-format=json"], cwd=ROOT,
                                   capture_output=True, text=True, timeout=1200)
            (artifact / "build.log").write_text(build.stdout + build.stderr)
            if build.returncode:
                raise ValueError("failed to build the actual binary E2E target; see build.log")
            records = [json.loads(line) for line in build.stdout.splitlines() if line.startswith("{")]
            binaries = {record["executable"] for record in records
                        if record.get("reason") == "compiler-artifact" and record.get("executable")
                        and record["target"]["name"] == "protocol_e2e" and record["profile"]["test"]}
            if len(binaries) != 1:
                raise ValueError("expected one compiled protocol_e2e test binary")
            binary = next(iter(binaries))
            for index, address in enumerate(ADDRESSES):
                command = ["sudo", "-n", "unshare", "--net", "--", sys.executable,
                           str(Path(__file__).resolve()), "--inside", binary, "--address", address]
                result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120)
                output = result.stdout + result.stderr
                (artifact / f"route-{index}.log").write_text(output)
                if result.returncode:
                    raise ValueError(f"namespace execution failed for {address}: {output[-4000:]}")
                check_result(output, address)
                report["cases"].append({"address": address, "argv": command, "passed": True,
                                        "log": f"route-{index}.log"})
            report["status"] = "passed"
            print("Public-address routing: isolated IPv4 and IPv6 binary cases passed")
        except BaseException:
            report["status"] = "failed"
            raise
        finally:
            (artifact / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"public-route verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
