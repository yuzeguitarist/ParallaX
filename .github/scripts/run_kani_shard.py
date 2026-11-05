#!/usr/bin/env python3
"""Partition the compiler's complete Kani harness inventory without omissions."""

import argparse
import json
from pathlib import Path
import re
import subprocess


# Keep the counts explicit: adding/removing a proof requires reviewing its CI
# assignment. Kani's compiler inventory includes macro-generated harnesses.
SHARDS = {
    "crypto-buffers": (("src/crypto/mldsa/fips202.rs", "src/crypto/replay.rs"), 5),
    "crypto-session": (("src/crypto/session.rs",), 5),
    "mux": (("src/client/runtime.rs", "src/handshake/server.rs", "src/traffic.rs"), 10),
    "records-tls": (("src/protocol/data.rs", "src/tls/safari26.rs"), 8),
    "quic-conn": (("src/transport/udp/quic/conn.rs",), 31),
    "quic-params": (("src/transport/udp/quic/spaces.rs",
                     "src/transport/udp/quic/transport_params.rs"), 11),
}


def partition(document):
    if document.get("kani-version") != "0.67.0" or document.get("file-version") != "0.1":
        raise ValueError("unexpected Kani inventory version")
    expected_total = sum(count for _, count in SHARDS.values())
    if document.get("totals") != {
        "standard-harnesses": expected_total,
        "contract-harnesses": 0,
        "functions-under-contract": 0,
    } or document.get("contract-harnesses") != {} or document.get("contracts") != []:
        raise ValueError("proof inventory changed; review all shard assignments")
    groups = {shard: [] for shard in SHARDS}
    seen = set()
    inventory = document.get("standard-harnesses")
    if not isinstance(inventory, dict):
        raise ValueError("missing compiler harness inventory")
    for source, names in inventory.items():
        owners = [shard for shard, (paths, _) in SHARDS.items() if source in paths]
        if len(owners) != 1 or not isinstance(names, list) or not names:
            raise ValueError(f"unassigned, duplicate or empty proof source: {source}")
        for name in names:
            if not isinstance(name, str) or "::" not in name or name in seen:
                raise ValueError(f"invalid or duplicate harness: {name!r}")
            seen.add(name)
            groups[owners[0]].append(name)
    if len(seen) != expected_total:
        raise ValueError("compiler harness count differs from inventory totals")
    for shard, (_, count) in SHARDS.items():
        if len(groups[shard]) != count:
            raise ValueError(f"{shard}: expected {count} harnesses, got {len(groups[shard])}")
        groups[shard].sort()
    return groups


def check_workflow_matrix():
    workflow = Path(__file__).resolve().parents[1] / "workflows/kani.yml"
    rows = re.findall(r"^        shard: (\[[^\n]*\])$", workflow.read_text(), re.MULTILINE)
    if len(rows) != 1:
        raise ValueError("expected one literal JSON shard matrix")
    matrix = json.loads(rows[0])
    if len(matrix) != len(SHARDS) or set(matrix) != set(SHARDS):
        raise ValueError("workflow matrix omits or duplicates a proof shard")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("shard", choices=SHARDS)
    parser.add_argument("--inventory", type=Path,
                        help="validate an existing compiler inventory without recompiling")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    check_workflow_matrix()
    inventory = args.inventory
    if inventory is None:
        inventory = Path("kani-list.json")
        inventory.unlink(missing_ok=True)
        subprocess.run(["cargo", "kani", "list", "--format", "json"], check=True)
    groups = partition(json.loads(inventory.read_text()))
    print("Complete compiler inventory: " + ", ".join(
        f"{shard}={len(names)}" for shard, names in groups.items()), flush=True)
    for shard, names in groups.items():
        for name in names:
            print(f"{shard}: {name}", flush=True)
    if args.check_only:
        return
    # Exact fully qualified names avoid substring/regex ambiguity. No proof
    # assumptions, solvers, unwind values or default safety checks are changed.
    command = ["cargo", "kani", "--exact"]
    for name in groups[args.shard]:
        command.extend(["--harness", name])
    subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
