#!/usr/bin/env python3
"""Reject drift between the descriptive protocol registry and production constants.

This checks documented constants, not statistical camouflage or interoperability.
Behavioral requirements and executed-test evidence have a separate contract ledger.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
COMMAND = "src/protocol/command.rs"
TICKET = "src/tls/quic/ticket.rs"


def check(spec: str, sources: dict[str, str]) -> int:
    checked = 0
    for name in ("CONNECT_RECORD_SIZE_BANDS", "PQ_FLIGHT_RECORD_TARGETS"):
        declaration = re.search(rf"\bconst {name}\b.*?=\s*\[([\d,\s]+)\]",
                                sources[COMMAND], re.DOTALL)
        if declaration is None:
            raise ValueError(f"missing literal production array: {name}")
        expected = [int(n) for n in re.findall(r"\d+", declaration[1])]
        occurrences = re.findall(rf"\b{name}\b[^\n\[]*\[([\d,\s]+)\]", spec)
        if not occurrences:
            raise ValueError(f"undocumented array: {name}")
        for values in occurrences:
            if [int(n) for n in re.findall(r"\d+", values)] != expected:
                raise ValueError(f"SPEC disagrees with {name}: expected {expected}")
        checked += len(occurrences)

    for name, path in (("MIN_SEALED_TICKET_LEN", TICKET),
                       ("MAX_SEALED_TICKET_LEN", TICKET),
                       ("SHAPED_RECORD_SIZE_JITTER", COMMAND)):
        declaration = re.search(rf"\bconst {name}\b[^=\n]*=\s*(\d+)", sources[path])
        values = re.findall(rf"\b{name}\s*=\s*(\d+)", spec)
        if declaration is None or not values:
            raise ValueError(f"missing production or documented bound: {name}")
        if any(int(value) != int(declaration[1]) for value in values):
            raise ValueError(f"SPEC disagrees with {name}: expected {declaration[1]}")
        checked += len(values)

    magics = set(re.findall(r'\bconst\s+\w*MAGIC\b[^=\n]*=\s*b"(PX1[A-Z])"',
                            sources[COMMAND]))
    registry = re.findall(r"^\| `(PX1[A-Z])` \| `([0-9A-Fa-f ]+)` \|", spec, re.MULTILINE)
    if len(registry) != len({magic for magic, _ in registry}):
        raise ValueError("duplicate command magic in SPEC registry")
    if not magics or {magic for magic, _ in registry} != magics:
        raise ValueError("SPEC command registry does not match production magics")
    for magic, encoded in registry:
        if bytes.fromhex(encoded) != magic.encode("ascii"):
            raise ValueError(f"incorrect registry hex for {magic}")
    return checked + len(registry)


def main() -> None:
    count = check((ROOT / "SPEC.md").read_text(),
                  {path: (ROOT / path).read_text() for path in (COMMAND, TICKET)})
    print(f"Protocol registry: {count} constant/encoding checks passed")


if __name__ == "__main__":
    main()
