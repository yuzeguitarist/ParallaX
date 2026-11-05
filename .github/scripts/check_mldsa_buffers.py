#!/usr/bin/env python3
"""Check reviewed ML-DSA temporary-buffer ownership using Rust AST boundaries.

The guards cover declared direct syntax/call sites, not arbitrary aliases,
compiler-created copies, process-memory erasure or complete side-channel safety.
"""
import argparse
import json
from pathlib import Path
import tempfile
import tomllib

from check_crypto_rules import replace_once, run
from check_quic_key_phase import method

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / ".github/semgrep/mldsa_buffers.yml"
OBSERVATIONS = ROOT / ".github/semgrep/mldsa_buffers_observe.yml"
FIPS = ROOT / "src/crypto/mldsa/fips202.rs"
POLY = ROOT / "src/crypto/mldsa/polyvec.rs"


def require_core_zeroize(manifest):
    dependency = tomllib.loads(manifest).get("dependencies", {}).get("sha3")
    if not isinstance(dependency, dict) or "zeroize" not in dependency.get("features", []):
        raise RuntimeError("ML-DSA SHAKE core state requires sha3's explicit zeroize feature")


def manifest_mutations():
    manifest = (ROOT / "Cargo.toml").read_text()
    require_core_zeroize(manifest)
    original = 'sha3 = { version = "0.10", features = ["zeroize"] }'
    for replacement in ('sha3 = { version = "0.10", features = [] }', 'sha3 = "0.10"'):
        changed = replace_once(manifest, original, replacement)
        try:
            require_core_zeroize(changed)
        except RuntimeError:
            continue
        raise RuntimeError("ML-DSA core zeroize manifest mutation escaped")
    print("ML-DSA SHAKE core feature: 2 parsed TOML mutations detected")


def findings(semgrep, rules, *targets):
    result = run(semgrep, "--strict", "--no-git-ignore", "--config", str(rules),
                 "--json", "--quiet", *(str(target) for target in targets))
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr + result.stdout)
    data = json.loads(result.stdout)
    if data.get("version") != "1.182.1" or data.get("errors") or data.get("skipped_rules"):
        raise RuntimeError(f"Incomplete or unpinned ML-DSA buffer scan: {data}")
    return data["results"]


def cardinality(semgrep, target, require_definitions=False):
    scopes = {"read": {"refill": 1, "prefix": 1, "copy": 0, "consume-wipe": 0, "cursor": 1},
              "prefix": {"copy": 1, "wipe": 1, "cursor": 1, "refill": 0, "return": 1},
              "absorb": {"finalize": 1, "feed": 1}, "wipe": {"zeroize": 1},
              "clear": {"wipe": 1}, "output": {"wipe": 1}}
    known = {f"observe-mldsa-{scope}-{kind}" for scope, effects in scopes.items()
             for kind in ("definition", *effects)}
    ranges = {}
    for finding in findings(semgrep, OBSERVATIONS, target):
        identifier = finding["check_id"].split(".")[-1]
        start, end = finding["start"]["offset"], finding["end"]["offset"]
        if identifier not in known or not isinstance(start, int) or not isinstance(end, int) or start >= end:
            raise RuntimeError(f"Invalid ML-DSA buffer AST observation: {finding}")
        ranges.setdefault((str(Path(finding["path"]).resolve()), identifier), set()).add((start, end))
    violations = {}
    observed_paths = {path for path, _ in ranges}
    for scope, effects in scopes.items():
        definition = f"observe-mldsa-{scope}-definition"
        paths = {path for path, identifier in ranges if identifier == definition}
        if require_definitions and paths != {str(Path(target).resolve())}:
            raise RuntimeError(f"Missing complete ML-DSA buffer production definition: {scope}")
        for path in observed_paths - paths:
            violations.setdefault(Path(path).name, set()).add(f"mldsa-{scope}-definition-count")
        for path in paths:
            definitions = ranges[(path, definition)]
            if len(definitions) != 1:
                raise RuntimeError(f"Ambiguous ML-DSA buffer AST scope: {path}")
            low, high = next(iter(definitions))
            for effect, expected in effects.items():
                calls = ranges.get((path, f"observe-mldsa-{scope}-{effect}"), set())
                if any(not (low <= start and end <= high) for start, end in calls):
                    raise RuntimeError(f"Unscoped ML-DSA buffer AST effect: {path}")
                if len(calls) != expected:
                    violations.setdefault(Path(path).name, set()).add(f"mldsa-{scope}-{effect}-count")
    return violations


def mutations(semgrep):
    source, poly = FIPS.read_text(), POLY.read_text()
    clear, drop, zeroize = (method(source, name) for name in ("clear", "drop", "zeroize"))
    wipe = method(source, "wipe_bytes")
    read, absorb = method(source, "read"), method(source, "new_reader<C>")
    prefix = method(source, "read_cached_prefix")
    product_l = method(poly, "pointwise_poly_montgomery")
    product_k = method(poly[poly.index("impl Polyveck {"):], "pointwise_poly_montgomery")
    accumulate = method(poly, "pointwise_acc_montgomery")
    variants = {}

    def add(name, original, old, new, policy, owner=source):
        changed = replace_once(original, old, new)
        variants[name + ".rs"] = (replace_once(owner, original, changed), policy)

    add("absorb_reset_without_wipe", clear, "wipe_bytes(self.0.pad_with_zeros().as_mut_slice());",
        "self.0.reset();", "parallax-mldsa-absorb-buffer-wipe")
    add("absorb_empty_slice", clear, "self.0.pad_with_zeros().as_mut_slice()", "&mut []",
        "parallax-mldsa-absorb-buffer-wipe")
    add("absorb_drop_does_nothing", drop, "self.clear();", "", "parallax-mldsa-absorb-drop-wipe")
    add("output_adapter_does_nothing", zeroize, "wipe_bytes(self.bytes.as_mut_slice());", "",
        "parallax-mldsa-output-block-wipe")
    add("output_adapter_empty_slice", zeroize, "self.bytes.as_mut_slice()", "&mut []",
        "parallax-mldsa-output-block-wipe")
    variants["unprotected_output_cache_type.rs"] = (
        replace_once(source, "block: Zeroizing<BlockBytes<R>>", "block: BlockBytes<R>"),
        "parallax-mldsa-output-cache-owner")
    add("missing_consumed_wipe", prefix, "        wipe_bytes(&mut self.block.bytes[self.offset..end]);\n", "",
        "parallax-mldsa-output-cache-prefix")
    add("wipe_unread_tail", prefix, "wipe_bytes(&mut self.block.bytes[self.offset..end])", "self.block.zeroize()",
        "parallax-mldsa-output-cache-prefix")
    add("advance_before_wipe", prefix,
        "        wipe_bytes(&mut self.block.bytes[self.offset..end]);\n        self.offset = end;",
        "        self.offset = end;\n        wipe_bytes(&mut self.block.bytes[self.offset..end]);",
        "parallax-mldsa-output-cache-prefix")
    add("wrong_refill_boundary", read, "self.offset == self.block.bytes.len()", "self.offset == 0",
        "parallax-mldsa-output-cache-read")
    add("no_remaining_output_bound", prefix, ".min(out.len())", "",
        "parallax-mldsa-output-cache-prefix")
    add("wrong_cache_cursor", prefix, "self.offset = end", "self.offset = 0",
        "parallax-mldsa-output-cache-prefix")
    add("drop_absorb_owner", absorb, "WipingBuffer::<C>(Buffer::<C>::default())", "Buffer::<C>::default()",
        "parallax-mldsa-core-absorb-owner")
    add("unprotected_generic_wrapper", absorb, "let mut core = C::default();",
        "let mut core = sha3::Shake256::default();", "parallax-mldsa-no-unwiped-xof-wrapper")
    for name, product in (("l", product_l), ("k", product_k)):
        add(f"copied_secret_poly_{name}", product,
            "            self.vec[i].pointwise_montgomery(a, &v.vec[i]);",
            "            let vi = v.vec[i];\n            self.vec[i].pointwise_montgomery(a, &vi);",
            "parallax-mldsa-borrow-pointwise-input", poly)
        for scope in ("plain", "if", "loop", "closure"):
            copy = "let vi = v.vec[i];"
            if scope == "if":
                copy = "if i == 0 { " + copy + " }"
            elif scope == "loop":
                copy = "for _ in 0..1 { " + copy + " }"
            elif scope == "closure":
                copy = "let _extra = || { " + copy + " };"
            add(f"canonical_retained_poly_copy_{name}_{scope}", product,
                "            self.vec[i].pointwise_montgomery(a, &v.vec[i]);",
                "            " + copy + "\n            self.vec[i].pointwise_montgomery(a, &v.vec[i]);",
                "parallax-mldsa-no-extra-secret-poly-copy", poly)
    add("unprotected_accumulator_temp", accumulate, "zeroize::Zeroizing::new(Poly::zero())", "Poly::zero()",
        "parallax-mldsa-wiping-accumulator-temp", poly)
    for scope in ("plain", "if", "loop", "closure"):
        extra = "let leaked = self.block.bytes.clone();"
        if scope == "if":
            extra = "if !out.is_empty() { " + extra + " }"
        elif scope == "loop":
            extra = "for _ in 0..1 { " + extra + " }"
        elif scope == "closure":
            extra = "let _extra = || { " + extra + " };"
        add(f"canonical_retained_output_copy_{scope}", read, "        while !out.is_empty() {",
            "        " + extra + "\n        while !out.is_empty() {", "parallax-mldsa-no-output-cache-copy")
        refill = "let _extra = Zeroizing::new(BlockBytes { bytes: self.core.read_block() });"
        if scope == "if":
            refill = "if !out.is_empty() { " + refill + " }"
        elif scope == "loop":
            refill = "for _ in 0..1 { " + refill + " }"
        elif scope == "closure":
            refill = "let _extra = || { " + refill + " };"
        add(f"duplicate_refill_{scope}", read, "        while !out.is_empty() {",
            "        " + refill + "\n        while !out.is_empty() {", "mldsa-read-refill-count")
    add("duplicate_copy_site", read, "        while !out.is_empty() {",
        "        let mut leaked = [0u8; 168];\n        leaked[..self.block.bytes.len()].copy_from_slice(&self.block.bytes);\n        while !out.is_empty() {",
        "mldsa-read-copy-count")
    add("duplicate_absorb_finalize", absorb, "    WipingReader::new(core.finalize_xof_core(&mut buffer.0))",
        "    let _extra = core.finalize_xof_core(&mut buffer.0);\n    WipingReader::new(core.finalize_xof_core(&mut buffer.0))",
        "mldsa-absorb-finalize-count")
    renamed_read = replace_once(prefix, "fn read_cached_prefix(", "fn cached_prefix_unchecked(")
    renamed_read = replace_once(renamed_read,
                                "        wipe_bytes(&mut self.block.bytes[self.offset..end]);\n", "")
    renamed_source = replace_once(source, prefix, renamed_read)
    renamed_source = renamed_source.replace("read_cached_prefix(", "cached_prefix_unchecked(")
    variants["renamed_reader_missing_consumed_wipe.rs"] = (
        renamed_source, "mldsa-prefix-definition-count")
    renamed_absorb = replace_once(absorb, "fn new_reader<C>(", "fn new_reader_unchecked<C>(")
    renamed_absorb = replace_once(renamed_absorb,
                                  "WipingBuffer::<C>(Buffer::<C>::default())", "Buffer::<C>::default()")
    renamed_absorb = replace_once(renamed_absorb, "buffer\n            .0\n            .digest_blocks", "buffer.digest_blocks")
    renamed_absorb = replace_once(renamed_absorb, "&mut buffer.0", "&mut buffer")
    renamed_source = replace_once(source, absorb, renamed_absorb)
    renamed_source = renamed_source.replace("new_reader::<", "new_reader_unchecked::<")
    variants["renamed_absorb_without_wiping_owner.rs"] = (
        renamed_source, "mldsa-absorb-definition-count")
    add("wipe_helper_noop", wipe, "bytes.zeroize();", "", "parallax-mldsa-wipe-bytes")
    add("wipe_helper_nonvolatile_fill", wipe, "bytes.zeroize()", "bytes.fill(0)",
        "parallax-mldsa-wipe-bytes")
    add("wipe_helper_only_prefix", wipe, "bytes.zeroize()", "bytes[..1].zeroize()",
        "parallax-mldsa-wipe-bytes")
    for scope in ("plain", "if", "loop", "closure"):
        early = "return;"
        if scope == "if":
            early = "if !bytes.is_empty() { return; }"
        elif scope == "loop":
            early = "for _ in 0..1 { return; }"
        elif scope == "closure":
            early = "let _extra = || { return; };"
        add(f"canonical_wipe_retained_early_return_{scope}", wipe, "    bytes.zeroize();",
            "    " + early + "\n    bytes.zeroize();", "parallax-mldsa-wipe-no-early-return")
        early = "return 0;"
        if scope == "if":
            early = "if !out.is_empty() { return 0; }"
        elif scope == "loop":
            early = "for _ in 0..1 { return 0; }"
        elif scope == "closure":
            early = "let _extra = || { return 0; };"
        add(f"canonical_prefix_retained_early_return_{scope}", prefix, "        let count =",
            "        " + early + "\n        let count =", "parallax-mldsa-prefix-no-early-return")
    add("missing_shipping_prefix_call", read, "self.read_cached_prefix(out)", "out.len()",
        "parallax-mldsa-output-cache-read")
    add("duplicate_shipping_prefix_call", read, "        while !out.is_empty() {",
        "        let _ = self.read_cached_prefix(out);\n        while !out.is_empty() {",
        "mldsa-read-prefix-count")
    add("prefix_sponge_refill", prefix, "        let count =",
        "        let _ = self.core.read_block();\n        let count =", "mldsa-prefix-refill-count")

    with tempfile.TemporaryDirectory(prefix="parallax-mldsa-buffers-") as directory:
        for name, (content, _) in variants.items():
            (Path(directory) / name).write_text(content)
        found = {}
        for finding in findings(semgrep, RULES, directory):
            found.setdefault(Path(finding["path"]).name, set()).add(finding["check_id"].split(".")[-1])
        counted = cardinality(semgrep, directory)
        count_only = sum(policy in counted.get(name, set()) and not found.get(name, set())
                         for name, (_, policy) in variants.items())
        for name, policies in counted.items():
            found.setdefault(name, set()).update(policies)
        for name, (_, policy) in variants.items():
            if policy not in found.get(name, set()):
                raise RuntimeError(f"ML-DSA buffer production mutation escaped: {name} ({policy})")
    print(f"ML-DSA buffer production mutations: {len(variants)} detected ({count_only} require AST cardinality)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", default="semgrep")
    args = parser.parse_args()
    result = run(args.semgrep, "--test", "--strict", "--config", str(RULES), str(RULES.with_suffix(".rs")))
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    print(result.stdout.strip())
    actual = findings(args.semgrep, RULES, FIPS, POLY)
    counts = cardinality(args.semgrep, FIPS, require_definitions=True)
    if actual or counts:
        raise RuntimeError(f"ML-DSA buffer production violations: {actual}, {counts}")
    mutations(args.semgrep)
    manifest_mutations()
    print("ML-DSA buffer guards passed (source, fixtures, AST cardinality, mutations)")


if __name__ == "__main__":
    main()
