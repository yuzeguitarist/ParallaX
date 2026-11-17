#!/usr/bin/env python3
"""Bounded site-identification and paired-vantage experiments on complete captures.

These tools measure the specified detectors. An evaluated experiment is never a
security PASS, and synthetic controls establish only that the machinery works.
"""

import argparse
from collections import Counter
import datetime
import hashlib
import json
import math
from pathlib import Path
import platform
import statistics
import sys

import analyze


MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_CAPTURES = 256
MAX_TRACE_RECORDS = 20_000
MAX_BINS = 512
MAX_SCORE_WORK = 10_000_000
PURPOSES = ("measurement", "machinery_control")


def load_manifest(path, schema):
    digest = analyze.artifact_hash(path)
    document = json.loads(path.read_text())
    analyze.require(isinstance(document, dict) and document.get("schema") == schema,
                    "wrong privacy corpus schema")
    analyze.require(document.get("purpose") in PURPOSES, "explicit corpus purpose required")
    return document, digest


class Captures:
    """Apply the same artifact and extraction rules to both experiment types."""

    def __init__(self, directory):
        self.directory = directory.resolve()
        self.ids, self.hashes = set(), set()
        self.bytes = 0
        self.provenance = []

    def load(self, entry):
        analyze.require(isinstance(entry, dict), "capture must be an object")
        for key in ("capture_id", "path", "sha256", "format"):
            analyze.require(isinstance(entry.get(key), str) and entry[key],
                            "capture metadata missing: " + key)
        analyze.require(entry.get("complete") is True, "complete capture attestation required")
        analyze.require(len(self.ids) < MAX_CAPTURES, "too many captures")
        analyze.require(entry["capture_id"] not in self.ids, "duplicate capture_id")
        artifact = (self.directory / entry["path"]).resolve()
        analyze.require(artifact.is_relative_to(self.directory), "capture path outside corpus")
        digest = analyze.artifact_hash(artifact)
        analyze.require(digest == entry["sha256"], "capture SHA-256 mismatch")
        analyze.require(digest not in self.hashes, "duplicate artifact is not independent evidence")
        self.bytes += artifact.stat().st_size
        analyze.require(self.bytes <= MAX_TOTAL_BYTES, "total capture bytes exceed bound")
        port = entry.get("server_port", 0)
        analyze.require(type(port) is int, "server_port must be an integer")
        records = analyze.load_records(artifact, entry["format"], port)
        analyze.require(len(records) <= MAX_TRACE_RECORDS, "trace record count exceeds bound")
        analyze.require(analyze.artifact_hash(artifact) == digest,
                        "capture changed while being analyzed")
        self.ids.add(entry["capture_id"])
        self.hashes.add(digest)
        self.provenance.append({"capture_id": entry["capture_id"], "sha256": digest,
                                "format": entry["format"], "records": len(records),
                                "completeness": "TCP FIN and reassembly" if entry["format"] == "pcap"
                                else "collector attestation; TSV has no transport FIN evidence"})
        return records


def metadata(entry, keys):
    analyze.require(isinstance(entry, dict), "observation must be an object")
    for key in keys:
        analyze.require(isinstance(entry.get(key), str) and entry[key],
                        "observation metadata missing: " + key)
    datetime.date.fromisoformat(entry["day"])


def website_partition(rows, seed):
    sites = sorted({row["site"] for row in rows})
    analyze.require(2 <= len(sites) <= 32, "site identification needs 2..32 known sites")
    analyze.require(len({row["group"] for row in rows}) == len(rows),
                    "one complete session observation per capture_group required")
    train, test = [], []
    for site in sites:
        selected = [row for row in rows if row["site"] == site]
        analyze.require(len(selected) >= 6, "each site needs six independent sessions")
        selected.sort(key=lambda row: hashlib.sha256(
            f"{seed}:{row['group']}".encode()).digest())
        cut = len(selected) * 3 // 5
        train.extend(selected[:cut])
        test.extend(selected[cut:])
    return train, test


def fit_sites(train):
    analyze.require(bool(train), "empty training partition")
    width = len(train[0]["x"])
    analyze.require(width > 0 and all(len(row["x"]) == width and
                    all(math.isfinite(x) for x in row["x"]) for row in train),
                    "invalid classifier feature vectors")
    columns = list(zip(*(row["x"] for row in train)))
    means = [statistics.mean(column) for column in columns]
    scales = [statistics.pstdev(column) or 1 for column in columns]
    centers = {site: [statistics.mean((row["x"][i] - means[i]) / scales[i]
                                     for row in train if row["site"] == site)
                      for i in range(width)] for site in sorted({row["site"] for row in train})}
    return {"means": means, "scales": scales, "centers": centers}


def predict_site(model, row):
    analyze.require(len(row["x"]) == len(model["means"]) and
                    all(math.isfinite(x) for x in row["x"]), "invalid held-out features")
    vector = [(x - mean) / scale for x, mean, scale in
              zip(row["x"], model["means"], model["scales"])]
    return min(model["centers"], key=lambda site:
               sum((a - b) ** 2 for a, b in zip(vector, model["centers"][site])))


def evaluate_websites(rows, seed):
    train, test = website_partition(rows, seed)
    model = fit_sites(train)
    sites = sorted(model["centers"])
    confusion = {site: {prediction: 0 for prediction in sites} for site in sites}
    for row in test:
        confusion[row["site"]][predict_site(model, row)] += 1
    correct = sum(confusion[site][site] for site in sites)
    per_site = {site: confusion[site][site] / sum(confusion[site].values()) for site in sites}
    return {"status": "evaluated", "model": "train_standardized_multiclass_centroid_v1",
            "sites": sites, "train_sessions": len(train), "test_sessions": len(test),
            "train_capture_groups": sorted(row["group"] for row in train),
            "test_capture_groups": sorted(row["group"] for row in test),
            "accuracy": correct / len(test), "macro_accuracy": statistics.mean(per_site.values()),
            "accuracy_ci95_clopper_pearson": analyze.binomial_interval(correct, len(test)),
            "uniform_chance": 1 / len(sites),
            "majority_baseline": max(Counter(row["site"] for row in test).values()) / len(test),
            "per_site_accuracy": per_site, "confusion": confusion,
            "scaling_fit_sessions": len(train)}


def websites(path, seed):
    analyze.require(type(seed) is int and 0 <= seed < 1 << 64, "seed outside unsigned 64-bit range")
    document, digest = load_manifest(path, "parallax-website-corpus-v1")
    entries = document.get("captures")
    analyze.require(isinstance(entries, list) and 0 < len(entries) <= MAX_CAPTURES,
                    "website corpus needs 1..256 captures")
    analyze.require(document.get("workload_scope") in
                    ("controlled_fetch", "rendered_visit", "synthetic_control"),
                    "explicit website workload_scope required")
    analyze.require(document["purpose"] == "machinery_control" or
                    document["workload_scope"] != "synthetic_control", "synthetic data is a machinery control")
    loaded, rows, contexts = Captures(path.parent), [], {}
    for entry in entries:
        metadata(entry, ("site", "capture_group", "implementation", "vantage", "workload", "day", "network"))
        vector = analyze.features(loaded.load(entry))
        rows.append({"site": entry["site"], "group": entry["capture_group"],
                     "x": [vector[name] for name in sorted(vector)]})
        contexts.setdefault(entry["site"], Counter())[(entry["workload"], entry["day"], entry["network"])] += 1
    analyze.require(len({entry["implementation"] for entry in entries}) == 1 and
                    len({entry["vantage"] for entry in entries}) == 1,
                    "website corpus needs one implementation and one capture vantage")
    analyze.require(all(context == next(iter(contexts.values())) for context in contexts.values()),
                    "site classes need matched workload/day/network counts")
    result = evaluate_websites(rows, seed)
    analyze.require(analyze.artifact_hash(path) == digest, "manifest changed while being analyzed")
    return report("website", document, digest, loaded, result, seed=seed,
                  workload_scope=document["workload_scope"], feature_names=sorted(vector),
                  limitations=["Closed-set known-site identification, not unknown-site discovery.",
                               "Only complete sessions are held out; this does not establish cross-day/network generalization.",
                               "Controlled fetches do not establish full rendered-website behavior.",
                               "Confidence intervals assume independent collection groups; provenance requires review."])


def binned_trace(records, bin_us):
    application = [record for record in records if record[2] == 23]
    analyze.require(len(application) >= 8 and {record[1] for record in application} == {0, 1},
                    "correlation needs eight application records and both directions")
    first = application[0][0]
    bins = int((application[-1][0] - first) // bin_us) + 1
    analyze.require(8 <= bins <= MAX_BINS, "trace duration/bin count outside 8..512 bound")
    vector = [[0.0, 0.0] for _ in range(bins)]
    for timestamp, direction, _, size in application:
        vector[int((timestamp-first) // bin_us)][direction] += size
    return vector


def lag_score(left, right, lag_bins):
    analyze.require(left and right and len(left) == len(right) and len(left) <= MAX_BINS
                    and type(lag_bins) is int and 0 <= lag_bins <= 32,
                    "inconsistent trace bins or lag bound")
    analyze.require(all(len(cell) == 2 and all(math.isfinite(value) and value >= 0 for value in cell)
                        for trace in (left, right) for cell in trace), "invalid directional byte bins")
    best = None
    for lag in range(-lag_bins, lag_bins + 1):
        start, end = max(0, -lag), min(len(left), len(right) - lag)
        if end - start < max(8, (len(left)*3 + 3)//4):
            continue
        a, b = [], []
        for direction in (0, 1):
            x = [left[i][direction] for i in range(start, end)]
            y = [right[i+lag][direction] for i in range(start, end)]
            mx, my = statistics.mean(x), statistics.mean(y)
            a.extend(value-mx for value in x)
            b.extend(value-my for value in y)
        denominator = math.sqrt(sum(x*x for x in a) * sum(y*y for y in b))
        if denominator:
            score = sum(x*y for x, y in zip(a, b)) / denominator
            candidate = (max(-1.0, min(1.0, score)), -abs(lag), -lag)
            if best is None or candidate > best:
                best = candidate
    analyze.require(best is not None, "constant traces have no correlation evidence")
    return best[0], -best[2]


def evaluate_correlation(pairs, bin_us, lag_bins):
    analyze.require(2 <= len(pairs) <= 64, "correlation needs 2..64 independent pairs")
    bins = max(len(trace) for pair in pairs for trace in pair)
    analyze.require(len(pairs)**2 * bins * (2*lag_bins+1) <= MAX_SCORE_WORK,
                    "correlation work exceeds bound")
    padded = [[trace + [[0.0, 0.0] for _ in range(bins-len(trace))] for trace in pair]
              for pair in pairs]
    scores = [[lag_score(left, pair[1], lag_bins) for pair in padded] for left, _ in padded]
    ranks, top1, top3, matches = [], [], [], []
    for index, row in enumerate(scores):
        true_score, lag = row[index]
        # Credit tied candidates equally instead of using manifest order as a
        # secret answer key. This keeps identical traces at chance top-1.
        better = sum(score > true_score + 1e-12 for score, _ in row)
        tied = sum(abs(score-true_score) <= 1e-12 for score, _ in row)
        rank = 1 + better + (tied-1)/2
        ranks.append(rank)
        top1.append(max(0, min(1-better, tied)) / tied)
        top3.append(max(0, min(3-better, tied)) / tied)
        matches.append({"pair_index": index, "true_match_score": true_score,
                        "relative_origin_lag_us": lag * bin_us, "midrank": rank,
                        "best_impostor_score": max(score for j, (score, _) in enumerate(row) if j != index)})
    return {"status": "evaluated", "model": "directional_byte_bin_pearson_lag_scan_v1",
            "pairs": len(pairs), "bins": bins, "bin_us": bin_us, "max_lag_bins": lag_bins,
            "tie_adjusted_top1": statistics.mean(top1), "top1_chance": 1/len(pairs),
            "tie_adjusted_top3": statistics.mean(top3), "mean_true_midrank": statistics.mean(ranks),
            "mean_reciprocal_midrank": statistics.mean(1/rank for rank in ranks), "matches": matches}


def correlate(path, bin_ms, max_lag_ms):
    analyze.require(type(bin_ms) is int and 1 <= bin_ms <= 1000 and type(max_lag_ms) is int
                    and 0 <= max_lag_ms <= 32*bin_ms, "invalid bin/lag budget")
    document, digest = load_manifest(path, "parallax-correlation-corpus-v1")
    analyze.require(all(isinstance(document.get(key), str) and document[key]
                        for key in ("ingress_vantage", "egress_vantage")) and
                    document["ingress_vantage"] != document["egress_vantage"],
                    "two distinct declared capture vantages required")
    analyze.require(document.get("direction_convention") == "initiator_to_responder",
                    "both vantage directions must share the initiator_to_responder convention")
    entries = document.get("pairs")
    analyze.require(isinstance(entries, list) and 2 <= len(entries) <= 64,
                    "correlation needs 2..64 independent pairs")
    loaded, pairs, ids, groups = Captures(path.parent), [], set(), set()
    for entry in entries:
        metadata(entry, ("pair_id", "capture_group", "workload", "day", "network"))
        analyze.require(entry["pair_id"] not in ids and entry["capture_group"] not in groups,
                        "duplicate pair or capture_group is not independent evidence")
        ids.add(entry["pair_id"])
        groups.add(entry["capture_group"])
        pairs.append([binned_trace(loaded.load(entry.get(side)), bin_ms*1000)
                      for side in ("ingress", "egress")])
    analyze.require(all(len({entry[key] for entry in entries}) == 1
                        for key in ("workload", "day", "network")),
                    "candidate cohort needs matched workload/day/network")
    result = evaluate_correlation(pairs, bin_ms*1000, max_lag_ms//bin_ms)
    analyze.require(analyze.artifact_hash(path) == digest, "manifest changed while being analyzed")
    return report("correlation", document, digest, loaded, result,
                  pair_ids=[entry["pair_id"] for entry in entries],
                  ingress_vantage=document["ingress_vantage"], egress_vantage=document["egress_vantage"],
                  limitations=["Scores measure this two-vantage detector, not resistance to correlation attacks.",
                               "Each trace is normalized to its first application record; lag is relative origin alignment, not network latency.",
                               "TLS-record bytes omit TCP/QUIC packet headers, retransmissions and non-TLS traffic.",
                               "Pair ground truth and independent collection require external provenance review."])


def report(kind, document, digest, captures, result, **extra):
    return {"schema": "parallax-privacy-evaluation-v1", "kind": kind,
            "purpose": document["purpose"], "manifest_sha256": digest,
            "analyzer_sha256": analyze.artifact_hash(Path(__file__)),
            "extractor_sha256": analyze.artifact_hash(Path(analyze.__file__)),
            "python_version": platform.python_version(), "unit": "whole_capture_session",
            "capture_provenance": captures.provenance, **result, **extra}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="kind", required=True)
    for kind in ("websites", "correlate"):
        command = commands.add_parser(kind)
        command.add_argument("manifest", type=Path)
        command.add_argument("--output", type=Path, required=True)
        if kind == "websites":
            command.add_argument("--seed", type=int, default=20261117)
        else:
            command.add_argument("--bin-ms", type=int, default=50)
            command.add_argument("--max-lag-ms", type=int, default=250)
    args = parser.parse_args(argv)
    try:
        result = websites(args.manifest, args.seed) if args.kind == "websites" else correlate(
            args.manifest, args.bin_ms, args.max_lag_ms)
    except (analyze.EvidenceError, OSError, ValueError, KeyError, TypeError, OverflowError) as error:
        result = {"schema": "parallax-privacy-evaluation-v1", "kind": args.kind,
                  "status": "insufficient_evidence", "reason": str(error)}
    # Retain old evidence rather than overwriting it, including on input failure.
    try:
        with args.output.open("x") as stream:
            json.dump(result, stream, indent=2, allow_nan=False)
            stream.write("\n")
    except OSError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(f"{result['status']}: {args.output}")
    return 0 if result["status"] == "evaluated" else 2


if __name__ == "__main__":
    raise SystemExit(main())
