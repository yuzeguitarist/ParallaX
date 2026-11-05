#!/usr/bin/env python3
"""Reproducible capture-group traffic evaluation; Python standard library only.

Manifest schema: parallax-traffic-corpus-v1, with captures containing capture_id,
label (browser/parallax), path, format (pcap/record_tsv/safari_tsv), sha256,
server_port, capture_group, workload, site, day, network, and vantage. All those
fields are provenance/split metadata, never classifier inputs. One capture is
one observation; windows from the same flow are never split into examples.

Examples:
  python3 scripts/traffic_lab/analyze.py analyze corpus.json --output report.json
  python3 scripts/traffic_lab/analyze.py compare old.tsv new.pcap \
    --left-format safari_tsv --right-format pcap --right-port 48443

The model is a fixed standardized linear-centroid baseline. A weak result only
describes this detector. Reports never certify universal indistinguishability.
"""

import argparse
import bisect
import csv
import datetime
import hashlib
import io
import json
import math
import os
from pathlib import Path
import platform
import random
import secrets
import statistics
import subprocess
import sys
import tempfile


MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_STREAM_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 250_000
MAX_PACKETS = 250_000
MAX_FLOWS = 4096
MAX_PENDING_RANGES = 4096
AXES = ("capture_group", "site", "workload", "day", "network")
MATCH_FIELDS = ("workload", "site", "day", "network", "vantage")
MODELS = ("centroid", "logistic", "random_forest")


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def artifact_hash(path):
    require(path.is_file() and path.stat().st_size <= MAX_ARTIFACT_BYTES,
            "missing or oversized capture artifact")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_records(records):
    require(0 < len(records) <= MAX_RECORDS, "empty or oversized record capture")
    for t, direction, content_type, length in records:
        require(math.isfinite(t) and t >= 0 and direction in (0, 1)
                and content_type in (20, 21, 22, 23) and 0 <= length <= 16640,
                "invalid TLS record metadata")
    records.sort(key=lambda record: record[0])
    start = records[0][0]
    return [(t - start, direction, ct, length) for t, direction, ct, length in records]


class TcpDirection:
    """Bounded TCP reassembly, retaining first-observed record completion times."""

    def __init__(self):
        self.base = None
        self.wire = bytearray()
        self.ranges = []
        self.cursor = 0
        self.records = []
        self.fin_end = None

    def feed(self, sequence, payload, syn, timestamp, direction,
             allocation_budget=MAX_STREAM_BYTES, *, fin=False):
        if syn:
            base = (sequence + 1) % (1 << 32)
            require(self.base in (None, base), "conflicting SYN sequence")
            self.base = base
            sequence = base
        if not payload and not fin:
            return
        require(self.base is not None, "capture starts after TCP SYN")
        start = (sequence - self.base) % (1 << 32)
        end = start + len(payload)
        require(end <= MAX_STREAM_BYTES, "TCP stream exceeds allocation bound")
        if fin:
            require(self.fin_end in (None, end), "conflicting TCP FIN sequence")
            require(len(self.wire) <= end, "TCP FIN precedes captured payload")
            self.fin_end = end
        require(self.fin_end is None or end <= self.fin_end, "TCP payload extends beyond FIN")
        if not payload:
            return
        require(max(0, end-len(self.wire)) <= allocation_budget,
                "capture exceeds total reassembly allocation bound")
        for lo, hi in self.ranges:
            a, b = max(start, lo), min(end, hi)
            if a < b:
                require(self.wire[a:b] == payload[a-start:b-start],
                        "conflicting TCP overlap")
        if end > len(self.wire):
            self.wire.extend(b"\0" * (end - len(self.wire)))
        self.wire[start:end] = payload
        ranges = sorted(self.ranges + [(start, end)])
        self.ranges = []
        for lo, hi in ranges:
            if self.ranges and lo <= self.ranges[-1][1]:
                self.ranges[-1] = (self.ranges[-1][0], max(hi, self.ranges[-1][1]))
            else:
                self.ranges.append((lo, hi))
        require(len(self.ranges) <= MAX_PENDING_RANGES, "excessive TCP reordering")
        available = self.ranges[0][1] if self.ranges[0][0] == 0 else 0
        while available - self.cursor >= 5:
            ct, major = self.wire[self.cursor:self.cursor + 2]
            length = int.from_bytes(self.wire[self.cursor+3:self.cursor+5], "big")
            require(ct in (20, 21, 22, 23) and major == 3 and length <= 16640,
                    "invalid TLS record in TCP capture")
            if self.cursor + 5 + length > available:
                break
            self.records.append((timestamp, direction, ct, length))
            require(len(self.records) <= MAX_RECORDS, "too many TLS records")
            self.cursor += 5 + length

    def finish(self):
        require(self.base is not None and self.records, "incomplete TCP direction")
        require(self.fin_end is not None, "TCP direction missing FIN completeness evidence")
        require(self.fin_end == len(self.wire), "TCP payload missing before FIN")
        require(self.ranges == [(0, len(self.wire))] and self.cursor == len(self.wire),
                "TCP capture gap or truncated TLS record")
        return self.records


def client_hello_structure(wire):
    """Public handshake shape only: omit random, session ID, keys and SNI values."""
    handshake = bytearray()
    cursor = 0
    while cursor + 5 <= len(wire):
        length = int.from_bytes(wire[cursor+3:cursor+5], "big")
        if wire[cursor] == 22:
            handshake.extend(wire[cursor+5:cursor+5+length])
        cursor += 5 + length
        require(len(handshake) <= 65536, "ClientHello structure exceeds bound")
        if len(handshake) >= 4:
            require(handshake[0] == 1, "first client handshake is not ClientHello")
            size = int.from_bytes(handshake[1:4], "big")
            if len(handshake) >= 4 + size:
                body = bytes(handshake[4:4+size])
                break
    else:
        return None
    position = 0

    def take(n):
        nonlocal position
        require(position+n <= len(body), "truncated ClientHello structure")
        value = body[position:position+n]
        position += n
        return value

    def vector(width):
        return take(int.from_bytes(take(width), "big"))

    def normalized(value):
        return 0x0a0a if value >> 8 == value & 255 and value & 0x0f0f == 0x0a0a else value

    def words(data):
        require(len(data) % 2 == 0, "odd ClientHello vector")
        return [normalized(int.from_bytes(data[i:i+2], "big")) for i in range(0, len(data), 2)]

    result = {"legacy_version": int.from_bytes(take(2), "big")}
    take(32)
    result["session_id_length"] = len(vector(1))
    result["cipher_suites"] = words(vector(2))
    result["compression_methods"] = list(vector(1))
    extensions = vector(2)
    require(position == len(body), "trailing ClientHello structure bytes")
    result["extension_types"], result["extension_lengths"] = [], []
    offset = 0
    while offset < len(extensions):
        require(offset+4 <= len(extensions), "truncated ClientHello extension")
        kind = int.from_bytes(extensions[offset:offset+2], "big")
        length = int.from_bytes(extensions[offset+2:offset+4], "big")
        payload = extensions[offset+4:offset+4+length]
        require(len(payload) == length, "truncated ClientHello extension payload")
        result["extension_types"].append(normalized(kind))
        result["extension_lengths"].append(length)
        if kind in (10, 13):
            require(length >= 2 and int.from_bytes(payload[:2], "big") == length-2,
                    "malformed ClientHello word vector")
            result["supported_groups" if kind == 10 else "signature_algorithms"] = words(payload[2:])
        elif kind == 43:
            require(length > 0 and payload[0] == length-1, "malformed supported_versions")
            result["supported_versions"] = words(payload[1:])
        elif kind == 51:
            require(length >= 2 and int.from_bytes(payload[:2], "big") == length-2,
                    "malformed key_share vector")
            shares, at = [], 2
            while at < length:
                require(at+4 <= length, "truncated key_share structure")
                group, size = int.from_bytes(payload[at:at+2], "big"), int.from_bytes(payload[at+2:at+4], "big")
                require(at+4+size <= length, "truncated key_share data")
                shares.append([normalized(group), size])
                at += 4+size
            result["key_share_group_lengths"] = shares
        elif kind == 16:
            require(length >= 2 and int.from_bytes(payload[:2], "big") == length-2,
                    "malformed ALPN vector")
            protocols, at = [], 2
            while at < length:
                size = payload[at]
                require(size > 0 and at+1+size <= length, "truncated ALPN protocol")
                protocols.append(payload[at+1:at+1+size].hex())
                at += 1+size
            result["alpn_protocols_hex"] = protocols
        offset += 4+length
    return result


def load_pcap(path, server_port, flow_summaries, include_sequences=False):
    require(1 <= server_port <= 65535, "pcap requires an explicit server_port")
    fields = ("tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.seq_raw",
              "tcp.flags.syn", "frame.time_relative", "tcp.payload", "tcp.flags.fin", "tcp.flags.reset")
    command = ["tshark", "-n", "-r", str(path), "-Y", f"tcp.port == {server_port}",
               "-T", "fields"]
    for field in fields:
        command.extend(("-e", field))
    flows = {}
    terminals = {}
    observed_records = []
    flow_records = {}
    flow_packets = {}
    total_bytes = total_allocated = total_records = 0
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               text=True)
    try:
        for packet, line in enumerate(process.stdout, 1):
            require(packet <= MAX_PACKETS and len(line) <= 200_000,
                    "packet capture exceeds processing bound")
            values = line.rstrip("\n").split("\t")
            require(len(values) == len(fields), "unexpected tshark field layout")
            stream, src, dst, sequence, syn, timestamp, payload, fin, reset = values
            require(bool(stream) and int(src) != int(dst), "ambiguous TCP endpoint")
            time_us = float(timestamp) * 1_000_000
            require(math.isfinite(time_us) and time_us >= 0, "invalid TCP timestamp")
            direction = int(int(src) == server_port)
            if stream not in flows:
                require(len(flows) < MAX_FLOWS, "too many TCP flows")
                flows[stream] = [TcpDirection(), TcpDirection()]
                flow_records[stream] = []
                flow_packets[stream] = []
                terminals[stream] = {"fin_directions": set(), "reset": False}
            if fin in ("1", "True"):
                terminals[stream]["fin_directions"].add(direction)
            if reset in ("1", "True"):
                terminals[stream]["reset"] = True
            data = bytes.fromhex(payload.replace(":", ""))
            if include_sequences:
                flow_packets[stream].append([time_us, direction, len(data),
                    syn in ("1", "True"), fin in ("1", "True"), reset in ("1", "True")])
            total_bytes += len(data)
            require(total_bytes <= MAX_STREAM_BYTES, "capture payload exceeds allocation bound")
            tracker = flows[stream][direction]
            before_bytes, before_records = len(tracker.wire), len(tracker.records)
            tracker.feed(int(sequence), data, syn in ("1", "True"),
                         time_us, direction,
                         MAX_STREAM_BYTES-total_allocated, fin=fin in ("1", "True"))
            completed = tracker.records[before_records:]
            observed_records.extend(completed)
            flow_records[stream].extend(completed)
            total_allocated += len(tracker.wire)-before_bytes
            total_records += len(tracker.records)-before_records
            require(total_records <= MAX_RECORDS, "capture exceeds total TLS record bound")
        require(process.wait() == 0, "tshark failed")
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
    for stream, flow in flows.items():
        terminal = terminals[stream]
        require(not terminal["reset"], "TCP reset does not prove complete payload coverage")
        require(terminal["fin_directions"] == {0, 1},
                "capture ends before TCP close; continue capture through relay shutdown")
        directional = [tracker.finish() for tracker in flow]
        flow_summaries.append({"capture_local_flow_id": stream,
                               "direction_record_counts": [len(part) for part in directional],
                               "direction_tcp_bytes": [len(tracker.wire) for tracker in flow],
                               "termination": {"fin_directions": sorted(terminal["fin_directions"]),
                                               "direction_fin_payload_ends": [tracker.fin_end for tracker in flow],
                                               "reset": terminal["reset"]}})
        if include_sequences:
            flow_summaries[-1]["client_hello"] = client_hello_structure(flow[0].wire)
            flow_summaries[-1]["records"] = sorted(
                flow_records[stream], key=lambda record: record[0])
            flow_summaries[-1]["tcp_packets"] = flow_packets[stream]
    if include_sequences and observed_records:
        origin = min(record[0] for record in observed_records)
        for flow in flow_summaries:
            flow["records"] = [(t-origin, d, ct, n) for t, d, ct, n in flow["records"]]
            flow["tcp_packets"] = [[t-origin, *metadata] for t, *metadata in flow["tcp_packets"]]
    return validate_records(observed_records)


def load_records(path, format_name, server_port=0, flow_summaries=None, include_sequences=False):
    artifact_hash(path)
    if format_name == "pcap":
        return load_pcap(path, server_port, [] if flow_summaries is None else flow_summaries,
                         include_sequences)
    text = path.read_text()
    records = []
    if format_name == "record_tsv":
        reader = csv.DictReader(io.StringIO("\n".join(
            line for line in text.splitlines() if not line.startswith("#"))), delimiter="\t")
        for row in reader:
            require(len(records) < MAX_RECORDS, "too many TSV records")
            require(row["direction"] in ("c2s", "s2c"), "invalid capture direction")
            records.append((int(row["t_micros"]), int(row["direction"] == "s2c"),
                            int(row["content_type"]), int(row["record_length"])))
    elif format_name == "safari_tsv":
        require(1 <= server_port <= 65535, "Safari TSV requires server_port")
        for row in csv.reader(io.StringIO(text), delimiter="\t"):
            require(len(row) >= 6, "short Safari TSV row")
            types = row[4].split(",")
            for index, length in enumerate(row[5].split(",")):
                ct = types[index] if index < len(types) else ""
                if length and ct in ("", "23"):
                    require(len(records) < MAX_RECORDS, "too many Safari records")
                    records.append((float(row[1]) * 1_000_000,
                                    int(int(row[3]) == server_port), 23, int(length)))
    else:
        raise EvidenceError("unsupported capture format")
    return validate_records(records)


def quantile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(fraction * (len(ordered) - 1)))]


def features(records):
    data = [r for r in records if r[2] == 23]
    require(data and all(any(r[1] == d for r in data) for d in (0, 1)),
            "capture needs outer application-data in both directions")
    result = {"log_record_count": math.log1p(len(data)),
              "log_duration_us": math.log1p(data[-1][0] - data[0][0])}
    for direction, prefix in ((0, "up"), (1, "down")):
        selected = [r for r in data if r[1] == direction]
        lengths = [r[3] for r in selected]
        gaps = [b[0] - a[0] for a, b in zip(selected, selected[1:])]
        result[prefix + "_log_bytes"] = math.log1p(sum(lengths))
        result[prefix + "_mean_length"] = statistics.mean(lengths)
        result[prefix + "_sd_length"] = statistics.pstdev(lengths)
        for fraction in (.5, .9, .99):
            result[f"{prefix}_length_p{int(fraction*100)}"] = quantile(lengths, fraction)
        result[prefix + "_tiny_fraction"] = sum(n < 100 for n in lengths) / len(lengths)
        result[prefix + "_full_fraction"] = sum(n == 16401 for n in lengths) / len(lengths)
        result[prefix + "_log_mean_iat"] = math.log1p(statistics.mean(gaps) if gaps else 0)
        result[prefix + "_log_p90_iat"] = math.log1p(quantile(gaps, .9) if gaps else 0)
    runs = []
    for record in data:
        if runs and runs[-1][0] == record[1]:
            runs[-1][1] += 1
        else:
            runs.append([record[1], 1])
    result["mean_direction_run"] = statistics.mean(run[1] for run in runs)
    result["down_record_fraction"] = sum(r[1] == 1 for r in data) / len(data)
    require(all(math.isfinite(value) for value in result.values()), "nonfinite features")
    return result


def auc(scored):
    positive = [score for score, label in scored if label == 1]
    negative = sorted(score for score, label in scored if label == 0)
    require(positive and negative and all(math.isfinite(s) and y in (0, 1) for s, y in scored),
            "AUC needs finite scores and both classes")
    return sum(bisect.bisect_left(negative, s)
               + .5 * (bisect.bisect_right(negative, s) - bisect.bisect_left(negative, s))
               for s in positive) / (len(positive) * len(negative))


def model_backend(name):
    if name == "centroid":
        return {"name": "standardized_linear_centroid_v1", "version": "stdlib-v1"}
    try:
        import sklearn
        import numpy
        return {"name": name, "sklearn": sklearn.__version__, "numpy": numpy.__version__}
    except ImportError as error:
        raise EvidenceError("optional sklearn backend unavailable: " + str(error)) from error


def fit(train, backend="centroid", seed=20261104):
    require(all(any(row["y"] == label for row in train) for label in (0, 1)),
            "training requires both classes")
    if backend != "centroid":
        model_backend(backend)
        if backend == "logistic":
            from sklearn.linear_model import LogisticRegression
            from sklearn.pipeline import make_pipeline
            from sklearn.preprocessing import StandardScaler
            model = make_pipeline(StandardScaler(), LogisticRegression(
                solver="liblinear", max_iter=1000, class_weight="balanced", random_state=seed))
        elif backend == "random_forest":
            from sklearn.ensemble import RandomForestClassifier
            model = RandomForestClassifier(n_estimators=128, max_depth=8,
                                           min_samples_leaf=2, class_weight="balanced",
                                           random_state=seed, n_jobs=1)
        else:
            raise EvidenceError("unsupported model backend")
        model.fit([row["x"] for row in train], [row["y"] for row in train])
        return lambda row: float(model.predict_proba([row["x"]])[0][1])
    columns = list(zip(*(row["x"] for row in train)))
    means = [statistics.mean(column) for column in columns]
    scales = [statistics.pstdev(column) or 1 for column in columns]
    centers = [[statistics.mean(row["x"][i] for row in train if row["y"] == label)
                for i in range(len(means))] for label in (0, 1)]
    weights = [(b - a) / (scale * scale) for a, b, scale in
               zip(centers[0], centers[1], scales)]
    return lambda row: sum((x - mean) * weight for x, mean, weight in
                           zip(row["x"], means, weights))


def binomial_cdf(k, n, probability):
    if probability <= 0:
        return 1.0
    if probability >= 1:
        return float(k >= n)
    logs = [math.lgamma(n+1) - math.lgamma(i+1) - math.lgamma(n-i+1)
            + i * math.log(probability) + (n-i) * math.log1p(-probability)
            for i in range(k+1)]
    peak = max(logs)
    return min(1.0, math.exp(peak) * sum(math.exp(value-peak) for value in logs))


def binomial_interval(k, n, alpha=.05):
    require(n > 0 and 0 <= k <= n, "binomial interval requires observations")

    def inverse_cdf(target, successes):
        low, high = 0.0, 1.0
        for _ in range(55):
            middle = (low + high) / 2
            if binomial_cdf(successes, n, middle) > target:
                low = middle
            else:
                high = middle
        return (low + high) / 2

    return [0.0 if k == 0 else inverse_cdf(1-alpha/2, k-1),
            1.0 if k == n else inverse_cdf(alpha/2, k)]


def read_manifest(path):
    artifact_hash(path)
    manifest = json.loads(path.read_text())
    require(isinstance(manifest, dict), "corpus manifest must be an object")
    require(manifest.get("schema") == "parallax-traffic-corpus-v1", "wrong corpus schema")
    purpose = manifest.get("purpose", "protocol_comparison")
    require(purpose in ("protocol_comparison", "negative_control", "positive_control"),
            "unknown corpus purpose")
    captures = manifest.get("captures", [])
    require(isinstance(captures, list), "corpus captures must be a list")
    require(0 < len(captures) <= 5000, "corpus needs 1..5000 captures")
    rows, ids, hashes = [], set(), set()
    for capture in captures:
        require(isinstance(capture, dict), "capture entry must be an object")
        for key in ("capture_id", "path", "format", "sha256", *AXES, "vantage"):
            require(isinstance(capture.get(key), str) and bool(capture[key]),
                    "capture metadata missing: " + key)
        if "class_label" in capture:
            require(capture["class_label"] in ("A", "B", 0, 1), "unknown class_label")
            label = int(capture["class_label"] in ("B", 1))
            require(isinstance(capture.get("implementation"), str)
                    and bool(capture["implementation"]), "implementation provenance missing")
        else:
            require(capture.get("label") in ("browser", "parallax"), "unknown capture class")
            label = int(capture["label"] == "parallax")
            capture = {**capture, "implementation": capture.get("implementation", capture["label"])}
        require(purpose != "negative_control" or "class_label" in capture,
                "negative controls require explicit class_label and implementation provenance")
        require(capture["capture_id"] not in ids, "duplicate capture_id")
        ids.add(capture["capture_id"])
        datetime.date.fromisoformat(capture["day"])
        artifact = (path.parent / capture["path"]).resolve()
        require(artifact.is_relative_to(path.parent.resolve()), "capture path outside corpus")
        digest = artifact_hash(artifact)
        require(digest == capture["sha256"], "capture SHA-256 mismatch")
        require(digest not in hashes, "duplicate artifact cannot be independent evidence")
        hashes.add(digest)
        flow_summaries = []
        vector = features(load_records(artifact, capture["format"],
                                       int(capture.get("server_port", 0)), flow_summaries))
        require(artifact_hash(artifact) == digest, "capture changed while being analyzed")
        rows.append({"meta": capture, "y": label, "flows": flow_summaries,
                     "feature_names": sorted(vector),
                     "x": [vector[name] for name in sorted(vector)]})
    for group in {row["meta"]["capture_group"] for row in rows}:
        paired = [row for row in rows if row["meta"]["capture_group"] == group]
        require({row["y"] for row in paired} == {0, 1}, "unmatched capture_group")
        for key in MATCH_FIELDS:
            require(len({row["meta"][key] for row in paired}) == 1,
                    "paired capture_group differs in " + key)
        if purpose == "negative_control":
            require(len({row["meta"]["implementation"] for row in paired}) == 1,
                    "negative-control pair must use the same actual implementation")
    return rows, purpose


def partition(rows, axis, seed):
    groups = sorted({row["meta"][axis] for row in rows}, key=lambda group:
                    hashlib.sha256(f"{seed}:{axis}:{group}".encode()).digest())
    require(len(groups) >= 6, "holdout needs at least six independent groups")
    cut1, cut2 = max(2, len(groups)*3//5), max(3, len(groups)*4//5)
    sets = [set(groups[:cut1]), set(groups[cut1:cut2]), set(groups[cut2:])]
    parts = [[row for row in rows if row["meta"][axis] in group_set] for group_set in sets]
    for part in parts:
        require(all(sum(row["y"] == label for row in part) >= 2 for label in (0, 1)),
                "each train/calibration/test partition needs two captures per class")
    return parts


def evaluate_axis(rows, axis, target_fpr, seed, repeats, backend="centroid"):
    try:
        backend_info = model_backend(backend)
        train, calibration, test = partition(rows, axis, seed)
        model = fit(train, backend, seed)
        normal_scores = sorted((model(row) for row in calibration if row["y"] == 0), reverse=True)
        threshold = normal_scores[min(len(normal_scores)-1, int(target_fpr*len(normal_scores)))]
        scored = [(model(row), row["y"]) for row in test]
        observed_auc = auc(scored)
        counts = {}
        for label, metric in ((0, "fpr"), (1, "tpr")):
            scores = [score for score, y in scored if y == label]
            detected = sum(score > threshold for score in scores)
            counts[metric] = {"events": detected, "n": len(scores),
                              "rate": detected/len(scores),
                              "ci95_clopper_pearson": binomial_interval(detected, len(scores))}
        rng = random.Random(seed)
        test_groups = sorted({row["meta"][axis] for row in test})
        bootstrap = []
        for _ in range(repeats):
            resampled = [row for group in rng.choices(test_groups, k=len(test_groups))
                         for row in test if row["meta"][axis] == group]
            if {row["y"] for row in resampled} == {0, 1}:
                bootstrap.append(auc([(model(row), row["y"]) for row in resampled]))
        null = []
        paired_groups = sorted({row["meta"]["capture_group"] for row in rows})
        for _ in range(repeats):
            flips = {group: rng.randrange(2) for group in paired_groups}
            permuted = [{**row, "y": row["y"] ^ flips[row["meta"]["capture_group"]]}
                        for row in rows]
            ptrain, _, ptest = partition(permuted, axis, seed)
            pmodel = fit(ptrain, backend, seed)
            null.append(auc([(pmodel(row), row["y"]) for row in ptest]))
        group_fp = sum(any(row["y"] == 0 and model(row) > threshold for row in test
                           if row["meta"][axis] == group) for group in test_groups)
        group_fpr_interval = binomial_interval(group_fp, len(test_groups))
        support = group_fpr_interval[1] <= target_fpr
        return {"status": "evaluated" if support else "insufficient_evidence",
                "reason": None if support else "independent held-out group count/FPR interval does not support target FPR",
                "axis": axis, "backend": backend_info,
                "partition_sizes": [len(part) for part in (train, calibration, test)],
                "heldout_groups": len(test_groups), "auc": observed_auc,
                "auc_group_bootstrap_ci95": [quantile(bootstrap, .025), quantile(bootstrap, .975)],
                "threshold_from_normal_calibration": threshold, "target_fpr": target_fpr,
                "heldout_group_any_false_positive": {"events": group_fp, "n": len(test_groups),
                                                      "ci95_clopper_pearson": group_fpr_interval},
                **counts, "paired_label_permutation_repeats": repeats,
                "two_sided_auc_permutation_p": (1 + sum(abs(value-.5) >= abs(observed_auc-.5)
                                                       for value in null))/(repeats+1)}
    except EvidenceError as error:
        return {"axis": axis, "backend": backend, "status": "insufficient_evidence", "reason": str(error)}


def controls():
    train = [{"x": [float(y)], "y": y} for _ in range(4) for y in (0, 1)]
    model = fit(train)
    positive = auc([(model(row), row["y"]) for row in train])
    negative = auc([(model({"x": [.5]}), y) for _ in range(4) for y in (0, 1)])
    require(positive == 1 and negative == .5, "classifier machinery controls failed")
    return {"synthetic_positive_auc": positive, "duplicated_feature_negative_auc": negative,
            "scope": "machinery self-checks; real independent negative controls still required"}


def analyze_manifest(path, axes, target_fpr, seed, repeats, backends=MODELS):
    require(0 < target_fpr < .5 and 19 <= repeats <= 999, "invalid evaluation parameters")
    rows, purpose = read_manifest(path)
    reports = [evaluate_axis(rows, axis, target_fpr, seed, repeats, backend)
               for axis in axes for backend in backends]
    return {"schema": "parallax-traffic-evaluation-v1",
            "status": "evaluated" if all(r["status"] == "evaluated" for r in reports)
            else "insufficient_evidence", "manifest_sha256": artifact_hash(path),
            "analyzer_sha256": artifact_hash(Path(__file__)),
            "python_version": platform.python_version(),
            "captures": len(rows), "purpose": purpose, "unit": "whole_capture", "seed": seed,
            "feature_names": rows[0]["feature_names"],
            "capture_provenance": [{"capture_id": row["meta"]["capture_id"],
                                    "sha256": row["meta"]["sha256"],
                                    "implementation": row["meta"]["implementation"],
                                    "class_label": row["y"], "flows": row["flows"]} for row in rows],
            "controls": controls(),
            "holdouts": reports,
            "limitations": ["No universal indistinguishability conclusion is supported.",
                            "Metadata/provenance claims require independent collection review.",
                            "Binomial intervals assume independent captures; paired/site correlation can widen uncertainty.",
                            "Group bootstrap conditions on the fitted model and observed held-out groups.",
                            "AUC permutation p-values are exploratory across multiple holdout axes."]}


def ks_distance(a, b):
    require(a and b, "KS distance requires observations")
    a, b = sorted(a), sorted(b)
    return max(abs(bisect.bisect_right(a, x)/len(a) - bisect.bisect_right(b, x)/len(b))
               for x in set(a+b))


def compare(left, right):
    report = {"status": "insufficient_evidence", "scope": "exploratory_unmatched_capture_comparison",
              "reason": "single captures, workload/source confounding and no independent holdout",
              "dimensions": {}}
    for direction, name in ((0, "up"), (1, "down")):
        a, b = [[r[3] for r in records if r[1] == direction and r[2] == 23]
                for records in (left, right)]
        require(a and b, "both captures need both directions")
        report["dimensions"][name] = {
            "left_records": len(a), "right_records": len(b),
            "record_length_ks_distance": ks_distance(a, b),
            "left_full16401_fraction": sum(n == 16401 for n in a)/len(a),
            "right_full16401_fraction": sum(n == 16401 for n in b)/len(b),
            "left_tiny_under100_fraction": sum(n < 100 for n in a)/len(a),
            "right_tiny_under100_fraction": sum(n < 100 for n in b)/len(b)}
    return report


def blind_export(path):
    rows, purpose = read_manifest(path)
    require(len({row["meta"]["format"] for row in rows}) == 1,
            "blind challenge requires uniform capture format to avoid source-format leakage")
    shuffle_seed = secrets.randbits(256)
    random.Random(shuffle_seed).shuffle(rows)
    challenge_id = secrets.token_hex(16)
    public = {"schema": "traffic-blind-challenge-v2", "challenge_id": challenge_id,
              "units": {"t": "relative_microseconds", "direction": "0_up_1_down",
                        "ct": "TLS_outer_content_type", "length": "TLS_payload_bytes",
                        "tcp_packets": ["t", "direction", "TCP_payload_bytes", "SYN", "FIN", "RST"]},
              "tcp_packet_observations": "available" if rows[0]["meta"]["format"] == "pcap" else "unavailable",
              "observation_limits": ["TCP packet times share the first TLS record's origin; SYN times can be negative.",
                                     "Other TCP flags, windows and sequence numbers are not exported.",
                                     "A captured TCP close can be controlled teardown; it does not establish natural connection lifetime."],
              "feature_names": rows[0]["feature_names"], "samples": []}
    oracle = {"schema": "traffic-blind-oracle-v1", "challenge_id": challenge_id,
              "manifest_sha256": artifact_hash(path), "purpose": purpose,
              "shuffle_seed_private": str(shuffle_seed), "samples": []}
    total_records = 0
    total_packets = 0
    for index, row in enumerate(rows):
        meta = row["meta"]
        flows = []
        records = load_records((path.parent/meta["path"]).resolve(), meta["format"],
                               int(meta.get("server_port", 0)), flows, include_sequences=True)
        require(artifact_hash((path.parent/meta["path"]).resolve()) == meta["sha256"],
                "capture changed during blind export")
        total_records += len(records)
        require(total_records <= MAX_RECORDS, "blind challenge exceeds total record bound; use batches")
        sample_id = f"sample-{index:05}"
        sample = {"sample_id": sample_id, "features": row["x"], "records": records,
                  "flows": []}
        for flow in flows:
            sequence = flow["records"]
            total_packets += len(flow["tcp_packets"])
            require(total_packets <= MAX_PACKETS, "blind challenge exceeds total TCP packet bound; use batches")
            start = records[0][0]
            sample["flows"].append({"features": features(sequence),
                                    "client_hello": flow["client_hello"],
                                    "termination": flow["termination"],
                                    "tcp_packets": [[t-start, *metadata] for t, *metadata in flow["tcp_packets"]],
                                    "records": [[t-start, d, ct, n] for t, d, ct, n in sequence]})
        public["samples"].append(sample)
        oracle["samples"].append({"sample_id": sample_id, "class_label": row["y"],
                                   "capture_id": meta["capture_id"], "sha256": meta["sha256"],
                                   "implementation": meta["implementation"],
                                   "capture_group": meta["capture_group"]})
    public_bytes = (json.dumps(public, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    require(len(public_bytes) <= MAX_ARTIFACT_BYTES, "blind export exceeds artifact size bound")
    oracle["challenge_sha256"] = hashlib.sha256(public_bytes).hexdigest()
    return public, oracle


def write_blind_artifacts(public, oracle, public_path, oracle_path):
    """Stage complete files, publish oracle first and public challenge last.

    Hard links publish exclusively without exposing an incomplete JSON file.
    Roll back only destinations created by this invocation on any failure.
    """
    require(public_path.resolve() != oracle_path.resolve(),
            "blind features and withheld oracle require separate output paths")
    require(not public_path.exists() and not oracle_path.exists(),
            "blind export refuses to overwrite either artifact")
    staged, published = [], []
    try:
        for destination, value in ((oracle_path, oracle), (public_path, public)):
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent,
                                             prefix=".traffic-export-", delete=False) as stream:
                temporary = Path(stream.name)
                staged.append((temporary, destination))
                json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
        for temporary, destination in staged:
            os.link(temporary, destination)
            published.append(destination)
    except BaseException:
        for destination in reversed(published):
            destination.unlink()
        raise
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze")
    analyze.add_argument("manifest", type=Path)
    analyze.add_argument("--holdout", action="append", choices=AXES)
    analyze.add_argument("--target-fpr", type=float, default=.01)
    analyze.add_argument("--seed", type=int, default=20261104)
    analyze.add_argument("--repeats", type=int, default=99)
    analyze.add_argument("--model", action="append", choices=MODELS)
    diagnostic = commands.add_parser("compare")
    diagnostic.add_argument("left", type=Path)
    diagnostic.add_argument("right", type=Path)
    for side in ("left", "right"):
        diagnostic.add_argument(f"--{side}-format", choices=("pcap", "record_tsv", "safari_tsv"), required=True)
        diagnostic.add_argument(f"--{side}-port", type=int, default=443)
    blind = commands.add_parser("blind-export")
    blind.add_argument("manifest", type=Path)
    blind.add_argument("--oracle-output", type=Path, required=True)
    for command in (analyze, diagnostic, blind):
        command.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "blind-export":
        try:
            require(args.output is not None, "blind export requires --output")
            report, oracle = blind_export(args.manifest)
            write_blind_artifacts(report, oracle, args.output, args.oracle_output)
        except (EvidenceError, OSError, ValueError, KeyError) as error:
            sys.stderr.write(json.dumps({"status": "incomplete_export", "reason": str(error)}) + "\n")
            return 2
        sys.stdout.write(json.dumps({"status": "exported", "samples": len(report["samples"]),
                                     "public_sha256": oracle["challenge_sha256"]}) + "\n")
        return 0
    try:
        if args.command == "analyze":
            report = analyze_manifest(args.manifest, args.holdout or list(AXES),
                                      args.target_fpr, args.seed, args.repeats,
                                      args.model or MODELS)
        elif args.command == "compare":
            report = compare(load_records(args.left, args.left_format, args.left_port),
                             load_records(args.right, args.right_format, args.right_port))
    except (EvidenceError, OSError, ValueError, KeyError) as error:
        report = {"status": "insufficient_evidence", "reason": str(error)}
    rendered = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output:
        with args.output.open("x") as output:
            output.write(rendered)
    else:
        sys.stdout.write(rendered)
    return 0 if report.get("status") == "evaluated" else 2


if __name__ == "__main__":
    sys.exit(main())
