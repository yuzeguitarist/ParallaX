"""Privacy detector controls on synthetic complete captures, not field claims."""

import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import random
import tempfile
import unittest

import analyze
import privacy


def artifact(directory, name, sizes, offset=0):
    path = directory / (name + ".tsv")
    path.write_text("t_micros\tdirection\tcontent_type\trecord_length\n" + "".join(
        f"{offset+i*50000}\t{'c2s' if i % 2 == 0 else 's2c'}\t23\t{size}\n"
        for i, size in enumerate(sizes)))
    return {"capture_id": name, "path": path.name, "format": "record_tsv",
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "complete": True}


def website_fixture(directory):
    captures = []
    for site in range(2):
        for session in range(6):
            name = f"s{site}-session{session}"
            entry = artifact(directory, name, [200+site*4000+session+i for i in range(12)], session)
            captures.append({**entry, "site": f"site-{site}", "capture_group": name,
                             "implementation": "synthetic-control", "vantage": "fixture",
                             "workload": "render-control", "day": "2026-11-17", "network": "fixture"})
    return {"schema": "parallax-website-corpus-v1", "purpose": "machinery_control",
            "workload_scope": "synthetic_control", "captures": captures}


def correlation_fixture(directory, count=4):
    pairs = []
    for i in range(count):
        rng = random.Random(i)
        sizes = [rng.randint(100, 16000) for _ in range(32)]
        pairs.append({"pair_id": f"pair{i}", "capture_group": f"session{i}",
                      "workload": "fixture", "day": "2026-11-17", "network": "fixture",
                      "ingress": artifact(directory, f"in{i}", sizes, i*100),
                      "egress": artifact(directory, f"out{i}", sizes, i*100+1)})
    return {"schema": "parallax-correlation-corpus-v1", "purpose": "machinery_control",
            "direction_convention": "initiator_to_responder", "ingress_vantage": "synthetic-in",
            "egress_vantage": "synthetic-out", "pairs": pairs}


def manifest(directory, document):
    path = directory / "corpus.json"
    path.write_text(json.dumps(document))
    return path


class WebsiteControls(unittest.TestCase):
    def test_known_site_signal_classifies_held_out_complete_sessions(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            report = privacy.websites(manifest(directory, website_fixture(directory)), 17)
        self.assertEqual(report["status"], "evaluated")
        self.assertEqual(report["purpose"], "machinery_control")
        self.assertEqual(report["accuracy"], 1)
        self.assertEqual(report["uniform_chance"], .5)
        self.assertEqual(report["scaling_fit_sessions"], report["train_sessions"])
        self.assertTrue(set(report["train_capture_groups"]).isdisjoint(report["test_capture_groups"]))
        self.assertEqual(len(report["capture_provenance"]), 12)

    def test_uninformative_features_remain_at_chance_and_shuffled_sites_lose_signal(self):
        rows = [{"site": str(site), "group": f"{site}:{i}", "x": [float(site)]}
                for site in range(2) for i in range(60)]
        self.assertEqual(privacy.evaluate_websites(rows, 17)["accuracy"], 1)
        uninformative = [{**row, "x": [0.0]} for row in rows]
        self.assertEqual(privacy.evaluate_websites(uninformative, 17)["accuracy"], .5)
        rng = random.Random(29)
        labels = [row["site"] for row in rows]
        rng.shuffle(labels)
        shuffled = [{**row, "site": site} for row, site in zip(rows, labels)]
        self.assertLess(privacy.evaluate_websites(shuffled, 17)["accuracy"], .7)

    def test_scaling_and_centroids_never_fit_held_out_outliers(self):
        rows = [{"site": str(site), "group": f"{site}:{i}", "x": [float(site)]}
                for site in range(2) for i in range(12)]
        train, test = privacy.website_partition(rows, 17)
        expected = copy.deepcopy(privacy.fit_sites(train))
        heldout = {row["group"] for row in test}
        poisoned = [{**row, "x": [1e20]} if row["group"] in heldout else row for row in rows]
        new_train, _ = privacy.website_partition(poisoned, 17)
        self.assertEqual(privacy.fit_sites(new_train), expected)

    def test_small_corpora_shared_sessions_and_confounded_sites_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            original = website_fixture(directory)
            for mutation in ("small", "same-session", "site-network", "mixed-implementation", "synthetic-measurement"):
                document = copy.deepcopy(original)
                if mutation == "small":
                    document["captures"].pop()
                elif mutation == "same-session":
                    document["captures"][1]["capture_group"] = document["captures"][0]["capture_group"]
                elif mutation == "site-network":
                    document["captures"][0]["network"] = "site-specific-network"
                elif mutation == "mixed-implementation":
                    document["captures"][0]["implementation"] = "different-product"
                else:
                    document["purpose"] = "measurement"
                with self.subTest(mutation=mutation), self.assertRaises(analyze.EvidenceError):
                    privacy.websites(manifest(directory, document), 17)


class CorrelationControls(unittest.TestCase):
    def test_known_pairs_rank_first_and_shuffled_ground_truth_does_not(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            document = correlation_fixture(directory)
            report = privacy.correlate(manifest(directory, document), 50, 100)
            self.assertEqual(report["tie_adjusted_top1"], 1)
            self.assertEqual(report["mean_true_midrank"], 1)
            self.assertEqual(report["top1_chance"], .25)
            egress = [entry["egress"] for entry in document["pairs"]]
            for i, entry in enumerate(document["pairs"]):
                entry["egress"] = egress[(i+1) % len(egress)]
            shuffled = privacy.correlate(manifest(directory, document), 50, 100)
            self.assertEqual(shuffled["tie_adjusted_top1"], 0)

    def test_identical_patterns_have_honest_chance_tie_credit(self):
        vector = [[float(i % 7), float(i*i % 11)] for i in range(32)]
        report = privacy.evaluate_correlation([[vector, vector] for _ in range(4)], 50000, 2)
        self.assertEqual(report["tie_adjusted_top1"], .25)
        self.assertEqual(report["mean_true_midrank"], 2.5)
        self.assertEqual(report["tie_adjusted_top3"], .75)

    def test_independent_noise_does_not_reveal_the_manifest_pairing(self):
        rng = random.Random(7351)
        pairs = [[[[float(rng.randrange(16000)), float(rng.randrange(16000))]
                   for _ in range(32)] for _ in range(2)] for _ in range(16)]
        report = privacy.evaluate_correlation(pairs, 50000, 2)
        self.assertLessEqual(report["tie_adjusted_top1"], .25)
        self.assertGreater(report["mean_true_midrank"], 4)

    def test_lag_scan_recovers_only_a_permitted_shift(self):
        rng = random.Random(11)
        left = [[float(rng.randrange(100)), float(rng.randrange(100))] for _ in range(32)]
        right = [[0.0, 0.0], [0.0, 0.0]] + left[:-2]
        score, lag = privacy.lag_score(left, right, 2)
        self.assertAlmostEqual(score, 1)
        self.assertEqual(lag, 2)
        restricted_score, _ = privacy.lag_score(left, right, 0)
        self.assertLess(restricted_score, .5)

    def test_constant_nonfinite_and_excessive_work_are_insufficient(self):
        constant = [[1.0, 1.0] for _ in range(32)]
        with self.assertRaisesRegex(analyze.EvidenceError, "constant"):
            privacy.lag_score(constant, constant, 2)
        for value in (float("nan"), float("inf"), -1.0):
            with self.subTest(value=value), self.assertRaises(analyze.EvidenceError):
                privacy.lag_score([[value, 0.0]] * 32, constant, 2)
        with self.assertRaisesRegex(analyze.EvidenceError, "work exceeds"):
            privacy.evaluate_correlation([[constant*16, constant*16] for _ in range(64)], 50000, 32)

    def test_pair_independence_context_and_direction_convention_are_required(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            original = correlation_fixture(directory)
            for mutation in ("same-group", "one-pair", "different-context", "directions", "same-vantage"):
                document = copy.deepcopy(original)
                if mutation == "same-group":
                    document["pairs"][1]["capture_group"] = document["pairs"][0]["capture_group"]
                elif mutation == "one-pair":
                    document["pairs"] = document["pairs"][:1]
                elif mutation == "different-context":
                    document["pairs"][1]["workload"] = "different-workload"
                elif mutation == "directions":
                    document["direction_convention"] = "unreviewed"
                else:
                    document["egress_vantage"] = document["ingress_vantage"]
                with self.subTest(mutation=mutation), self.assertRaises(analyze.EvidenceError):
                    privacy.correlate(manifest(directory, document), 50, 100)


class ArtifactControls(unittest.TestCase):
    def test_bad_hash_duplicate_incomplete_and_escape_never_count_as_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            original = website_fixture(directory)
            for mutation in ("hash", "duplicate", "incomplete", "escape", "symlink"):
                document = copy.deepcopy(original)
                if mutation == "hash":
                    document["captures"][0]["sha256"] = "0" * 64
                elif mutation == "duplicate":
                    first = document["captures"][0]
                    document["captures"][1].update(path=first["path"], sha256=first["sha256"])
                elif mutation == "incomplete":
                    document["captures"][0]["complete"] = False
                elif mutation == "escape":
                    document["captures"][0]["path"] = "../outside.tsv"
                else:
                    directory.joinpath("escape.tsv").symlink_to(directory.parent / "outside.tsv")
                    document["captures"][0]["path"] = "escape.tsv"
                with self.subTest(mutation=mutation), self.assertRaises(analyze.EvidenceError):
                    privacy.websites(manifest(directory, document), 17)

    def test_cli_retains_insufficient_report_and_never_overwrites_existing_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            input_path = manifest(directory, {"schema": "parallax-website-corpus-v1",
                                               "purpose": "measurement", "captures": []})
            output = directory / "result.json"
            argv = ["websites", str(input_path), "--output", str(output)]
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(privacy.main(argv), 2)
                first = output.read_bytes()
                self.assertEqual(json.loads(first)["status"], "insufficient_evidence")
                self.assertEqual(privacy.main(argv), 2)
            self.assertEqual(output.read_bytes(), first)


if __name__ == "__main__":
    unittest.main()
