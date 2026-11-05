"""Evidence-integrity regressions; synthetic inputs do not claim field security."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import analyze


def rows(groups=20):
    return [{"y": label, "x": [float(label), group / 100],
             "meta": {"capture_group": f"trial-{group}", "site": f"site-{group}",
                      "workload": f"work-{group}", "day": f"2026-10-{group+1:02}",
                      "network": "one-network", "vantage": "synthetic-test"}}
            for group in range(groups) for label in (0, 1)]


class ReassemblyTests(unittest.TestCase):
    def test_reordering_duplicates_and_completion_timestamp(self):
        tracker = analyze.TcpDirection()
        record = bytes([23, 3, 3, 0, 3, 10, 11, 12])
        tracker.feed(100, b"", True, 0, 0)
        tracker.feed(105, record[4:], False, 10, 0)
        self.assertEqual(tracker.records, [])
        tracker.feed(101, record[:4], False, 30, 0)
        self.assertEqual(tracker.records, [(30, 0, 23, 3)])
        tracker.feed(101, record, False, 40, 0)
        tracker.feed(109, b"", False, 50, 0, fin=True)
        self.assertEqual(tracker.finish(), [(30, 0, 23, 3)])
        with self.assertRaisesRegex(analyze.EvidenceError, "conflicting TCP overlap"):
            tracker.feed(108, b"\xff", False, 50, 0)

    def test_missing_syn_truncation_and_allocation_bound_fail(self):
        tracker = analyze.TcpDirection()
        with self.assertRaises(analyze.EvidenceError):
            tracker.feed(100, b"x", False, 0, 0)
        tracker.feed(100, b"", True, 0, 0)
        with self.assertRaisesRegex(analyze.EvidenceError, "allocation bound"):
            tracker.feed(1100, b"x", False, 0, 0, allocation_budget=32)
        self.assertEqual(len(tracker.wire), 0)
        tracker.feed(101, bytes([23, 3, 3, 0, 2, 1]), False, 0, 0)
        tracker.feed(107, b"", False, 1, 0, fin=True)
        with self.assertRaises(analyze.EvidenceError):
            tracker.finish()

    def test_multiple_flows_remain_one_capture_with_flow_provenance(self):
        lines = []
        for stream in (0, 1):
            for source, destination, sequence in ((50000+stream, 443, 100),
                                                   (443, 50000+stream, 200)):
                lines.append(f"{stream}\t{source}\t{destination}\t{sequence}\t1\t0\t\t0\t0\n")
                lines.append(f"{stream}\t{source}\t{destination}\t{sequence+1}\t0\t.001\t170303000178\t0\t0\n")
                lines.append(f"{stream}\t{source}\t{destination}\t{sequence+7}\t0\t.002\t\t1\t0\n")
        process = mock.Mock(stdout=io.StringIO("".join(lines)))
        process.wait.return_value = 0
        process.poll.return_value = 0
        summaries = []
        with mock.patch.object(analyze.subprocess, "Popen", return_value=process):
            records = analyze.load_pcap(Path("unused.pcap"), 443, summaries)
        self.assertEqual(len(records), 4)
        self.assertEqual(len(summaries), 2)
        self.assertTrue(all(flow["direction_record_counts"] == [1, 1] for flow in summaries))

    def test_public_clienthello_structure_omits_site_keys_and_random(self):
        fixture = Path(__file__).resolve().parents[2] / "tests/fixtures/safari26_cloudflare_com_clienthello.bin"
        profile = analyze.client_hello_structure(fixture.read_bytes())
        self.assertIsNotNone(profile)
        self.assertGreater(len(profile["extension_types"]), 5)
        self.assertIn("key_share_group_lengths", profile)
        for forbidden in ("cloudflare", "random", "server_name", "key_bytes", "session_id_bytes"):
            self.assertNotIn(forbidden, json.dumps(profile))

    def load_mock_packets(self, lines):
        process = mock.Mock(stdout=io.StringIO("".join(lines)))
        process.wait.return_value = 0
        process.poll.return_value = 0
        flows = []
        with mock.patch.object(analyze.subprocess, "Popen", return_value=process):
            records = analyze.load_pcap(Path("unused.pcap"), 443, flows, True)
        return records, flows

    def test_missing_whole_tail_record_before_fin_is_not_complete(self):
        # Complete first record ends at seq107, but FIN114 proves seven more
        # payload bytes existed. Omitting an entire TLS record must not pass just
        # because the captured prefix itself ends on a valid record boundary.
        lines = ["0\t50000\t443\t100\t1\t0\t\t0\t0\n",
                 "0\t443\t50000\t200\t1\t0\t\t0\t0\n",
                 "0\t50000\t443\t101\t0\t.001\t170303000178\t0\t0\n",
                 "0\t50000\t443\t114\t0\t.002\t\t1\t0\n",
                 "0\t443\t50000\t201\t0\t.003\t170303000178\t0\t0\n",
                 "0\t443\t50000\t207\t0\t.004\t\t1\t0\n"]
        with self.assertRaisesRegex(analyze.EvidenceError, "missing before FIN"):
            self.load_mock_packets(lines)

    def test_fin_with_reordered_payload_retransmission_and_sequence_wrap(self):
        first = bytes([23, 3, 3, 0, 1, 10])
        final = bytes([23, 3, 3, 0, 2, 11, 12])
        for initial_sequence in (100, (1 << 32)-5):
            tracker = analyze.TcpDirection()
            base = (initial_sequence+1) % (1 << 32)
            tracker.feed(initial_sequence, b"", True, 0, 0)
            tracker.feed((base+len(first)) % (1 << 32), final, False, 10, 0, fin=True)
            self.assertEqual(tracker.records, [])
            tracker.feed(base, first, False, 20, 0)
            # An identical FIN-only retransmission consumes no extra payload.
            tracker.feed((base+len(first)+len(final)) % (1 << 32), b"", False, 30, 0, fin=True)
            self.assertEqual(tracker.finish(), [(20, 0, 23, 1), (20, 0, 23, 2)])
            self.assertEqual(tracker.fin_end, 13)

    def test_fin_conflicts_and_payload_after_fin_are_rejected(self):
        tracker = analyze.TcpDirection()
        tracker.feed(100, b"", True, 0, 0)
        tracker.feed(101, bytes([23, 3, 3, 0, 1, 10]), False, 10, 0, fin=True)
        with self.assertRaisesRegex(analyze.EvidenceError, "conflicting TCP FIN"):
            tracker.feed(108, b"", False, 20, 0, fin=True)
        with self.assertRaisesRegex(analyze.EvidenceError, "extends beyond FIN"):
            tracker.feed(107, b"x", False, 20, 0)

    def test_reset_flag_cannot_stand_in_for_unobserved_payload_end(self):
        lines = ["0\t50000\t443\t100\t1\t0\t\t0\t0\n",
                 "0\t443\t50000\t200\t1\t0\t\t0\t0\n",
                 "0\t50000\t443\t101\t0\t.001\t170303000178\t0\t0\n",
                 "0\t443\t50000\t201\t0\t.001\t170303000178\t0\t0\n",
                 "0\t50000\t443\t114\t0\t.002\t\t0\t1\n"]
        with self.assertRaisesRegex(analyze.EvidenceError, "reset does not prove complete"):
            self.load_mock_packets(lines)

    def test_equal_timestamp_records_preserve_wire_and_packet_completion_order(self):
        def payload(*lengths):
            return b"".join(bytes([23, 3, 3]) + n.to_bytes(2, "big") + b"x"*n
                            for n in lengths)
        down, up = payload(5, 2, 4), payload(3)
        lines = ["0\t50000\t443\t100\t1\t0\t\t0\t0\n",
                 "0\t443\t50000\t200\t1\t0\t\t0\t0\n",
                 f"0\t443\t50000\t201\t0\t.001\t{down.hex()}\t0\t0\n",
                 f"0\t50000\t443\t101\t0\t.001\t{up.hex()}\t0\t0\n",
                 f"0\t443\t50000\t{201+len(down)}\t0\t.002\t\t1\t0\n",
                 f"0\t50000\t443\t{101+len(up)}\t0\t.002\t\t1\t0\n"]
        process = mock.Mock(stdout=io.StringIO("".join(lines)))
        process.wait.return_value = 0
        process.poll.return_value = 0
        flows = []
        with mock.patch.object(analyze.subprocess, "Popen", return_value=process):
            records = analyze.load_pcap(Path("unused.pcap"), 443, flows, True)
        expected = [(1, 5), (1, 2), (1, 4), (0, 3)]
        self.assertEqual([(d, n) for _, d, _, n in records], expected)
        self.assertEqual([(d, n) for _, d, _, n in flows[0]["records"]], expected)


    def test_packet_timeline_retains_idle_fin_and_zero_payload_packets(self):
        lines = ["0\t50000\t443\t100\t1\t0\t\t0\t0\n",
                 "0\t443\t50000\t200\t1\t.0001\t\t0\t0\n",
                 "0\t50000\t443\t101\t0\t1\t170303000178\t0\t0\n",
                 "0\t443\t50000\t201\t0\t2\t170303000178\t0\t0\n",
                 "0\t50000\t443\t107\t0\t12\t\t0\t0\n",
                 "0\t50000\t443\t107\t0\t31\t\t1\t0\n",
                 "0\t443\t50000\t207\t0\t31.2\t\t1\t0\n"]
        records, flows = self.load_mock_packets(lines)
        self.assertIn("tcp_packets", flows[0])
        packets = flows[0]["tcp_packets"]
        self.assertEqual(len(packets), 7)
        self.assertEqual(packets[0], [-1_000_000, 0, 0, True, False, False])
        self.assertEqual(packets[4], [11_000_000, 0, 0, False, False, False])
        fin = next(packet for packet in packets if packet[1] == 0 and packet[4])
        self.assertEqual(fin[0] - records[-1][0], 29_000_000)
        self.assertNotIn("tcp_packets", flows[0]["termination"])

    def test_nonfinite_or_negative_control_timestamp_is_rejected(self):
        for timestamp in ("nan", "inf", "-0.1"):
            lines = [f"0\t50000\t443\t100\t1\t{timestamp}\t\t0\t0\n",
                     "0\t443\t50000\t200\t1\t0\t\t0\t0\n",
                     "0\t50000\t443\t101\t0\t1\t170303000178\t0\t0\n",
                     "0\t443\t50000\t201\t0\t2\t170303000178\t0\t0\n",
                     "0\t50000\t443\t107\t0\t3\t\t1\t0\n",
                     "0\t443\t50000\t207\t0\t4\t\t1\t0\n"]
            with self.subTest(timestamp=timestamp), self.assertRaisesRegex(
                    analyze.EvidenceError, "TCP timestamp"):
                self.load_mock_packets(lines)


class StatisticalTests(unittest.TestCase):
    def test_absent_classes_and_nonfinite_data_never_return_chance(self):
        for scored in ([], [(0, 0)], [(0, 0), (float("nan"), 1)],
                       [(0, 0), (1, 1), (2, 2)]):
            with self.assertRaises(analyze.EvidenceError):
                analyze.auc(scored)
        self.assertEqual(analyze.auc([(0, 0), (0, 1)]), .5)

    def test_capture_groups_never_cross_partition_boundaries(self):
        data = rows()
        for axis in ("capture_group", "site", "workload", "day"):
            parts = analyze.partition(data, axis, 12)
            sets = [{row["meta"][axis] for row in part} for part in parts]
            self.assertTrue(sets[0].isdisjoint(sets[1]))
            self.assertTrue(sets[0].isdisjoint(sets[2]))
            self.assertTrue(sets[1].isdisjoint(sets[2]))
        with self.assertRaises(analyze.EvidenceError):
            analyze.partition(data, "network", 12)

    def test_small_heldout_set_is_insufficient_even_for_perfect_auc(self):
        result = analyze.evaluate_axis(rows(), "site", .01, 12, 19)
        self.assertEqual(result["auc"], 1)
        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertGreater(result["heldout_group_any_false_positive"]["ci95_clopper_pearson"][1], .01)
        self.assertEqual(result["paired_label_permutation_repeats"], 19)

    def test_clopper_pearson_boundaries_and_controls(self):
        interval = analyze.binomial_interval(0, 100)
        self.assertEqual(interval[0], 0)
        self.assertAlmostEqual(interval[1], 1 - .025 ** .01)
        interval = analyze.binomial_interval(100, 100)
        self.assertAlmostEqual(interval[0], .025 ** .01)
        self.assertEqual(interval[1], 1)
        self.assertEqual(analyze.controls()["synthetic_positive_auc"], 1)

    @unittest.skipUnless(importlib.util.find_spec("scipy"), "optional SciPy oracle unavailable")
    def test_binomial_intervals_agree_with_independent_beta_quantile_oracle(self):
        from scipy.stats import beta
        for n in (1, 2, 5, 10, 25):
            for k in range(n+1):
                expected = [0 if k == 0 else beta.ppf(.025, k, n-k+1),
                            1 if k == n else beta.ppf(.975, k+1, n-k)]
                actual = analyze.binomial_interval(k, n)
                for a, e in zip(actual, expected):
                    self.assertAlmostEqual(a, e, places=10)

    @unittest.skipUnless(importlib.util.find_spec("sklearn"), "optional sklearn unavailable")
    def test_optional_models_fit_only_explicit_training_rows_and_report_version(self):
        for backend in ("logistic", "random_forest"):
            info = analyze.model_backend(backend)
            self.assertIn("sklearn", info)
            data = rows(8)
            model = analyze.fit(data, backend, 12)
            self.assertEqual(analyze.auc([(model(row), row["y"]) for row in data]), 1)


class ManifestTests(unittest.TestCase):
    def make_manifest(self, directory):
        captures = []
        for label in ("browser", "parallax"):
            artifact = directory / (label + ".tsv")
            length = 100 if label == "browser" else 101
            text = ("t_micros\tdirection\tcontent_type\trecord_length\n"
                    f"0\tc2s\t23\t{length}\n1\ts2c\t23\t{length}\n")
            artifact.write_text(text)
            captures.append({"capture_id": label, "label": label, "path": artifact.name,
                             "format": "record_tsv", "sha256": hashlib.sha256(text.encode()).hexdigest(),
                             "capture_group": "pair", "site": "same", "workload": "same",
                             "day": "2026-11-04", "network": "same", "vantage": "synthetic-test"})
        path = directory / "manifest.json"
        path.write_text(json.dumps({"schema": "parallax-traffic-corpus-v1", "captures": captures}))
        return path, captures

    def test_hash_mismatch_and_unmatched_source_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, captures = self.make_manifest(Path(temporary))
            data, purpose = analyze.read_manifest(path)
            self.assertEqual(len(data), 2)
            self.assertEqual(purpose, "protocol_comparison")
            captures[1]["vantage"] = "different-source"
            path.write_text(json.dumps({"schema": "parallax-traffic-corpus-v1", "captures": captures}))
            with self.assertRaisesRegex(analyze.EvidenceError, "differs in vantage"):
                analyze.read_manifest(path)
            captures[1]["vantage"] = "synthetic-test"
            captures[1]["sha256"] = "0" * 64
            path.write_text(json.dumps({"schema": "parallax-traffic-corpus-v1", "captures": captures}))
            with self.assertRaisesRegex(analyze.EvidenceError, "SHA-256 mismatch"):
                analyze.read_manifest(path)

    def test_duplicate_artifacts_cannot_multiply_independent_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, captures = self.make_manifest(Path(temporary))
            captures[1].update(path=captures[0]["path"], sha256=captures[0]["sha256"])
            path.write_text(json.dumps({"schema": "parallax-traffic-corpus-v1", "captures": captures}))
            with self.assertRaisesRegex(analyze.EvidenceError, "duplicate artifact"):
                analyze.read_manifest(path)

    def test_real_negative_control_has_separate_classes_and_same_implementation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, captures = self.make_manifest(Path(temporary))
            for capture, label in zip(captures, ("A", "B")):
                capture.pop("label")
                capture.update(class_label=label, implementation="actual-browser")
            path.write_text(json.dumps({"schema": "parallax-traffic-corpus-v1",
                                        "purpose": "negative_control", "captures": captures}))
            data, purpose = analyze.read_manifest(path)
            self.assertEqual([row["y"] for row in data], [0, 1])
            self.assertEqual(purpose, "negative_control")

    def test_blind_export_withholds_oracle_and_source_identifiers(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _ = self.make_manifest(Path(temporary))
            public, oracle = analyze.blind_export(path)
            encoded = json.dumps(public, indent=2, sort_keys=True, allow_nan=False) + "\n"
            self.assertNotIn("browser", encoded)
            self.assertNotIn("parallax", encoded)
            self.assertEqual(public["schema"], "traffic-blind-challenge-v2")
            self.assertEqual(public["tcp_packet_observations"], "unavailable")
            for sample in public["samples"]:
                self.assertEqual(set(sample), {"sample_id", "features", "records", "flows"})
                self.assertNotIn("class_label", sample)
            self.assertEqual({sample["class_label"] for sample in oracle["samples"]}, {0, 1})
            self.assertEqual(oracle["challenge_sha256"], hashlib.sha256(encoded.encode()).hexdigest())

    def test_packet_metadata_export_and_cross_capture_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _ = self.make_manifest(Path(temporary))
            rows, purpose = analyze.read_manifest(path)
            for row in rows:
                row["meta"]["format"] = "pcap"
            sequence = [(0, 0, 23, 1), (1_000_000, 1, 23, 1)]
            packets = [[-1000, 0, 0, True, False, False],
                       [30_000_000, 0, 0, False, True, False]]

            def load_metadata(_path, _format, _port, flows, include_sequences):
                self.assertTrue(include_sequences)
                flows.append({"records": sequence, "tcp_packets": packets,
                              "client_hello": None, "termination": {"reset": False}})
                return sequence

            with mock.patch.object(analyze, "read_manifest", return_value=(rows, purpose)), \
                    mock.patch.object(analyze, "load_records", side_effect=load_metadata):
                public, _ = analyze.blind_export(path)
                self.assertEqual(public["tcp_packet_observations"], "available")
                for sample in public["samples"]:
                    self.assertEqual(sample["flows"][0]["tcp_packets"], packets)
                    self.assertEqual(sample["records"], sequence)
                with mock.patch.object(analyze, "MAX_PACKETS", 3), self.assertRaisesRegex(
                        analyze.EvidenceError, "total TCP packet bound"):
                    analyze.blind_export(path)

    def run_export_cli(self, manifest, public_path, oracle_path):
        return subprocess.run([sys.executable, "-B", str(Path(analyze.__file__)), "blind-export",
                               str(manifest), "--output", str(public_path),
                               "--oracle-output", str(oracle_path)],
                              text=True, capture_output=True, timeout=20)

    def test_blind_export_cli_publishes_exact_hash_and_private_oracle_exclusively(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest, _ = self.make_manifest(directory)
            public_path, oracle_path = directory/"samples.json", directory/"oracle.json"
            result = self.run_export_cli(manifest, public_path, oracle_path)
            self.assertEqual(result.returncode, 0, result.stderr)
            public_bytes = public_path.read_bytes()
            private_bytes = oracle_path.read_bytes()
            oracle = json.loads(private_bytes)
            self.assertEqual(json.loads(public_bytes)["schema"], "traffic-blind-challenge-v2")
            self.assertEqual(oracle["challenge_sha256"], hashlib.sha256(public_bytes).hexdigest())
            self.assertEqual(json.loads(result.stdout)["public_sha256"], oracle["challenge_sha256"])
            self.assertEqual(stat.S_IMODE(oracle_path.stat().st_mode), 0o600)
            repeated = self.run_export_cli(manifest, public_path, oracle_path)
            self.assertEqual(repeated.returncode, 2)
            self.assertEqual(json.loads(repeated.stderr)["status"], "incomplete_export")
            self.assertEqual(public_path.read_bytes(), public_bytes)
            self.assertEqual(oracle_path.read_bytes(), private_bytes)

    def test_failed_cli_export_creates_no_misleading_public_error_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest, _ = self.make_manifest(directory)
            public_path, oracle_path = directory/"missing"/"samples.json", directory/"oracle.json"
            result = self.run_export_cli(manifest, public_path, oracle_path)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertEqual(json.loads(result.stderr)["status"], "incomplete_export")
            self.assertFalse(public_path.exists())
            self.assertFalse(oracle_path.exists())
            self.assertFalse(list(directory.glob(".traffic-export-*")))

    def test_second_publish_failure_rolls_back_only_own_oracle(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            public_path, oracle_path = directory/"samples.json", directory/"oracle.json"
            real_link = analyze.os.link

            def fail_public(source, destination):
                if destination == public_path:
                    raise OSError("simulated public publication failure")
                real_link(source, destination)

            with mock.patch.object(analyze.os, "link", side_effect=fail_public):
                with self.assertRaisesRegex(OSError, "simulated public publication failure"):
                    analyze.write_blind_artifacts({"samples": []}, {"private": True},
                                                 public_path, oracle_path)
            self.assertFalse(public_path.exists())
            self.assertFalse(oracle_path.exists())
            self.assertFalse(list(directory.glob(".traffic-export-*")))


if __name__ == "__main__":
    unittest.main()
