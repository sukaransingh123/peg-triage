import csv
import json
import tempfile
import unittest
from pathlib import Path

from peg_triage.cli import correlate, load_iocs, main, read_records, verify_manifest, write_outputs


class CorrelationTests(unittest.TestCase):
    def test_correlated_independent_signals_apply_multiplier(self):
        records = [
            {"signal_type": "process", "value": "sample.proc", "timestamp": "2026-01-01T00:00:00+00:00", "sticky": False},
            {"signal_type": "domain", "value": "host.invalid", "timestamp": "2026-01-01T00:01:00+00:00", "sticky": False},
        ]
        iocs = {"process": [{"value": "sample.proc", "name": "demo"}],
                "domain": [{"value": "host.invalid", "name": "demo"}], "path": []}
        hits, score, verdict, cluster = correlate(records, iocs, 120)
        self.assertEqual((len(hits), score, verdict, cluster), (2, 120.0, "High", True))

    def test_single_signal_does_not_cluster(self):
        records = [{"signal_type": "process", "value": "sample.proc", "timestamp": "2026-01-01T00:00:00+00:00", "sticky": False}]
        iocs = {"process": [{"value": "sample.proc", "name": "demo"}], "domain": [], "path": []}
        _, score, verdict, cluster = correlate(records, iocs, 120)
        self.assertEqual((score, verdict, cluster), (40, "Medium", False))

    def test_unsupported_time_and_nonmatching_signal_do_not_add_weight(self):
        records = [{"signal_type": "process", "value": "ordinary", "timestamp": None, "sticky": False}]
        _, score, verdict, cluster = correlate(records, {"process": [], "domain": [], "path": []}, 120)
        self.assertEqual((score, verdict, cluster), (0, "Low", False))


class EvidenceTests(unittest.TestCase):
    def test_hash_manifest_accepts_and_rejects_modified_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "evidence"
            root.mkdir()
            item = root / "events.csv"
            item.write_text("signal_type,value\nprocess,sample.proc\n", encoding="utf-8")
            _, hashes = read_records(root)
            manifest = Path(tmp) / "custody.csv"
            with manifest.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["path", "sha256"])
                writer.writeheader()
                writer.writerow({"path": hashes[0]["path"], "sha256": hashes[0]["sha256"]})
            verify_manifest(root, manifest)
            item.write_text("changed", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Integrity check failed"):
                verify_manifest(root, manifest)

    def test_stix_bundle_subset_loads_indicator(self):
        with tempfile.TemporaryDirectory() as tmp:
            feed = Path(tmp) / "iocs.json"
            feed.write_text(json.dumps({"type": "bundle", "objects": [
                {"type": "indicator", "name": "sample process", "pattern": "[process:name = 'sample.proc']"},
                {"type": "indicator", "name": "other", "pattern": "[domain-name:value = 'host.invalid']"},
            ]}), encoding="utf-8")
            iocs = load_iocs(feed)
            self.assertEqual(iocs["process"][0]["value"], "sample.proc")
            self.assertEqual(iocs["domain"][0]["value"], "host.invalid")

    def test_dashboard_and_audit_outputs_are_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "evidence"
            root.mkdir()
            (root / "events.csv").write_text("timestamp,signal_type,value\n2026-01-01T00:00:00Z,profile,demo\n", encoding="utf-8")
            records, hashes = read_records(root)
            _, score, verdict, cluster = correlate(records, {"process": [], "domain": [], "path": []}, 120)
            out = Path(tmp) / "report"
            write_outputs(out, root, records, hashes, score, verdict, cluster, 120)
            html = (out / "report.html").read_text(encoding="utf-8")
            self.assertIn("Evidence correlation", html)
            self.assertIn("report-data", html)
            self.assertTrue((out / "report.json").is_file())
            self.assertTrue((out / "timeline.csv").is_file())

    def test_demo_uses_fabricated_iocs_and_produces_correlated_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "demo"
            self.assertEqual(main(["--demo", "--out", str(out)]), 0)
            result = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(result["verdict"], "High")
            self.assertTrue(result["temporal_cluster"])
            self.assertEqual(len(result["input_hashes"]), 1)
            self.assertTrue((out / "report.html").is_file())


if __name__ == "__main__":
    unittest.main()
