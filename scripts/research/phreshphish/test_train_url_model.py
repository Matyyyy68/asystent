import importlib.util
import hashlib
import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("train-url-model.py")
SPEC = importlib.util.spec_from_file_location("phreshphish_train_url_model", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ResearchModelTests(unittest.TestCase):
    def setUp(self):
        self.psl = MODULE.PublicSuffixList(str(SCRIPT.parents[3] / "src" / "Sentinel.Core" / "Data" / "public_suffix_list.dat"))

    def test_registrable_domain_honors_multilabel_private_and_wildcard_rules(self):
        self.assertEqual("example.co.uk", self.psl.registrable_domain("login.example.co.uk"))
        self.assertEqual("alice.github.io", self.psl.registrable_domain("alice.github.io"))
        self.assertEqual("www.ck", self.psl.registrable_domain("www.ck"))

    def test_ip_and_public_suffix_have_no_registrable_domain(self):
        self.assertIsNone(self.psl.registrable_domain("192.0.2.5"))
        self.assertIsNone(self.psl.registrable_domain("co.uk"))

    def test_domain_partition_is_deterministic_and_complete(self):
        first = MODULE.split_for_domain("example.co.uk")
        self.assertEqual(first, MODULE.split_for_domain("example.co.uk"))
        self.assertIn(first, {"train", "calibration", "holdout"})

    def test_record_id_digest_uses_canonical_utf8_newlines(self):
        record_id = "a" * 64
        digest = hashlib.sha256()
        MODULE.update_record_id_digest(digest, record_id)
        self.assertEqual(digest.hexdigest(), hashlib.sha256((record_id + "\n").encode("utf-8")).hexdigest())

    def test_invalid_urls_are_isolated_by_record_id(self):
        self.assertNotEqual(
            MODULE.domain_key("not a url", self.psl, "a" * 64),
            MODULE.domain_key("not a url", self.psl, "b" * 64),
        )

    def test_metrics_and_low_base_rate_projection(self):
        import numpy as np

        result = MODULE.confusion(np.asarray([1, 1, 0, 0]), np.asarray([2.0, -1.0, 2.0, -1.0]), 0.0)
        self.assertEqual((result["TP"], result["FP"], result["TN"], result["FN"]), (1, 1, 1, 1))
        self.assertAlmostEqual(result["precisionProjectionAtBaseRates"]["0.0500%"], 0.0005)

    def test_train_loader_checks_csv_and_record_id_manifest_hashes(self):
        rows = [
            {"sha256": "a" * 64, "url": "https://a.com/", "label": "benign"},
            {"sha256": "b" * 64, "url": "https://b.com/", "label": "phish"},
            {"sha256": "c" * 64, "url": "https://c.com/", "label": "benign"},
        ]
        counts = {"benign": 2, "phish": 1}
        id_digest = hashlib.sha256()
        for row in rows:
            MODULE.update_record_id_digest(id_digest, row["sha256"])
        with tempfile.TemporaryDirectory(prefix="sentinel-phreshphish-unit-") as directory:
            csv_path = Path(directory, "fixture.csv")
            manifest_path = Path(directory, "manifest.json")
            with csv_path.open("w", encoding="utf-8", newline="") as output:
                writer = csv.DictWriter(output, fieldnames=["sha256", "url", "label"])
                writer.writeheader()
                writer.writerows(rows)
            csv_sha = hashlib.sha256(csv_path.read_bytes()).hexdigest().upper()
            manifest = {
                "dataset": "phreshphish/phreshphish",
                "datasetRevision": MODULE.DATASET_REVISION,
                "split": "train",
                "rows": len(rows),
                "counts": counts,
                "license": "cc-by-4.0; anti-phishing research use only",
                "extractedCsvSha256": csv_sha,
                "recordIdsSha256": id_digest.hexdigest().upper(),
            }
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            partitions = {"a.com": "train", "b.com": "calibration", "c.com": "holdout"}
            with patch.multiple(MODULE, EXPECTED_ROWS=3, EXPECTED_COUNTS=counts), \
                    patch.object(MODULE, "split_for_domain", side_effect=lambda domain: partitions[domain]):
                loaded = MODULE.load_data(str(csv_path), str(manifest_path), self.psl)
                self.assertEqual(len(loaded[0]["train"]) + len(loaded[0]["calibration"]) + len(loaded[0]["holdout"]), 3)
                manifest["recordIdsSha256"] = "0" * 64
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "record hashes"):
                    MODULE.load_data(str(csv_path), str(manifest_path), self.psl)


if __name__ == "__main__":
    unittest.main()
