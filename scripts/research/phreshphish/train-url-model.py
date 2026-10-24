#!/usr/bin/env python3
"""Research-only character n-gram screening on PhreshPhish train-derived domain splits."""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import math
import random
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier


DATASET_REVISION = "eca603e0ecd4f698f8d4d226c088659e72681239"
EXPECTED_ROWS = 498_255
EXPECTED_COUNTS = {"benign": 276_729, "phish": 221_526}
EXPECTED_TEST_ROWS = 168_059
EXPECTED_TEST_COUNTS = {"benign": 91_259, "phish": 76_800}
EXPECTED_TEST_IDS_SHA256 = "389C98EAF3D02D0E149218F4A8A0E92F06CA2F45821F1CE08A53E3F935CA343C"
EXPECTED_TEST_CSV_SHA256 = "001926172EDAD6A7E612AC9B53585E2AC775847D14FFCD58CA1A960B7EE691A1"
SPLIT_SEED = "sentinel-phreshphish-train-registrable-domain-v1"
MAX_URL_LENGTH = 100_000


class PublicSuffixList:
    def __init__(self, path: str):
        self.rules: set[str] = set()
        self.wildcards: set[str] = set()
        self.exceptions: set[str] = set()
        for raw in Path(path).read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("//"):
                continue
            bucket = self.rules
            if line.startswith("!"):
                bucket, line = self.exceptions, line[1:]
            elif line.startswith("*."):
                bucket, line = self.wildcards, line[2:]
            self._insert(bucket, line)

    @staticmethod
    def _insert(bucket: set[str], rule: str) -> None:
        try:
            bucket.add(rule.encode("idna").decode("ascii").lower())
        except UnicodeError:
            return

    def registrable_domain(self, host: str) -> str | None:
        host = host.strip("[].").lower()
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
        labels = host.split(".")
        suffix_length = 1
        for index in range(len(labels)):
            tail = ".".join(labels[index:])
            if tail in self.exceptions:
                return tail if index == 0 else ".".join(labels[index:])
            if tail in self.rules:
                suffix_length = max(suffix_length, len(labels) - index)
            if index > 0 and tail in self.wildcards:
                suffix_length = max(suffix_length, len(labels) - index + 1)
        if len(labels) <= suffix_length:
            return None
        return ".".join(labels[-(suffix_length + 1) :])


def domain_key(url: str, psl: PublicSuffixList, record_id: str) -> str:
    candidate = url if "://" in url else "https://" + url
    try:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("not a web URL")
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        if len(host) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.split(".")
        ):
            raise ValueError("invalid DNS hostname")
        return psl.registrable_domain(host) or host
    except (ValueError, UnicodeError):
        return "invalid:" + record_id


def split_for_domain(domain: str) -> str:
    digest = hashlib.sha256(f"{SPLIT_SEED}\n{domain}".encode("utf-8")).digest()
    bucket = int.from_bytes(digest[:4], "big") % 100
    if bucket < 70:
        return "train"
    if bucket < 85:
        return "calibration"
    return "holdout"


def update_record_id_digest(digest, record_id: str) -> None:
    digest.update((record_id + "\n").encode("utf-8"))


def load_data(csv_path: str, manifest_path: str, psl: PublicSuffixList):
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if (manifest.get("dataset") != "phreshphish/phreshphish" or
            manifest.get("datasetRevision") != DATASET_REVISION or
            manifest.get("split") != "train" or
            manifest.get("rows") != EXPECTED_ROWS or
            manifest.get("counts") != EXPECTED_COUNTS or
            manifest.get("license") != "cc-by-4.0; anti-phishing research use only"):
        raise ValueError("Input manifest is not the pinned PhreshPhish anti-phishing research train split")

    digest = hashlib.sha256()
    with open(csv_path, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    csv_sha = digest.hexdigest().upper()
    if csv_sha != manifest.get("extractedCsvSha256"):
        raise ValueError("CSV bytes do not match the extractor checksum")

    urls: dict[str, list[str]] = {name: [] for name in ("train", "calibration", "holdout")}
    labels: dict[str, list[int]] = {name: [] for name in urls}
    record_ids: dict[str, list[str]] = {name: [] for name in urls}
    counts: dict[str, Counter[str]] = {name: Counter() for name in urls}
    seen_ids: set[str] = set()
    id_digest = hashlib.sha256()
    domains: dict[str, set[str]] = {name: set() for name in urls}
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != ["sha256", "url", "label"]:
            raise ValueError("Unexpected PhreshPhish train CSV schema")
        for row_number, row in enumerate(reader, start=2):
            record_id = row["sha256"].lower()
            url = row["url"].strip()
            label = row["label"]
            if (len(record_id) != 64 or any(char not in "0123456789abcdef" for char in record_id) or
                    record_id in seen_ids or not url or len(url) > MAX_URL_LENGTH or
                    label not in {"benign", "phish"}):
                raise ValueError(f"Invalid or duplicate record at row {row_number}; URL values are not logged")
            seen_ids.add(record_id)
            update_record_id_digest(id_digest, record_id)
            domain = domain_key(url, psl, record_id)
            partition = split_for_domain(domain)
            urls[partition].append(url)
            labels[partition].append(1 if label == "phish" else 0)
            record_ids[partition].append(record_id)
            counts[partition][label] += 1
            domains[partition].add(domain)
    actual_counts: Counter[str] = Counter()
    for partition_counts in counts.values():
        actual_counts.update(partition_counts)
    if (len(seen_ids) != EXPECTED_ROWS or dict(actual_counts) != EXPECTED_COUNTS or
            id_digest.hexdigest().upper() != manifest.get("recordIdsSha256") or
            any(not urls[name] for name in urls)):
        raise ValueError("Train row count, labels, record hashes, or deterministic split do not match the manifest")
    if set.intersection(*(domains[name] for name in domains)):
        raise ValueError("Registrable-domain leakage detected between train/calibration/holdout")
    return urls, labels, record_ids, counts, domains, csv_sha, id_digest.hexdigest().upper()


def confusion(y_true: np.ndarray, scores: np.ndarray, threshold: float):
    predicted = scores > threshold
    positive = y_true == 1
    negative = ~positive
    tp = int(np.count_nonzero(predicted & positive))
    fp = int(np.count_nonzero(predicted & negative))
    tn = int(np.count_nonzero(~predicted & negative))
    fn = int(np.count_nonzero(~predicted & positive))
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    precision = tp / max(1, tp + fp)
    prevalence = float(np.mean(y_true))
    projections = {}
    for base_rate in (0.0005, 0.001, 0.005, 0.01, 0.05):
        projected_precision = recall * base_rate / max(1e-15, recall * base_rate + fpr * (1 - base_rate))
        projections[f"{base_rate:.4%}"] = projected_precision
    return {
        "rows": int(len(y_true)),
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "recall": recall, "falsePositiveRate": fpr, "precisionAtObservedPrevalence": precision,
        "observedPrevalence": prevalence, "precisionProjectionAtBaseRates": projections,
        "threshold": float(threshold),
    }


def transform_in_batches(vectorizer: HashingVectorizer, urls: list[str], batch_size: int = 8192):
    for start in range(0, len(urls), batch_size):
        yield start, vectorizer.transform(urls[start : start + batch_size])


def evaluate_official_test(csv_path: str, manifest_path: str, vectorizer: HashingVectorizer,
                           model: SGDClassifier, thresholds: dict[str, float]):
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if (manifest.get("dataset") != "phreshphish/phreshphish" or
            manifest.get("datasetRevision") != DATASET_REVISION or manifest.get("split") != "test" or
            manifest.get("excludedRows") != 1 or manifest.get("rows") != EXPECTED_TEST_ROWS or
            manifest.get("counts") != EXPECTED_TEST_COUNTS or
            manifest.get("recordIdsSha256") != EXPECTED_TEST_IDS_SHA256 or
            manifest.get("extractedCsvSha256") != EXPECTED_TEST_CSV_SHA256):
        raise ValueError("Official test extraction does not match the previously pinned URL-only row set")
    digest = hashlib.sha256()
    with open(csv_path, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest().upper() != EXPECTED_TEST_CSV_SHA256:
        raise ValueError("Official test CSV checksum mismatch")

    urls: list[str] = []
    labels: list[int] = []
    id_digest = hashlib.sha256()
    counts: Counter[str] = Counter()
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != ["url", "label", "split", "record_sha256"]:
            raise ValueError("Unexpected official test CSV schema")
        for row_number, row in enumerate(reader, start=2):
            label = row["label"]
            record_id = row["record_sha256"].lower()
            url = row["url"].strip()
            if (row["split"] != "test" or label not in {"benign", "phish"} or
                    len(record_id) != 64 or any(char not in "0123456789abcdef" for char in record_id) or
                    not url or len(url) > MAX_URL_LENGTH):
                raise ValueError(f"Invalid official test row {row_number}; URL values are not logged")
            update_record_id_digest(id_digest, record_id)
            urls.append(url)
            labels.append(1 if label == "phish" else 0)
            counts[label] += 1
    if (len(urls) != EXPECTED_TEST_ROWS or dict(counts) != EXPECTED_TEST_COUNTS or
            id_digest.hexdigest().upper() != EXPECTED_TEST_IDS_SHA256):
        raise ValueError("Official test row count, labels, or record IDs do not match the pinned set")

    all_scores: list[np.ndarray] = []
    for _, matrix in transform_in_batches(vectorizer, urls):
        all_scores.append(model.decision_function(matrix))
    scores = np.concatenate(all_scores)
    y_true = np.asarray(labels, dtype=np.int8)
    return {name: confusion(y_true, scores, threshold) for name, threshold in thresholds.items()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--psl", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--official-test-csv", required=True)
    parser.add_argument("--test-manifest", required=True)
    args = parser.parse_args()

    psl = PublicSuffixList(args.psl)
    urls, labels, record_ids, split_counts, domains, csv_sha, record_ids_sha = load_data(args.csv, args.manifest, psl)
    vectorizer = HashingVectorizer(analyzer="char", ngram_range=(3, 5), n_features=2**18,
                                   alternate_sign=False, norm="l2", dtype=np.float32,
                                   lowercase=True, strip_accents=None)
    model = SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-5, max_iter=1,
                          tol=None, random_state=42, learning_rate="optimal", average=True)
    rng = random.Random(42)
    batch_size = 8192
    for epoch in range(4):
        order = list(range(len(urls["train"])))
        rng.shuffle(order)
        first_batch = True
        for start in range(0, len(order), batch_size):
            selected = order[start : start + batch_size]
            x = vectorizer.transform([urls["train"][index] for index in selected])
            y = np.asarray([labels["train"][index] for index in selected], dtype=np.int8)
            if first_batch:
                model.partial_fit(x, y, classes=np.asarray([0, 1], dtype=np.int8))
                first_batch = False
            else:
                model.partial_fit(x, y)

    scores: dict[str, np.ndarray] = {}
    for partition in ("calibration", "holdout"):
        predicted_parts = []
        for start, matrix in transform_in_batches(vectorizer, urls[partition], batch_size):
            predicted_parts.append(model.decision_function(matrix))
        scores[partition] = np.concatenate(predicted_parts)
    calibration_y = np.asarray(labels["calibration"], dtype=np.int8)
    holdout_y = np.asarray(labels["holdout"], dtype=np.int8)
    calibration_negative_scores = np.sort(scores["calibration"][calibration_y == 0])
    results = {}
    thresholds = {}
    for target_fpr in (0.001, 0.005, 0.01):
        index = min(len(calibration_negative_scores) - 1,
                    max(0, math.ceil((1 - target_fpr) * len(calibration_negative_scores)) - 1))
        threshold = float(calibration_negative_scores[index])
        key = f"calibratedFpr_{target_fpr:.1%}"
        thresholds[key] = threshold
        results[key] = {
            "calibration": confusion(calibration_y, scores["calibration"], threshold),
            "registrableDomainHoldout": confusion(holdout_y, scores["holdout"], threshold),
        }

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    holdout_path = output_dir / "phreshphish-train-derived-holdout.csv"
    with holdout_path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(["url", "label", "split", "record_sha256"])
        writer.writerows((url, "phish" if label else "benign", "test", record_id)
                         for url, label, record_id in zip(urls["holdout"], labels["holdout"], record_ids["holdout"]))

    report = {
        "dataset": "phreshphish/phreshphish",
        "revision": DATASET_REVISION,
        "trainingSourceSplit": "train only; official test labels were not used for fitting, threshold selection, or model changes",
        "licenseScope": "anti-phishing research only; no product model generated or distributed",
        "sourceCsvSha256": csv_sha,
        "sourceRecordIdsSha256": record_ids_sha,
        "splitSeed": SPLIT_SEED,
        "splitMethod": "hash of exact registrable domain from Sentinel public_suffix_list.dat; 70/15/15 bucket thresholds",
        "splitRows": {name: len(urls[name]) for name in urls},
        "splitLabelCounts": {name: dict(split_counts[name]) for name in urls},
        "splitRegistrableDomains": {name: len(domains[name]) for name in urls},
        "model": "SGD logistic loss over signed-free hashed URL character n-grams 3-5",
        "parameters": {"hashFeatures": 262144, "epochs": 4, "alpha": 0.00001, "seed": 42},
        "calibrationAndDomainHoldout": results,
        "officialTestOnce": evaluate_official_test(args.official_test_csv, args.test_manifest,
                                                   vectorizer, model, thresholds),
        "holdoutCsvSha256": hashlib.sha256(holdout_path.read_bytes()).hexdigest().upper(),
        "urlsOpened": 0,
    }
    Path(args.output, "model-screening-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, csv.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
