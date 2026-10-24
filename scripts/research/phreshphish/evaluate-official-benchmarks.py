#!/usr/bin/env python3
"""Evaluate frozen train-calibrated URL scores on official PhreshPhish subsets."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import sys
from collections import Counter
from pathlib import Path

import numpy as np


REVISION = "eca603e0ecd4f698f8d4d226c088659e72681239"
EXPECTED_GROUP_COUNTS = {
    "benchmark-005": 586,
    "benchmark-010": 296,
    "benchmark-050": 59,
    "benchmark-100": 29,
    "benchmark-500": 5,
}
EXPECTED_BASE_RATES = {
    "benchmark-005": 0.0005,
    "benchmark-010": 0.001,
    "benchmark-050": 0.005,
    "benchmark-100": 0.01,
    "benchmark-500": 0.05,
}
THRESHOLD_KEYS = ("calibratedFpr_0.1%", "calibratedFpr_0.5%", "calibratedFpr_1.0%")
BOOTSTRAP_SEED = 20261024
BOOTSTRAP_REPLICATES = 10_000


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def read_id_file(path: Path) -> set[str]:
    values = path.read_text(encoding="utf-8").split()
    canonical = [value.lower() for value in values]
    if (not values or any(len(value) != 64 or any(c not in "0123456789abcdef" for c in value)
                          for value in canonical) or len(canonical) != len(set(canonical))):
        raise ValueError(f"Malformed or duplicate benchmark IDs in {path.name}")
    return set(canonical)


def load_scores(path: Path, expected_sha256: str) -> dict[str, tuple[int, float]]:
    if digest_file(path) != expected_sha256:
        raise ValueError("Full-test score CSV checksum mismatch")
    scores: dict[str, tuple[int, float]] = {}
    counts: Counter[str] = Counter()
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != ["record_sha256", "label", "score"]:
            raise ValueError("Unexpected score CSV schema")
        for row_number, row in enumerate(reader, start=2):
            record_id = row["record_sha256"].lower()
            label = row["label"]
            if (len(record_id) != 64 or any(c not in "0123456789abcdef" for c in record_id) or
                    record_id in scores or label not in {"benign", "phish"}):
                raise ValueError(f"Invalid or duplicate score row {row_number}")
            try:
                score = float(row["score"])
            except ValueError as error:
                raise ValueError(f"Invalid model score at row {row_number}") from error
            if not np.isfinite(score):
                raise ValueError(f"Non-finite model score at row {row_number}")
            scores[record_id] = (int(label == "phish"), score)
            counts[label] += 1
    if len(scores) != 168_060 or dict(counts) != {"benign": 91_260, "phish": 76_800}:
        raise ValueError("Full-test score count or labels changed")
    return scores


def confusion_for_ids(ids: set[str], scores: dict[str, tuple[int, float]], threshold: float):
    tp = fp = tn = fn = 0
    for record_id in ids:
        if record_id not in scores:
            raise ValueError("Official benchmark references a record missing from full-test scores")
        label, score = scores[record_id]
        predicted = score > threshold
        if label and predicted:
            tp += 1
        elif label:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    return {
        "rows": len(ids), "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "precision": tp / max(1, tp + fp),
        "recall": tp / max(1, tp + fn),
        "falsePositiveRate": fp / max(1, fp + tn),
    }


def bootstrap_interval(values: list[float], rng: np.random.Generator) -> dict:
    if not values:
        raise ValueError("Cannot bootstrap an empty benchmark group")
    samples = np.asarray(values, dtype=np.float64)
    draws = rng.integers(0, len(samples), size=(BOOTSTRAP_REPLICATES, len(samples)))
    means = samples[draws].mean(axis=1)
    return {
        "mean": float(samples.mean()),
        "confidence95": [float(np.quantile(means, 0.025)), float(np.quantile(means, 0.975))],
        "unit": "benchmark subset; percentile bootstrap of the mean",
    }


def evaluate(scores: dict[str, tuple[int, float]], manifest: dict, benchmark_root: Path,
             thresholds: dict[str, float]) -> dict:
    if manifest.get("dataset") != "phreshphish/phreshphish" or manifest.get("revision") != REVISION:
        raise ValueError("Benchmark file manifest is not pinned to the expected dataset revision")
    files = manifest.get("files")
    if not isinstance(files, list) or len(files) != 976:
        raise ValueError("Official benchmark inventory must include 975 subsets and benign.txt")
    expected_names = {"benign.txt"} | {
        f"{group}/{index}.txt"
        for group, count in EXPECTED_GROUP_COUNTS.items()
        for index in range(count)
    }
    names = [entry.get("file") for entry in files if isinstance(entry, dict)]
    if len(names) != len(files) or len(set(names)) != len(names) or set(names) != expected_names:
        raise ValueError("Official benchmark filenames or inventory are not the expected pinned layout")
    inventory_digest = hashlib.sha256()
    for entry in files:
        path = benchmark_root / entry["file"]
        inventory_digest.update(f"{entry['file']}\t{entry['rows']}\t{entry['sha256']}\n".encode("utf-8"))
        if digest_file(path) != entry.get("sha256"):
            raise ValueError(f"Benchmark list checksum mismatch: {entry['file']}")
        if len(read_id_file(path)) != entry.get("rows"):
            raise ValueError(f"Benchmark list row count mismatch: {entry['file']}")
    if inventory_digest.hexdigest().upper() != manifest.get("inventorySha256"):
        raise ValueError("Benchmark inventory digest mismatch")

    benign_ids = read_id_file(benchmark_root / "benign.txt")
    if len(benign_ids) != 90_262:
        raise ValueError("Official shared benign list changed")
    for record_id in benign_ids:
        if record_id not in scores or scores[record_id][0] != 0:
            raise ValueError("Shared benign list is missing a benign test score")

    rng = np.random.default_rng(BOOTSTRAP_SEED)
    benign_counts = {}
    for key, threshold in thresholds.items():
        fp = sum(scores[record_id][1] > threshold for record_id in benign_ids)
        benign_counts[key] = {"FP": fp, "TN": len(benign_ids) - fp}
    groups = {}
    for group_name, expected_count in EXPECTED_GROUP_COUNTS.items():
        entries = sorted((entry for entry in files if entry["file"].startswith(group_name + "/")),
                         key=lambda entry: entry["file"])
        if len(entries) != expected_count:
            raise ValueError(f"Unexpected number of benchmark subsets in {group_name}")
        per_threshold = {key: [] for key in THRESHOLD_KEYS}
        phish_count_range = [None, None]
        for entry in entries:
            phish_ids = read_id_file(benchmark_root / entry["file"])
            if len(phish_ids) != entry["rows"] or phish_ids & benign_ids:
                raise ValueError(f"Invalid phishing subset: {entry['file']}")
            expected_rate = EXPECTED_BASE_RATES[group_name]
            actual_rate = len(phish_ids) / (len(benign_ids) + len(phish_ids))
            if abs(actual_rate - expected_rate) > 0.00002:
                raise ValueError(f"Unexpected base rate in {entry['file']}")
            if phish_count_range[0] is None:
                phish_count_range = [len(phish_ids), len(phish_ids)]
            else:
                phish_count_range[0] = min(phish_count_range[0], len(phish_ids))
                phish_count_range[1] = max(phish_count_range[1], len(phish_ids))
            for record_id in phish_ids:
                if record_id not in scores or scores[record_id][0] != 1:
                    raise ValueError("Official phishing list is missing a phishing test score")
            for key, threshold in thresholds.items():
                tp = sum(scores[record_id][1] > threshold for record_id in phish_ids)
                fn = len(phish_ids) - tp
                fp = benign_counts[key]["FP"]
                tn = benign_counts[key]["TN"]
                per_threshold[key].append({
                    "rows": len(benign_ids) + len(phish_ids),
                    "TP": tp, "FP": fp, "TN": tn, "FN": fn,
                    "precision": tp / max(1, tp + fp),
                    "recall": tp / max(1, tp + fn),
                    "falsePositiveRate": fp / max(1, fp + tn),
                })
        group_results = {}
        for key in THRESHOLD_KEYS:
            metrics = {}
            for metric in ("precision", "recall", "falsePositiveRate"):
                metrics[metric] = bootstrap_interval([row[metric] for row in per_threshold[key]], rng)
            group_results[key] = {
                "benchmarks": len(per_threshold[key]),
                "sharedBenignRows": len(benign_ids),
                "phishRowsPerBenchmarkRange": phish_count_range,
                "metrics": metrics,
            }
        groups[group_name] = group_results
    return {
        "dataset": "phreshphish/phreshphish",
        "revision": REVISION,
        "protocol": "official shared benign list plus each pinned phishing list; model and thresholds fixed using train/calibration only",
        "benchmarkInventorySha256": manifest["inventorySha256"],
        "thresholds": thresholds,
        "bootstrap": {"replicates": BOOTSTRAP_REPLICATES, "seed": BOOTSTRAP_SEED, "confidenceLevel": 0.95},
        "groups": groups,
        "benchmarkCount": sum(EXPECTED_GROUP_COUNTS.values()),
        "urlsOpened": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scores", required=True)
    parser.add_argument("--score-sha256", required=True)
    parser.add_argument("--model-report", required=True)
    parser.add_argument("--benchmark-directory", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    model_report = json.loads(Path(args.model_report).read_text(encoding="utf-8"))
    if model_report.get("revision") != REVISION:
        raise ValueError("Model report is not from the pinned PhreshPhish revision")
    scores = load_scores(Path(args.scores), args.score_sha256.upper())
    benchmark_root = Path(args.benchmark_directory)
    manifest = json.loads((benchmark_root / "manifest.json").read_text(encoding="utf-8"))
    thresholds = {
        key: float(model_report["calibrationAndDomainHoldout"][key]["calibration"]["threshold"])
        for key in THRESHOLD_KEYS
    }
    result = evaluate(scores, manifest, benchmark_root, thresholds)
    result["modelScoresSha256"] = args.score_sha256.upper()
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, csv.Error, KeyError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
