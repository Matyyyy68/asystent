#!/usr/bin/env python3
"""Diagnostic Multinomial Naive Bayes URL model, pinned to PhishVN train/validation only."""

from __future__ import annotations

import argparse
import csv
import hashlib
import math
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlsplit


SPLITS = {
    "url_train.csv": (
        "568E788EDA4BDF62531ADCDDD093373EF6A1E97FEEC1354063AE337325367B61",
        7_826_219,
        "train",
    ),
    "url_val.csv": (
        "D9EF64D29DF6639AF698EF228E5AF5EC6F8AE44C8F1A1DD1367F9BA6D073D81F",
        1_476_590,
        "val",
    ),
}


@dataclass(frozen=True)
class Sample:
    phishing: bool
    features: Counter[str]


def parse_rows(stream, expected_split: str) -> list[tuple[str, str]]:
    reader = csv.DictReader(stream)
    required = {"url", "label", "tier"}
    if not required.issubset(reader.fieldnames or []):
        raise ValueError("CSV must contain url, label, and tier columns")
    rows: list[tuple[str, str]] = []
    for row_number, row in enumerate(reader, start=2):
        label = (row.get("label") or "").lower()
        tier = (row.get("tier") or "").lower()
        if label not in {"phishing", "benign"} or tier not in {"gold", "silver", "bronze"}:
            raise ValueError(f"invalid label or tier at row {row_number}; URL values are not logged")
        if "split" in row and row["split"] != expected_split:
            raise ValueError(f"row outside {expected_split} split at row {row_number}")
        if tier in {"gold", "silver"}:
            url = (row.get("url") or "").strip().lower()
            url = re.sub(r"^[a-z][a-z0-9+.-]*://", "", url)
            if url.startswith("www."):
                url = url[4:]
            rows.append((label, url))
    return rows


def load_split(path: str) -> tuple[list[Sample], str]:
    name = os.path.basename(path)
    if name not in SPLITS:
        raise ValueError("only the official url_train.csv and url_val.csv inputs are accepted")
    expected_hash, expected_size, split = SPLITS[name]
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
        size = source.tell()
    actual_hash = digest.hexdigest().upper()
    if size != expected_size or actual_hash != expected_hash:
        raise ValueError(f"{name} does not match its pinned official size and SHA-256")
    with open(path, "r", encoding="utf-8-sig", newline="") as source:
        rows = parse_rows(source, split)
    return [Sample(label == "phishing", char_ngrams(url)) for label, url in rows], actual_hash


def char_ngrams(url: str) -> Counter[str]:
    features: Counter[str] = Counter()
    for length in (3, 4, 5):
        for start in range(max(0, len(url) - length + 1)):
            features[url[start : start + length]] += 1
    return features


def fit(samples: list[Sample], alpha: float = 0.1):
    counts = {False: Counter(), True: Counter()}
    totals = {False: 0, True: 0}
    documents = {False: 0, True: 0}
    for sample in samples:
        documents[sample.phishing] += 1
        counts[sample.phishing].update(sample.features)
        totals[sample.phishing] += sum(sample.features.values())
    vocabulary = set(counts[False]) | set(counts[True])
    if not vocabulary or not documents[False] or not documents[True]:
        raise ValueError("train split must contain phishing and benign samples")
    prior = math.log(documents[True] / len(samples)) - math.log(documents[False] / len(samples))
    weights = {}
    for token in vocabulary:
        positive = (counts[True][token] + alpha) / (totals[True] + alpha * len(vocabulary))
        negative = (counts[False][token] + alpha) / (totals[False] + alpha * len(vocabulary))
        weights[token] = math.log(positive) - math.log(negative)
    return prior, weights, len(vocabulary)


def score(sample: Sample, model) -> float:
    prior, weights, _ = model
    return prior + sum(count * weights.get(token, 0.0) for token, count in sample.features.items())


def confusion(samples: list[Sample], scores: list[float], threshold: float, inclusive: bool):
    tp = fp = tn = fn = 0
    for sample, value in zip(samples, scores):
        predicted = value >= threshold if inclusive else value > threshold
        if sample.phishing and predicted:
            tp += 1
        elif sample.phishing:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    return tp, fp, tn, fn


def report(name: str, samples: list[Sample], values: list[float], threshold: float, inclusive: bool):
    tp, fp, tn, fn = confusion(samples, values, threshold, inclusive)
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    print(f"{name}: TP={tp} FP={fp} TN={tn} FN={fn} recall={recall:.6f} FPR={fpr:.6f}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", required=True, help="official checksum-pinned url_train.csv")
    parser.add_argument("--validation", required=True, help="official checksum-pinned url_val.csv")
    args = parser.parse_args()
    train, train_hash = load_split(args.train)
    validation, validation_hash = load_split(args.validation)
    model = fit(train)
    train_scores = [score(sample, model) for sample in train]
    validation_scores = [score(sample, model) for sample in validation]
    negatives = sorted(value for sample, value in zip(train, train_scores) if not sample.phishing)
    threshold = negatives[max(0, math.ceil(0.999 * len(negatives)) - 1)]
    print(f"train_rows={len(train)} validation_rows={len(validation)} char_ngram_vocab={model[2]} alpha=0.1")
    print(f"train_sha256={train_hash} validation_sha256={validation_hash} urls_opened=0 test_split_read=false")
    print(f"threshold_from_train_negative_99.9_percentile={threshold:.6f}; strict_greater_than")
    report("train_threshold_zero", train, train_scores, 0.0, True)
    report("train_threshold_selected", train, train_scores, threshold, False)
    report("validation_threshold_zero", validation, validation_scores, 0.0, True)
    report("validation_threshold_selected", validation, validation_scores, threshold, False)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
