# PhreshPhish URL-only research evaluation

This isolated research tool measures the current Sentinel URL rules on PhreshPhish. It is not a product dependency and is not included in the Windows installer. The dataset is released under CC BY 4.0 for anti-phishing research; cite the [dataset paper](https://arxiv.org/abs/2507.10854) and retain attribution when sharing results.

The extractor pins dataset revision `eca603e0ecd4f698f8d4d226c088659e72681239`, verifies the Parquet manifest, and reads only `sha256`, `url`, and `label` from the test split using HTTP range requests. It refuses full-file responses, limits any one range to 16 MiB, and never requests the HTML column or visits dataset URLs. The first test row was inspected during a one-row API feasibility check, so the extractor skips it. It writes the selected columns to a unique temporary directory, passes them to Sentinel's local URL evaluator, and removes the directory in `finally`.

Run from the repository root:

```powershell
npm ci --prefix scripts/research/phreshphish
pwsh -NoProfile -File scripts/research/phreshphish/evaluate.ps1
```

The report includes the dataset revision, row counts, SHA-256 of extracted record IDs and temporary CSV, range-request count/bytes, confusion matrix, threshold, rule version, and `URLsOpened=0`. The script rejects a changed dataset revision, partial Parquet conversion, changed test file sizes, invalid records, or a server that ignores range requests. The generated CSV is deleted after evaluation.
