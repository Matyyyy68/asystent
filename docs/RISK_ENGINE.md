# Risk scoring

## Current behavior

The persisted event model uses the ordinal `RiskLevel` values `Information`, `Low`, `Moderate`, `High`, and `Critical`. Rule-specific code creates those levels with evidence codes and a written explanation. Examples include selected Office → script-host parent relationships (moderate heuristic) and a match against an imported local reputation list (source trust is disclosed). Confidence is separate metadata and is not an independent calibrated probability.

There is **no central calibrated 0–100 score engine** implementing the example thresholds from the product brief. No claim is made that local rules have measured precision/recall across an independent production holdout. Individual unknown processes/files are not automatically elevated to malware.

## Guardrails

AI output does not set `RiskLevel`. A recommendation to review an event does not mean a response was executed. A local feed match remains attributable to that feed; an unverified list does not become independent confirmation. Future numerical scoring needs evidence weights, duplicate-signal handling, calibration data, explanation output, and regression/holdout evaluation before it can drive responses.

See [detection engine](DETECTION_ENGINE.md) and [evaluation report](DETECTION-EVALUATION.md).
