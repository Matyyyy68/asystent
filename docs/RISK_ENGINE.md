# Risk scoring

## Current behavior

`RiskEngine` centrally aggregates distinct `ThreatIndicator` evidence returned by manual text/URL analysis. It returns a deterministic score and level: 0–19 Information, 20–39 Low, 40–59 Moderate, 60–79 High, and 80–100 Critical. Indicator weights are bounded to 0–4, duplicate IDs count once, and corroborating indicators are needed to reach the top bands. `ThreatAssessment` includes `RiskScore` beside its level and explanation.

This is a rule-derived severity scale, not a probability or statistical calibration. Its band transitions preserve prior alert behavior; they have not been tuned against an independent representative holdout. The persisted system-event `SecurityEvent` schema, process/file/network monitors, and history still use `RiskLevel`; they do not yet receive or retain this numeric score. The score also does not independently verify reputation provenance, publisher identity, or source reliability. Individual unknown processes/files are not automatically elevated to malware.

## Guardrails

AI output does not set the score or `RiskLevel`. A recommendation to review an event does not mean a response was executed. A local feed match remains attributable to that feed; an unverified list does not become independent confirmation. Extending the score to system events or allowing it to drive responses requires provenance-aware evidence, persisted rationale, independent calibration data, and regression/holdout evaluation.

See [detection engine](DETECTION_ENGINE.md) and [evaluation report](DETECTION-EVALUATION.md).
