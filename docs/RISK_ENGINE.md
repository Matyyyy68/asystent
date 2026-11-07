# Risk scoring

## Current behavior

`RiskEngine` centrally aggregates distinct `ThreatIndicator` evidence returned by manual text/URL analysis. It returns a deterministic score and level: 0–19 Information, 20–39 Low, 40–59 Moderate, 60–79 High, and 80–100 Critical. Indicator weights are bounded to 0–4, duplicate IDs count once, and corroborating indicators are needed to reach the top bands. `ThreatAssessment` includes `RiskScore` beside its level and explanation.

For system-monitor events, `EvaluateEvidenceCodes` scores only an allowlist of evidence identifiers. Unknown identifiers do not increase the score. A matched domain feed is combined with the matching Windows observation. User-imported IP lists have no trusted provenance/signature contract, so an IP match remains visible as context but does not increase numeric risk; independent process-behavior evidence can still score. A downloaded-file hash match from a locally imported list marked as unverified receives no numeric risk score by itself. Process behavior/correlation and writable persistence evidence have separate bounded weights. Events persist both the resulting score and corresponding `RiskLevel` in SQLite v41, Agent→Service forwarding, and JSON/CSV exports.

Reputation from the automatically refreshed CERT Polska domain feed can raise the rule-derived score. A user-imported exact-URL list has no authenticated source or signature, so its match remains visible as context but cannot raise numeric risk by itself; independent rule evidence still determines the score. Enterprise combination merges bounded indicator evidence and recomputes both score and level locally; an unsupported remote `RiskLevel` alone cannot escalate the merged assessment.

Input processing is bounded: at most 1,024 raw evidence items and 256 distinct indicators per evaluation. Excess input is rejected rather than silently truncated or scored from a partial list; tests cover oversized unique and duplicate input. This limits work but is not a CPU or memory service-level objective.

This is a rule-derived severity scale, not a probability or statistical calibration. Band transitions have not been tuned against an independent representative holdout. The score does not independently verify reputation provenance, publisher identity, or source reliability. Individual unknown processes/files are not automatically elevated to malware.

## Guardrails

AI output does not set the score or `RiskLevel`. A recommendation to review an event does not mean a response was executed. A local feed match remains attributable to that feed; an unverified list does not become independent confirmation. The score does not drive automatic responses. Independent calibration data and regression/holdout evaluation remain future work.

See [detection engine](DETECTION_ENGINE.md) and [evaluation report](DETECTION-EVALUATION.md).
