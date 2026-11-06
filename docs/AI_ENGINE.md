# AI analysis engine

## Scope

The optional local Ollama adapter supports text/knowledge analysis through `AnalysisOrchestrator`. Rule-based URL, process, file, and network checks operate independently of model availability. The adapter has bounded timeouts and local knowledge storage. Remote Enterprise analysis is a separately configured mode with explicit context-sharing consent.

The event-history UI offers an explicit local analysis action for correlated process/domain groups. It passes only normalized evidence codes, rule risk/score, and a coarse source family; it omits application names, paths, hashes, URLs, explanations, recommendations, command lines, and file contents. The action does not set the Enterprise sharing flag. It runs only after a user click, and unavailable AI falls back to the existing rule-only analysis path.

AI does not independently determine the risk level, quarantine a file, stop a process, or block traffic. In `AnalysisOrchestrator`, the model's proposed severity is discarded; the returned severity remains the local deterministic rule result. Model-provided context and category can still help explain a finding, but do not raise its severity. A regression test checks that a model-only Critical proposal remains Informational without rule evidence, while local rule severity is preserved.

Raw file contents are not automatically uploaded for process or Downloads analysis. Local event context is bounded and redacted before it is passed to the analyzer. See [privacy](PRIVACY.md) and [risk scoring](RISK_ENGINE.md).

## Remaining limitations

- Event analysis is user initiated, not an autonomous background AI pipeline.
- Explanation quality depends on the locally configured model; no independent accuracy benchmark is claimed.
- If the model is unavailable, rule-based monitoring and scoring continue.
