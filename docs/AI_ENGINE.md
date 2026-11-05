# AI analysis engine

## Scope

The optional local Ollama adapter supports text/knowledge analysis through `AnalysisOrchestrator`. Rule-based URL and reputation checks operate independently of model availability. The adapter has bounded timeouts and local knowledge storage. Remote Enterprise analysis is a separately configured mode with explicit context-sharing consent.

AI does not independently determine the risk level, quarantine a file, stop a process, or block traffic. In `AnalysisOrchestrator`, the model's proposed severity is discarded; the returned severity remains the local deterministic rule result. Model-provided context and category can still help explain a finding, but do not raise its severity. A regression test checks that a model-only Critical proposal remains Informational without rule evidence, while local rule severity is preserved. Current process/file/network collector events do not flow through an autonomous AI incident-analysis pipeline. The AI feature is therefore a supporting text-analysis capability, not an endpoint protection dependency.

Raw file contents are not automatically uploaded for process or Downloads analysis. See [privacy](PRIVACY.md) and [risk scoring](RISK_ENGINE.md).
