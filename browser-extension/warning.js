const token = new URLSearchParams(location.search).get("token");
const signals = document.getElementById("signals");
const version = document.getElementById("rule-version");
chrome.runtime.sendMessage({ type: "details", token }).then((details) => {
  for (const signal of details?.indicators ?? []) {
    const item = document.createElement("li");
    item.textContent = signal.description;
    signals.append(item);
  }
  version.textContent = details?.rulesVersion ? `Poziom: ${details.risk} · reguły ${details.rulesVersion}. Pełny adres nie jest zapisywany w historii.` :
    "Reguły lokalne wykryły sygnał. Pełny adres nie jest zapisywany w historii.";
}).catch(() => {
  version.textContent = "Nie można pobrać szczegółów analizy. Pełny adres nie jest zapisywany w historii.";
});
document.getElementById("close").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "close-warning", token });
});
document.getElementById("continue").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "continue", token });
});
