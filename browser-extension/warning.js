const token = new URLSearchParams(location.search).get("token");
const signals = document.getElementById("signals");
const version = document.getElementById("rule-version");
const title = document.getElementById("warning-title");
const description = document.getElementById("warning-description");
const footnote = document.getElementById("warning-footnote");
const continueButton = document.getElementById("continue");
const stopDownloadButton = document.getElementById('stop-download');
const downloadActionStatus = document.getElementById('download-action-status');
chrome.runtime.sendMessage({ type: "details", token }).then((details) => {
  if (details?.kind === 'download') {
    title.textContent = 'Podejrzane źródło pobierania';
    description.textContent = 'Pobieranie mogło już się rozpocząć. Nie otwieraj pliku. Sprawdź go lokalnym skanem Sentinel lub usuń; możesz też zatrzymać pobieranie w przeglądarce.';
    footnote.textContent = 'Rozszerzenie sprawdza adres źródła, nie zawartość pobranego pliku.';
    continueButton.hidden = true;
    stopDownloadButton.hidden = !details.canStopDownload;
    document.getElementById('close').textContent = 'Zamknij ostrzeżenie';
  }
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
stopDownloadButton.addEventListener('click', async () => {
  stopDownloadButton.disabled = true;
  downloadActionStatus.hidden = false;
  downloadActionStatus.textContent = 'Zatrzymuję pobieranie…';
  try {
    const result = await chrome.runtime.sendMessage({ type: 'stop-download', token });
    downloadActionStatus.textContent = result?.ok
      ? 'Przeglądarka przyjęła polecenie zatrzymania. Jeśli pobieranie zdążyło się zakończyć, plik trzeba usunąć ręcznie.'
      : 'Nie udało się zatrzymać transferu. Sprawdź stan pobierania w przeglądarce.';
  } catch {
    downloadActionStatus.textContent = 'Nie udało się zatrzymać transferu. Sprawdź stan pobierania w przeglądarce.';
  }
});
