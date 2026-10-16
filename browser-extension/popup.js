const status = document.getElementById("status");
chrome.runtime.sendMessage({ type: "status" }).then((result) => {
  if (result?.available) {
    status.className = "status active";
    status.textContent = `Silnik lokalny działa · reguły ${result.rulesVersion}`;
  } else {
    status.className = "status unavailable";
    status.textContent = "Silnik niedostępny. Zwykłe przeglądanie nie jest wstrzymywane.";
  }
}).catch(() => {
  status.className = "status unavailable";
  status.textContent = "Nie można połączyć z Sentinel AI.";
});
