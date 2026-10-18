const status = document.getElementById("status");
const enabled = document.getElementById('enabled');
enabled.addEventListener('change', () => chrome.runtime.sendMessage({ type: 'toggle', enabled: enabled.checked }));
chrome.runtime.sendMessage({ type: "status" }).then((result) => {
  enabled.checked = result?.enabled !== false;
  if (!enabled.checked) {
    status.className = "status unavailable";
    status.textContent = "Integracja jest wyłączona dla tej przeglądarki.";
  } else if (result?.available) {
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
