const unavailable = /niedostępny|niedostępna|nie można|nie mogę|nie może|nie mógł|nie mogła|wyłączon(?:y|a|e)|wstrzyman(?:y|a|e)|nie działa|błąd|limit|nie zostało uruchomione|jeszcze nie wykonano/i;

export function getProtectionStatus(status, firstRun, firstAssessment, machineService) {
  if (!status) return { title: 'Ochrona niedostępna', description: 'Silnik nie odpowiada. Nie można potwierdzić działania monitorowania.' };
  if (firstRun && firstAssessment === 'failed')
    return { title: 'Ochrona ograniczona', description: 'Pierwsze sprawdzenie nie powiodło się; stan źródeł monitorowania nie jest potwierdzony.' };
  if (firstRun && firstAssessment !== 'complete')
    return { title: 'Sprawdzanie ochrony', description: 'Sentinel sprawdza dostępne źródła na tym komputerze.' };
  if (status.settings?.paused)
    return { title: 'Ochrona wstrzymana', description: 'Monitorowanie jest wstrzymane. Nie można potwierdzić bieżącej ochrony.' };
  if (machineService !== undefined && machineService?.available !== true)
    return { title: 'Ochrona ograniczona', description: 'Nie mogę potwierdzić działania chronionej usługi systemowej. Monitorowanie w tej sesji może działać, ale nie potwierdzono ochrony w tle.' };

  const monitors = [
    ['Procesy', status.processes, true],
    ['Pobrane pliki', status.downloadedFiles, status.settings?.monitorDownloadedFiles],
    ['Zmiany autostartu', status.persistence, status.settings?.monitorPersistenceChanges],
    ['Połączenia sieciowe', status.tcpConnections, status.settings?.monitorNetworkConnections]
  ];
  if (typeof status.dns === 'string') monitors.push(['Cache DNS', status.dns, true]);
  const problems = monitors.filter(([, value, enabled]) => enabled !== true || typeof value !== 'string' || unavailable.test(value));
  if (problems.length)
    return { title: 'Ochrona ograniczona', description: `Nie działa lub jest wyłączone: ${problems.map(([name]) => name).join(', ')}. Pozostałe źródła mogą nadal działać.` };
  const securityCenter = status.windowsSecurityCenter;
  if (securityCenter) {
    const providers = [['Antywirus', securityCenter.antivirus], ['Zapora', securityCenter.firewall]];
    const attention = providers.filter(([, value]) => typeof value === 'string' && /wymaga uwagi|wstrzymane|nie jest monitorowane/i.test(value));
    if (attention.length)
      return { title: 'Wymagana uwaga', description: `Windows Security Center zgłasza problem: ${attention.map(([name, value]) => `${name} — ${value}`).join('; ')}. Sentinel AI nie zmienia ustawień Windows.` };
    const unknown = providers.filter(([, value]) => typeof value !== 'string' || !/stan dobry/i.test(value));
    if (unknown.length)
      return { title: 'Stan Windows niepotwierdzony', description: `Nie można potwierdzić stanu: ${unknown.map(([name, value]) => `${name} — ${typeof value === 'string' ? value : 'brak danych'}`).join('; ')}. Monitory Sentinel mogą działać, ale ich stan nie potwierdza ochrony antywirusowej Windows.` };
  }
  return { title: 'Monitorowanie działa', description: 'Dostępne źródła działają lokalnie. Sentinel nie blokuje ruchu ani nie zastępuje ochrony antywirusowej Windows.' };
}

