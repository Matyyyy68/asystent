const assert = require('node:assert/strict');
const test = require('node:test');

async function getStatus(...args) {
  const { getProtectionStatus } = await import('../src/protection-status.js');
  return getProtectionStatus(...args);
}

test('shows unavailable and first-run states before claiming monitoring is active', async () => {
  assert.equal((await getStatus(null, false, 'complete')).title, 'Ochrona niedostępna');
  assert.equal((await getStatus({ settings: { paused: false } }, true, 'running')).title, 'Sprawdzanie ochrony');
  assert.equal((await getStatus({ settings: { paused: false } }, true, 'failed')).title, 'Ochrona ograniczona');
  assert.equal((await getStatus({ settings: { paused: true } }, false, 'complete')).title, 'Ochrona wstrzymana');
});

test('reports limited protection when a required local monitor is disabled or unavailable', async () => {
  const status = {
    settings: { paused: false, monitorDownloadedFiles: true, monitorPersistenceChanges: true, monitorNetworkConnections: true },
    processes: 'Snapshot procesów działa; 80 PID',
    downloadedFiles: 'Monitoring pobranych plików niedostępny: katalog Downloads nie istnieje.',
    persistence: 'Monitor zmian autostartu działa; ustawiono baseline.',
    tcpConnections: 'Ciągła migawka TCP/UDP działa; 4 połączenia.'
  };
  assert.equal((await getStatus(status, false, 'complete')).title, 'Ochrona ograniczona');
  status.downloadedFiles = 'Monitoring Downloads działa; zaimportuj lokalną listę hashy, aby sprawdzać pliki.';
  status.settings.monitorNetworkConnections = false;
  assert.match((await getStatus(status, false, 'complete')).description, /Połączenia sieciowe/);
  status.settings.monitorNetworkConnections = true;
  status.tcpConnections = 'Ciągła obserwacja TCP/UDP jest wyłączona.';
  assert.match((await getStatus(status, false, 'complete')).description, /Połączenia sieciowe/);
});

test('claims background monitoring only when all required sources report healthy', async () => {
  const status = {
    settings: { paused: false, monitorDownloadedFiles: true, monitorPersistenceChanges: true, monitorNetworkConnections: true },
    processes: 'Snapshot procesów działa; 80 PID',
    downloadedFiles: 'Monitoring Downloads działa; brak lokalnej listy hashy.',
    persistence: 'Monitor zmian autostartu działa; baseline ustawiony.',
    tcpConnections: 'Ciągła migawka TCP/UDP działa; 4 połączenia.'
  };
  assert.equal((await getStatus(status, false, 'complete')).title, 'Monitorowanie działa');
});

test('reports DNS cache failures and uncollected DNS state as limited protection', async () => {
  const status = {
    settings: { paused: false, monitorDownloadedFiles: true, monitorPersistenceChanges: true, monitorNetworkConnections: true },
    processes: 'Snapshot procesów działa; 80 PID',
    downloadedFiles: 'Monitoring Downloads działa; brak lokalnej listy hashy.',
    persistence: 'Monitor zmian autostartu działa; baseline ustawiony.',
    tcpConnections: 'Ciągła migawka TCP/UDP działa; 4 połączenia.',
    dns: 'Odczyt cache DNS niedostępny: IOException',
    dnsOperational: 'Kanał DNS Operational jest wyłączony; nie zmieniono konfiguracji systemu'
  };
  const failed = await getStatus(status, false, 'complete');
  assert.equal(failed.title, 'Ochrona ograniczona');
  assert.match(failed.description, /Cache DNS/);

  status.dns = 'Jeszcze nie wykonano odczytu cache DNS';
  assert.match((await getStatus(status, false, 'complete')).description, /Cache DNS/);
  status.dns = 'Odczyt cache DNS działa; bez DoH, pełnych URL i PID';
  assert.equal((await getStatus(status, false, 'complete')).title, 'Monitorowanie działa');
});

test('reflects Windows Security Center attention and unknown health in the main status', async () => {
  const status = {
    settings: { paused: false, monitorDownloadedFiles: true, monitorPersistenceChanges: true, monitorNetworkConnections: true },
    processes: 'Snapshot procesów działa; 80 PID',
    downloadedFiles: 'Monitoring Downloads działa; brak lokalnej listy hashy.',
    persistence: 'Monitor zmian autostartu działa; baseline ustawiony.',
    tcpConnections: 'Ciągła migawka TCP/UDP działa; 4 połączenia.',
    windowsSecurityCenter: {
      antivirus: 'stan dobry według Windows Security Center',
      firewall: 'wymaga uwagi według Windows Security Center'
    }
  };
  assert.equal((await getStatus(status, false, 'complete')).title, 'Wymagana uwaga');
  status.windowsSecurityCenter.firewall = 'nieznany stan Windows Security Center';
  assert.equal((await getStatus(status, false, 'complete')).title, 'Stan Windows niepotwierdzony');
  status.windowsSecurityCenter.firewall = 'stan dobry według Windows Security Center';
  assert.equal((await getStatus(status, false, 'complete')).title, 'Monitorowanie działa');
});
