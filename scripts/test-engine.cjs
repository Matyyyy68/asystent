const { spawn, execFileSync } = require('node:child_process');
const { createInterface } = require('node:readline');
const { createServer } = require('node:http');
const net = require('node:net');
const os = require('node:os');
const { createSocket } = require('node:dgram');
const { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, truncateSync, copyFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const root = mkdtempSync(path.join(tmpdir(), 'sentinel-engine-test-'));
const downloadsDirectory = path.join(root, 'Downloads'); mkdirSync(downloadsDirectory);
const child = spawn(path.resolve('artifacts/engine/Sentinel.Engine.exe'), [], { windowsHide: true,
  env: { ...process.env, SENTINEL_DATA_ROOT: root, SENTINEL_DOWNLOADS_PATH: downloadsDirectory }, stdio: ['pipe','pipe','inherit'] });
const lines = createInterface({ input: child.stdout });
const pending = new Map(); let id = 0;
let ollamaServer, ollamaPayload, udpSocket, tcpMonitorServer, tcpMonitorClient;
lines.on('line', line => { const response = JSON.parse(line); pending.get(response.id)?.(response); pending.delete(response.id); });
function call(method, data = {}) { return new Promise(resolve => { const key = String(++id); pending.set(key, resolve); child.stdin.write(JSON.stringify({ ...data, id: key, version: 1, method }) + '\n'); }); }
const timeout = setTimeout(() => { child.kill(); process.exitCode = 1; console.error('Engine timeout'); }, 90000);
(async () => {
 try {
  const initialStatus = await call('status'); assert.equal(initialStatus.result.engine, 'ready');
  assert.equal(initialStatus.result.lastDnsReadUtc, null);
  assert.equal(initialStatus.result.lastDnsErrorUtc, null);
  assert.ok(initialStatus.result.storage.history.totalBytes > 0, 'status must include history database size');
  assert.ok(initialStatus.result.storage.knowledge.totalBytes > 0, 'status must include knowledge database size');
  assert.equal(initialStatus.result.storage.history.recordCount, 0);
  assert.equal(initialStatus.result.storage.knowledge.recordCount, 0);
  assert.equal(initialStatus.result.enterprise.variant, 'User');
  assert.equal(initialStatus.result.enterprise.paired, false);
  assert.equal(initialStatus.result.settings.monitorNetworkConnections, false, 'continuous TCP monitoring must default to off');
  assert.deepEqual(initialStatus.result.ipReputation, { networkCount: 0, importedAt: null }, 'IP reputation must start empty and local');
  assert.equal(initialStatus.result.settings.monitorDownloadedFiles, false, 'Downloads monitoring must default to off');
  assert.equal(initialStatus.result.settings.monitorPersistenceChanges, false, 'Windows persistence monitoring must default to off');
  assert.equal(initialStatus.result.persistence, 'Monitor zmian autostartu jest wyłączony.');
  assert.equal((await call('malwareBazaarLookup', { sha256: 'a'.repeat(64), consent: false })).ok, false,
    'MalwareBazaar hash lookup must require explicit consent');
  assert.equal((await call('malwareBazaarConfigure', { apiKey: 'synthetic-test-key', consent: false })).ok, false,
    'MalwareBazaar key configuration must require explicit consent');
  assert.equal((await call('status')).result.malwareBazaar.configured, false,
    'a rejected key configuration must not persist the API key');
  assert.equal((await call('enterprisePair', { server: 'https://sentinel.example', invitationCode: 'test-code', shareSecurityMetadata: false })).ok, false,
    'Enterprise pairing must require explicit metadata consent');
  assert.equal((await call('enterpriseConsent', { enabled: true })).ok, false,
    'Enterprise metadata consent must require a paired Enterprise profile');
  assert.equal((await call('status')).result.enterprise.variant, 'User', 'declined consent must not change the installed profile');
  assert.ok(initialStatus.result.runtime.workingSetBytes > 0);
  assert.ok(initialStatus.result.runtime.privateMemoryBytes > 0);
  assert.ok(initialStatus.result.runtime.cpuTimeMilliseconds >= 0);
  assert.ok(initialStatus.result.runtime.processorCount > 0);
  const unsignedFixture = path.join(root, 'synthetic-unsigned.ps1'); writeFileSync(unsignedFixture, 'Write-Output synthetic');
  const fileCheck = await call('file', { path: unsignedFixture });
  assert.equal(fileCheck.ok, true, fileCheck.error); assert.equal(fileCheck.result.signature.status, 'NotSigned', JSON.stringify(fileCheck.result.signature));
  assert.equal(fileCheck.result.sha256.length, 64); assert.match(fileCheck.result.verdict, /Brak lokalnej listy hashy/);
  const windowsPowerShell = path.join(process.env.SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const trustedSignature = await call('file', { path: windowsPowerShell });
  assert.equal(trustedSignature.ok, true, trustedSignature.error);
  assert.equal(trustedSignature.result.signature.status, 'Valid', 'Windows PowerShell must provide a trusted Authenticode fixture');
  const tamperedFixture = path.join(root, 'synthetic-tampered-powershell.exe'); copyFileSync(windowsPowerShell, tamperedFixture);
  writeFileSync(tamperedFixture, Buffer.from('XX'), { flag: 'r+' });
  const tamperedSignature = await call('file', { path: tamperedFixture });
  assert.equal(tamperedSignature.ok, true, tamperedSignature.error);
  assert.notEqual(tamperedSignature.result.signature.status, 'Valid', 'tampered Authenticode files must not be reported as valid');
  const oversizedFixture = path.join(root, 'synthetic-oversized.bin'); writeFileSync(oversizedFixture, 'x');
  truncateSync(oversizedFixture, 256 * 1024 * 1024 + 1);
  const oversizedCheck = await call('file', { path: oversizedFixture });
  assert.equal(oversizedCheck.ok, false, 'files larger than 256 MiB must be rejected before hashing');
  assert.match(oversizedCheck.error, /256 MiB/);
  const fileHashFeed = path.join(root, 'file-hashes.txt'); writeFileSync(fileHashFeed, `${fileCheck.result.sha256}\n`);
  const importedFileFeed = await call('fileHashFeedImport', { path: fileHashFeed });
  assert.equal(importedFileFeed.ok, true, importedFileFeed.error); assert.equal(importedFileFeed.result.hashCount, 1);
  const matchedFile = await call('file', { path: unsignedFixture });
  assert.equal(matchedFile.ok, true, matchedFile.error); assert.equal(matchedFile.result.reputation.feedImported, true);
  assert.equal(matchedFile.result.reputation.match, true);
  assert.match(matchedFile.result.reputation.explanation, /nie zostało niezależnie zweryfikowane/);
  const repeatedMatchedFile = await call('file', { path: unsignedFixture });
  assert.equal(repeatedMatchedFile.ok, true, repeatedMatchedFile.error);
  assert.equal((await call('history')).result.filter(event => event.source === 'manual-file-analysis').length, 1,
    'repeated manual scans of the same locally listed file must not create duplicate alerts within the deduplication window');
  const ipFeedPath = path.join(root, 'ip-addresses.txt');
  writeFileSync(ipFeedPath, '192.0.2.17\n198.51.100.0/24 # TEST-NET fixture\n2001:db8::/32\n');
  const importedIpFeed = await call('ipReputationImport', { path: ipFeedPath });
  assert.equal(importedIpFeed.ok, true, importedIpFeed.error);
  assert.equal(importedIpFeed.result.networkCount, 3);
  assert.ok(Number.isFinite(Date.parse(importedIpFeed.result.importedAt)));
  const invalidIpFeedPath = path.join(root, 'invalid-ip-addresses.txt'); writeFileSync(invalidIpFeedPath, '198.51.100.0/129\n');
  assert.equal((await call('ipReputationImport', { path: invalidIpFeedPath })).ok, false,
    'invalid IP/CIDR import must be rejected through Engine IPC');
  assert.equal((await call('status')).result.ipReputation.networkCount, 3,
    'rejected IP/CIDR import must preserve the last accepted feed');
  const clearedIpFeed = await call('ipReputationClear');
  assert.equal(clearedIpFeed.ok, true, clearedIpFeed.error);
  assert.deepEqual(clearedIpFeed.result, { networkCount: 0, importedAt: null });
  assert.deepEqual((await call('status')).result.ipReputation, { networkCount: 0, importedAt: null },
    'clearing IP/CIDR reputation must remove the persisted feed and import metadata');
  const exactFeedUrl = 'https://example.test/checkout/continue?case=synthetic#ignored-fragment';
  await call('clearHistory');
  const urlFeedPath = path.join(root, 'local-url-feed.csv');
  writeFileSync(urlFeedPath, `phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n1,${exactFeedUrl},https://phishtank.example/detail/1,2026-10-23T09:00:00Z,yes,2026-10-23T09:10:00Z,yes,Fixture\n2,https://inactive.example.test/,https://phishtank.example/detail/2,2026-10-23T09:00:00Z,yes,2026-10-23T09:10:00Z,no,Fixture\n`);
  const importedUrlFeed = await call('urlReputationImport', { path: urlFeedPath });
  assert.equal(importedUrlFeed.ok, true, importedUrlFeed.error); assert.equal(importedUrlFeed.result.urlCount, 1);
  const exactUrlAnalysis = await call('analyze', { text: '', url: exactFeedUrl });
  assert.equal(exactUrlAnalysis.ok, true, exactUrlAnalysis.error);
  assert.equal(exactUrlAnalysis.result.risk, 'High');
  assert.ok(exactUrlAnalysis.result.indicators.some(indicator => indicator.id === 'reputation.url-feed'));
  const exactUrlHistory = (await call('history')).result;
  assert.equal(exactUrlHistory.length, 1);
  assert.ok(!JSON.stringify(exactUrlHistory).includes('example.test'));
  assert.ok(!JSON.stringify(exactUrlHistory).includes('checkout/continue'));
  assert.ok(!JSON.stringify(exactUrlHistory).includes('case=synthetic'));
  const normalizedFeedUrl = new URL(exactFeedUrl); normalizedFeedUrl.hash = '';
  const exactUrlSignalHash = createHash('sha256').update(normalizedFeedUrl.href, 'utf8').digest('hex').toUpperCase();
  assert.ok(!JSON.stringify(exactUrlHistory).includes(exactUrlSignalHash));
  assert.equal((await call('urlReputationClear')).ok, true);
  await call('clearHistory');
  assert.equal((await call('aiSettings', { useLocalAI: true, endpoint: 'http://example.com:11434', model: 'remote' })).ok, false);
  assert.equal((await call('status')).result.settings.useLocalAI, false);
  ollamaServer = createServer((request, response) => {
    if (request.url === '/api/tags') { response.writeHead(200, { 'content-type': 'application/json' }); response.end('{"models":[{"name":"sentinel-test:latest","size":1024,"details":{"family":"test"}}]}'); return; }
    if (request.url === '/api/chat') {
      let body = ''; request.on('data', chunk => body += chunk); request.on('end', () => {
        ollamaPayload = JSON.parse(body); response.writeHead(200, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ message: { content: JSON.stringify({ category: 'CredentialPhishing', risk: 'High', indicators: ['Mock model sygnał'], uncertainties: ['Mock model nie weryfikuje nadawcy'], recommendations: ['Sprawdź innym kanałem'], explanation: 'Mock model wykrył sygnał testowy.' }) } }));
      }); return;
    }
    response.writeHead(404); response.end();
  });
  await new Promise(resolve => ollamaServer.listen(0, '127.0.0.1', resolve));
  const ollamaEndpoint = `http://127.0.0.1:${ollamaServer.address().port}`;
  udpSocket = createSocket('udp4'); await new Promise(resolve => udpSocket.bind(0, '127.0.0.1', resolve));
  await call('pause', { paused: false });
  const warmup = await call('collect'); assert.equal(warmup.ok, true, warmup.error);
  await call('settings', { retentionDays: 30, notifications: true, monitorDownloadedFiles: true });
  const downloadedFixture = path.join(downloadsDirectory, 'synthetic-download.ps1');
  writeFileSync(downloadedFixture, 'Write-Output synthetic');
  await new Promise(resolve => setTimeout(resolve, 1000));
  const downloadSample = await call('collect'); assert.equal(downloadSample.ok, true, downloadSample.error);
  let downloadedHistory = (await call('history')).result;
  assert.ok(downloadedHistory.some(event => event.observations?.some(observation => observation.source === 'downloads-local-hash') &&
      !JSON.stringify(event).includes('synthetic-download.ps1')),
    'opt-in Downloads monitor must merge matching local file signals without storing the filename or sending data to a service');
  const oversizedDownload = path.join(downloadsDirectory, 'synthetic-oversized-download.bin'); writeFileSync(oversizedDownload, 'x');
  truncateSync(oversizedDownload, 256 * 1024 * 1024 + 1);
  mkdirSync(path.join(downloadsDirectory, 'nested'));
  writeFileSync(path.join(downloadsDirectory, 'nested', 'synthetic-nested.ps1'), 'Write-Output synthetic');
  await new Promise(resolve => setTimeout(resolve, 900)); await call('collect');
  downloadedHistory = (await call('history')).result;
  assert.equal(downloadedHistory.filter(event => event.source === 'downloads-local-hash').length, 2,
    'Downloads monitor must skip oversized files and include a matching file in a subdirectory');
  await call('pause', { paused: true });
  writeFileSync(path.join(downloadsDirectory, 'synthetic-paused.ps1'), 'Write-Output synthetic');
  await new Promise(resolve => setTimeout(resolve, 900)); await call('collect');
  downloadedHistory = (await call('history')).result;
  assert.equal(downloadedHistory.filter(event => event.source === 'downloads-local-hash').length, 2,
    'paused monitoring must not inspect or record downloaded files');
  await call('pause', { paused: false });
  await call('settings', { retentionDays: 30, notifications: true, monitorDownloadedFiles: false });
  writeFileSync(path.join(downloadsDirectory, 'synthetic-disabled.ps1'), 'Write-Output synthetic');
  await call('collect'); await new Promise(resolve => setTimeout(resolve, 900)); await call('collect');
  downloadedHistory = (await call('history')).result;
  assert.equal(downloadedHistory.filter(event => event.source === 'downloads-local-hash').length, 2,
    'disabled Downloads monitoring must stop processing new files');
  const clearedHashFeed = await call('fileHashFeedClear');
  assert.equal(clearedHashFeed.ok, true, clearedHashFeed.error);
  assert.deepEqual(clearedHashFeed.result, { hashCount: 0, importedAt: null });
  const fileAfterHashFeedClear = await call('file', { path: unsignedFixture });
  assert.equal(fileAfterHashFeedClear.ok, true, fileAfterHashFeedClear.error);
  assert.deepEqual(fileAfterHashFeedClear.result.reputation, { feedImported: false, match: false, explanation: 'Brak lokalnej listy hashy.' });
  await call('settings', { retentionDays: 30, notifications: true, monitorPersistenceChanges: true });
  const persistenceBaseline = await call('collect'); assert.equal(persistenceBaseline.ok, true, persistenceBaseline.error);
  assert.match(persistenceBaseline.result.persistence, /ustawiono baseline/,
    'opt-in Windows persistence monitor must take a silent per-user baseline');
  assert.equal((await call('history')).result.filter(event => event.source === 'windows-persistence-snapshot').length, 0,
    'taking a persistence baseline must not create events for existing entries');
  await call('pause', { paused: true });
  const persistencePaused = await call('collect'); assert.equal(persistencePaused.ok, true, persistencePaused.error);
  assert.match(persistencePaused.result.persistence, /wstrzymany/,
    'global pause must stop per-user persistence monitoring');
  await call('pause', { paused: false });
  await call('settings', { retentionDays: 30, notifications: true, monitorPersistenceChanges: false });
  const persistenceDisabled = await call('collect'); assert.equal(persistenceDisabled.ok, true, persistenceDisabled.error);
  assert.match(persistenceDisabled.result.persistence, /wyłączony/,
    'disabling Windows persistence monitoring must clear its baseline');
  const snapshotStarted = performance.now();
  const connectionSnapshot = await call('connections'); assert.equal(connectionSnapshot.ok, true, connectionSnapshot.error);
  assert.ok(performance.now() - snapshotStarted < 5000, 'IP Helper connection snapshot exceeded 5 seconds');
  assert.ok(connectionSnapshot.result.some(c => c.protocol === 'TCP' && c.localPort === ollamaServer.address().port && c.processId === process.pid), 'IP Helper TCP table must attribute the controlled loopback listener to this test process');
  assert.ok(connectionSnapshot.result.some(c => c.protocol === 'UDP' && c.localPort === udpSocket.address().port && c.processId === process.pid), 'IP Helper UDP table must attribute the controlled endpoint to this test process');
  const monitoredProcess = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 30000)'], { windowsHide: true, stdio: 'ignore' });
  await new Promise((resolve, reject) => { monitoredProcess.once('spawn', resolve); monitoredProcess.once('error', reject); });
  const sampleStarted = performance.now(); const startSample = await call('collect');
  const sampleDurationMs = performance.now() - sampleStarted;
  assert.equal(startSample.ok, true, startSample.error); assert.ok(sampleDurationMs < 5000, `sample exceeded 5s: ${sampleDurationMs.toFixed(1)}ms`);
  let processHistory = (await call('history')).result;
  assert.ok(processHistory.some(e => e.processId === monitoredProcess.pid && e.source === 'process-snapshot' && e.category === 'Proces zaobserwowany'), 'new process must be recorded with PID');
  const processExited = new Promise(resolve => monitoredProcess.once('exit', resolve)); monitoredProcess.kill(); await processExited;
  await call('collect'); processHistory = (await call('history')).result;
  assert.ok(processHistory.some(e => e.processId === monitoredProcess.pid && e.category === 'Proces zniknął z migawki'), 'process disappearance must be recorded');
  const enabledSettings = await call('settings', { retentionDays: 30, notifications: true, dnsPollIntervalSeconds: 15, monitorNetworkConnections: true });
  assert.equal(enabledSettings.ok, true, enabledSettings.error);
  const tcpBaseline = await call('collect'); assert.equal(tcpBaseline.ok, true, tcpBaseline.error);
  assert.match(tcpBaseline.result.tcpConnections, /baza początkowa|działa/);
  assert.equal((await call('status')).result.settings.monitorNetworkConnections, true);
  if (process.argv.includes('--tcp-live')) {
    const address = Object.values(os.networkInterfaces()).flat().find(item => item.family === 'IPv4' && !item.internal && !item.address.startsWith('169.254.'))?.address;
    assert.ok(address, 'a non-loopback IPv4 interface is required for the controlled TCP monitor test');
    const liveIpFeedPath = path.join(root, 'live-ip-address.txt'); writeFileSync(liveIpFeedPath, `${address}/32\n`);
    const liveIpFeed = await call('ipReputationImport', { path: liveIpFeedPath });
    assert.equal(liveIpFeed.ok, true, liveIpFeed.error);
    tcpMonitorServer = net.createServer(socket => socket.on('data', () => {}));
    await new Promise((resolve, reject) => { tcpMonitorServer.once('error', reject); tcpMonitorServer.listen(0, address, resolve); });
    tcpMonitorClient = net.createConnection({ host: address, port: tcpMonitorServer.address().port });
    await new Promise((resolve, reject) => { tcpMonitorClient.once('connect', resolve); tcpMonitorClient.once('error', reject); });
    await new Promise(resolve => setTimeout(resolve, 10_500));
    const tcpDelta = await call('collect'); assert.equal(tcpDelta.ok, true, tcpDelta.error);
    const tcpHistory = (await call('history')).result;
    const matchedTcpEvent = tcpHistory.find(event => event.source === 'tcp-connection-snapshot' && event.explanation.includes(address));
    assert.ok(matchedTcpEvent,
      'enabled monitor must persist the controlled non-loopback TCP connection with its remote IP');
    assert.equal(matchedTcpEvent.risk, 'High', 'new TCP connection matching the imported feed must raise a local high-risk alert');
    assert.ok(matchedTcpEvent.evidenceCodes.includes('reputation.ip-feed.match'));
    tcpMonitorClient.end(); await new Promise(resolve => tcpMonitorServer.close(resolve)); tcpMonitorClient = null; tcpMonitorServer = null;
    console.log('PASS: opt-in TCP monitor matched the controlled non-loopback connection against the imported local IP feed');
  }
  await call('pause', { paused: true });
  const tcpPaused = await call('collect'); assert.equal(tcpPaused.ok, true, tcpPaused.error);
  assert.match(tcpPaused.result.tcpConnections, /wstrzymana/);
  const disabledSettings = await call('settings', { retentionDays: 30, notifications: true, dnsPollIntervalSeconds: 15, monitorNetworkConnections: false });
  assert.equal(disabledSettings.ok, true, disabledSettings.error);
  assert.equal((await call('status')).result.settings.monitorNetworkConnections, false);
  console.log(`PASS: process snapshot and child lifecycle; sample IPC+DB=${sampleDurationMs.toFixed(1)}ms`);
  await call('clearHistory'); await call('pause', { paused: true });
  if (process.argv.includes('--windows-live') || process.argv.includes('--dns-live')) {
    if (process.argv.includes('--windows-live')) {
      const feed = await call('updateFeed'); assert.equal(feed.ok, true); assert.ok(feed.result.count > 100);
      console.log('PASS: CERT feed import; domain count=' + feed.result.count);
    }
    await call('pause', {paused:false}); await new Promise(resolve => setTimeout(resolve, 15_100));
    const dns = await call('collect'); assert.equal(dns.ok,true);
    assert.ok(dns.result.dns.startsWith('Odczyt cache DNS działa'), dns.result.dns);
    assert.match(dns.result.dnsOperational, /Kanał DNS Operational|Dziennik DNS Operational/, 'collect must expose DNS event channel status');
    const dnsStatus = (await call('status')).result;
    assert.match(dnsStatus.dnsOperational, /Kanał DNS Operational|Dziennik DNS Operational/, 'DNS event channel status must be visible');
    const channelConfiguration = execFileSync(path.join(process.env.SystemRoot, 'System32', 'wevtutil.exe'),
      ['gl', 'Microsoft-Windows-DNS-Client/Operational', '/f:xml'], { encoding: 'utf8' });
    if (/enabled="false"/i.test(channelConfiguration))
      assert.match(dnsStatus.dnsOperational, /wyłączony/i, 'disabled system channel must use a visible read-only fallback');
    assert.ok(Number.isFinite(Date.parse(dnsStatus.lastDnsReadUtc)), 'successful DNS cache read must expose its UTC timestamp');
    assert.equal(dnsStatus.lastDnsErrorUtc, null, 'successful first DNS cache read must not report an error');
    const snapshot = await call('connections'); assert.equal(snapshot.ok, true, snapshot.error);
    assert.ok(Array.isArray(snapshot.result));
    assert.ok(snapshot.result.some(c => c.protocol === 'TCP' && c.localPort === ollamaServer.address().port && c.processId === process.pid), 'loopback TCP listener must be attributed to this test process');
    assert.ok(snapshot.result.some(c => c.protocol === 'UDP' && c.localPort === udpSocket.address().port && c.processId === process.pid), 'loopback UDP endpoint must be attributed to this test process');
    await call('pause', {paused:true}); console.log('PASS: Windows DNS cache; TCP/UDP loopback snapshots attributed to process PID');
    await call('clearHistory');
  }
  assert.equal((await call('history')).result.length, 0);
  const embeddedPhishingUrl = 'https://paypal.com.evil.test/login';
  const embeddedAnalysis = await call('analyze', { text: `Pilnie zaloguj się i podaj hasło: ${embeddedPhishingUrl}`, url: 'https://example.com' });
  assert.equal(embeddedAnalysis.ok, true); assert.ok(['High','Critical'].includes(embeddedAnalysis.result.risk));
  assert.ok(embeddedAnalysis.result.indicators.some(indicator => indicator.id === 'url.brand'), 'embedded suspicious URL must contribute rule evidence');
  assert.ok(embeddedAnalysis.result.uncertainties.some(item => item.includes('faktyczny cel kliknięcia nie został potwierdzony')));
  const explicitSameHost = await call('analyze', { text: 'Oddzielna kontrola hosta', url: embeddedPhishingUrl });
  assert.equal(explicitSameHost.ok, true, explicitSameHost.error);
  const correlatedHistory = (await call('history')).result;
  assert.equal(correlatedHistory.length, 2);
  assert.equal(new Set(correlatedHistory.map(event => event.correlationId)).size, 1,
    'an embedded suspicious URL must correlate with a later explicit analysis of that same host, not an unrelated typed URL: ' +
      JSON.stringify(correlatedHistory.map(({ correlationId, evidenceCodes, risk }) => ({ correlationId, evidenceCodes, risk }))));
  assert.ok(!JSON.stringify(correlatedHistory).includes('paypal.com.evil.test'));
  const repeatedSameSignal = await call('analyze', { text: 'Oddzielna kontrola hosta', url: embeddedPhishingUrl });
  assert.equal(repeatedSameSignal.ok, true, repeatedSameSignal.error);
  const repeatedSameRisk = await call('analyze', { text: 'Oddzielna kontrola hosta', url: embeddedPhishingUrl });
  assert.equal(repeatedSameRisk.ok, true, repeatedSameRisk.error);
  assert.equal((await call('history')).result.length, 2,
    'repeating an identical manual URL signal from the same source within ten minutes must not add another history event');
  await call('clearHistory');
  const result = await call('analyze', { text: `Pilnie zaloguj się i podaj hasło: ${embeddedPhishingUrl}`, url: 'https://example.com' });
  assert.equal(result.ok, true); assert.ok(['High','Critical'].includes(result.result.risk));
  const history = (await call('history')).result; assert.equal(history.length, 1);
  assert.ok(!JSON.stringify(history).includes(embeddedPhishingUrl));
  assert.equal(history[0].schemaVersion, 1); assert.equal(history[0].source, 'manual-analysis');
  assert.ok(history[0].correlationId, 'manual URL warning should receive a short-lived domain correlation id');
  assert.equal((await call('eventStatus', { eventId: history[0].id, status: 'FalsePositive' })).ok, true);
  assert.equal((await call('history')).result[0].status, 'FalsePositive');
  assert.equal((await call('eventStatus', { eventId: history[0].id, status: 'Bogus' })).ok, false);
  const backups = path.join(root, 'backups'); mkdirSync(backups);
  const historyExportPath = path.join(backups, 'history.json');
  const exportResult = await call('historyExport', { path: historyExportPath }); assert.equal(exportResult.ok, true, exportResult.error);
  const exportedHistory = readFileSync(historyExportPath, 'utf8');
  assert.ok(exportedHistory.includes(history[0].id));
  assert.ok(!exportedHistory.includes(embeddedPhishingUrl));
  assert.ok(!exportedHistory.includes('Pilnie zaloguj się i podaj hasło'));
  assert.ok(!exportedHistory.includes('dont-send-me'));
  const historyCsvPath = path.join(backups, 'history.csv');
  const csvExportResult = await call('historyExportCsv', { path: historyCsvPath }); assert.equal(csvExportResult.ok, true, csvExportResult.error);
  const exportedCsv = readFileSync(historyCsvPath, 'utf8');
  assert.ok(exportedCsv.includes('timestamp_utc,processed_at_utc,risk,category'));
  assert.ok(exportedCsv.includes(history[0].id));
  assert.ok(!exportedCsv.includes('https://paypal.com.evil.test/login'));
  assert.ok(!exportedCsv.includes('Pilnie zaloguj się i podaj hasło'));
  assert.ok(!exportedCsv.includes('dont-send-me'));
  const diagnosticsPath = path.join(backups, 'diagnostics.json');
  const diagnosticsResult = await call('diagnosticsExport', { path: diagnosticsPath, hostLifecycle: { status: 'restarting', lastExitCode: 'exit code 23', stderrObserved: true, stderrExceptionType: 'System.InvalidOperationException' }, hostFailures: [
    { occurredAtUtc: '2026-10-22T12:00:00.000Z', reasonCode: '3765269347', stderrObserved: true, exceptionType: 'System.InvalidOperationException' },
    { occurredAtUtc: '2026-10-22T12:00:01.000Z', reasonCode: 'C:\\Users\\private', stderrObserved: true, exceptionType: 'System.InvalidOperationException:private-data' }
  ] }); assert.equal(diagnosticsResult.ok, true, diagnosticsResult.error);
  const diagnostics = readFileSync(diagnosticsPath, 'utf8');
  assert.ok(diagnostics.includes('applicationVersion') && diagnostics.includes('monitorDownloadedFiles'));
  assert.ok(diagnostics.includes('lastDnsReadUtc') && diagnostics.includes('lastDnsErrorUtc'));
  assert.ok(diagnostics.includes('"hostLifecycle":{"status":"restarting","lastExitCode":"exitcode23","stderrObserved":true,"stderrExceptionType":"System.InvalidOperationException"}'));
  assert.ok(diagnostics.includes('"recentEngineFailures":[{"occurredAtUtc":"2026-10-22T12:00:00+00:00","reasonCode":"3765269347","stderrObserved":true,"exceptionType":"System.InvalidOperationException"},{"occurredAtUtc":"2026-10-22T12:00:01+00:00","reasonCode":"unknown","stderrObserved":true,"exceptionType":null}]'));
  const untrustedDiagnosticsPath = path.join(backups, 'diagnostics-untrusted.json');
  const untrustedDiagnosticsResult = await call('diagnosticsExport', { path: untrustedDiagnosticsPath, hostLifecycle: { stderrExceptionType: 'System.InvalidOperationException:private-data' } }); assert.equal(untrustedDiagnosticsResult.ok, true, untrustedDiagnosticsResult.error);
  assert.ok(!readFileSync(untrustedDiagnosticsPath, 'utf8').includes('private-data'));
  assert.ok(!diagnostics.includes('paypal.com.evil.test'));
  assert.ok(!diagnostics.includes('Users\\private') && !diagnostics.includes('private-data'));
  assert.ok(!diagnostics.includes('LocalAIEndpoint') && !diagnostics.includes('ExcludedApplications'));
  assert.ok(!diagnostics.includes(root));
  const databaseBackupPath = path.join(backups, 'sentinel.db');
  const databaseBackup = await call('databaseBackup', { path: databaseBackupPath }); assert.equal(databaseBackup.ok, true, databaseBackup.error);
  assert.equal(readFileSync(databaseBackupPath).subarray(0, 16).toString(), 'SQLite format 3\0');
  assert.equal((await call('eventStatus', { eventId: history[0].id, status: 'Reviewed' })).ok, true);
  const restoredDatabase = await call('databaseRestore', { path: databaseBackupPath }); assert.equal(restoredDatabase.ok, true, restoredDatabase.error);
  assert.equal(restoredDatabase.result.eventCount, 1); assert.equal(restoredDatabase.result.installationProfilePreserved, true);
  assert.equal((await call('history')).result[0].status, 'FalsePositive');
  const knowledgeFile = path.join(root, 'private-knowledge-fixture.txt');
  writeFileSync(knowledgeFile, 'kbfixture offline response procedure');
  const imported = await call('knowledgeImport', { path: knowledgeFile }); assert.equal(imported.ok, true);
  assert.equal((await call('knowledgeList')).result.length, 1);
  const hits = await call('knowledgeSearch', { query: 'kbfixture' }); assert.equal(hits.ok, true); assert.equal(hits.result.length, 1);
  assert.ok(!JSON.stringify(await call('history')).includes('kbfixture'));
  const knowledgeBackupPath = path.join(backups, 'knowledge.db');
  const knowledgeBackup = await call('knowledgeBackup', { path: knowledgeBackupPath }); assert.equal(knowledgeBackup.ok, true, knowledgeBackup.error);
  assert.equal(readFileSync(knowledgeBackupPath).subarray(0, 16).toString(), 'SQLite format 3\0');
  assert.equal((await call('knowledgeDelete', { documentId: imported.result.id })).result.deleted, true);
  const restoredKnowledge = await call('knowledgeRestore', { path: knowledgeBackupPath }); assert.equal(restoredKnowledge.ok, true, restoredKnowledge.error);
  assert.equal(restoredKnowledge.result.restoredDocuments, 1);
  assert.equal((await call('knowledgeList')).result[0].id, imported.result.id);
  assert.equal((await call('knowledgeSearch', { query: 'kbfixture' })).result.length, 1);
  const models = await call('aiModels', { endpoint: ollamaEndpoint }); assert.equal(models.ok, true); assert.equal(models.result[0].name, 'sentinel-test:latest');
  assert.equal((await call('aiSettings', { useLocalAI: true, endpoint: ollamaEndpoint, model: 'sentinel-test:latest', timeoutSeconds: 5 })).ok, true);
  const aiAnalysis = await call('analyze', { text: 'Pilnie zaloguj się, aby chronić konto. kbfixture alice@example.test password: dont-send-me', url: null });
  assert.equal(aiAnalysis.ok, true, JSON.stringify(aiAnalysis));
  assert.match(ollamaPayload.messages[0].content, /niezaufane dane/i);
  assert.match(ollamaPayload.messages[1].content, /Źródło 1:/);
  assert.match(ollamaPayload.messages[1].content, /Fragment: \[kbfixture\] offline response procedure/);
  assert.doesNotMatch(ollamaPayload.messages[1].content, /private-knowledge-fixture\.txt/);
  assert.doesNotMatch(ollamaPayload.messages[1].content, /alice@example\.test|dont-send-me/);
  assert.equal((await call('status')).result.settings.useLocalAI, true);
  assert.equal((await call('knowledgeDelete', { documentId: imported.result.id })).result.deleted, true);
  assert.equal((await call('unknown')).ok, false);
  assert.equal((await call('pause', { paused: true })).ok, true);
  assert.deepEqual((await call('connections')).result, []);
  assert.equal((await call('collect')).result.dns, 'Obserwacja wstrzymana');
  await call('clearHistory'); assert.equal((await call('history')).result.length, 0);
  console.log('PASS: engine IPC, process start/stop snapshots, AI loopback mock, private knowledge, false-positive and privacy');
 } catch (error) { console.error(error); process.exitCode = 1; }
 finally { clearTimeout(timeout); if (tcpMonitorClient) tcpMonitorClient.destroy(); if (tcpMonitorServer) await new Promise(resolve => tcpMonitorServer.close(resolve)); if (udpSocket) udpSocket.close(); if (ollamaServer) await new Promise(resolve => ollamaServer.close(resolve)); child.stdin.end(); child.on('exit', () => rmSync(root, { recursive: true, force: true })); }
})();
