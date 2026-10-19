const { spawn } = require('node:child_process');
const { createInterface } = require('node:readline');
const { createServer } = require('node:http');
const { createSocket } = require('node:dgram');
const { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = mkdtempSync(path.join(tmpdir(), 'sentinel-engine-test-'));
const child = spawn(path.resolve('artifacts/engine/Sentinel.Engine.exe'), [], { windowsHide: true,
  env: { ...process.env, SENTINEL_DATA_ROOT: root }, stdio: ['pipe','pipe','inherit'] });
const lines = createInterface({ input: child.stdout });
const pending = new Map(); let id = 0;
let ollamaServer, ollamaPayload, udpSocket;
lines.on('line', line => { const response = JSON.parse(line); pending.get(response.id)?.(response); pending.delete(response.id); });
function call(method, data = {}) { return new Promise(resolve => { const key = String(++id); pending.set(key, resolve); child.stdin.write(JSON.stringify({ ...data, id: key, version: 1, method }) + '\n'); }); }
const timeout = setTimeout(() => { child.kill(); process.exitCode = 1; console.error('Engine timeout'); }, 90000);
(async () => {
 try {
  const initialStatus = await call('status'); assert.equal(initialStatus.result.engine, 'ready');
  assert.equal(initialStatus.result.enterprise.variant, 'User');
  assert.equal(initialStatus.result.enterprise.paired, false);
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
  assert.equal(fileCheck.result.sha256.length, 64); assert.match(fileCheck.result.verdict, /Brak audytowanego feedu reputacji/);
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
  console.log(`PASS: process snapshot and child lifecycle; sample IPC+DB=${sampleDurationMs.toFixed(1)}ms`);
  await call('clearHistory'); await call('pause', { paused: true });
  if (process.argv.includes('--windows-live')) {
    const feed = await call('updateFeed'); assert.equal(feed.ok, true); assert.ok(feed.result.count > 100);
    console.log('PASS: CERT feed import; domain count=' + feed.result.count);
    await call('pause', {paused:false}); const dns = await call('collect'); assert.equal(dns.ok,true);
    assert.ok(dns.result.dns.startsWith('Odczyt cache DNS działa'), dns.result.dns);
    const snapshot = await call('connections'); assert.equal(snapshot.ok, true, snapshot.error);
    assert.ok(Array.isArray(snapshot.result));
    assert.ok(snapshot.result.some(c => c.protocol === 'TCP' && c.localPort === ollamaServer.address().port && c.processId === process.pid), 'loopback TCP listener must be attributed to this test process');
    assert.ok(snapshot.result.some(c => c.protocol === 'UDP' && c.localPort === udpSocket.address().port && c.processId === process.pid), 'loopback UDP endpoint must be attributed to this test process');
    await call('pause', {paused:true}); console.log('PASS: Windows DNS cache; TCP/UDP loopback snapshots attributed to process PID');
    await call('clearHistory');
  }
  assert.equal((await call('history')).result.length, 0);
  const result = await call('analyze', { text: 'Pilnie zaloguj się i podaj hasło', url: 'https://paypal.com.evil.test/login' });
  assert.equal(result.ok, true); assert.ok(['High','Critical'].includes(result.result.risk));
  const history = (await call('history')).result; assert.equal(history.length, 1);
  assert.ok(!JSON.stringify(history).includes('https://paypal.com.evil.test/login'));
  assert.equal(history[0].schemaVersion, 1); assert.equal(history[0].source, 'manual-analysis');
  assert.equal((await call('eventStatus', { eventId: history[0].id, status: 'FalsePositive' })).ok, true);
  assert.equal((await call('history')).result[0].status, 'FalsePositive');
  assert.equal((await call('eventStatus', { eventId: history[0].id, status: 'Bogus' })).ok, false);
  const backups = path.join(root, 'backups'); mkdirSync(backups);
  const historyExportPath = path.join(backups, 'history.json');
  const exportResult = await call('historyExport', { path: historyExportPath }); assert.equal(exportResult.ok, true, exportResult.error);
  const exportedHistory = readFileSync(historyExportPath, 'utf8');
  assert.ok(exportedHistory.includes(history[0].id));
  assert.ok(!exportedHistory.includes('https://paypal.com.evil.test/login'));
  assert.ok(!exportedHistory.includes('Pilnie zaloguj się i podaj hasło'));
  assert.ok(!exportedHistory.includes('dont-send-me'));
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
 finally { clearTimeout(timeout); if (udpSocket) udpSocket.close(); if (ollamaServer) await new Promise(resolve => ollamaServer.close(resolve)); child.stdin.end(); child.on('exit', () => rmSync(root, { recursive: true, force: true })); }
})();
