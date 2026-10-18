const { spawn } = require('node:child_process');
const { createInterface } = require('node:readline');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = mkdtempSync(path.join(tmpdir(), 'sentinel-engine-test-'));
const child = spawn(path.resolve('artifacts/engine/Sentinel.Engine.exe'), [], { windowsHide: true,
  env: { ...process.env, SENTINEL_DATA_ROOT: root }, stdio: ['pipe','pipe','inherit'] });
const lines = createInterface({ input: child.stdout });
const pending = new Map(); let id = 0;
lines.on('line', line => { const response = JSON.parse(line); pending.get(response.id)?.(response); pending.delete(response.id); });
function call(method, data = {}) { return new Promise(resolve => { const key = String(++id); pending.set(key, resolve); child.stdin.write(JSON.stringify({ ...data, id: key, version: 1, method }) + '\n'); }); }
const timeout = setTimeout(() => { child.kill(); process.exitCode = 1; console.error('Engine timeout'); }, 90000);
(async () => {
 try {
  assert.equal((await call('status')).result.engine, 'ready');
  if (process.argv.includes('--windows-live')) {
    const feed = await call('updateFeed'); assert.equal(feed.ok, true); assert.ok(feed.result.count > 100);
    console.log('PASS: CERT feed import; domain count=' + feed.result.count);
    await call('pause', {paused:false}); const dns = await call('collect'); assert.equal(dns.ok,true);
    assert.ok(dns.result.dns.startsWith('Odczyt cache DNS działa'), dns.result.dns);
    assert.ok(Array.isArray((await call('connections')).result));
    await call('pause', {paused:true}); console.log('PASS: Windows DNS cache and TCP snapshot');
  }
  assert.equal((await call('history')).result.length, 0);
  const result = await call('analyze', { text: 'Pilnie zaloguj się i podaj hasło', url: 'https://paypal.com.evil.test/login' });
  assert.equal(result.ok, true); assert.ok(['High','Critical'].includes(result.result.risk));
  const history = (await call('history')).result; assert.equal(history.length, 1);
  assert.ok(!JSON.stringify(history).includes('https://paypal.com.evil.test/login'));
  assert.equal((await call('unknown')).ok, false);
  assert.equal((await call('pause', { paused: true })).ok, true);
  assert.deepEqual((await call('connections')).result, []);
  assert.equal((await call('collect')).result.dns, 'Obserwacja wstrzymana');
  await call('clearHistory'); assert.equal((await call('history')).result.length, 0);
  console.log('PASS: engine IPC, rules → SQLite history, privacy, pause, invalid method, delete');
 } catch (error) { console.error(error); process.exitCode = 1; }
 finally { clearTimeout(timeout); child.stdin.end(); child.on('exit', () => rmSync(root, { recursive: true, force: true })); }
})();
