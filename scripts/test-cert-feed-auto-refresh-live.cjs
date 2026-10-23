const { spawn } = require('node:child_process');
const { createInterface } = require('node:readline');
const { mkdtempSync, rmSync, mkdirSync } = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');

if (process.env.SENTINEL_LIVE_CERT_FEED_AUTO !== '1') {
  throw new Error('Set SENTINEL_LIVE_CERT_FEED_AUTO=1 to explicitly permit the fixed CERT Polska HTTPS request.');
}

const repositoryRoot = path.resolve(__dirname, '..');
const root = mkdtempSync(path.join(os.tmpdir(), 'sentinel-cert-auto-live-'));
const downloadsDirectory = path.join(root, 'Downloads');
mkdirSync(downloadsDirectory);
const child = spawn(path.join(repositoryRoot, 'artifacts/engine/Sentinel.Engine.exe'), [], {
  windowsHide: true,
  env: { ...process.env, SENTINEL_DATA_ROOT: root, SENTINEL_DOWNLOADS_PATH: downloadsDirectory },
  stdio: ['pipe', 'pipe', 'ignore']
});
const lines = createInterface({ input: child.stdout });
const pending = new Map();
let id = 0;
lines.on('line', line => {
  try {
    const response = JSON.parse(line);
    const resolve = pending.get(response.id);
    if (resolve) { pending.delete(response.id); resolve(response); }
  } catch { /* malformed output is handled by the request timeout */ }
});
function call(method, data = {}) {
  return new Promise((resolve, reject) => {
    const key = String(++id);
    const timer = setTimeout(() => { pending.delete(key); reject(new Error(`${method} timed out`)); }, 5000);
    pending.set(key, response => { clearTimeout(timer); resolve(response); });
    child.stdin.write(JSON.stringify({ ...data, id: key, version: 1, method }) + '\n');
  });
}

(async () => {
  let outcome = 1;
  try {
    assert.equal((await call('status')).result.settings.autoUpdateCertFeed, false, 'auto-refresh must be opt-in');
    const settings = (await call('status')).result.settings;
    const saved = await call('settings', { retentionDays: settings.retentionDays,
      notifications: settings.notifications, autoUpdateCertFeed: true });
    assert.equal(saved.ok, true, saved.error);
    const collect = await call('collect');
    assert.equal(collect.ok, true, collect.error);

    const deadline = Date.now() + 45_000;
    let status;
    while (Date.now() < deadline) {
      status = (await call('status')).result;
      if (status.certFeedRefresh.state === 'Zaktualizowana' && status.reputation.count > 0 && !status.reputation.expired) break;
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    assert.ok(status, 'engine returned a status response');
    assert.equal(status.certFeedRefresh.state, 'Zaktualizowana', `auto-refresh did not finish; safe error type: ${status.certFeedRefresh.lastErrorCode}`);
    assert.ok(status.reputation.count > 0, 'feed must be populated in the temporary data directory');
    assert.ok(status.reputation.fetchedAt, 'feed fetch time must be recorded');
    assert.equal(status.settings.autoUpdateCertFeed, true);
    console.log(JSON.stringify({ result: 'PASS', domainCount: status.reputation.count,
      feedFetchedAt: status.reputation.fetchedAt, feedSha256: status.reputation.version, schedulerState: status.certFeedRefresh.state,
      autoRefreshOptIn: status.settings.autoUpdateCertFeed, analyzedUrlsSent: 0 }));
    outcome = 0;
  } catch (error) {
    console.error(`CERT auto-refresh live E2E failed: ${error.message}`);
  } finally {
    child.stdin.end();
    await new Promise(resolve => {
      if (child.exitCode !== null) resolve();
      else { child.once('exit', resolve); setTimeout(() => { child.kill(); resolve(); }, 5000).unref(); }
    });
    lines.close();
    rmSync(root, { recursive: true, force: true });
  }
  process.exitCode = outcome;
})();
