const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

const backgroundPath = path.resolve(__dirname, '../../browser-extension/background.js');
const backgroundSource = readFileSync(backgroundPath, 'utf8');

function createWorker(sessionStorage, shared) {
  const listeners = {};
  const portListeners = {};
  const port = {
    onMessage: { addListener(listener) { portListeners.message = listener; } },
    onDisconnect: { addListener(listener) { portListeners.disconnect = listener; } },
    postMessage(message) { shared.nativeRequests.push(message); }
  };
  const chrome = {
    runtime: {
      id: 'sentinel-extension-test',
      getURL(resource) { return `chrome-extension://sentinel-extension-test/${resource}`; },
      connectNative(host) { assert.equal(host, 'com.sentinelai.urlcheck'); return port; },
      onMessage: { addListener(listener) { listeners.message = listener; } }
    },
    storage: {
      local: { get: async () => ({ integrationEnabled: true }), set: async () => {} },
      session: {
        get: async (keys) => {
          if (keys === null) return Object.fromEntries(sessionStorage);
          return { [keys]: sessionStorage.get(keys) };
        },
        set: async (values) => { for (const [key, value] of Object.entries(values)) sessionStorage.set(key, value); },
        remove: async (keys) => { for (const key of Array.isArray(keys) ? keys : [keys]) sessionStorage.delete(key); }
      }
    },
    webNavigation: { onBeforeNavigate: { addListener(listener) { listeners.navigate = listener; } } },
    tabs: {
      onRemoved: { addListener(listener) { listeners.removed = listener; } },
      update: async (tabId, update) => { shared.tabUpdates.push({ tabId, update }); },
      remove: async (tabId) => { shared.removedTabs.push(tabId); }
    }
  };
  vm.runInNewContext(backgroundSource, {
    chrome,
    crypto: webcrypto,
    navigator: { userAgent: 'Chrome/140.0.0.0' },
    setTimeout,
    clearTimeout,
    Date,
    Map,
    Promise
  }, { filename: backgroundPath });
  return {
    navigate(event) { listeners.navigate(event); },
    respondToNative(message) { portListeners.message(message); },
    sendMessage(message, page = 'warning.html') {
      return new Promise((resolve) => {
        const keepChannelOpen = listeners.message(message,
          { id: chrome.runtime.id, url: chrome.runtime.getURL(page) }, resolve);
        assert.equal(keepChannelOpen, true);
      });
    }
  };
}

test('warning details and actions survive a service worker restart within the browser session', async () => {
  const sessionStorage = new Map();
  const shared = { nativeRequests: [], tabUpdates: [], removedTabs: [] };
  const firstWorker = createWorker(sessionStorage, shared);
  const targetUrl = 'https://paypal.com.evil.test/login?account=private';
  firstWorker.navigate({ tabId: 7, frameId: 0, url: targetUrl });

  const request = shared.nativeRequests[0];
  assert.equal(request.type, 'analyze');
  firstWorker.respondToNative({
    id: request.id,
    available: true,
    shouldWarn: true,
    risk: 'High',
    indicators: [{ id: 'url.brand', description: 'Domena naśladuje markę.' }],
    rulesVersion: 'test-rules'
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(shared.tabUpdates.length, 1);
  const warningUrl = shared.tabUpdates[0].update.url;
  assert.match(warningUrl, /^chrome-extension:\/\/sentinel-extension-test\/warning\.html\?token=/);
  const token = new URL(warningUrl).searchParams.get('token');
  assert.ok(sessionStorage.has(`warningTarget:${token}`));

  const restartedWorker = createWorker(sessionStorage, shared);
  const details = await restartedWorker.sendMessage({ type: 'details', token });
  assert.equal(details.risk, 'High');
  assert.deepEqual(details.indicators.map((item) => item.id), ['url.brand']);

  const continued = await restartedWorker.sendMessage({ type: 'continue', token });
  assert.equal(continued.ok, true);
  assert.equal(shared.tabUpdates[1].tabId, 7);
  assert.equal(shared.tabUpdates[1].update.url, targetUrl);
  assert.equal(sessionStorage.has(`warningTarget:${token}`), false);
});

test('warning token is validated and expired warning state is removed', async () => {
  const sessionStorage = new Map([
    ['warningTarget:00000000-0000-0000-0000-000000000000', { tabId: 1, url: 'https://example.test/', expiresAt: 1 }]
  ]);
  const worker = createWorker(sessionStorage, { nativeRequests: [], tabUpdates: [], removedTabs: [] });
  const invalid = await worker.sendMessage({ type: 'details', token: '../warningTarget' });
  const expired = await worker.sendMessage({ type: 'details', token: '00000000-0000-0000-0000-000000000000' });
  assert.equal(invalid, null);
  assert.equal(expired, null);
  assert.equal(sessionStorage.size, 0);
});
