const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

const backgroundPath = path.resolve(__dirname, '../../browser-extension/background.js');
const backgroundSource = readFileSync(backgroundPath, 'utf8');

function createWorker(sessionStorage, shared, {
  integrationSettings = Promise.resolve({ integrationEnabled: true }),
  connectNative,
  cancelDownload
} = {}) {
  const listeners = {};
  const portListeners = {};
  const createdTabs = [];
  const port = {
    onMessage: { addListener(listener) { portListeners.message = listener; } },
    onDisconnect: { addListener(listener) { portListeners.disconnect = listener; } },
    postMessage(message) { shared.nativeRequests.push(message); }
  };
  const chrome = {
    runtime: {
      id: 'sentinel-extension-test',
      getURL(resource) { return `chrome-extension://sentinel-extension-test/${resource}`; },
      connectNative(host) {
        assert.equal(host, 'com.sentinelai.urlcheck');
        return connectNative ? connectNative(port) : port;
      },
      onMessage: { addListener(listener) { listeners.message = listener; } }
    },
    storage: {
      local: { get: () => integrationSettings, set: async () => {} },
      session: {
        get: async (keys) => {
          if (keys === null) return Object.fromEntries(sessionStorage);
          return { [keys]: sessionStorage.get(keys) };
        },
        set: async (values) => { for (const [key, value] of Object.entries(values)) sessionStorage.set(key, value); },
        remove: async (keys) => { for (const key of Array.isArray(keys) ? keys : [keys]) sessionStorage.delete(key); }
      }
    },
    webNavigation: {
      onBeforeNavigate: { addListener(listener) { listeners.navigate = listener; } },
      onCommitted: { addListener(listener) { listeners.committed = listener; } },
      onHistoryStateUpdated: { addListener(listener) { listeners.historyNavigate = listener; } }
    },
    downloads: {
      onCreated: { addListener(listener) { listeners.download = listener; } },
      cancel: async (downloadId) => {
        if (cancelDownload) return cancelDownload(downloadId);
        shared.cancelledDownloads.push(downloadId);
      }
    },
    tabs: {
      onRemoved: { addListener(listener) { listeners.removed = listener; } },
      update: async (tabId, update) => { shared.tabUpdates.push({ tabId, update }); },
      create: async (createProperties) => {
        const tab = { id: 100 + createdTabs.length, ...createProperties };
        createdTabs.push(tab);
        return tab;
      },
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
    commit(event) { listeners.committed(event); },
    historyNavigate(event) { listeners.historyNavigate(event); },
    download(item) { listeners.download(item); },
    createdTabs,
    removeTab(tabId) { listeners.removed(tabId); },
    disconnectNative() { portListeners.disconnect?.(); },
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

test('navigation waits for saved integration setting before contacting the native host', async () => {
  let resolveSettings;
  const integrationSettings = new Promise((resolve) => { resolveSettings = resolve; });
  const shared = { nativeRequests: [], tabUpdates: [], removedTabs: [] };
  const worker = createWorker(new Map(), shared, { integrationSettings });

  const route = { tabId: 3, frameId: 0, url: 'https://paypal.com.evil.test/login' };
  worker.navigate(route);
  worker.historyNavigate({ ...route, url: 'https://paypal.com.evil.test/spa-login' });
  resolveSettings({ integrationEnabled: false });
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(shared.nativeRequests.length, 0,
    'a navigation arriving during service-worker startup must respect the persisted disabled setting');
  assert.equal(shared.tabUpdates.length, 0);
});

test('navigation stays local when the saved integration setting cannot be read', async () => {
  const shared = { nativeRequests: [], tabUpdates: [], removedTabs: [], cancelledDownloads: [] };
  const worker = createWorker(new Map(), shared, {
    integrationSettings: Promise.reject(new Error('storage unavailable'))
  });

  const route = { tabId: 4, frameId: 0, url: 'https://paypal.com.evil.test/login' };
  worker.navigate(route);
  worker.historyNavigate({ ...route, url: 'https://paypal.com.evil.test/spa-login' });
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(shared.nativeRequests.length, 0,
    'a storage read failure must not enable browser analysis or contact the native host');
});

test('navigation is not interrupted when the Native Messaging host is missing', async () => {
  const shared = { nativeRequests: [], tabUpdates: [], removedTabs: [] };
  const worker = createWorker(new Map(), shared, {
    connectNative() { throw new Error('Specified native messaging host not found.'); }
  });

  worker.navigate({ tabId: 6, frameId: 0, url: 'https://paypal.com.evil.test/login' });
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(shared.nativeRequests.length, 0);
  assert.equal(shared.tabUpdates.length, 0,
    'a missing host must not block navigation or attempt to show a warning');
});

test('navigation is not interrupted when the Native Messaging host disconnects', async () => {
  const shared = { nativeRequests: [], tabUpdates: [], removedTabs: [] };
  const worker = createWorker(new Map(), shared);

  worker.navigate({ tabId: 8, frameId: 0, url: 'https://paypal.com.evil.test/login' });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(shared.nativeRequests.length, 1);

  worker.disconnectNative();
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(shared.tabUpdates.length, 0,
    'a disconnected host must resolve pending analysis without blocking or showing a warning');
});

test('SPA history changes are analyzed once for the main frame', async () => {
  const shared = { nativeRequests: [], tabUpdates: [], removedTabs: [] };
  const worker = createWorker(new Map(), shared);
  const route = { tabId: 5, frameId: 0, url: 'https://example.test/account/login' };

  worker.historyNavigate(route);
  worker.historyNavigate(route);
  worker.historyNavigate({ ...route, frameId: 2, url: 'https://example.test/frame/login' });
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(shared.nativeRequests.length, 1);
  assert.equal(shared.nativeRequests[0].type, 'analyze');
  assert.equal(shared.nativeRequests[0].url, route.url);
});

test('committed redirect destinations are analyzed once and iframe commits are ignored', async () => {
  const shared = { nativeRequests: [], tabUpdates: [], removedTabs: [] };
  const worker = createWorker(new Map(), shared);
  const source = { tabId: 9, frameId: 0, url: 'https://example.test/redirect' };
  const destination = { tabId: 9, frameId: 0, url: 'https://paypal-login.test/final' };

  worker.navigate(source);
  await new Promise((resolve) => setImmediate(resolve));
  const initialRequest = shared.nativeRequests[0];
  worker.respondToNative({ id: initialRequest.id, available: true, shouldWarn: false });
  await new Promise((resolve) => setImmediate(resolve));

  worker.commit(source);
  worker.commit(destination);
  worker.commit(destination);
  worker.commit({ ...destination, frameId: 2, url: 'https://paypal-login.test/iframe' });
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(shared.nativeRequests.length, 2);
  assert.equal(shared.nativeRequests[1].url, destination.url);
  worker.respondToNative({ id: shared.nativeRequests[1].id, available: true, shouldWarn: false });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(shared.tabUpdates.length, 0);
});

test('suspicious download final URLs are analyzed and warned in a separate tab without sending file metadata', async () => {
  const sessionStorage = new Map();
  const shared = { nativeRequests: [], tabUpdates: [], removedTabs: [], cancelledDownloads: [] };
  const worker = createWorker(sessionStorage, shared);

  worker.download({
    id: 42,
    tabId: 12,
    url: 'https://downloads.example.test/start',
    finalUrl: 'https://paypal-login.test/account.exe',
    filename: 'C:\\Users\\Mateusz\\Downloads\\private-name.exe',
    referrer: 'https://example.test/private-page'
  });
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(shared.nativeRequests.length, 1);
  assert.equal(shared.nativeRequests[0].type, 'analyze');
  assert.equal(shared.nativeRequests[0].url, 'https://paypal-login.test/account.exe');
  assert.equal('filename' in shared.nativeRequests[0], false);
  assert.equal('referrer' in shared.nativeRequests[0], false);

  worker.respondToNative({
    id: shared.nativeRequests[0].id,
    available: true,
    shouldWarn: true,
    risk: 'High',
    indicators: [],
    rulesVersion: 'test'
  });
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(worker.createdTabs.length, 1);
  assert.equal(shared.tabUpdates[0].tabId, worker.createdTabs[0].id);
  const warningUrl = shared.tabUpdates[0].update.url;
  assert.match(warningUrl, /^chrome-extension:\/\/sentinel-extension-test\/warning\.html\?token=/);
  const token = new URL(warningUrl).searchParams.get('token');
  const details = await worker.sendMessage({ type: 'details', token });
  assert.equal(details.kind, 'download');
  assert.equal(details.risk, 'High');
  assert.equal(details.canStopDownload, true);
  const stopped = await worker.sendMessage({ type: 'stop-download', token });
  assert.equal(stopped.ok, true);
  assert.deepEqual(shared.cancelledDownloads, [42]);
});

test('download cancellation rejects forged or expired warning targets', async () => {
  const shared = { nativeRequests: [], tabUpdates: [], removedTabs: [], cancelledDownloads: [] };
  const worker = createWorker(new Map(), shared);
  const navigationCancel = await worker.sendMessage({ type: 'stop-download', token: '00000000-0000-0000-0000-000000000000' });
  assert.equal(navigationCancel.ok, false);
  assert.deepEqual(shared.cancelledDownloads, []);
});

test('download cancellation cannot be used with a navigation warning', async () => {
  const shared = { nativeRequests: [], tabUpdates: [], removedTabs: [], cancelledDownloads: [] };
  const worker = createWorker(new Map(), shared);
  worker.navigate({ tabId: 15, frameId: 0, url: 'https://paypal-login.test/account' });
  await new Promise((resolve) => setImmediate(resolve));
  worker.respondToNative({
    id: shared.nativeRequests[0].id, available: true, shouldWarn: true,
    risk: 'High', indicators: [], rulesVersion: 'test'
  });
  await new Promise((resolve) => setImmediate(resolve));
  const token = new URL(shared.tabUpdates[0].update.url).searchParams.get('token');
  const details = await worker.sendMessage({ type: 'details', token });
  assert.equal(details.canStopDownload, false);
  const response = await worker.sendMessage({ type: 'stop-download', token });
  assert.equal(response.ok, false);
  assert.deepEqual(shared.cancelledDownloads, []);
});

test('download warnings cannot continue as a page navigation', async () => {
  const sessionStorage = new Map();
  const shared = { nativeRequests: [], tabUpdates: [], removedTabs: [], cancelledDownloads: [] };
  const worker = createWorker(sessionStorage, shared);
  worker.download({ id: 44, tabId: 17, url: 'https://paypal-login.test/file.exe' });
  await new Promise((resolve) => setImmediate(resolve));
  worker.respondToNative({
    id: shared.nativeRequests[0].id, available: true, shouldWarn: true,
    risk: 'High', indicators: [], rulesVersion: 'test'
  });
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  const warningUrl = shared.tabUpdates[0].update.url;
  const token = new URL(warningUrl).searchParams.get('token');
  const result = await worker.sendMessage({ type: 'continue', token });

  assert.equal(result.ok, false);
  assert.equal(shared.tabUpdates.length, 1, 'the warning tab must not navigate back to the download URL');
  assert.equal(sessionStorage.has(`warningTarget:${token}`), true, 'the warning remains available for explicit close or cancellation');
});

test('download without a source tab still warns and can be stopped by its download ID', async () => {
  const sessionStorage = new Map();
  const shared = { nativeRequests: [], tabUpdates: [], removedTabs: [], cancelledDownloads: [] };
  const worker = createWorker(sessionStorage, shared);
  worker.download({ id: 45, url: 'https://paypal-login.test/unassociated-download.exe' });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(shared.nativeRequests.length, 1, 'a missing source tab must not suppress URL analysis');
  worker.respondToNative({
    id: shared.nativeRequests[0].id, available: true, shouldWarn: true,
    risk: 'High', indicators: [], rulesVersion: 'test'
  });
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  const token = new URL(shared.tabUpdates[0].update.url).searchParams.get('token');
  const details = await worker.sendMessage({ type: 'details', token });
  assert.equal(details.kind, 'download');
  assert.equal(details.canStopDownload, true);
  assert.equal((await worker.sendMessage({ type: 'stop-download', token })).ok, true);
  assert.deepEqual(shared.cancelledDownloads, [45]);
});

test('download cancellation reports a browser error without claiming success', async () => {
  const sessionStorage = new Map();
  const shared = { nativeRequests: [], tabUpdates: [], removedTabs: [], cancelledDownloads: [] };
  const worker = createWorker(sessionStorage, shared, {
    cancelDownload: async () => { throw new Error('download already complete'); }
  });
  worker.download({ id: 43, tabId: 16, url: 'https://paypal-login.test/file.exe' });
  await new Promise((resolve) => setImmediate(resolve));
  worker.respondToNative({
    id: shared.nativeRequests[0].id, available: true, shouldWarn: true,
    risk: 'High', indicators: [], rulesVersion: 'test'
  });
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  const token = new URL(shared.tabUpdates[0].update.url).searchParams.get('token');
  const response = await worker.sendMessage({ type: 'stop-download', token });
  assert.equal(response.ok, false);
  assert.deepEqual(shared.cancelledDownloads, []);
});

test('downloads remain local when browser integration is disabled', async () => {
  let resolveSettings;
  const integrationSettings = new Promise((resolve) => { resolveSettings = resolve; });
  const shared = { nativeRequests: [], tabUpdates: [], removedTabs: [] };
  const worker = createWorker(new Map(), shared, { integrationSettings });

  worker.download({ tabId: 13, url: 'https://paypal-login.test/file.exe' });
  resolveSettings({ integrationEnabled: false });
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(shared.nativeRequests.length, 0);
  assert.equal(worker.createdTabs.length, 0);
});

test('a top-level navigation download is not warned twice by both browser events', async () => {
  const sessionStorage = new Map();
  const shared = { nativeRequests: [], tabUpdates: [], removedTabs: [] };
  const worker = createWorker(sessionStorage, shared);
  const item = { tabId: 14, url: 'https://paypal-login.test/download', finalUrl: 'https://paypal-login.test/download' };

  worker.navigate({ tabId: item.tabId, frameId: 0, url: item.url });
  await new Promise((resolve) => setImmediate(resolve));
  const request = shared.nativeRequests[0];
  worker.download({ ...item, id: 72 });
  await new Promise((resolve) => setImmediate(resolve));
  worker.respondToNative({ id: request.id, available: true, shouldWarn: true, risk: 'High', indicators: [], rulesVersion: 'test' });
  for (let i = 0; i < 5; i++) await new Promise((resolve) => setImmediate(resolve));

  assert.equal(shared.nativeRequests.length, 1,
    'webNavigation already covers a top-level download navigation');
  assert.equal(shared.tabUpdates.length, 1, 'the matching events should produce one warning page');
  const token = new URL(shared.tabUpdates[0].update.url).searchParams.get('token');
  assert.equal(sessionStorage.get(`warningTarget:${token}`).kind, 'download');
  assert.equal(sessionStorage.get(`warningTarget:${token}`).downloadId, 72);
});

test('a top-level navigation warning is upgraded when the response becomes a download', async () => {
  const sessionStorage = new Map();
  const shared = { nativeRequests: [], tabUpdates: [], removedTabs: [] };
  const worker = createWorker(sessionStorage, shared);
  const item = { id: 73, tabId: 29, url: 'https://paypal-login.test/download', finalUrl: 'https://paypal-login.test/download' };

  worker.navigate({ tabId: item.tabId, frameId: 0, url: item.url });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(shared.nativeRequests.length, 1);
  worker.respondToNative({
    id: shared.nativeRequests[0].id, available: true, shouldWarn: true,
    risk: 'High', indicators: [], rulesVersion: 'test'
  });
  for (let i = 0; i < 5; i++) await new Promise((resolve) => setImmediate(resolve));
  assert.equal(shared.tabUpdates.length, 1, 'the initial navigation warning should be shown once');
  const token = new URL(shared.tabUpdates[0].update.url).searchParams.get('token');
  assert.equal(sessionStorage.get(`warningTarget:${token}`).kind, 'navigation');

  worker.download(item);
  for (let i = 0; i < 5; i++) await new Promise((resolve) => setImmediate(resolve));

  assert.equal(shared.nativeRequests.length, 1, 'navigation and download events must share one URL analysis');
  assert.equal(shared.tabUpdates.length, 2, 'the existing warning page must reload with download guidance');
  assert.match(shared.tabUpdates[1].update.url, /warning\.html\?token=.*&download=1$/);
  assert.equal(sessionStorage.get(`warningTarget:${token}`).kind, 'download');
  assert.equal(sessionStorage.get(`warningTarget:${token}`).downloadId, item.id);
});

test('closing a tab ignores pending analysis and clears its saved warning details', async () => {
  const sessionStorage = new Map();
  const shared = { nativeRequests: [], tabUpdates: [], removedTabs: [] };
  const worker = createWorker(sessionStorage, shared);

  worker.navigate({ tabId: 21, frameId: 0, url: 'https://paypal-login.test/pending' });
  await new Promise((resolve) => setImmediate(resolve));
  const pendingRequest = shared.nativeRequests[0];
  worker.removeTab(21);
  worker.respondToNative({ id: pendingRequest.id, available: true, shouldWarn: true, risk: 'High', indicators: [] });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(shared.tabUpdates.length, 0, 'a late host response must not redirect a closed tab to a warning');

  worker.navigate({ tabId: 22, frameId: 0, url: 'https://paypal-login.test/warning' });
  await new Promise((resolve) => setImmediate(resolve));
  const warningRequest = shared.nativeRequests[1];
  worker.respondToNative({ id: warningRequest.id, available: true, shouldWarn: true, risk: 'High', indicators: [] });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(shared.tabUpdates.length, 1);
  assert.equal(sessionStorage.size, 1);

  worker.removeTab(22);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(sessionStorage.size, 0, 'closing a warning tab must remove its session-only details');
});

test('warning details and actions survive a service worker restart within the browser session', async () => {
  const sessionStorage = new Map();
  const shared = { nativeRequests: [], tabUpdates: [], removedTabs: [] };
  const firstWorker = createWorker(sessionStorage, shared);
  const targetUrl = 'https://paypal.com.evil.test/login?account=private';
  firstWorker.navigate({ tabId: 7, frameId: 0, url: targetUrl });
  await new Promise((resolve) => setImmediate(resolve));

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
