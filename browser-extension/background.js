const HOST = "com.sentinelai.urlcheck";
const WARNING_TARGET_PREFIX = "warningTarget:";
const pending = new Map();
const latestByTab = new Map();
const navigationStartedAtByTab = new Map();
const navigationStatesByTab = new Map();
const oneTimeAllow = new Map();
let port = null;
let nextId = 0;
let hostAvailable = null;
let integrationEnabled = false;
const integrationSettingsReady = chrome.storage.local.get('integrationEnabled')
  .then(data => { integrationEnabled = data.integrationEnabled !== false; })
  .catch(() => {});

function warningTargetKey(token) {
  return typeof token === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token)
    ? `${WARNING_TARGET_PREFIX}${token}` : null;
}

async function getWarningTarget(token) {
  const key = warningTargetKey(token);
  if (!key) return null;
  const stored = await chrome.storage.session.get(key);
  const target = stored[key];
  if (!target || !Number.isFinite(target.expiresAt) || target.expiresAt <= Date.now()) {
    if (target) await chrome.storage.session.remove(key);
    return null;
  }
  return target;
}

async function removeWarningTarget(token) {
  const key = warningTargetKey(token);
  if (key) await chrome.storage.session.remove(key);
}

function connect() {
  if (port) return port;
  try {
    port = chrome.runtime.connectNative(HOST);
    port.onMessage.addListener((message) => {
      const item = pending.get(message.id);
      if (!item) return;
      clearTimeout(item.timeout);
      pending.delete(message.id);
      hostAvailable = message.available === true;
      item.resolve(message);
    });
    port.onDisconnect.addListener(() => {
      port = null;
      hostAvailable = false;
      for (const [id, item] of pending) {
        clearTimeout(item.timeout);
        item.resolve(null);
        pending.delete(id);
      }
    });
    return port;
  } catch {
    hostAvailable = false;
    return null;
  }
}

function request(type, url = null) {
  const channel = connect();
  if (!channel) return Promise.resolve(null);
  const id = `${Date.now()}-${++nextId}`;
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      pending.delete(id);
      resolve(null);
    }, 3000);
    pending.set(id, { resolve, timeout });
    try { channel.postMessage({ id, type, url, browser: navigator.userAgent.includes('Edg/') ? 'edge' : 'chrome', enabled: integrationEnabled }); }
    catch {
      clearTimeout(timeout);
      pending.delete(id);
      resolve(null);
      hostAvailable = false;
    }
  });
}

async function presentWarning(tabId, url, result, kind = 'navigation', downloadId = null) {
  const token = crypto.randomUUID();
  const target = {
    tabId,
    url,
    kind,
    downloadId: Number.isInteger(downloadId) && downloadId >= 0 ? downloadId : null,
    risk: result.risk,
    indicators: result.indicators ?? [],
    rulesVersion: result.rulesVersion,
    expiresAt: Date.now() + 10 * 60 * 1000
  };
  try {
    await chrome.storage.session.set({ [`${WARNING_TARGET_PREFIX}${token}`]: target });
    await chrome.tabs.update(tabId, { url: chrome.runtime.getURL(`warning.html?token=${token}`) });
    return token;
  } catch {
    await removeWarningTarget(token).catch(() => {});
    return null;
  }
}

async function promoteWarningToDownload(tabId, state) {
  const token = state.warningToken;
  const key = warningTargetKey(token);
  if (!key || !Number.isInteger(state.downloadId)) return;
  const stored = await chrome.storage.session.get(key);
  const target = stored[key];
  if (!target || target.tabId !== tabId || target.url !== state.url) return;
  if (target.kind === 'download' && target.downloadId === state.downloadId) return;
  target.kind = 'download';
  target.downloadId = state.downloadId;
  await chrome.storage.session.set({ [key]: target });
  // Reload the already-open warning page so it renders download-specific guidance
  // and exposes cancellation for the exact browser transfer ID.
  await chrome.tabs.update(tabId, { url: chrome.runtime.getURL(`warning.html?token=${token}&download=1`) });
}

function inspectNavigation(event, { skipIfCurrent = false } = {}) {
  void (async () => {
    await integrationSettingsReady;
    if (!integrationEnabled || event.frameId !== 0 || !/^https?:\/\//i.test(event.url)) return;
    // SPA route changes can fire alongside a regular navigation for the same URL.
    if (skipIfCurrent && latestByTab.get(event.tabId) === event.url) return;
    const allow = oneTimeAllow.get(event.tabId);
    if (allow) {
      oneTimeAllow.delete(event.tabId);
      if (allow.url === event.url && allow.expiresAt >= Date.now()) {
        latestByTab.set(event.tabId, event.url);
        return;
      }
    }
    latestByTab.set(event.tabId, event.url);
    const state = { url: event.url, startedAt: Date.now(), downloadId: null, warningToken: null };
    navigationStartedAtByTab.set(event.tabId, state.startedAt);
    navigationStatesByTab.set(event.tabId, state);
    request("analyze", event.url).then(async (result) => {
      if (!result || !result.available || navigationStatesByTab.get(event.tabId) !== state
          || latestByTab.get(event.tabId) !== event.url || !result.shouldWarn) return;
      const kind = state.downloadId === null ? 'navigation' : 'download';
      const token = await presentWarning(event.tabId, event.url, result, kind, state.downloadId);
      state.warningToken = token;
      if (token && state.downloadId !== null && kind !== 'download') {
        await promoteWarningToDownload(event.tabId, state);
      }
    });
  })();
}

function inspectDownload(item) {
  void (async () => {
    await integrationSettingsReady;
    if (!integrationEnabled || !item || item.byExtensionId === chrome.runtime.id) return;
    const url = typeof item.finalUrl === 'string' && item.finalUrl ? item.finalUrl : item.url;
    if (typeof url !== 'string' || !/^https?:\/\//i.test(url)) return;
    const sourceTabId = Number.isInteger(item.tabId) && item.tabId >= 0 ? item.tabId : null;
    const activeNavigation = sourceTabId !== null
      && Date.now() - (navigationStartedAtByTab.get(sourceTabId) ?? 0) < 3000;
    if (activeNavigation && (latestByTab.get(sourceTabId) === url || latestByTab.get(sourceTabId) === item.url)) {
      const state = navigationStatesByTab.get(sourceTabId);
      if (state && state.url === url && Date.now() - state.startedAt < 3000) {
        state.downloadId = item.id;
        if (state.warningToken) await promoteWarningToDownload(sourceTabId, state);
        return;
      }
    }
    const result = await request('analyze', url);
    if (!integrationEnabled || !result?.available || !result.shouldWarn) return;
    try {
      const warningTab = await chrome.tabs.create({ url: 'about:blank', active: true });
      await presentWarning(warningTab.id, url, result, 'download', item.id);
    } catch {
      // A failed warning tab must not interrupt the browser's download.
    }
  })();
}

chrome.webNavigation.onBeforeNavigate.addListener((event) => inspectNavigation(event));
chrome.webNavigation.onCommitted.addListener((event) => inspectNavigation(event, { skipIfCurrent: true }));
chrome.webNavigation.onHistoryStateUpdated.addListener((event) => inspectNavigation(event, { skipIfCurrent: true }));
chrome.downloads.onCreated.addListener((item) => inspectDownload(item));

chrome.tabs.onRemoved.addListener((tabId) => {
  latestByTab.delete(tabId);
  navigationStartedAtByTab.delete(tabId);
  navigationStatesByTab.delete(tabId);
  oneTimeAllow.delete(tabId);
  chrome.storage.session.get(null).then((items) => {
    const keys = Object.entries(items)
      .filter(([key, target]) => key.startsWith(WARNING_TARGET_PREFIX) && target?.tabId === tabId)
      .map(([key]) => key);
    if (keys.length) return chrome.storage.session.remove(keys);
  }).catch(() => {});
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || ![chrome.runtime.getURL('popup.html'), chrome.runtime.getURL('warning.html')].some(url => sender.url?.startsWith(url))) return false;
  if (message?.type === 'toggle') {
    integrationSettingsReady.then(async () => {
      integrationEnabled = message.enabled === true;
      await chrome.storage.local.set({ integrationEnabled });
      request('status');
      sendResponse({ enabled: integrationEnabled });
    }).catch(() => sendResponse({ enabled: integrationEnabled }));
    return true;
  }
  if (message?.type === "details" && typeof message.token === "string") {
    getWarningTarget(message.token).then((target) =>
      sendResponse(target ? {
        kind: target.kind ?? 'navigation', risk: target.risk, indicators: target.indicators,
        rulesVersion: target.rulesVersion, canStopDownload: target.kind === 'download' && Number.isInteger(target.downloadId)
      } : null)
    ).catch(() => sendResponse(null));
    return true;
  }
  if (message?.type === "stop-download" && typeof message.token === "string") {
    getWarningTarget(message.token).then(async (target) => {
      if (!target || target.kind !== 'download' || !Number.isInteger(target.downloadId)) {
        sendResponse({ ok: false });
        return;
      }
      try {
        await chrome.downloads.cancel(target.downloadId);
        sendResponse({ ok: true });
      } catch {
        sendResponse({ ok: false });
      }
    }).catch(() => sendResponse({ ok: false }));
    return true;
  }
  if (message?.type === "status") {
    request("status").then((result) => sendResponse({
      enabled: integrationEnabled,
      available: result?.available === true,
      rulesVersion: result?.rulesVersion ?? null
    }));
    return true;
  }
  if (message?.type === "continue" && typeof message.token === "string") {
    getWarningTarget(message.token).then(async (target) => {
      if (!target || target.kind === 'download') { sendResponse({ ok: false }); return; }
      await removeWarningTarget(message.token);
      oneTimeAllow.set(target.tabId, { url: target.url, expiresAt: Date.now() + 5000 });
      await chrome.tabs.update(target.tabId, { url: target.url });
      sendResponse({ ok: true });
    }).catch(() => sendResponse({ ok: false }));
    return true;
  }
  if (message?.type === "close-warning" && typeof message.token === "string") {
    getWarningTarget(message.token).then(async (target) => {
      if (!target) { sendResponse({ ok: false }); return; }
      await removeWarningTarget(message.token);
      await chrome.tabs.remove(target.tabId);
      sendResponse({ ok: true });
    }).catch(() => sendResponse({ ok: false }));
    return true;
  }
  return false;
});
