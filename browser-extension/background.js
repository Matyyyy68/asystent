const HOST = "com.sentinelai.urlcheck";
const WARNING_TARGET_PREFIX = "warningTarget:";
const pending = new Map();
const latestByTab = new Map();
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

chrome.webNavigation.onBeforeNavigate.addListener((event) => {
  void (async () => {
    await integrationSettingsReady;
    if (!integrationEnabled || event.frameId !== 0 || !/^https?:\/\//i.test(event.url)) return;
    const allow = oneTimeAllow.get(event.tabId);
    if (allow) {
      oneTimeAllow.delete(event.tabId);
      if (allow.url === event.url && allow.expiresAt >= Date.now()) {
        latestByTab.set(event.tabId, event.url);
        return;
      }
    }
    latestByTab.set(event.tabId, event.url);
    request("analyze", event.url).then(async (result) => {
      if (!result || !result.available || latestByTab.get(event.tabId) !== event.url || !result.shouldWarn) return;
      const token = crypto.randomUUID();
      const target = {
        tabId: event.tabId,
        url: event.url,
        risk: result.risk,
        indicators: result.indicators ?? [],
        rulesVersion: result.rulesVersion,
        expiresAt: Date.now() + 10 * 60 * 1000
      };
      try {
        await chrome.storage.session.set({ [`${WARNING_TARGET_PREFIX}${token}`]: target });
        await chrome.tabs.update(event.tabId, { url: chrome.runtime.getURL(`warning.html?token=${token}`) });
      } catch {
        await removeWarningTarget(token).catch(() => {});
      }
    });
  })();
});

chrome.tabs.onRemoved.addListener((tabId) => {
  latestByTab.delete(tabId);
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
      sendResponse(target ? { risk: target.risk, indicators: target.indicators, rulesVersion: target.rulesVersion } : null)
    ).catch(() => sendResponse(null));
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
      if (!target) { sendResponse({ ok: false }); return; }
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
