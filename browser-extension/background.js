const HOST = "com.sentinelai.urlcheck";
const pending = new Map();
const latestByTab = new Map();
const oneTimeAllow = new Map();
const warnedTargets = new Map();
let port = null;
let nextId = 0;
let hostAvailable = null;

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
    try { channel.postMessage({ id, type, url }); }
    catch {
      clearTimeout(timeout);
      pending.delete(id);
      resolve(null);
      hostAvailable = false;
    }
  });
}

chrome.webNavigation.onBeforeNavigate.addListener((event) => {
  if (event.frameId !== 0 || !/^https?:\/\//i.test(event.url)) return;
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
    warnedTargets.set(token, {
      tabId: event.tabId,
      url: event.url,
      risk: result.risk,
      indicators: result.indicators ?? [],
      rulesVersion: result.rulesVersion
    });
    try {
      await chrome.tabs.update(event.tabId, { url: chrome.runtime.getURL(`warning.html?token=${token}`) });
    } catch {
      warnedTargets.delete(token);
    }
  });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  latestByTab.delete(tabId);
  oneTimeAllow.delete(tabId);
  for (const [token, target] of warnedTargets) if (target.tabId === tabId) warnedTargets.delete(token);
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "details" && typeof message.token === "string") {
    const target = warnedTargets.get(message.token);
    sendResponse(target ? { risk: target.risk, indicators: target.indicators, rulesVersion: target.rulesVersion } : null);
    return false;
  }
  if (message?.type === "status") {
    request("status").then((result) => sendResponse({
      available: result?.available === true,
      rulesVersion: result?.rulesVersion ?? null
    }));
    return true;
  }
  if (message?.type === "continue" && typeof message.token === "string") {
    const target = warnedTargets.get(message.token);
    if (!target) { sendResponse({ ok: false }); return false; }
    warnedTargets.delete(message.token);
    oneTimeAllow.set(target.tabId, { url: target.url, expiresAt: Date.now() + 5000 });
    chrome.tabs.update(target.tabId, { url: target.url })
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }
  if (message?.type === "close-warning" && typeof message.token === "string") {
    const target = warnedTargets.get(message.token);
    if (!target) { sendResponse({ ok: false }); return false; }
    warnedTargets.delete(message.token);
    chrome.tabs.remove(target.tabId).then(() => sendResponse({ ok: true })).catch(() => sendResponse({ ok: false }));
    return true;
  }
  return false;
});
