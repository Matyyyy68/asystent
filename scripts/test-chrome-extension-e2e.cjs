#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { createServer } = require('node:http');

const hostName = 'com.sentinelai.urlcheck';
const browserName = process.argv[2] ?? 'chrome';
const browsers = {
  chrome: {
    displayName: 'Chrome',
    registryPath: 'Software\\Google\\Chrome\\NativeMessagingHosts\\',
    executablePaths: [
      path.join(process.env.PROGRAMFILES || 'C:\\Program Files', 'Google', 'Chrome', 'Application', 'chrome.exe'),
      path.join(process.env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)', 'Google', 'Chrome', 'Application', 'chrome.exe')
    ]
  },
  edge: {
    displayName: 'Edge',
    registryPath: 'Software\\Microsoft\\Edge\\NativeMessagingHosts\\',
    executablePaths: [
      path.join(process.env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      path.join(process.env.PROGRAMFILES || 'C:\\Program Files', 'Microsoft', 'Edge', 'Application', 'msedge.exe')
    ]
  }
};
const browserConfig = browsers[browserName];
if (!browserConfig) throw new Error('Choose chrome or edge as the browser argument.');
const registryKey = 'HKCU\\' + browserConfig.registryPath + hostName;
const expectedExtensionId = 'nakmencmekkefmcddpihiiohjgabfemg';
const timeoutMs = 30_000;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: 'utf8', windowsHide: true, ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || '').trim();
    throw new Error(`${path.basename(command)} exited ${result.status}${detail ? `: ${detail}` : ''}`);
  }
  return result.stdout.trim();
}

function extensionIdFromKey(key) {
  const digest = crypto.createHash('sha256').update(Buffer.from(key, 'base64')).digest().subarray(0, 16);
  return [...digest].map(byte => String.fromCharCode(97 + (byte >> 4), 97 + (byte & 15))).join('');
}

function registryValue() {
  const result = spawnSync('reg.exe', ['query', registryKey, '/ve'], { encoding: 'utf8', windowsHide: true });
  if (result.status !== 0) return null;
  const match = result.stdout.match(/\(Default\)\s+REG_SZ\s+(.+)/i);
  return match?.[1]?.trim() ?? null;
}

function sendRegistryValue(manifestPath) {
  run('reg.exe', ['add', registryKey, '/ve', '/t', 'REG_SZ', '/d', manifestPath, '/f']);
}

function removeRegistryValue(manifestPath) {
  if (registryValue() !== manifestPath) throw new Error('Refusing to remove a Native Messaging registry value that changed during the test.');
  run('reg.exe', ['delete', registryKey, '/f']);
}

function connectCdp(webSocketUrl) {
  const socket = new WebSocket(webSocketUrl);
  let nextId = 0;
  const pending = new Map();
  const opened = new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', reject, { once: true });
  });
  socket.addEventListener('message', event => {
    const message = JSON.parse(String(event.data));
    const operation = pending.get(message.id);
    if (!operation) return;
    pending.delete(message.id);
    clearTimeout(operation.timer);
    if (message.error) operation.reject(new Error(`${message.error.code}: ${message.error.message}`));
    else operation.resolve(message.result ?? {});
  });
  return {
    socket,
    opened,
    command(method, params = {}) {
      const id = ++nextId;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`CDP command timed out: ${method}`));
        }, timeoutMs);
        pending.set(id, { resolve, reject, timer });
        socket.send(JSON.stringify({ id, method, params }));
      });
    }
  };
}

async function waitForExtensionWorker(port, extensionId) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const response = await fetch(`http://127.0.0.1:${port}/json/list`);
    const targets = await response.json();
    const worker = targets.find(target => target.type === 'service_worker' && target.url.includes(extensionId));
    if (worker) return worker;
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  throw new Error('The extension service worker did not start.');
}

async function waitForBrowser(profilePath, browserProcess) {
  const activePortFile = path.join(profilePath, 'DevToolsActivePort');
  const deadline = Date.now() + timeoutMs;
  let exitedAt;
  while (Date.now() < deadline) {
    try {
      const [port] = fs.readFileSync(activePortFile, 'utf8').split(/\r?\n/);
      if (port) {
        const response = await fetch(`http://127.0.0.1:${port}/json/version`);
        if (response.ok) return { port, ...(await response.json()) };
      }
    } catch {}
    if (browserProcess.exitCode !== null) {
      exitedAt ??= Date.now();
      if (Date.now() - exitedAt > 2000) throw new Error(`${browserConfig.displayName} exited early with code ${browserProcess.exitCode}.`);
    }
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  throw new Error(`${browserConfig.displayName} DevTools endpoint did not become ready.`);
}

async function evaluatePage(page, expression) {
  const response = await page.command('Runtime.evaluate', { expression, returnByValue: true });
  return response.result?.value;
}

async function main() {
  if (process.platform !== 'win32') throw new Error('This optional E2E test requires Windows.');
  const repoRoot = path.resolve(__dirname, '..');
  const manifestSource = path.join(repoRoot, 'browser-extension', 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestSource, 'utf8'));
  const extensionId = extensionIdFromKey(manifest.key);
  if (extensionId !== expectedExtensionId) throw new Error('The repository extension ID does not match the Native Messaging host contract.');
  if (registryValue() !== null) throw new Error(`The ${browserConfig.displayName} Native Messaging registration already exists; refusing to overwrite ${registryKey}.`);

  const browserPath = browserConfig.executablePaths.find(candidate => fs.existsSync(candidate));
  if (!browserPath) throw new Error(`${browserConfig.displayName} was not found in Program Files.`);

  const root = fs.mkdtempSync(path.join(repoRoot, `.tmp-${browserName}-e2e-`));
  const profilePath = path.join(root, 'profile');
  const extensionPath = path.join(root, 'extension');
  const engineHostProject = path.join(repoRoot, 'tests', 'Sentinel.NativeMessagingEngineHost', 'Sentinel.NativeMessagingEngineHost.csproj');
  const engineHostOutput = path.join(root, 'engine-host');
  const hostPath = path.join(engineHostOutput, 'Sentinel.NativeMessagingEngineHost.exe');
  const hostManifestPath = path.join(root, 'native-host.json');
  const hostManifest = {
    name: hostName,
    description: 'Temporary test-only Native Messaging host using Sentinel URL rules',
    path: hostPath,
    type: 'stdio',
    allowed_origins: [`chrome-extension://${extensionId}/`]
  };

  let browserProcess;
  let fixtureServer;
  let browser;
  let worker;
  let page;
  let spaPage;
  try {
    fs.cpSync(path.dirname(manifestSource), extensionPath, { recursive: true });
    manifest.host_permissions = ['http://*.test/*', 'https://*.test/*'];
    manifest.web_accessible_resources[0].matches = ['http://*.test/*', 'https://*.test/*'];
    fs.writeFileSync(path.join(extensionPath, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);

    run('dotnet', ['publish', engineHostProject, '-c', 'Release', '-o', engineHostOutput, '--nologo', '-p:NuGetAudit=false', '--ignore-failed-sources']);
    fs.writeFileSync(hostManifestPath, `${JSON.stringify(hostManifest, null, 2)}\n`);
    sendRegistryValue(hostManifestPath);
    if (registryValue() !== hostManifestPath) throw new Error(`${browserConfig.displayName} Native Messaging registration was not written.`);

    fixtureServer = createServer((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      response.end('<!doctype html><title>Sentinel local fixture</title><h1>Local .test fixture</h1>');
    });
    await new Promise((resolve, reject) => {
      fixtureServer.once('error', reject);
      fixtureServer.listen(0, '127.0.0.1', resolve);
    });
    const fixturePort = fixtureServer.address().port;

    const browserArgs = [
      `--user-data-dir=${profilePath}`,
      '--no-first-run', '--no-default-browser-check', '--disable-sync',
      '--disable-background-networking', '--disable-component-update', '--disable-default-apps',
      '--enable-unsafe-extension-debugging', '--remote-allow-origins=*', '--remote-debugging-port=0',
      '--host-resolver-rules=MAP *.test 127.0.0.1,MAP * ~NOTFOUND',
      'about:blank'
    ];
    browserProcess = spawn(browserPath, browserArgs, { stdio: 'ignore', windowsHide: false });
    const browserInfo = await waitForBrowser(profilePath, browserProcess);
    const browserPort = browserInfo.port;
    browser = connectCdp(browserInfo.webSocketDebuggerUrl);
    await browser.opened;

    const loaded = await browser.command('Extensions.loadUnpacked', { path: extensionPath, enableInIncognito: false });
    if (loaded.id !== extensionId) throw new Error(`${browserConfig.displayName} loaded unexpected extension ID ${loaded.id}.`);
    const extensions = await browser.command('Extensions.getExtensions');
    if (!extensions.extensions?.some(extension => extension.id === extensionId && extension.enabled)) {
      throw new Error(`${browserConfig.displayName} did not enable the unpacked extension.`);
    }

    await browser.command('Target.createTarget', { url: 'about:blank' });
    const serviceWorker = await waitForExtensionWorker(browserPort, extensionId);
    worker = connectCdp(serviceWorker.webSocketDebuggerUrl);
    await worker.opened;
    await worker.command('Runtime.enable');
    const nativeProbe = await worker.command('Runtime.evaluate', {
      expression: `new Promise(resolve => {
        let port;
        try { port = chrome.runtime.connectNative('${hostName}'); }
        catch (error) { resolve({ error: String(error) }); return; }
        const timer = setTimeout(() => resolve({ timeout: true }), 5000);
        port.onMessage.addListener(message => { clearTimeout(timer); resolve({ reply: message }); });
        port.onDisconnect.addListener(() => { clearTimeout(timer); resolve({ disconnect: chrome.runtime.lastError?.message || 'unknown' }); });
        port.postMessage({ id: 'manual-probe', type: 'status', url: null });
      })`,
      awaitPromise: true,
      returnByValue: true
    });
    const probeResult = nativeProbe.result?.value;
    if (!probeResult?.reply?.available) {
      throw new Error(`Native Messaging Sentinel host probe failed: ${JSON.stringify(probeResult)}`);
    }

    const fixtureUrl = `http://paypal-login.test:${fixturePort}/login`;
    const created = await browser.command('Target.createTarget', { url: fixtureUrl });
    const targetsResponse = await fetch(`http://127.0.0.1:${browserPort}/json/list`);
    const targets = await targetsResponse.json();
    const tab = targets.find(target => target.id === created.targetId);
    if (!tab?.webSocketDebuggerUrl) throw new Error(`${browserConfig.displayName} did not expose the local fixture tab.`);
    page = connectCdp(tab.webSocketDebuggerUrl);
    await page.opened;
    await page.command('Runtime.enable');

    let observed;
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const value = await evaluatePage(page, 'JSON.stringify({href:location.href,text:document.body?.innerText||""})');
      try { observed = JSON.parse(value); } catch {}
      if (observed?.href?.startsWith(`chrome-extension://${extensionId}/warning.html`) &&
          observed.text.includes('Domena przypomina znaną markę') &&
          observed.text.includes('reguły 2026.10.9')) break;
      await new Promise(resolve => setTimeout(resolve, 200));
    }
    if (!observed?.href?.startsWith(`chrome-extension://${extensionId}/warning.html`)) {
      const requestLog = path.join(engineHostOutput, 'native-host-requests.log');
      const requestTypes = fs.existsSync(requestLog) ? fs.readFileSync(requestLog, 'utf8').trim().split(/\r?\n/).filter(Boolean) : [];
      throw new Error(`The warning page was not reached in ${browserConfig.displayName}. Final page: ${observed?.href ?? 'unavailable'}; Native Messaging requests: ${requestTypes.join(',') || 'none'}.`);
    }
    if (!observed.text.includes('Sprawdź ten adres przed kontynuowaniem') ||
        !observed.text.includes('Domena przypomina znaną markę') ||
        !observed.text.includes('reguły 2026.10.9')) {
      throw new Error(`The warning page did not render the expected production rule and indicator. Page text: ${observed.text}`);
    }
    if (observed.text.includes('paypal-login.test') || observed.text.includes(fixtureUrl)) {
      throw new Error('The warning page displayed the submitted URL or host.');
    }
    const requestLog = path.join(engineHostOutput, 'native-host-requests.log');
    const requestTypes = fs.existsSync(requestLog) ? fs.readFileSync(requestLog, 'utf8').trim().split(/\r?\n/).filter(Boolean) : [];
    if (!requestTypes.includes('analyze')) throw new Error('The Native Messaging Sentinel host did not receive an analyze request.');

    const analyzeCount = () => fs.existsSync(requestLog)
      ? fs.readFileSync(requestLog, 'utf8').split(/\r?\n/).filter(type => type === 'analyze').length
      : 0;
    const beforeSpaCount = analyzeCount();
    const spaTarget = await browser.command('Target.createTarget', { url: `http://example.test:${fixturePort}/spa-start` });
    const spaDeadline = Date.now() + timeoutMs;
    let spaTab;
    while (Date.now() < spaDeadline) {
      const response = await fetch(`http://127.0.0.1:${browserPort}/json/list`);
      const targets = await response.json();
      spaTab = targets.find(target => target.id === spaTarget.targetId);
      if (spaTab?.webSocketDebuggerUrl) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!spaTab?.webSocketDebuggerUrl) throw new Error(`${browserConfig.displayName} did not expose the SPA fixture tab.`);
    spaPage = connectCdp(spaTab.webSocketDebuggerUrl);
    await spaPage.opened;
    await spaPage.command('Runtime.enable');

    const initialAnalysisDeadline = Date.now() + timeoutMs;
    while (analyzeCount() <= beforeSpaCount && Date.now() < initialAnalysisDeadline) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (analyzeCount() <= beforeSpaCount) throw new Error(`The initial SPA fixture navigation was not analyzed in ${browserConfig.displayName}.`);
    const beforeHistoryChangeCount = analyzeCount();
    await evaluatePage(spaPage, `history.pushState({}, '', '/spa-route?step=2'); location.href`);
    const historyAnalysisDeadline = Date.now() + timeoutMs;
    while (analyzeCount() <= beforeHistoryChangeCount && Date.now() < historyAnalysisDeadline) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (analyzeCount() <= beforeHistoryChangeCount) throw new Error(`${browserConfig.displayName} SPA history change did not reach the Native Messaging host.`);

    console.log(JSON.stringify({
      result: 'PASS',
      browser: browserInfo.Browser,
      extensionId,
      fixtureHost: 'paypal-login.test',
      nativeMessagingRequests: requestTypes,
      warningRendered: true,
      productionRuleRendered: true,
      submittedUrlRedacted: true,
      spaHistoryChangeAnalyzed: true,
      externalDns: `blocked by ${browserConfig.displayName} host resolver rules`
    }, null, 2));
  } finally {
    try { if (browser) await browser.command('Browser.close'); } catch {}
    try { spaPage?.socket.close(); } catch {}
    try { page?.socket.close(); } catch {}
    try { worker?.socket.close(); } catch {}
    try { browser?.socket.close(); } catch {}
    if (browserProcess?.pid) {
      spawnSync('taskkill.exe', ['/PID', String(browserProcess.pid), '/T', '/F'], { encoding: 'utf8', windowsHide: true });
    }
    if (fixtureServer) {
      fixtureServer.closeAllConnections?.();
      await new Promise(resolve => fixtureServer.close(resolve));
    }
    try {
      if (registryValue() === hostManifestPath) removeRegistryValue(hostManifestPath);
    } finally {
      const temporaryRoot = path.resolve(root);
      if (!temporaryRoot.startsWith(repoRoot + path.sep)) throw new Error('Refusing to remove a test directory outside the repository.');
      fs.rmSync(temporaryRoot, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 });
    }
  }
}

main().catch(error => {
  console.error(`${browserConfig.displayName} extension E2E failed: ${error.stack ?? error.message}`);
  process.exitCode = 1;
});
