#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { createServer } = require('node:http');

const hostName = 'com.sentinelai.urlcheck';
const registryKey = 'HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\' + hostName;
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

async function waitForBrowser(profilePath, chromeProcess) {
  const activePortFile = path.join(profilePath, 'DevToolsActivePort');
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (chromeProcess.exitCode !== null) throw new Error(`Chrome exited early with code ${chromeProcess.exitCode}.`);
    try {
      const [port] = fs.readFileSync(activePortFile, 'utf8').split(/\r?\n/);
      if (port) {
        const response = await fetch(`http://127.0.0.1:${port}/json/version`);
        if (response.ok) return { port, ...(await response.json()) };
      }
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  throw new Error('Chrome DevTools endpoint did not become ready.');
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
  if (registryValue() !== null) throw new Error(`The Chrome Native Messaging registration already exists; refusing to overwrite ${registryKey}.`);

  const chromeCandidates = [
    path.join(process.env.PROGRAMFILES || 'C:\\Program Files', 'Google', 'Chrome', 'Application', 'chrome.exe'),
    path.join(process.env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)', 'Google', 'Chrome', 'Application', 'chrome.exe')
  ];
  const chromePath = chromeCandidates.find(candidate => fs.existsSync(candidate));
  if (!chromePath) throw new Error('Google Chrome was not found in Program Files.');

  const root = fs.mkdtempSync(path.join(repoRoot, '.tmp-chrome-e2e-'));
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

  let registryRegistered = false;
  let chromeProcess;
  let fixtureServer;
  let browser;
  let worker;
  let page;
  try {
    fs.cpSync(path.dirname(manifestSource), extensionPath, { recursive: true });
    manifest.host_permissions = ['http://*.test/*', 'https://*.test/*'];
    manifest.web_accessible_resources[0].matches = ['http://*.test/*', 'https://*.test/*'];
    fs.writeFileSync(path.join(extensionPath, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);

    run('dotnet', ['publish', engineHostProject, '-c', 'Release', '-o', engineHostOutput, '--nologo', '-p:NuGetAudit=false', '--ignore-failed-sources']);
    fs.writeFileSync(hostManifestPath, `${JSON.stringify(hostManifest, null, 2)}\n`);
    sendRegistryValue(hostManifestPath);
    registryRegistered = true;

    fixtureServer = createServer((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      response.end('<!doctype html><title>Sentinel local fixture</title><h1>Local .test fixture</h1>');
    });
    await new Promise((resolve, reject) => {
      fixtureServer.once('error', reject);
      fixtureServer.listen(0, '127.0.0.1', resolve);
    });
    const fixturePort = fixtureServer.address().port;

    const chromeArgs = [
      `--user-data-dir=${profilePath}`,
      '--no-first-run', '--no-default-browser-check', '--disable-sync',
      '--disable-background-networking', '--disable-component-update', '--disable-default-apps',
      '--enable-unsafe-extension-debugging', '--remote-allow-origins=*', '--remote-debugging-port=0',
      '--host-resolver-rules=MAP *.test 127.0.0.1,MAP * ~NOTFOUND',
      'about:blank'
    ];
    chromeProcess = spawn(chromePath, chromeArgs, { stdio: 'ignore', windowsHide: false });
    const browserInfo = await waitForBrowser(profilePath, chromeProcess);
    const browserPort = browserInfo.port;
    browser = connectCdp(browserInfo.webSocketDebuggerUrl);
    await browser.opened;

    const loaded = await browser.command('Extensions.loadUnpacked', { path: extensionPath, enableInIncognito: false });
    if (loaded.id !== extensionId) throw new Error(`Chrome loaded unexpected extension ID ${loaded.id}.`);
    const extensions = await browser.command('Extensions.getExtensions');
    if (!extensions.extensions?.some(extension => extension.id === extensionId && extension.enabled)) {
      throw new Error('Chrome did not enable the unpacked extension.');
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
    if (!tab?.webSocketDebuggerUrl) throw new Error('Chrome did not expose the local fixture tab.');
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
      throw new Error(`The warning page was not reached. Final page: ${observed?.href ?? 'unavailable'}; Native Messaging requests: ${requestTypes.join(',') || 'none'}.`);
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

    console.log(JSON.stringify({
      result: 'PASS',
      browser: browserInfo.Browser,
      extensionId,
      fixtureHost: 'paypal-login.test',
      nativeMessagingRequests: requestTypes,
      warningRendered: true,
      productionRuleRendered: true,
      submittedUrlRedacted: true,
      externalDns: 'blocked by Chrome host resolver rules'
    }, null, 2));
  } finally {
    try { page?.socket.close(); } catch {}
    try { worker?.socket.close(); } catch {}
    try { browser?.socket.close(); } catch {}
    if (chromeProcess?.pid) {
      spawnSync('taskkill.exe', ['/PID', String(chromeProcess.pid), '/T', '/F'], { encoding: 'utf8', windowsHide: true });
    }
    if (fixtureServer) {
      fixtureServer.closeAllConnections?.();
      await new Promise(resolve => fixtureServer.close(resolve));
    }
    try {
      if (registryRegistered) removeRegistryValue(hostManifestPath);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }
}

main().catch(error => {
  console.error(`Chrome extension E2E failed: ${error.stack ?? error.message}`);
  process.exitCode = 1;
});
