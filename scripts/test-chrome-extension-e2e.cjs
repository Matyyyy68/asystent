#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { createServer } = require('node:http');

const hostName = 'com.sentinelai.urlcheck';
const browserName = process.argv[2] ?? 'chrome';
const allowVisibleBrowser = process.argv.includes('--allow-visible-browser');
const allowHeadlessBrowser = process.argv.includes('--allow-headless-browser');
const allowLocalDownloadFixtures = process.argv.includes('--allow-local-download-fixtures');
const useInstalledHost = process.argv.includes('--use-installed-host');
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

if (!allowVisibleBrowser && !allowHeadlessBrowser) {
  console.error('This E2E launches a browser and writes a temporary Native Messaging registration under HKCU. Re-run with --allow-visible-browser or --allow-headless-browser only in an isolated test environment.');
  process.exit(2);
}

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

async function waitForNativeHostProbe(worker) {
  const deadline = Date.now() + 5000;
  let lastResult;
  while (Date.now() < deadline) {
    const nativeProbe = await worker.command('Runtime.evaluate', {
      expression: `new Promise(resolve => {
        let port;
        try { port = chrome.runtime.connectNative('${hostName}'); }
        catch (error) { resolve({ error: String(error) }); return; }
        const timer = setTimeout(() => resolve({ timeout: true }), 1500);
        port.onMessage.addListener(message => { clearTimeout(timer); resolve({ reply: message }); });
        port.onDisconnect.addListener(() => { clearTimeout(timer); resolve({ disconnect: chrome.runtime.lastError?.message || 'unknown' }); });
        port.postMessage({ id: 'manual-probe', type: 'status', url: null, browser: '${browserName}', enabled: true });
      })`,
      awaitPromise: true,
      returnByValue: true
    });
    lastResult = nativeProbe.result?.value;
    if (lastResult?.reply?.available || !lastResult?.error?.includes('chrome is not defined')) return lastResult;
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  return lastResult ?? { timeout: true };
}

async function main() {
  if (process.platform !== 'win32') throw new Error('This optional E2E test requires Windows.');
  const repoRoot = path.resolve(__dirname, '..');
  const manifestSource = path.join(repoRoot, 'browser-extension', 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestSource, 'utf8'));
  const extensionId = extensionIdFromKey(manifest.key);
  if (extensionId !== expectedExtensionId) throw new Error('The repository extension ID does not match the Native Messaging host contract.');
  const registeredManifestPath = registryValue();
  if (!useInstalledHost && registeredManifestPath !== null) throw new Error(`The ${browserConfig.displayName} Native Messaging registration already exists; refusing to overwrite ${registryKey}.`);
  if (useInstalledHost && !registeredManifestPath) throw new Error(`The installed ${browserConfig.displayName} Native Messaging host is not registered.`);

  const browserPath = browserConfig.executablePaths.find(candidate => fs.existsSync(candidate));
  if (!browserPath) throw new Error(`${browserConfig.displayName} was not found in Program Files.`);

  const root = fs.mkdtempSync(path.join(repoRoot, `.tmp-${browserName}-e2e-`));
  const profilePath = path.join(root, 'profile');
  const downloadPath = path.join(root, 'downloads');
  const extensionPath = path.join(root, 'extension');
  const engineHostProject = path.join(repoRoot, 'tests', 'Sentinel.NativeMessagingEngineHost', 'Sentinel.NativeMessagingEngineHost.csproj');
  const engineHostOutput = path.join(root, 'engine-host');
  const hostPath = path.join(engineHostOutput, 'Sentinel.NativeMessagingEngineHost.exe');
  const hostManifestPath = path.join(root, 'native-host.json');
  const installRoot = process.env.SENTINEL_TEST_INSTALL_ROOT;
  if (useInstalledHost) {
    if (!installRoot) throw new Error('--use-installed-host requires SENTINEL_TEST_INSTALL_ROOT to identify the isolated installer target.');
    const expectedManifestPath = path.join(installRoot, 'resources', 'engine', 'com.sentinelai.urlcheck.json');
    if (path.resolve(registeredManifestPath) !== path.resolve(expectedManifestPath)) {
      throw new Error(`Registered Native Messaging manifest does not belong to the isolated installation: ${registeredManifestPath}`);
    }
    const installedManifest = JSON.parse(fs.readFileSync(registeredManifestPath, 'utf8'));
    const expectedHostPath = path.join(installRoot, 'resources', 'engine', 'Sentinel.UrlHost.exe');
    if (installedManifest.name !== hostName || installedManifest.type !== 'stdio' ||
        installedManifest.path !== expectedHostPath || !fs.existsSync(expectedHostPath) ||
        !installedManifest.allowed_origins?.includes(`chrome-extension://${extensionId}/`)) {
      throw new Error('The installed Native Messaging manifest does not point to the expected production Sentinel host.');
    }
  }
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
  let redirectPage;
  let iframePage;
  let spaPage;
  let linkBrowser;
  let lifecyclePages = [];
  try {
    fs.cpSync(path.dirname(manifestSource), extensionPath, { recursive: true });
    manifest.host_permissions = ['http://*.test/*', 'https://*.test/*'];
    manifest.web_accessible_resources[0].matches = ['http://*.test/*', 'https://*.test/*'];
    fs.writeFileSync(path.join(extensionPath, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);

    if (!useInstalledHost) {
      run('dotnet', ['publish', engineHostProject, '-c', 'Release', '-o', engineHostOutput, '--nologo', '--no-restore', '-p:NuGetAudit=false']);
      fs.writeFileSync(hostManifestPath, `${JSON.stringify(hostManifest, null, 2)}\n`);
      sendRegistryValue(hostManifestPath);
      if (registryValue() !== hostManifestPath) throw new Error(`${browserConfig.displayName} Native Messaging registration was not written.`);
    }

    const requestLog = path.join(engineHostOutput, 'native-host-requests.log');
    const statusDirectory = process.env.SENTINEL_TEST_STATUS_DIRECTORY ||
      path.join(process.env.LOCALAPPDATA || '', 'SentinelAI');
    const statusMarker = path.join(statusDirectory, `browser-${browserName}.json`);
    const initialStatusMarker = useInstalledHost && fs.existsSync(statusMarker) ? fs.readFileSync(statusMarker, 'utf8') : null;

    fixtureServer = createServer((request, response) => {
      const requestUrl = new URL(request.url, 'http://127.0.0.1');
      const fixturePort = fixtureServer.address()?.port;
      if (requestUrl.pathname === '/download') {
        response.writeHead(200, {
          'content-type': 'text/plain; charset=utf-8',
          'content-disposition': 'attachment; filename="sentinel-download.txt"',
          'cache-control': 'no-store'
        });
        response.end('sentinel-download-fixture');
        return;
      }
      if (requestUrl.pathname === '/download-link-response') {
        response.writeHead(200, {
          'content-type': 'text/plain; charset=utf-8',
          'content-disposition': 'attachment; filename="sentinel-link-download.txt"',
          'cache-control': 'no-store'
        });
        response.end('sentinel-link-download-fixture');
        return;
      }
      if (requestUrl.pathname === '/redirect-to-brand') {
        response.writeHead(302, { location: `http://paypal-login.test:${fixturePort}/redirect-final` });
        response.end();
        return;
      }
      if (requestUrl.pathname === '/iframe') {
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
        response.end(`<!doctype html><title>Local iframe fixture</title><h1>Local iframe main</h1><iframe id="child" src="http://paypal-login.test:${fixturePort}/iframe-content" onload="document.body.dataset.frameLoaded='yes'"></iframe>`);
        return;
      }
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      response.end(requestUrl.pathname === '/iframe-content'
        ? '<!doctype html><title>Local iframe child</title><p>iframe loaded</p>'
        : '<!doctype html><title>Sentinel local fixture</title><h1>Local .test fixture</h1>');
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
    if (allowHeadlessBrowser) browserArgs.unshift('--headless=new');
    browserProcess = spawn(browserPath, browserArgs, { stdio: 'ignore', windowsHide: !allowVisibleBrowser });
    const browserInfo = await waitForBrowser(profilePath, browserProcess);
    const browserPort = browserInfo.port;
    browser = connectCdp(browserInfo.webSocketDebuggerUrl);
    await browser.opened;
    fs.mkdirSync(downloadPath, { recursive: true });
    if (allowLocalDownloadFixtures) {
      await browser.command('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath });
    }

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
    const probeResult = await waitForNativeHostProbe(worker);
    if (!probeResult?.reply?.available) {
      throw new Error(`Native Messaging Sentinel host probe failed: ${JSON.stringify(probeResult)}`);
    }
    if (useInstalledHost) {
      const deadline = Date.now() + 5000;
      while (Date.now() < deadline) {
        if (fs.existsSync(statusMarker) && fs.readFileSync(statusMarker, 'utf8') !== initialStatusMarker) break;
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      if (!fs.existsSync(statusMarker) || fs.readFileSync(statusMarker, 'utf8') === initialStatusMarker) {
        throw new Error(`The production host replied but did not update its ${browserName} status marker.`);
      }
      const status = JSON.parse(fs.readFileSync(statusMarker, 'utf8'));
      if (status.Enabled !== true) throw new Error(`The production ${browserName} host marker reports the browser integration disabled.`);
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
          observed.text.includes('reguły 2026.10.12')) break;
      await new Promise(resolve => setTimeout(resolve, 200));
    }
    if (!observed?.href?.startsWith(`chrome-extension://${extensionId}/warning.html`)) {
      const requestTypes = fs.existsSync(requestLog) ? fs.readFileSync(requestLog, 'utf8').trim().split(/\r?\n/).filter(Boolean) : [];
      throw new Error(`The warning page was not reached in ${browserConfig.displayName}. Final page: ${observed?.href ?? 'unavailable'}; Native Messaging requests: ${requestTypes.join(',') || 'none'}.`);
    }
    if (!observed.text.includes('Sprawdź ten adres przed kontynuowaniem') ||
        !observed.text.includes('Domena przypomina znaną markę') ||
        !observed.text.includes('reguły 2026.10.12')) {
      throw new Error(`The warning page did not render the expected production rule and indicator. Page text: ${observed.text}`);
    }
    if (observed.text.includes('paypal-login.test') || observed.text.includes(fixtureUrl)) {
      throw new Error('The warning page displayed the submitted URL or host.');
    }
    const requestTypes = fs.existsSync(requestLog) ? fs.readFileSync(requestLog, 'utf8').trim().split(/\r?\n/).filter(Boolean) : [];
    if (!useInstalledHost && !requestTypes.includes('analyze')) throw new Error('The Native Messaging Sentinel host did not receive an analyze request.');
    if (useInstalledHost && !fs.existsSync(statusMarker)) throw new Error(`The production host did not create its ${browserName} status marker.`);

    let lastProductionMarker = initialStatusMarker;
    let productionMarkerChanges = 0;
    const analyzeCount = () => {
      if (!useInstalledHost) return fs.existsSync(requestLog)
        ? fs.readFileSync(requestLog, 'utf8').split(/\r?\n/).filter(type => type === 'analyze').length
        : 0;
      if (!fs.existsSync(statusMarker)) return productionMarkerChanges;
      const currentMarker = fs.readFileSync(statusMarker, 'utf8');
      if (currentMarker !== lastProductionMarker) {
        lastProductionMarker = currentMarker;
        productionMarkerChanges++;
      }
      return productionMarkerChanges;
    };

    const beforeRedirectCount = analyzeCount();
    const redirectTarget = await browser.command('Target.createTarget', { url: `http://example.test:${fixturePort}/redirect-to-brand` });
    const redirectDeadline = Date.now() + timeoutMs;
    let redirectTab;
    while (Date.now() < redirectDeadline) {
      const response = await fetch(`http://127.0.0.1:${browserPort}/json/list`);
      const targets = await response.json();
      redirectTab = targets.find(target => target.id === redirectTarget.targetId);
      if (redirectTab?.webSocketDebuggerUrl && redirectTab.url.startsWith(`chrome-extension://${extensionId}/warning.html`)) break;
      if (redirectTab?.url.includes('/redirect-final') && analyzeCount() > beforeRedirectCount + 1) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!redirectTab?.webSocketDebuggerUrl) throw new Error(`${browserConfig.displayName} did not expose the redirect fixture tab.`);
    redirectPage = connectCdp(redirectTab.webSocketDebuggerUrl);
    await redirectPage.opened;
    await redirectPage.command('Runtime.enable');
    let redirectObserved;
    const redirectWarningDeadline = Date.now() + timeoutMs;
    while (Date.now() < redirectWarningDeadline) {
      const redirectState = await evaluatePage(redirectPage, 'JSON.stringify({href:location.href,text:document.body?.innerText||""})');
      try { redirectObserved = JSON.parse(redirectState); } catch {}
      if (redirectObserved?.href?.startsWith(`chrome-extension://${extensionId}/warning.html`) &&
          redirectObserved.text.includes('Pełny adres nie jest zapisywany w historii.')) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    const redirectDestinationWarned = redirectObserved?.href?.startsWith(`chrome-extension://${extensionId}/warning.html`) === true;
    if (!redirectDestinationWarned) {
      throw new Error(`${browserConfig.displayName} did not warn about the suspicious server-redirect destination; final URL: ${redirectObserved?.href ?? 'unavailable'}.`);
    }
    const redirectWarningRedacted = !redirectObserved.text.includes('paypal-login.test') &&
      !redirectObserved.text.includes('redirect-final');
    if (!redirectWarningRedacted) {
      throw new Error(`${browserConfig.displayName} did not redact the suspicious server-redirect URL and host from the warning.`);
    }

    const beforeIframeCount = analyzeCount();
    const iframeTarget = await browser.command('Target.createTarget', { url: `http://example.test:${fixturePort}/iframe` });
    const iframeDeadline = Date.now() + timeoutMs;
    let iframeTab;
    while (Date.now() < iframeDeadline) {
      const response = await fetch(`http://127.0.0.1:${browserPort}/json/list`);
      const targets = await response.json();
      iframeTab = targets.find(target => target.id === iframeTarget.targetId);
      if (iframeTab?.webSocketDebuggerUrl && iframeTab.url.endsWith('/iframe')) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!iframeTab?.webSocketDebuggerUrl) throw new Error(`${browserConfig.displayName} did not expose the iframe fixture tab.`);
    iframePage = connectCdp(iframeTab.webSocketDebuggerUrl);
    await iframePage.opened;
    await iframePage.command('Runtime.enable');
    const iframeDeadlineComplete = Date.now() + timeoutMs;
    let iframeLoaded;
    while (Date.now() < iframeDeadlineComplete) {
      iframeLoaded = await evaluatePage(iframePage, `document.body?.dataset.frameLoaded === 'yes'`);
      if (iframeLoaded) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!iframeLoaded) throw new Error(`${browserConfig.displayName} did not finish loading the iframe fixture.`);
    const iframeAnalysisDeadline = Date.now() + timeoutMs;
    while (analyzeCount() <= beforeIframeCount && Date.now() < iframeAnalysisDeadline) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    await new Promise(resolve => setTimeout(resolve, 500));
    const iframeAnalysisDelta = analyzeCount() - beforeIframeCount;
    if (iframeAnalysisDelta !== 1) throw new Error(`${browserConfig.displayName} should analyze the main-frame URL once and ignore the iframe (observed ${iframeAnalysisDelta}).`);

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

    let suspiciousDownloadAnalyzed = false;
    let suspiciousDownloadSavedInTemporaryProfile = false;
    let suspiciousDownloadWarningTargetId = null;
    let linkInitiatedDownloadWarned = false;
    let linkDownloadNoticeExplainsTransferStarted = false;
    if (allowLocalDownloadFixtures) {
    const beforeDownloadCount = analyzeCount();
    await browser.command('Target.createTarget', { url: `http://paypal-login.test:${fixturePort}/download` });
    const downloadDeadline = Date.now() + timeoutMs;
    let downloadedFile = false;
    let downloadWarningRendered = false;
    let downloadWarningTab;
    while (Date.now() < downloadDeadline) {
      const [response, names] = await Promise.all([
        fetch(`http://127.0.0.1:${browserPort}/json/list`),
        fs.promises.readdir(downloadPath)
      ]);
      const targets = await response.json();
      downloadedFile = names.includes('sentinel-download.txt');
      downloadWarningTab = targets.find(target => target.url?.startsWith(`chrome-extension://${extensionId}/warning.html`));
      downloadWarningRendered = Boolean(downloadWarningTab);
      if (downloadedFile && downloadWarningRendered && analyzeCount() > beforeDownloadCount) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!downloadedFile) throw new Error(`${browserConfig.displayName} did not save the isolated download fixture.`);
    const downloadContents = fs.readFileSync(path.join(downloadPath, 'sentinel-download.txt'), 'utf8');
    if (downloadContents !== 'sentinel-download-fixture') throw new Error(`${browserConfig.displayName} downloaded unexpected fixture contents.`);
    if (analyzeCount() <= beforeDownloadCount) throw new Error(`${browserConfig.displayName} did not analyze the suspicious download URL.`);
    if (!downloadWarningRendered) throw new Error(`${browserConfig.displayName} did not warn about the suspicious download URL.`);
    suspiciousDownloadWarningTargetId = downloadWarningTab?.id ?? null;

    const linkTarget = await browser.command('Target.createTarget', { url: 'about:blank' });
    let linkPage;
    const linkPageDeadline = Date.now() + timeoutMs;
    while (Date.now() < linkPageDeadline) {
      const response = await fetch(`http://127.0.0.1:${browserPort}/json/list`);
      const targets = await response.json();
      linkPage = targets.find(target => target.id === linkTarget.targetId && target.webSocketDebuggerUrl);
      if (linkPage) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!linkPage) throw new Error(`${browserConfig.displayName} download-link fixture did not open.`);
    linkBrowser = connectCdp(linkPage.webSocketDebuggerUrl);
    await linkBrowser.opened;
    const pageReadyDeadline = Date.now() + timeoutMs;
    let linkReady = false;
    while (Date.now() < pageReadyDeadline) {
      linkReady = await evaluatePage(linkBrowser, "document.readyState === 'complete' && !!document.body");
      if (linkReady) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!linkReady) throw new Error(`${browserConfig.displayName} download-link fixture did not finish loading.`);
    const beforeLinkDownloadCount = analyzeCount();
    const linkDownloadUrl = `http://paypal-login.test:${fixturePort}/download-link-response`;
    const clickBoundsValue = await evaluatePage(linkBrowser, `(() => { const link = document.createElement('a'); link.id = 'download'; link.href = ${JSON.stringify(linkDownloadUrl)}; link.textContent = 'Download fixture'; document.body.append(link); const bounds = link.getBoundingClientRect(); return JSON.stringify({ x: bounds.x, y: bounds.y, width: bounds.width, height: bounds.height }); })()`);
    const clickBounds = JSON.parse(clickBoundsValue);
    if (!(clickBounds.width > 0 && clickBounds.height > 0)) throw new Error(`${browserConfig.displayName} download fixture link has no clickable bounds.`);
    const clickX = clickBounds.x + clickBounds.width / 2;
    const clickY = clickBounds.y + clickBounds.height / 2;
    await linkBrowser.command('Input.dispatchMouseEvent', { type: 'mousePressed', x: clickX, y: clickY, button: 'left', clickCount: 1 });
    await linkBrowser.command('Input.dispatchMouseEvent', { type: 'mouseReleased', x: clickX, y: clickY, button: 'left', clickCount: 1 });
    const linkDownloadDeadline = Date.now() + timeoutMs;
    let linkFileSaved = false;
    let linkWarningTab;
    let warningPage;
    let downloadNotice;
    const observedWarningKinds = new Map();
    while (Date.now() < linkDownloadDeadline) {
      const [response, names] = await Promise.all([
        fetch(`http://127.0.0.1:${browserPort}/json/list`),
        fs.promises.readdir(downloadPath)
      ]);
      const targets = await response.json();
      linkFileSaved = names.includes('sentinel-link-download.txt');
      if (linkFileSaved && analyzeCount() > beforeLinkDownloadCount) {
        const warningCandidates = targets.filter(target => target.id !== suspiciousDownloadWarningTargetId
          && typeof target.webSocketDebuggerUrl === 'string'
          && target.url?.startsWith(`chrome-extension://${extensionId}/warning.html`));
        for (const candidate of warningCandidates) {
          const candidatePage = connectCdp(candidate.webSocketDebuggerUrl);
          try {
            await candidatePage.opened;
            const notice = await evaluatePage(candidatePage, "({ title: document.querySelector('h1')?.textContent, continueHidden: document.getElementById('continue')?.hidden, text: document.body.innerText })");
            if (notice?.title) observedWarningKinds.set(candidate.id, {
              title: notice.title,
              continueHidden: notice.continueHidden,
              downloadSpecific: notice.title.includes('pobierania') && notice.continueHidden
                && notice.text.includes('Pobieranie mogło już się rozpocząć')
            });
            if (notice?.title?.includes('pobierania') && notice.continueHidden
                && notice.text.includes('Pobieranie mogło już się rozpocząć')) {
              linkWarningTab = candidate;
              warningPage = candidatePage;
              downloadNotice = notice;
              break;
            }
          } catch {
            // Other warning tabs may close while the isolated fixture is running.
          }
          if (candidatePage !== warningPage) candidatePage.socket.close();
        }
      }
      if (linkFileSaved && linkWarningTab) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!linkFileSaved) throw new Error(`${browserConfig.displayName} did not save the isolated link-download fixture.`);
    if (fs.readFileSync(path.join(downloadPath, 'sentinel-link-download.txt'), 'utf8') !== 'sentinel-link-download-fixture') {
      throw new Error(`${browserConfig.displayName} downloaded unexpected link fixture contents.`);
    }
    if (analyzeCount() <= beforeLinkDownloadCount) throw new Error(`${browserConfig.displayName} did not analyze a link-initiated download.`);
    if (!linkWarningTab?.webSocketDebuggerUrl) {
      let runtimeDiagnostics = null;
      try {
        const result = await worker.command('Runtime.evaluate', {
          expression: `Promise.all([new Promise(resolve => chrome.downloads.search({filename: ${JSON.stringify(path.join(downloadPath, 'sentinel-link-download.txt'))}}, items => resolve(items.map(item => ({ id: item.id, tabId: Number.isInteger(item.tabId) ? item.tabId : null, tabIdType: typeof item.tabId, hasTabId: Object.prototype.hasOwnProperty.call(item, 'tabId'), byExtensionId: item.byExtensionId ?? null }))))), chrome.storage.session.get(null).then(items => Object.values(items).filter(item => item && item.tabId !== undefined && item.kind).map(({ tabId, kind, downloadId }) => ({ tabId, kind, hasDownloadId: Number.isInteger(downloadId) }))) ]).then(([downloads, warnings]) => ({ downloads, warnings }))`,
          awaitPromise: true,
          returnByValue: true
        });
        runtimeDiagnostics = result.result?.value ?? null;
      } catch {}
      throw new Error(`${browserConfig.displayName} did not render a download-specific warning for the link-initiated download (warning pages observed: ${JSON.stringify([...observedWarningKinds.values()]) || 'none'}; runtime metadata: ${JSON.stringify(runtimeDiagnostics)}).`);
    }
    if (!warningPage) throw new Error(`${browserConfig.displayName} did not render the expected download-specific warning.`);
    if (!downloadNotice?.title?.includes('pobierania') || !downloadNotice.continueHidden || !downloadNotice.text.includes('Pobieranie mogło już się rozpocząć')) {
      throw new Error(`${browserConfig.displayName} link-download warning had unexpected content: ${JSON.stringify(downloadNotice)}`);
    }
    await browser.command('Target.closeTarget', { targetId: linkWarningTab.id });
    await warningPage.socket.close();
    suspiciousDownloadAnalyzed = true;
    suspiciousDownloadSavedInTemporaryProfile = true;
    linkInitiatedDownloadWarned = true;
    linkDownloadNoticeExplainsTransferStarted = true;
    } else {
      console.log('SKIP download fixtures: pass --allow-local-download-fixtures only when local test files in the isolated browser profile are intended.');
    }
    try { linkBrowser?.socket.close(); } catch {}

    const lifecycleTargetA = await browser.command('Target.createTarget', { url: `http://paypal-login.test:${fixturePort}/multi-tab-a` });
    const lifecycleTargetB = await browser.command('Target.createTarget', { url: `http://paypal-login.test:${fixturePort}/multi-tab-b` });
    const lifecycleDeadline = Date.now() + timeoutMs;
    let lifecycleTabs = [];
    while (Date.now() < lifecycleDeadline) {
      const response = await fetch(`http://127.0.0.1:${browserPort}/json/list`);
      const targets = await response.json();
      lifecycleTabs = [lifecycleTargetA.targetId, lifecycleTargetB.targetId]
        .map(id => targets.find(target => target.id === id));
      if (lifecycleTabs.every(target => target?.webSocketDebuggerUrl)) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!lifecycleTabs.every(target => target?.webSocketDebuggerUrl)) {
      throw new Error(`${browserConfig.displayName} did not expose both lifecycle fixture tabs.`);
    }
    lifecyclePages = lifecycleTabs.map(target => connectCdp(target.webSocketDebuggerUrl));
    await Promise.all(lifecyclePages.map(async tab => {
      await tab.opened;
      await tab.command('Runtime.enable');
    }));
    let lifecycleWarningsVisible = false;
    const lifecycleWarningDeadline = Date.now() + timeoutMs;
    while (Date.now() < lifecycleWarningDeadline) {
      const bodies = await Promise.all(lifecyclePages.map(tab => evaluatePage(tab, 'document.body?.innerText||""')));
      lifecycleWarningsVisible = bodies.every(body => body.includes('Domena przypomina znaną markę'));
      if (lifecycleWarningsVisible) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!lifecycleWarningsVisible) throw new Error(`${browserConfig.displayName} did not show isolated warnings in both tabs.`);

    await browser.command('Target.closeTarget', { targetId: lifecycleTargetA.targetId });
    const remainingTabDeadline = Date.now() + timeoutMs;
    let remainingTabIsWarned = false;
    while (Date.now() < remainingTabDeadline) {
      const [response, remainingBody] = await Promise.all([
        fetch(`http://127.0.0.1:${browserPort}/json/list`),
        evaluatePage(lifecyclePages[1], 'JSON.stringify({href:location.href,text:document.body?.innerText||""})')
      ]);
      const targets = await response.json();
      let remaining;
      try { remaining = JSON.parse(remainingBody); } catch {}
      const closedTabGone = !targets.some(target => target.id === lifecycleTargetA.targetId);
      remainingTabIsWarned = closedTabGone &&
        remaining?.href?.startsWith(`chrome-extension://${extensionId}/warning.html`) &&
        remaining.text.includes('Domena przypomina znaną markę');
      if (remainingTabIsWarned) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!remainingTabIsWarned) throw new Error(`${browserConfig.displayName} closing one warning tab affected the other tab.`);

    console.log(JSON.stringify({
      result: 'PASS',
      browser: browserInfo.Browser,
      extensionId,
      fixtureHost: 'paypal-login.test',
      nativeMessagingRequests: requestTypes,
      nativeMessagingHost: useInstalledHost ? 'installed-production-host' : 'test-host',
      productionStatusMarkerUpdated: useInstalledHost,
      warningRendered: true,
      productionRuleRendered: true,
      submittedUrlRedacted: true,
      redirectDestinationWarned: true,
      redirectWarningRedacted: true,
      iframeNavigationAnalyzed: false,
      spaHistoryChangeAnalyzed: true,
      suspiciousDownloadAnalyzed,
      suspiciousDownloadSavedInTemporaryProfile,
      linkInitiatedDownloadWarned,
      linkDownloadNoticeExplainsTransferStarted,
      simultaneousTabWarningsIsolated: true,
      closingOneTabKeepsOtherWarning: true,
      externalDns: `blocked by ${browserConfig.displayName} host resolver rules`
    }, null, 2));
  } finally {
    try { if (browser) await browser.command('Browser.close'); } catch {}
    try { iframePage?.socket.close(); } catch {}
    try { redirectPage?.socket.close(); } catch {}
    try { spaPage?.socket.close(); } catch {}
    for (const lifecyclePage of lifecyclePages) try { lifecyclePage.socket.close(); } catch {}
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
      if (!useInstalledHost && registryValue() === hostManifestPath) removeRegistryValue(hostManifestPath);
      if (useInstalledHost && registryValue() !== registeredManifestPath) {
        throw new Error('The installed Native Messaging registration changed during the browser E2E.');
      }
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
