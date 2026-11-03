const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { EngineClient } = require('./engine-client.cjs');
const { CoreAgentClient } = require('./core-agent-client.cjs');
const { requestEnterpriseContextConsent } = require('./enterprise-context-consent.cjs');
const { readFailures, readLastFailure, recordFailure } = require('./diagnostic-log.cjs');
const { watchSmokeTestWindow } = require('./smoke-test.cjs');
const { shouldShowInitialWindow } = require('./window-visibility.cjs');
const { requestedFileCheck } = require('./file-check-args.cjs');
const { readServiceStatus } = require('./service-status.cjs');
const { createFileCheckBatcher } = require('./file-check-batch.cjs');
const { formatFileCheckResult } = require('./file-check-format.cjs');
const { quarantineDownloadedFile, restoreDownloadedFile } = require('./downloaded-file-actions.cjs');
const { isolatedElectronPaths, lifecycleLogDirectory: resolveLifecycleLogDirectory } = require('./lifecycle-log-path.cjs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const fs = require('node:fs');
let win, quitting = false, fileCheckHandler = null;
const pendingFileChecks = [];
const smokeTest = process.argv.includes('--smoke-test');
if (smokeTest && process.env.SENTINEL_DATA_ROOT) {
  const isolatedPaths = isolatedElectronPaths(process.env.SENTINEL_DATA_ROOT);
  app.setPath('userData', isolatedPaths.userData);
  app.setPath('sessionData', isolatedPaths.sessionData);
}
const isAutostartEnabled = () => {
  const settings = app.getLoginItemSettings({ path: process.execPath });
  return settings.executableWillLaunchAtLogin === true &&
    settings.launchItems?.some(item => item.name === 'Sentinel AI' && item.scope === 'user' && item.enabled && item.args?.includes('--minimized')) === true;
};
const allowed = new Set(['status', 'history', 'quarantineList', 'installedApplications', 'collect', 'eventStatus', 'quarantineDownloadedFile', 'restoreDownloadedFile', 'pause', 'settings', 'analyze', 'connections', 'clearHistory', 'updateFeed', 'rollbackFeed', 'urlReputationImport', 'urlReputationRollback', 'urlReputationClear', 'ipReputationClear', 'fileHashFeedClear', 'knowledgeList', 'knowledgeSearch', 'knowledgeDelete', 'aiModels', 'aiSettings', 'enterpriseStatus', 'enterprisePair', 'enterpriseSync', 'enterpriseConsent', 'enterpriseRotateCredential', 'malwareBazaarConfigure', 'malwareBazaarLookup']);
const page = pathToFileURL(path.join(__dirname, '../dist/index.html')).href;
if (!app.requestSingleInstanceLock()) app.quit();
else {
app.on('second-instance', (_event, commandLine) => {
  if (commandLine.includes('--quit-ui')) { quitting = true; app.quit(); return; }
  const filePath = requestedFileCheck(commandLine);
  if (filePath) {
    if (fileCheckHandler) void fileCheckHandler(filePath);
    else pendingFileChecks.push(filePath);
    return;
  }
  if (commandLine.includes('--alerts')) { win?.loadURL(`${page}#alerts`); win?.show(); return; }
  win?.show();
});
app.whenReady().then(() => {
  if (process.argv.includes('--quit-ui')) { app.quit(); return; }
  const executable = app.isPackaged ? path.join(process.resourcesPath, 'engine/Sentinel.Engine.exe') : path.join(__dirname, '../../artifacts/engine/Sentinel.Engine.exe');
  const agentExecutable = app.isPackaged ? path.join(process.resourcesPath, 'engine/Sentinel.Agent.exe') : path.join(__dirname, '../../artifacts/engine/Sentinel.Agent.exe');
  const lifecycleLogDirectory = resolveLifecycleLogDirectory({
    smokeTest,
    isolatedDataRoot: process.env.SENTINEL_DATA_ROOT,
    localAppData: process.env.LOCALAPPDATA,
    userDataPath: app.getPath('userData')
  });
  const engine = smokeTest
    ? new EngineClient(executable, { onDiagnostic: failure => recordFailure(lifecycleLogDirectory, failure) })
    : new CoreAgentClient(agentExecutable, { onDiagnostic: failure => recordFailure(lifecycleLogDirectory, failure) });
  engine.start();
  const call = (method, data) => engine.call(method, data);
  ipcMain.handle('sentinel', async (event, method, data) => {
    if (event.sender !== win.webContents || event.senderFrame?.url !== page) throw new Error('Niezaufane źródło');
    if (method === 'engineStatus') return { ...engine.diagnostics(), lastFailure: readLastFailure(lifecycleLogDirectory) };
    if (method === 'machineServiceStatus') return readServiceStatus();
    if (method === 'autostart') {
      const loginItem = { path: process.execPath, args: ['--minimized'], name: 'Sentinel AI' };
      app.setLoginItemSettings({ ...loginItem, args: ['--', ...loginItem.args], openAtLogin: data.enabled === true });
      return isAutostartEnabled();
    }
    if (method === 'getAutostart') return isAutostartEnabled();
    if (method === 'chooseFile') {
      const choice = await dialog.showOpenDialog(win, { properties: ['openFile'] });
      return choice.canceled ? null : call('file', { path: choice.filePaths[0] });
    }
    if (method === 'chooseHashFeed') {
      const choice = await dialog.showOpenDialog(win, { properties: ['openFile'], filters: [{ name: 'Lista hashy SHA-256', extensions: ['txt', 'sha256', 'list'] }] });
      return choice.canceled ? null : call('fileHashFeedImport', { path: choice.filePaths[0] });
    }
    if (method === 'chooseIpFeed') {
      const choice = await dialog.showOpenDialog(win, { properties: ['openFile'], filters: [{ name: 'Lista adresów IP/CIDR', extensions: ['txt', 'list', 'cidr'] }] });
      return choice.canceled ? null : call('ipReputationImport', { path: choice.filePaths[0] });
    }
    if (method === 'chooseUrlFeed') {
      const choice = await dialog.showOpenDialog(win, { properties: ['openFile'], filters: [{ name: 'Lista URL lub PhishTank CSV', extensions: ['txt', 'list', 'csv'] }] });
      return choice.canceled ? null : call('urlReputationImport', { path: choice.filePaths[0] });
    }
    if (method === 'chooseKnowledgeFile') {
      const choice = await dialog.showOpenDialog(win, { properties: ['openFile'], filters: [{ name: 'Dokumenty tekstowe i PDF', extensions: ['txt', 'md', 'docx', 'pdf'] }] });
      return choice.canceled ? null : call('knowledgeImport', { path: choice.filePaths[0] });
    }
    if (['databaseRestore', 'knowledgeRestore'].includes(method)) {
      const title = method === 'databaseRestore' ? 'Kopia historii Sentinel AI' : 'Kopia bazy wiedzy Sentinel AI';
      const choice = await dialog.showOpenDialog(win, { title, properties: ['openFile'], filters: [{ name: title, extensions: ['db'] }] });
      return choice.canceled ? null : call(method, { path: choice.filePaths[0] });
    }
    if (['historyExport', 'historyExportCsv', 'databaseBackup', 'knowledgeBackup'].includes(method)) {
      const date = new Date().toISOString().replace(/[:.]/g, '-');
      const names = { historyExport: `Sentinel-history-${date}.json`, historyExportCsv: `Sentinel-history-${date}.csv`, databaseBackup: `Sentinel-data-${date}.db`, knowledgeBackup: `Sentinel-knowledge-${date}.db` };
      const isHistoryExport = method === 'historyExport' || method === 'historyExportCsv';
      const extension = method === 'historyExport' ? 'json' : method === 'historyExportCsv' ? 'csv' : 'db';
      const choice = await dialog.showSaveDialog(win, { defaultPath: names[method], filters: [{ name: isHistoryExport ? extension.toUpperCase() : 'SQLite', extensions: [extension] }] });
      if (choice.canceled || !choice.filePath) return null;
      if (fs.existsSync(choice.filePath)) throw new Error('Plik już istnieje. Wybierz inną nazwę, aby nie nadpisać kopii.');
      return call(method, { path: choice.filePath });
    }
    if (method === 'diagnosticsExport') {
      const date = new Date().toISOString().replace(/[:.]/g, '-');
      const choice = await dialog.showSaveDialog(win, { defaultPath: `Sentinel-diagnostics-${date}.json`, filters: [{ name: 'JSON', extensions: ['json'] }] });
      if (choice.canceled || !choice.filePath) return null;
      if (fs.existsSync(choice.filePath)) throw new Error('Plik już istnieje. Wybierz inną nazwę, aby nie nadpisać diagnostyki.');
      return call(method, { path: choice.filePath, hostLifecycle: engine.diagnostics(), hostFailures: readFailures(lifecycleLogDirectory) });
    }
    if (method === 'quarantineDownloadedFile') {
      return quarantineDownloadedFile({ dialog, window: win, call, downloadsPath: app.getPath('downloads'), eventId: data?.eventId });
    }
    if (method === 'restoreDownloadedFile') {
      return restoreDownloadedFile({ dialog, window: win, call, eventId: data?.eventId });
    }
    if (!allowed.has(method) || JSON.stringify(data).length > 23000) throw new Error('Nieprawidłowe żądanie');
    if (method === 'analyze' && data?.shareWithEnterprise === true) {
      const confirmed = await requestEnterpriseContextConsent(
        () => call('enterpriseStatus'),
        async server => {
          const consent = await dialog.showMessageBox(win, {
            type: 'warning',
            buttons: ['Anuluj', 'Wyślij jednorazowo'],
            defaultId: 0,
            cancelId: 0,
            noLink: true,
            message: 'Przekazać tę treść i adres do serwera Enterprise?',
            detail: `Dane zostaną wysłane jednorazowo do ${server} przez HTTPS. Serwer przetworzy je w pamięci zgodnie z bieżącą polityką; Sentinel sprawdzi, że API potwierdza brak trwałego zapisu treści. Zwykła synchronizacja nadal wysyła wyłącznie metadane.`
          });
          return consent.response === 1;
        });
      if (!confirmed) return null;
    }
    return call(method, data);
  });
  const startupFileCheck = requestedFileCheck(process.argv);
  const oneShotFileCheck = startupFileCheck !== null;
  let oneShotTimer = null;
  const fileCheckBatcher = createFileCheckBatcher(async filePaths => {
    const results = [];
    for (const filePath of filePaths) {
      try {
        const result = await call('file', { path: filePath });
        results.push({ name: path.basename(filePath), matched: result.reputation?.match === true,
          feedImported: result.reputation?.feedImported === true,
          signatureStatus: result.signature?.status, error: null });
      } catch (error) {
        results.push({ name: path.basename(filePath), matched: false, error: String(error?.message || 'Błąd silnika').slice(0, 240) });
      }
    }
    const matched = results.filter(result => result.matched).length;
    const failed = results.filter(result => result.error).length;
    const lines = results.map(formatFileCheckResult);
    const detail = results.some(result => result.matched)
      ? 'Co najmniej jeden SHA-256 pasuje do lokalnej listy. Źródło listy nie zostało niezależnie zweryfikowane; to nie jest automatyczny werdykt zagrożenia.'
      : 'Lokalnie sprawdzono SHA-256 i podpis cyfrowy. Wynik podpisu nie jest gwarancją bezpieczeństwa, a brak dopasowania nie potwierdza bezpieczeństwa. Sentinel nie zablokował ani nie usunął plików.';
    await dialog.showMessageBox({ type: matched ? 'warning' : failed ? 'error' : 'info', buttons: ['OK'],
      title: 'Sentinel AI — sprawdzenie plików',
      message: `Sprawdzono ${results.length} plików${matched ? `; dopasowania: ${matched}` : ''}${failed ? `; błędy: ${failed}` : ''}.`,
      detail: `${detail}\n\n${lines.join('\n')}`.slice(0, 3500) });
    return { checked: results.length, matched, failed };
  });
  win = new BrowserWindow({ show: !startupFileCheck && shouldShowInitialWindow(process.argv), width: 1180, height: 800, minWidth: 760, minHeight: 560, backgroundColor: '#101927',
    webPreferences: { preload: path.join(__dirname, 'preload.cjs'), sandbox: true, contextIsolation: true, nodeIntegration: false } });
  const stopSmokeTestWatch = smokeTest ? watchSmokeTestWindow(win.webContents, message => {
    console.error(message);
    quitting = true;
    app.exit(1);
  }) : () => {};
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', e => e.preventDefault());
  win.on('close', e => { if (!quitting) { e.preventDefault(); win.hide(); } });
  win.loadURL(process.argv.includes('--alerts') ? `${page}#alerts` : page);
  fileCheckHandler = filePath => {
    if (oneShotTimer) clearTimeout(oneShotTimer);
    void fileCheckBatcher.enqueue(filePath).finally(() => {
      if (oneShotFileCheck && !quitting) {
        if (oneShotTimer) clearTimeout(oneShotTimer);
        const closeWhenIdle = () => {
          if (quitting) return;
          if (!fileCheckBatcher.isIdle()) { oneShotTimer = setTimeout(closeWhenIdle, 500); return; }
          quitting = true;
          app.quit();
        };
        oneShotTimer = setTimeout(closeWhenIdle, 1800);
      }
    });
  };
  for (const filePath of pendingFileChecks.splice(0)) fileCheckHandler(filePath);
  if (startupFileCheck) fileCheckHandler(startupFileCheck);
  if (process.argv.includes('--smoke-test')) win.webContents.once('did-finish-load', async () => {
    try {
      const firstRunScreen = await win.webContents.executeJavaScript('document.querySelector(".first-run-screen") !== null && document.querySelector(".layout") === null');
      if (!firstRunScreen) throw new Error('Zwykły interfejs pojawił się przed zakończeniem pierwszego sprawdzenia');
      const status = await win.webContents.executeJavaScript('window.sentinel.call("status")');
      if (status.engine !== 'ready') throw new Error('Silnik niegotowy');
      await new Promise(resolve => setTimeout(resolve, 500));
      let configured;
      for (let attempt = 0; attempt < 20; attempt++) {
        configured = await win.webContents.executeJavaScript('window.sentinel.call("status")');
        const firstRunComplete = await win.webContents.executeJavaScript('localStorage.getItem("sentinel-first-run") === "complete"');
        if (firstRunComplete) break;
        await new Promise(resolve => setTimeout(resolve, 250));
      }
      if (await win.webContents.executeJavaScript('localStorage.getItem("sentinel-first-run") !== "complete"'))
        throw new Error('Automatyczne pierwsze sprawdzenie nie zakończyło się');
      const assessment = await win.webContents.executeJavaScript('window.sentinel.call("analyze", {text:"Pilnie zaloguj się i podaj hasło",url:"https://paypal.com.evil.test/login"})');
      if (!['High','Critical'].includes(assessment.risk)) throw new Error('Nieprawidłowa ocena');
      await new Promise(resolve => setTimeout(resolve, 1500));
      fs.writeFileSync(path.join(process.env.SENTINEL_DATA_ROOT, 'smoke-test.passed'), 'renderer and engine checks passed');
      console.log('PASS: Electron renderer → isolated preload → IPC → .NET → SQLite');
      stopSmokeTestWatch();
      quitting = true; app.quit();
    } catch (error) { stopSmokeTestWatch(); console.error(error); quitting = true; app.exit(1); }
  });
  app.on('before-quit', () => {
    if (oneShotTimer) clearTimeout(oneShotTimer);
    fileCheckBatcher.dispose();
    engine.dispose();
  });
});
app.on('before-quit', () => { quitting = true; });
}
