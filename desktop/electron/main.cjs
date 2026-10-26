const { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage, dialog, Notification } = require('electron');
const { EngineClient } = require('./engine-client.cjs');
const { requestEnterpriseContextConsent } = require('./enterprise-context-consent.cjs');
const { readFailures, readLastFailure, recordFailure } = require('./diagnostic-log.cjs');
const { watchSmokeTestWindow } = require('./smoke-test.cjs');
const { shouldShowInitialWindow } = require('./window-visibility.cjs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const fs = require('node:fs');
let win, tray, quitting = false;
const smokeTest = process.argv.includes('--smoke-test');
const allowed = new Set(['status', 'history', 'eventStatus', 'pause', 'settings', 'analyze', 'connections', 'clearHistory', 'updateFeed', 'rollbackFeed', 'urlReputationImport', 'urlReputationRollback', 'urlReputationClear', 'ipReputationClear', 'fileHashFeedClear', 'knowledgeList', 'knowledgeSearch', 'knowledgeDelete', 'aiModels', 'aiSettings', 'enterpriseStatus', 'enterprisePair', 'enterpriseSync', 'enterpriseConsent', 'enterpriseRotateCredential', 'malwareBazaarConfigure', 'malwareBazaarLookup']);
const page = pathToFileURL(path.join(__dirname, '../dist/index.html')).href;
if (!app.requestSingleInstanceLock()) app.quit();
else {
app.on('second-instance', () => win?.show());
app.whenReady().then(() => {
  const executable = app.isPackaged ? path.join(process.resourcesPath, 'engine/Sentinel.Engine.exe') : path.join(__dirname, '../../artifacts/engine/Sentinel.Engine.exe');
  const lifecycleLogDirectory = path.join(process.env.LOCALAPPDATA || app.getPath('userData'), 'Sentinel AI', 'Logs');
  const engine = new EngineClient(executable, { onDiagnostic: failure => recordFailure(lifecycleLogDirectory, failure) });
  engine.start();
  const call = (method, data) => engine.call(method, data);
  ipcMain.handle('sentinel', async (event, method, data) => {
    if (event.sender !== win.webContents || event.senderFrame?.url !== page) throw new Error('Niezaufane źródło');
    if (method === 'engineStatus') return { ...engine.diagnostics(), lastFailure: readLastFailure(lifecycleLogDirectory) };
    if (method === 'autostart') {
      const loginItem = { path: process.execPath, args: ['--minimized'], name: 'Sentinel AI' };
      app.setLoginItemSettings({ ...loginItem, args: ['--', ...loginItem.args], openAtLogin: data.enabled === true });
      return app.getLoginItemSettings({ ...loginItem, args: ['--', ...loginItem.args] }).openAtLogin;
    }
    if (method === 'getAutostart') return app.getLoginItemSettings({ path: process.execPath, args: ['--', '--minimized'] }).openAtLogin;
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
  win = new BrowserWindow({ show: shouldShowInitialWindow(process.argv), width: 1180, height: 800, minWidth: 760, minHeight: 560, backgroundColor: '#101927',
    webPreferences: { preload: path.join(__dirname, 'preload.cjs'), sandbox: true, contextIsolation: true, nodeIntegration: false } });
  const stopSmokeTestWatch = smokeTest ? watchSmokeTestWindow(win.webContents, message => {
    console.error(message);
    quitting = true;
    app.exit(1);
  }) : () => {};
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', e => e.preventDefault());
  win.on('close', e => { if (!quitting) { e.preventDefault(); win.hide(); } });
  win.loadURL(page);
  if (process.argv.includes('--smoke-test')) win.webContents.once('did-finish-load', async () => {
    try {
      const status = await win.webContents.executeJavaScript('window.sentinel.call("status")');
      if (status.engine !== 'ready') throw new Error('Silnik niegotowy');
      await new Promise(resolve => setTimeout(resolve, 500));
      await win.webContents.executeJavaScript(`(() => {
        const select = document.querySelector('select');
        if (!select) throw new Error('Brak kreatora pierwszego uruchomienia');
        select.value = 'resources'; select.dispatchEvent(new Event('change', { bubbles: true }));
        const button = [...document.querySelectorAll('button')].find(button => button.textContent.includes('Zastosuj i sprawdź'));
        if (!button || button.disabled) throw new Error('Przycisk konfiguracji pierwszego uruchomienia jest niedostępny');
        button.click();
      })()`);
      let configured;
      for (let attempt = 0; attempt < 20; attempt++) {
        configured = await win.webContents.executeJavaScript('window.sentinel.call("status")');
        if (configured.settings.dnsPollIntervalSeconds === 60 && !configured.settings.paused) break;
        await new Promise(resolve => setTimeout(resolve, 250));
      }
      if (configured.settings.dnsPollIntervalSeconds !== 60 || configured.settings.paused)
        throw new Error(`Kreator nie zapisał priorytetu (DNS=${configured.settings.dnsPollIntervalSeconds}, paused=${configured.settings.paused})`);
      const assessment = await win.webContents.executeJavaScript('window.sentinel.call("analyze", {text:"Pilnie zaloguj się i podaj hasło",url:"https://paypal.com.evil.test/login"})');
      if (!['High','Critical'].includes(assessment.risk)) throw new Error('Nieprawidłowa ocena');
      await new Promise(resolve => setTimeout(resolve, 1500));
      fs.writeFileSync(path.join(process.env.SENTINEL_DATA_ROOT, 'smoke-test.passed'), 'renderer and engine checks passed');
      console.log('PASS: Electron renderer → isolated preload → IPC → .NET → SQLite');
      stopSmokeTestWatch();
      quitting = true; app.quit();
    } catch (error) { stopSmokeTestWatch(); console.error(error); quitting = true; app.exit(1); }
  });
  let collecting = false;
  const collector = smokeTest ? null : setInterval(async () => {
    if (collecting || quitting) return;
    collecting = true;
    try {
      const state = await call('collect', {});
      tray?.setToolTip('Sentinel AI — ' + state.dns + ' · procesy: ' + state.processes);
      if (state.detections > 0 && state.notifications && Notification.isSupported())
        new Notification({ title: 'Sentinel AI — ostrzeżenie DNS', body: 'W źródle DNS wykryto domenę z listy CERT Polska. Ruch nie został zablokowany.' }).show();
    } catch { tray?.setToolTip('Sentinel AI — silnik niedostępny'); }
    finally { collecting = false; }
  }, 1000);
  app.on('before-quit', () => { clearInterval(collector); engine.dispose(); });
  if (!smokeTest) {
    const icon = nativeImage.createFromPath(path.join(__dirname, "../assets/icon-32.png"));
    tray = new Tray(icon);
    tray.setToolTip('Sentinel AI — otwórz, aby sprawdzić status');
    tray.on('double-click', () => win.show());
    tray.setContextMenu(Menu.buildFromTemplate([{ label: 'Otwórz Sentinel AI', click: () => win.show() },
      { label: 'Zakończ', click: async () => { const answer = await dialog.showMessageBox({ type: 'question', message: 'Zakończyć Sentinel AI i zatrzymać silnik?', buttons: ['Anuluj', 'Zakończ'], defaultId: 0, cancelId: 0 }); if (answer.response === 1) { quitting = true; app.quit(); } } }]));
  }
});
app.on('before-quit', () => { quitting = true; });
}
