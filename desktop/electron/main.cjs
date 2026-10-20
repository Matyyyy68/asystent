const { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage, dialog, Notification } = require('electron');
const { spawn } = require('node:child_process');
const { createInterface } = require('node:readline');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const fs = require('node:fs');
let win, tray, engine, quitting = false, sequence = 0;
const pending = new Map();
const allowed = new Set(['status', 'history', 'eventStatus', 'pause', 'settings', 'analyze', 'connections', 'clearHistory', 'updateFeed', 'rollbackFeed', 'knowledgeList', 'knowledgeSearch', 'knowledgeDelete', 'aiModels', 'aiSettings', 'enterpriseStatus', 'enterprisePair', 'enterpriseSync', 'enterpriseConsent', 'malwareBazaarConfigure', 'malwareBazaarLookup']);
const page = pathToFileURL(path.join(__dirname, '../dist/index.html')).href;
if (!app.requestSingleInstanceLock()) app.quit();
else {
app.on('second-instance', () => win?.show());
app.whenReady().then(() => {
  const executable = app.isPackaged ? path.join(process.resourcesPath, 'engine/Sentinel.Engine.exe') : path.join(__dirname, '../../artifacts/engine/Sentinel.Engine.exe');
  engine = spawn(executable, [], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const fail = () => { for (const p of pending.values()) { clearTimeout(p.timer); p.reject(new Error('Silnik jest niedostępny. Uruchom aplikację ponownie.')); } pending.clear(); };
  engine.on('error', fail); engine.on('exit', fail);
  engine.stderr.on('data', () => {});
  createInterface({ input: engine.stdout }).on('line', line => {
    try { const response = JSON.parse(line); const p = pending.get(response.id); if (!p) return;
      pending.delete(response.id); clearTimeout(p.timer); response.ok ? p.resolve(response.result) : p.reject(new Error(response.error));
    } catch { fail(); }
  });
  function call(method, data) {
    return new Promise((resolve, reject) => {
      if (!engine.pid || engine.exitCode !== null || engine.stdin.destroyed) return reject(new Error('Silnik niedostępny'));
      const id = String(++sequence);
      const timer = setTimeout(() => { pending.delete(id); reject(new Error('Przekroczono czas odpowiedzi silnika')); }, 45000);
      pending.set(id, { resolve, reject, timer });
      engine.stdin.write(JSON.stringify({ ...data, id, version: 1, method }) + '\n');
    });
  }
  ipcMain.handle('sentinel', async (event, method, data) => {
    if (event.sender !== win.webContents || event.senderFrame?.url !== page) throw new Error('Niezaufane źródło');
    if (method === 'autostart') { app.setLoginItemSettings({ openAtLogin: data.enabled === true, args: ['--minimized'], name: 'Sentinel AI' }); return app.getLoginItemSettings({ name: 'Sentinel AI' }).openAtLogin; }
    if (method === 'getAutostart') return app.getLoginItemSettings({ name: 'Sentinel AI' }).openAtLogin;
    if (method === 'chooseFile') {
      const choice = await dialog.showOpenDialog(win, { properties: ['openFile'] });
      return choice.canceled ? null : call('file', { path: choice.filePaths[0] });
    }
    if (method === 'chooseHashFeed') {
      const choice = await dialog.showOpenDialog(win, { properties: ['openFile'], filters: [{ name: 'Lista hashy SHA-256', extensions: ['txt', 'sha256', 'list'] }] });
      return choice.canceled ? null : call('fileHashFeedImport', { path: choice.filePaths[0] });
    }
    if (method === 'chooseKnowledgeFile') {
      const choice = await dialog.showOpenDialog(win, { properties: ['openFile'], filters: [{ name: 'Dokumenty tekstowe', extensions: ['txt', 'md', 'docx'] }] });
      return choice.canceled ? null : call('knowledgeImport', { path: choice.filePaths[0] });
    }
    if (['databaseRestore', 'knowledgeRestore'].includes(method)) {
      const title = method === 'databaseRestore' ? 'Kopia historii Sentinel AI' : 'Kopia bazy wiedzy Sentinel AI';
      const choice = await dialog.showOpenDialog(win, { title, properties: ['openFile'], filters: [{ name: title, extensions: ['db'] }] });
      return choice.canceled ? null : call(method, { path: choice.filePaths[0] });
    }
    if (['historyExport', 'databaseBackup', 'knowledgeBackup'].includes(method)) {
      const date = new Date().toISOString().replace(/[:.]/g, '-');
      const names = { historyExport: `Sentinel-history-${date}.json`, databaseBackup: `Sentinel-data-${date}.db`, knowledgeBackup: `Sentinel-knowledge-${date}.db` };
      const choice = await dialog.showSaveDialog(win, { defaultPath: names[method], filters: [{ name: method === 'historyExport' ? 'JSON' : 'SQLite', extensions: [method === 'historyExport' ? 'json' : 'db'] }] });
      if (choice.canceled || !choice.filePath) return null;
      if (fs.existsSync(choice.filePath)) throw new Error('Plik już istnieje. Wybierz inną nazwę, aby nie nadpisać kopii.');
      return call(method, { path: choice.filePath });
    }
    if (!allowed.has(method) || JSON.stringify(data).length > 23000) throw new Error('Nieprawidłowe żądanie');
    return call(method, data);
  });
  win = new BrowserWindow({ width: 1180, height: 800, minWidth: 760, minHeight: 560, backgroundColor: '#101927',
    webPreferences: { preload: path.join(__dirname, 'preload.cjs'), sandbox: true, contextIsolation: true, nodeIntegration: false } });
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
        [...document.querySelectorAll('button')].find(button => button.textContent.includes('Zastosuj i sprawdź'))?.click();
      })()`);
      await new Promise(resolve => setTimeout(resolve, 500));
      const configured = await win.webContents.executeJavaScript('window.sentinel.call("status")');
      if (configured.settings.dnsPollIntervalSeconds !== 60 || configured.settings.paused) throw new Error('Kreator nie zapisał priorytetu');
      const assessment = await win.webContents.executeJavaScript('window.sentinel.call("analyze", {text:"Pilnie zaloguj się i podaj hasło",url:"https://paypal.com.evil.test/login"})');
      if (!['High','Critical'].includes(assessment.risk)) throw new Error('Nieprawidłowa ocena');
      await new Promise(resolve => setTimeout(resolve, 1500));
      fs.writeFileSync(path.join(process.env.SENTINEL_DATA_ROOT, 'smoke-test.passed'), 'renderer and engine checks passed');
      console.log('PASS: Electron renderer → isolated preload → IPC → .NET → SQLite');
      quitting = true; app.quit();
    } catch (error) { console.error(error); quitting = true; app.exit(1); }
  });
  let collecting = false;
  const collector = setInterval(async () => {
    if (collecting || quitting) return;
    collecting = true;
    try {
      const state = await call('collect', {});
      tray?.setToolTip('Sentinel AI — ' + state.dns + ' · procesy: ' + state.processes);
      if (state.detections > 0 && state.notifications && Notification.isSupported())
        new Notification({ title: 'Sentinel AI — ostrzeżenie DNS', body: 'W cache DNS wykryto domenę z listy CERT Polska. Ruch nie został zablokowany.' }).show();
    } catch { tray?.setToolTip('Sentinel AI — silnik niedostępny'); }
    finally { collecting = false; }
  }, 5000);
  app.on('before-quit', () => clearInterval(collector));
  if (process.argv.includes('--minimized')) win.hide();
  const icon = nativeImage.createFromPath(path.join(__dirname, "../assets/icon-32.png"));
  tray = new Tray(icon);
  tray.setToolTip('Sentinel AI — otwórz, aby sprawdzić status');
  tray.on('double-click', () => win.show());
  tray.setContextMenu(Menu.buildFromTemplate([{ label: 'Otwórz Sentinel AI', click: () => win.show() },
    { label: 'Zakończ', click: async () => { const answer = await dialog.showMessageBox({ type: 'question', message: 'Zakończyć Sentinel AI i zatrzymać silnik?', buttons: ['Anuluj', 'Zakończ'], defaultId: 0, cancelId: 0 }); if (answer.response === 1) { quitting = true; app.quit(); } } }]));
});
app.on('before-quit', () => { quitting = true; engine?.kill(); });
}
