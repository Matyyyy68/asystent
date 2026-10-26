const path = require('node:path');
const name = 'Sentinel AI';
const args = ['--minimized'];
let changed = false;
let loginItem;

async function run(app) {
  await app.whenReady();
  loginItem = {
    path: path.join(app.getPath('temp'), 'Sentinel AI Autostart Test', 'Sentinel AI.exe'),
    args: ['--', ...args],
    name
  };
  const before = app.getLoginItemSettings({ path: loginItem.path });
  if (before.executableWillLaunchAtLogin || before.launchItems?.some(item => item.name === name)) {
    throw new Error('Refusing to overwrite a pre-existing Sentinel AI login item.');
  }

  try {
    app.setLoginItemSettings({ ...loginItem, openAtLogin: true });
    changed = true;
    const enabled = app.getLoginItemSettings({ path: loginItem.path });
    const entry = enabled.launchItems?.find(item => item.name === name);
    if (!enabled.executableWillLaunchAtLogin || !entry?.args?.includes('--minimized') || entry.scope !== 'user' || !entry.enabled) {
      throw new Error(`Electron did not register the expected Windows login item: ${JSON.stringify({ openAtLogin: enabled.openAtLogin, executableWillLaunchAtLogin: enabled.executableWillLaunchAtLogin, entry })}`);
    }

    app.setLoginItemSettings({ ...loginItem, openAtLogin: false });
    const disabled = app.getLoginItemSettings({ path: loginItem.path });
    if (disabled.executableWillLaunchAtLogin || disabled.launchItems?.some(item => item.name === name)) {
      throw new Error('Electron did not remove the Windows login item.');
    }
    changed = false;

    console.log('PASS: Electron Windows login item enable/disable uses --minimized and cleans up HKCU.');
  } finally {
    if (changed) {
      app.setLoginItemSettings({ ...loginItem, openAtLogin: false });
      const cleaned = app.getLoginItemSettings({ path: loginItem.path });
      if (cleaned.executableWillLaunchAtLogin || cleaned.launchItems?.some(item => item.name === name)) {
        throw new Error('The Windows login item test could not clean its HKCU registration.');
      }
    }
  }
}

if (process.env.SENTINEL_TEST_ALLOW_LOGIN_ITEM_MUTATION !== '1') {
  console.error('Refusing to modify login items outside the explicitly enabled isolated CI test.');
  process.exitCode = 1;
} else {
  const { app } = require('electron');
  if (!app?.whenReady) {
    console.error('Launch this integration test with the Electron executable.');
    process.exitCode = 1;
  } else {
    run(app).then(() => app.quit(), error => {
      console.error(`Electron autostart integration test failed: ${error.message}`);
      app.exit(1);
    });
  }
}
