const test = require('node:test');
const assert = require('node:assert/strict');
const { lifecycleLogDirectory } = require('../electron/lifecycle-log-path.cjs');

test('smoke diagnostics stay inside the isolated test data directory', () => {
  assert.equal(lifecycleLogDirectory({
    smokeTest: true,
    isolatedDataRoot: 'C:\\Temp\\sentinel-smoke\\data',
    localAppData: 'C:\\Users\\tester\\AppData\\Local',
    userDataPath: 'C:\\Users\\tester\\AppData\\Roaming\\Sentinel'
  }), 'C:\\Temp\\sentinel-smoke\\data\\logs');
});

test('normal app diagnostics keep using the per-user local log directory', () => {
  assert.equal(lifecycleLogDirectory({
    smokeTest: false,
    isolatedDataRoot: 'C:\\Temp\\sentinel-smoke\\data',
    localAppData: 'C:\\Users\\tester\\AppData\\Local',
    userDataPath: 'C:\\Users\\tester\\AppData\\Roaming\\Sentinel'
  }), 'C:\\Users\\tester\\AppData\\Local\\Sentinel AI\\Logs');
});

test('normal app falls back to Electron userData when LOCALAPPDATA is missing', () => {
  assert.equal(lifecycleLogDirectory({
    smokeTest: false,
    isolatedDataRoot: undefined,
    localAppData: undefined,
    userDataPath: 'C:\\Users\\tester\\AppData\\Roaming\\Sentinel'
  }), 'C:\\Users\\tester\\AppData\\Roaming\\Sentinel\\Sentinel AI\\Logs');
});
