const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

test('tray alert route opens the event history and defaults to the overview', async () => {
  const { sectionFromHash } = await import('../src/initial-section.js');
  assert.equal(sectionFromHash(''), 0);
  assert.equal(sectionFromHash('#alerts'), 1);
  assert.equal(sectionFromHash('#other'), 0);

  const electronMain = fs.readFileSync(path.resolve(__dirname, '../electron/main.cjs'), 'utf8');
  const agent = fs.readFileSync(path.resolve(__dirname, '../../src/Sentinel.Agent/Program.cs'), 'utf8');
  assert.match(electronMain, /commandLine\.includes\('--alerts'\)[\s\S]*?loadURL\(`\$\{page\}#alerts`\)/,
    'A second-instance tray request must route the running app to event history.');
  assert.match(electronMain, /win\.loadURL\(process\.argv\.includes\('--alerts'\) \? `\$\{page\}#alerts` : page\)/,
    'A cold app launch from the tray must open event history directly.');
  assert.match(agent, /menu\.Items\.Add\("Ostatnie alerty"[\s\S]*?OpenUi\(appRoot, "--alerts"\)/,
    'The user-mode tray must expose the recent-events action.');
});
