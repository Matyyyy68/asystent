const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('main dashboard keeps detailed monitor status collapsed by default', () => {
  const uiPath = path.resolve(__dirname, '../src/main.tsx');
  const ui = fs.readFileSync(uiPath, 'utf8');
  const overview = /\{section === 0 && <>[\s\S]*?\n\s*\{section === 1 &&/.exec(ui)?.[0];

  assert.ok(overview, 'The main overview section must exist.');
  assert.match(overview, /<details className="protection-details"><summary>Szczegóły monitorowania<\/summary>/,
    'Monitor diagnostics must be hidden behind an accessible disclosure.');
  assert.match(overview, /protectionStatus\.title/,
    'The main screen must retain the real protection status.');
  assert.match(overview, /Ostatni cykl monitorowania:.*lastCollectionAtUtc/,
    'The main screen must show the timestamp reported by the Engine, not a fabricated scan time.');
  assert.match(overview, /Zdarzenia startu\/zakończenia WMI:.*processEvents.*droppedProcessEvents/,
    'The detailed monitor view must expose WMI process-event availability and queue drops.');
});

test('settings describe enabled defaults for network, Downloads, and persistence monitoring', () => {
  const ui = fs.readFileSync(path.resolve(__dirname, '../src/main.tsx'), 'utf8');
  const models = fs.readFileSync(path.resolve(__dirname, '../../src/Sentinel.Core/Models.cs'), 'utf8');
  const expectedDefaultText = 'Domyślnie włączone dla nowych profili. Zapisane ustawienia pozostają bez zmian.';

  for (const setting of ['MonitorNetworkConnections', 'MonitorDownloadedFiles', 'MonitorPersistenceChanges']) {
    assert.match(models, new RegExp(`bool ${setting} = true`), `${setting} must default to enabled for new profiles.`);
  }
  assert.equal(ui.split(expectedDefaultText).length - 1, 3,
    'Each monitoring setting must explain its new-profile default and preserved saved value.');
});
