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
  assert.match(overview, /<h2>STAN SENTINEL AI|STAN SENTINEL AI|protectionStatus\.title/,
    'The main screen must retain the real protection status.');
});
