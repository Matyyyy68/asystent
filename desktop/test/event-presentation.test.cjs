const assert = require('node:assert/strict');
const test = require('node:test');

async function presentation() {
  return import('../src/event-presentation.js');
}

test('translates every stored risk and status into ordinary Polish labels', async () => {
  const { presentRisk, presentEventStatus } = await presentation();
  for (const [stored, expected] of Object.entries({
    Information: 'Informacja', Low: 'Niskie ryzyko', Moderate: 'Podejrzenie',
    High: 'Wysokie ryzyko', Critical: 'Poważne zagrożenie'
  })) assert.equal(presentRisk(stored), expected);
  for (const [stored, expected] of Object.entries({
    New: 'Nowe', Reviewed: 'Sprawdzone', FalsePositive: 'Oznaczone jako fałszywy alarm'
  })) assert.equal(presentEventStatus(stored), expected);
  assert.equal(presentRisk('FutureRisk'), 'Wymaga sprawdzenia');
  assert.equal(presentEventStatus('FutureStatus'), 'Status nieznany');
});

test('keeps technical event metadata behind details and offers a reviewed action', async () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const ui = fs.readFileSync(path.resolve(__dirname, '../src/main.tsx'), 'utf8');
  const renderer = /const renderHistoryEvent = \(e: any\) => \{([\s\S]*?)\n  \};/.exec(ui)?.[1];
  assert.ok(renderer, 'History event renderer exists.');
  const details = renderer.indexOf('<details>');
  assert.ok(details >= 0, 'Technical evidence is disclosed on demand.');
  for (const technical of ['e.source', 'e.ruleVersion', 'e.schemaVersion', 'e.evidenceCodes']) {
    assert.ok(renderer.indexOf(technical) > details, `${technical} must stay behind the details disclosure.`);
  }
  assert.match(renderer, /e\.status === 'New'[\s\S]*?status: 'Reviewed'/,
    'New observations can be acknowledged without mislabeling them as false positives.');
  assert.match(renderer, /presentRisk\(e\.risk\)/);
  assert.match(renderer, /presentEventStatus\(e\.status\)/);
});

test('uses the same plain-language risk label for correlated event groups', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const ui = fs.readFileSync(path.resolve(__dirname, '../src/main.tsx'), 'utf8');
  const groupRenderer = /const latest = group\.events\[0\];([\s\S]*?)\n\s*\}\)/.exec(ui)?.[1];
  assert.ok(groupRenderer, 'Correlated event group renderer exists.');
  assert.match(groupRenderer, /presentRisk\(latest\.risk\)/);
  assert.doesNotMatch(groupRenderer, /<h2>\{latest\.risk\}/,
    'The raw English enum must not appear in the user-facing group heading.');
  assert.match(groupRenderer, /SYGNAŁY POWIĄZANE W CZASIE/);
});
