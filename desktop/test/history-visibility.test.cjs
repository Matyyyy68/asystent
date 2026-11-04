const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const visibleHistoryEvents = async () => (await import('../src/history-visibility.js')).visibleHistoryEvents;

test('hides routine information from the default event list without changing stored events', async () => {
  const filter = await visibleHistoryEvents();
  const events = [
    { id: 1, risk: 'Information', category: 'Proces zaobserwowany' },
    { id: 2, risk: 'Moderate', category: 'Podejrzane uruchomienie procesu' },
    { id: 3, risk: 'High', category: 'Dopasowanie reputacji' }
  ];

  assert.deepEqual(filter(events).map(event => event.id), [2, 3]);
  assert.equal(events.length, 3);
});

test('shows all history when the information toggle is enabled', async () => {
  const filter = await visibleHistoryEvents();
  const events = [{ risk: 'Information' }, { risk: 'Low' }, { risk: 'unknown' }];

  assert.deepEqual(filter(events, true), events);
});

test('keeps unknown risks visible when information is hidden', async () => {
  const filter = await visibleHistoryEvents();

  assert.deepEqual(filter([{ risk: 'FutureRisk' }, { risk: 'Information' }]), [{ risk: 'FutureRisk' }]);
});

test('wires the information toggle into the history UI without changing exports', () => {
  const ui = fs.readFileSync(path.join(__dirname, '../src/main.tsx'), 'utf8');

  assert.match(ui, /Pokaż też informacje systemowe/);
  assert.match(ui, /visibleHistoryEvents\(events, showInformationalHistory\)/);
  assert.match(ui, /call\('historyExport'\)/);
  assert.match(ui, /call\('historyExportCsv'\)/);
});
