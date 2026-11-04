const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { readRetainedServiceHistory, includeServiceHistoryInJsonExport, includeServiceHistoryInCsvExport } = require('../electron/service-history-export.cjs');

const makeEvent = id => ({ id, timestamp: `2026-11-04T00:00:${String(id % 60).padStart(2, '0')}.000Z`, risk: 'Low',
  category: 'service event', application: 'system', explanation: 'Observed event', recommendation: 'Review', status: 'New' });

test('service history export walks backward through bounded pages and avoids duplicate ids', async () => {
  const requests = [];
  const result = await readRetainedServiceHistory(async cursor => {
    requests.push(cursor);
    const start = (cursor.beforeEventId ?? 38) - 1;
    return { available: true, events: Array.from({ length: Math.min(12, start) }, (_, index) => makeEvent(start - index)) };
  }, { maxItems: 25 });
  assert.equal(result.events.length, 25);
  assert.deepEqual(requests, [{}, { beforeEventId: 26 }, { beforeEventId: 14 }]);
  assert.equal(new Set(result.events.map(event => event.id)).size, 25);
});

test('service export stops at the documented 500-record retention boundary', async () => {
  const result = await readRetainedServiceHistory(async cursor => {
    const before = cursor.beforeEventId ?? 600;
    return { available: true, events: Array.from({ length: 12 }, (_, index) => makeEvent(before - index - 1)) };
  });
  assert.equal(result.events.length, 500);
  assert.equal(new Set(result.events.map(event => event.id)).size, 500);
});

test('JSON export includes retained service events and labels both database origins', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-export-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const target = path.join(directory, 'history.json');
  await fs.writeFile(target, JSON.stringify([{ id: 1, timestamp: '2026-11-03T00:00:00Z', category: 'local' }]), { flag: 'wx' });
  const result = await includeServiceHistoryInJsonExport(target, async cursor => ({ available: true,
    events: cursor.beforeEventId ? [] : [makeEvent(7), makeEvent(6)] }));
  const exported = JSON.parse(await fs.readFile(target, 'utf8'));
  assert.deepEqual(result, { included: true, count: 2, available: true });
  assert.deepEqual(exported.map(event => event.origin), ['system-service', 'system-service', 'user-engine']);
  assert.equal(exported[0].id, 'service-7');
});

test('unavailable service leaves the Engine export intact', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-export-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const target = path.join(directory, 'history.json');
  const original = JSON.stringify([{ id: 1, timestamp: '2026-11-03T00:00:00Z' }]);
  await fs.writeFile(target, original, { flag: 'wx' });
  const result = await includeServiceHistoryInJsonExport(target, async () => ({ available: false, events: [] }));
  assert.deepEqual(result, { included: false, count: 0, available: false });
  assert.equal(await fs.readFile(target, 'utf8'), original);
});

test('CSV export appends service events with source labels, formula neutralization, and BOM', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-export-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const target = path.join(directory, 'history.csv');
  const header = 'id,timestamp_utc,processed_at_utc,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,analysis_limitations,observations,origin';
  await fs.writeFile(target, `\uFEFF${header}\r\n1,"2026-11-03T00:00:00Z",,,,,,,,,,,,,,,,,,,user-engine\r\n`, { flag: 'wx' });
  const event = { ...makeEvent(9), explanation: '=HYPERLINK("https://example.test")' };
  const result = await includeServiceHistoryInCsvExport(target, async () => ({ available: true, events: [event] }));
  const bytes = await fs.readFile(target);
  const csv = bytes.toString('utf8');
  assert.deepEqual(result, { included: true, count: 1, available: true });
  assert.equal(bytes.subarray(0, 3).toString('hex'), 'efbbbf');
  assert.match(csv, /"service-9".*"'=?HYPERLINK/u);
  assert.match(csv, /"system-service"\r\n/u);
});

