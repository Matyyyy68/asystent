const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { MAX_FAILURES, readFailures, recordFailure } = require('../electron/diagnostic-log.cjs');

test('persists only bounded, redacted engine failure records', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-engine-log-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));

  assert.equal(recordFailure(directory, {
    occurredAtUtc: '2026-10-22T12:00:00.000Z', reasonCode: 3765269347,
    stderrObserved: true, exceptionType: 'System.InvalidOperationException: C:\\Users\\private'
  }), true);
  assert.deepEqual(readFailures(directory), [{
    occurredAtUtc: '2026-10-22T12:00:00.000Z', reasonCode: '3765269347',
    stderrObserved: true, exceptionType: null
  }]);

  for (let i = 0; i < MAX_FAILURES + 8; i++) {
    assert.equal(recordFailure(directory, {
      occurredAtUtc: new Date(Date.UTC(2026, 9, 22, 12, 1, i)).toISOString(),
      reasonCode: 'response-timeout', stderrObserved: false, exceptionType: null
    }), true);
  }
  const failures = readFailures(directory);
  assert.equal(failures.length, MAX_FAILURES);
  assert.equal(failures.at(-1).reasonCode, 'response-timeout');
  assert.ok(fs.readFileSync(path.join(directory, 'engine-lifecycle.jsonl'), 'utf8').length < 20_000);
});

test('ignores corrupt records and rejects invalid timestamps', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-engine-log-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, 'engine-lifecycle.jsonl'), '{bad json}\n{"occurredAtUtc":"not-a-time"}\n');
  assert.deepEqual(readFailures(directory), []);
  assert.equal(recordFailure(directory, { occurredAtUtc: 'not-a-time' }), false);
});
