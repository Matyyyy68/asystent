const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const test = require('node:test');
const { watchSmokeTestWindow } = require('../electron/smoke-test.cjs');

test('fails promptly on a main-frame load error without reporting the page URL', () => {
  const webContents = new EventEmitter();
  const failures = [];
  watchSmokeTestWindow(webContents, message => failures.push(message), { setTimeout: () => 1, clearTimeout: () => {} });

  webContents.emit('did-fail-load', {}, -6, 'ERR_FILE_NOT_FOUND', 'file:///C:/private/Sentinel/dist/index.html', true);
  assert.deepEqual(failures, ['Smoke test failed to load its main frame (net error -6).']);

  webContents.emit('render-process-gone', {}, { reason: 'crashed', exitCode: 17 });
  assert.equal(failures.length, 1);
  assert.ok(!failures[0].includes('C:/private'));
});

test('ignores subframe load failures and reports renderer exits with bounded values', () => {
  const webContents = new EventEmitter();
  const failures = [];
  watchSmokeTestWindow(webContents, message => failures.push(message), { setTimeout: () => 1, clearTimeout: () => {} });

  webContents.emit('did-fail-load', {}, -105, 'ERR_NAME_NOT_RESOLVED', 'https://private.example/', false);
  assert.deepEqual(failures, []);

  webContents.emit('render-process-gone', {}, { reason: 'untrusted reason with path C:\\private', exitCode: 'bad' });
  assert.deepEqual(failures, ['Smoke test renderer exited (reason unknown, code unknown).']);
});

test('uses a bounded timeout for the whole smoke flow, even after the main frame loads', () => {
  const webContents = new EventEmitter();
  const failures = [];
  let onTimeout;
  const cleared = [];
  watchSmokeTestWindow(webContents, message => failures.push(message), {
    timeoutMs: 60_000,
    setTimeout: (callback, timeout) => { assert.equal(timeout, 60_000); onTimeout = callback; return 7; },
    clearTimeout: id => cleared.push(id)
  });

  webContents.emit('did-finish-load');
  assert.deepEqual(cleared, []);
  onTimeout();
  assert.deepEqual(failures, ['Smoke test did not complete within the 60-second limit.']);
});

test('stops the whole-smoke deadline after successful verification', () => {
  const webContents = new EventEmitter();
  const failures = [];
  let onTimeout;
  const removed = [];
  const stop = watchSmokeTestWindow(webContents, message => failures.push(message), {
    setTimeout: callback => { onTimeout = callback; return 7; },
    clearTimeout: id => removed.push(id)
  });

  stop();
  onTimeout();
  webContents.emit('render-process-gone', {}, { reason: 'crashed', exitCode: 3 });
  assert.deepEqual(failures, []);
  assert.deepEqual(removed, [7]);
  assert.equal(webContents.listenerCount('did-fail-load'), 0);
  assert.equal(webContents.listenerCount('render-process-gone'), 0);
});
