const assert = require('node:assert/strict');
const test = require('node:test');
const { requestedFileCheck } = require('../electron/file-check-args.cjs');

test('reads a single file path passed by the Windows context command', () => {
  assert.equal(requestedFileCheck(['Sentinel AI.exe', '--check-file', 'C:\\Users\\Public\\sample.exe']), 'C:\\Users\\Public\\sample.exe');
});

test('ignores absent, empty, option-like, and oversized context paths', () => {
  assert.equal(requestedFileCheck(['Sentinel AI.exe']), null);
  assert.equal(requestedFileCheck(['Sentinel AI.exe', '--check-file', '']), null);
  assert.equal(requestedFileCheck(['Sentinel AI.exe', '--check-file', '--minimized']), null);
  assert.equal(requestedFileCheck(['Sentinel AI.exe', '--check-file', 'x'.repeat(32761)]), null);
});
