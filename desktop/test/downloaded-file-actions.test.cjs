'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { quarantineDownloadedFile, restoreDownloadedFile } = require('../electron/downloaded-file-actions.cjs');

function harness({ confirmation = 1, selection = { canceled: false, filePaths: ['C:/Users/test/Downloads/sample.bin'] } } = {}) {
  const messages = [];
  const calls = [];
  const dialog = {
    async showMessageBox(_window, options) { messages.push(options); return { response: messages.length === 1 ? confirmation : 0 }; },
    async showOpenDialog(_window, options) { messages.push(options); return selection; }
  };
  return { dialog, messages, calls, call: async (method, data) => { calls.push({ method, data }); return { fileName: 'sample.bin', state: method.startsWith('restore') ? 'Restored' : 'Quarantined' }; } };
}

test('quarantine requires confirmation and a user-selected file before calling the engine', async () => {
  const testHarness = harness();
  const result = await quarantineDownloadedFile({ ...testHarness, window: {}, downloadsPath: 'C:/Users/test/Downloads', eventId: 12 });
  assert.equal(result.state, 'Quarantined');
  assert.equal(testHarness.messages[0].defaultId, 0);
  assert.equal(testHarness.messages[1].defaultPath, 'C:/Users/test/Downloads');
  assert.deepEqual(testHarness.calls, [{ method: 'quarantineDownloadedFile', data: { eventId: 12, path: 'C:/Users/test/Downloads/sample.bin' } }]);
});

test('quarantine cancellation never opens the picker or calls the engine', async () => {
  const testHarness = harness({ confirmation: 0 });
  assert.equal(await quarantineDownloadedFile({ ...testHarness, window: {}, downloadsPath: 'Downloads', eventId: 12 }), null);
  assert.equal(testHarness.messages.length, 1);
  assert.deepEqual(testHarness.calls, []);
});

test('cancelled file picker never calls the engine', async () => {
  const testHarness = harness({ selection: { canceled: true, filePaths: [] } });
  assert.equal(await quarantineDownloadedFile({ ...testHarness, window: {}, downloadsPath: 'Downloads', eventId: 12 }), null);
  assert.deepEqual(testHarness.calls, []);
});

test('restoration also requires a separate confirmation', async () => {
  const testHarness = harness();
  const eventId = '31fbe893-4472-483e-83f3-7b3c7d5842b1';
  const result = await restoreDownloadedFile({ ...testHarness, window: {}, eventId });
  assert.equal(result.state, 'Restored');
  assert.deepEqual(testHarness.calls, [{ method: 'restoreDownloadedFile', data: { eventId } }]);
});

test('declining restoration does not call the engine', async () => {
  const testHarness = harness({ confirmation: 0 });
  assert.equal(await restoreDownloadedFile({ ...testHarness, window: {}, eventId: '31fbe893-4472-483e-83f3-7b3c7d5842b1' }), null);
  assert.deepEqual(testHarness.calls, []);
});
