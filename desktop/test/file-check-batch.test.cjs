'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createFileCheckBatcher, MAX_BATCH_SIZE } = require('../electron/file-check-batch.cjs');

test('groups distinct context-menu file invocations and deduplicates repeated paths', async () => {
  const batches = [];
  const batcher = createFileCheckBatcher(async paths => { batches.push(paths); return paths.length; }, { delayMs: 10 });
  const results = await Promise.all([
    batcher.enqueue('C:\\one.exe'),
    batcher.enqueue('C:\\two.exe'),
    batcher.enqueue('C:\\one.exe')
  ]);
  assert.deepEqual(batches, [['C:\\one.exe', 'C:\\two.exe']]);
  assert.deepEqual(results, [2, 2, 2]);
  batcher.dispose();
});

test('bounds each verification batch and drains the rest in a later batch', async () => {
  const batches = [];
  const batcher = createFileCheckBatcher(async paths => { batches.push(paths); return true; }, { delayMs: 0 });
  const paths = Array.from({ length: MAX_BATCH_SIZE + 2 }, (_, i) => `C:\\${i}.exe`);
  await Promise.all(paths.map(filePath => batcher.enqueue(filePath)));
  assert.deepEqual(batches.map(batch => batch.length), [MAX_BATCH_SIZE, 2]);
  batcher.dispose();
});

test('keeps requests arriving during an active batch queued until the engine is free', async () => {
  const batches = [];
  let releaseFirst;
  let startedFirst;
  const firstStarted = new Promise(resolve => { startedFirst = resolve; });
  const firstGate = new Promise(resolve => { releaseFirst = resolve; });
  const batcher = createFileCheckBatcher(async paths => {
    batches.push(paths);
    if (batches.length === 1) { startedFirst(); await firstGate; }
    return true;
  }, { delayMs: 0 });
  const first = batcher.enqueue('C:\\first.exe');
  await firstStarted;
  assert.equal(batcher.isIdle(), false);
  const second = batcher.enqueue('C:\\second.exe');
  releaseFirst();
  await Promise.all([first, second]);
  assert.deepEqual(batches, [['C:\\first.exe'], ['C:\\second.exe']]);
  assert.equal(batcher.isIdle(), true);
  batcher.dispose();
});

test('rejects malformed paths and resolves queued requests on disposal', async () => {
  const batcher = createFileCheckBatcher(async () => true, { delayMs: 1000 });
  assert.equal(await batcher.enqueue('--minimized'), false);
  assert.equal(await batcher.enqueue('x'.repeat(32761)), false);
  const pending = batcher.enqueue('C:\\pending.exe');
  batcher.dispose();
  assert.equal(await pending, false);
});
