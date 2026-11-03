const assert = require('node:assert/strict');
const test = require('node:test');
const { EventEmitter } = require('node:events');
const { PIPE_PATH, parseServiceStatusLine, readServiceStatus } = require('../electron/service-status.cjs');

test('service status parser requires a versioned running response with a fresh collection', () => {
  const now = Date.parse('2026-11-03T12:00:00.000Z');
  const line = JSON.stringify({ id: 'desktop-health', version: 1, ok: true, result: { state: 'running', lastCollectionAtUtc: '2026-11-03T11:59:45.000Z' } });
  assert.deepEqual(parseServiceStatusLine(line, now), { available: true, state: 'running', lastCollectionAtUtc: '2026-11-03T11:59:45.000Z' });
  assert.equal(parseServiceStatusLine(line.replace('running', 'stopped'), now).available, false);
  assert.equal(parseServiceStatusLine(line.replace('11:59:45', '11:59:00'), now).reason, 'stale-heartbeat');
  assert.equal(parseServiceStatusLine(line.replace('11:59:45', '12:00:05'), now).reason, 'stale-heartbeat');
  assert.equal(parseServiceStatusLine('x'.repeat(4097), now).reason, 'invalid-response');
});

test('service query does not attempt a pipe connection outside Windows', async () => {
  let connected = false;
  const status = await readServiceStatus({ platform: 'linux', connect: () => { connected = true; } });
  assert.deepEqual(status, { available: false, reason: 'unsupported-platform' });
  assert.equal(connected, false);
  assert.equal(PIPE_PATH, String.raw`\\.\pipe\SentinelAI.Service.Status.v1`);
});

test('Windows service query sends only the versioned status request and returns a fresh response', async () => {
  const socket = new EventEmitter();
  socket.setEncoding = encoding => assert.equal(encoding, 'utf8');
  socket.destroy = () => {};
  socket.write = request => {
    assert.equal(request, '{"id":"desktop-health","version":1,"method":"status"}\n');
    process.nextTick(() => socket.emit('data', JSON.stringify({ id: 'desktop-health', version: 1, ok: true, result: { state: 'running', lastCollectionAtUtc: new Date().toISOString() } }) + '\n'));
  };
  const status = await readServiceStatus({ platform: 'win32', connect: pipe => { assert.equal(pipe, PIPE_PATH); process.nextTick(() => socket.emit('connect')); return socket; } });
  assert.equal(status.available, true);
  assert.equal(status.state, 'running');
});
