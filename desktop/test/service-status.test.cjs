const assert = require('node:assert/strict');
const test = require('node:test');
const { EventEmitter } = require('node:events');
const { PIPE_PATH, parseServiceStatusLine, parseServiceEventsLine, readServiceStatus, readServiceEvents, updateServiceEventStatus } = require('../electron/service-status.cjs');

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

test('service events parser accepts only bounded, typed event summaries', () => {
  const event = { id: 1, timestamp: '2026-11-04T12:00:00.000Z', risk: 'Moderate', status: 'New',
    category: 'Process', application: 'Synthetic', explanation: 'Test only', recommendation: 'Review' };
  const valid = parseServiceEventsLine(JSON.stringify({ id: 'desktop-events', version: 1, ok: true, result: { events: [event] } }));
  assert.equal(valid.available, true);
  assert.deepEqual(valid.events, [event]);
  assert.equal(parseServiceEventsLine(JSON.stringify({ id: 'desktop-events', version: 1, ok: true, result: { events: [{ ...event, risk: 'Unknown' }] } })).available, false);
  assert.equal(parseServiceEventsLine(JSON.stringify({ id: 'desktop-events', version: 1, ok: true, result: { events: Array(13).fill(event) } })).available, false);
  assert.equal(parseServiceEventsLine('x'.repeat(32769)).available, false);
});

test('service event history and status writes use bounded versioned pipe requests', async () => {
  const event = { id: 2, timestamp: '2026-11-04T12:00:00.000Z', risk: 'Low', status: 'New',
    category: 'Synthetic', application: 'Test', explanation: 'Fixture', recommendation: 'Review' };
  let request = '';
  let response = { id: 'desktop-events', version: 1, ok: true, result: { events: [event] } };
  const connect = pipe => {
    assert.equal(pipe, PIPE_PATH);
    const socket = new EventEmitter();
    socket.setEncoding = () => {};
    socket.destroy = () => {};
    socket.write = value => { request = value; process.nextTick(() => socket.emit('data', JSON.stringify(response) + '\n')); };
    process.nextTick(() => socket.emit('connect'));
    return socket;
  };

  assert.deepEqual(await readServiceEvents({ platform: 'win32', connect }), { available: true, events: [event] });
  assert.equal(request, '{"id":"desktop-events","version":1,"method":"recentEvents"}\n');

  response = { id: 'desktop-event-status', version: 1, ok: true, result: { updated: true } };
  assert.deepEqual(await updateServiceEventStatus(2, 'Reviewed', { platform: 'win32', connect }), { available: true });
  assert.equal(JSON.parse(request).eventId, 2);
  assert.equal(JSON.parse(request).status, 'Reviewed');
  assert.equal((await updateServiceEventStatus(0, 'New', { platform: 'win32', connect })).reason, 'invalid-request');
});
