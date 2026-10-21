const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough, Writable } = require('node:stream');
const test = require('node:test');
const { EngineClient } = require('../electron/engine-client.cjs');

function makeEngine() {
  const child = new EventEmitter();
  child.pid = 123;
  child.exitCode = null;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.stdin = new Writable({
    write(chunk, _encoding, callback) {
      const request = JSON.parse(chunk.toString().trim());
      setImmediate(() => {
        child.stdout.write(JSON.stringify({ id: request.id, ok: true, result: { method: request.method } }) + '\n');
        callback();
      });
    }
  });
  child.kill = () => {
    child.exitCode = 0;
    child.emit('exit', 0, null);
  };
  return child;
}

test('restarts the engine with backoff and serves requests after recovery', async () => {
  const engines = [];
  const timers = new Map();
  const states = [];
  let nextTimer = 0;
  const client = new EngineClient('engine.exe', {
    spawnProcess: () => { const child = makeEngine(); engines.push(child); return child; },
    setTimer: (callback, delay) => { const id = ++nextTimer; timers.set(id, { callback, delay }); return id; },
    clearTimer: id => timers.delete(id),
    onState: state => states.push(state.status)
  });

  client.start();
  assert.deepEqual(await client.call('status'), { method: 'status' });
  engines[0].emit('exit', 23, null);
  assert.equal(client.status, 'restarting');
  assert.deepEqual(client.diagnostics(), { status: 'restarting', lastExitCode: '23', stderrObserved: false, stderrExceptionType: null });
  assert.equal(timers.size, 1);
  const [restartId, restart] = timers.entries().next().value;
  assert.equal(restart.delay, 1000);
  timers.delete(restartId);
  restart.callback();
  assert.equal(engines.length, 2);
  assert.deepEqual(await client.call('collect'), { method: 'collect' });
  assert.equal(client.status, 'ready');
  assert.deepEqual(states, ['starting', 'starting', 'ready', 'restarting', 'restarting', 'ready']);
  client.dispose();
  assert.equal(client.status, 'stopped');
  assert.equal(timers.size, 0);
});

test('does not restart after shutdown and rejects outstanding requests on child exit', async () => {
  const timers = new Map();
  const engines = [];
  let nextTimer = 0;
  const client = new EngineClient('engine.exe', {
    spawnProcess: () => {
      const child = makeEngine();
      child.stdin = new Writable({ write(_chunk, _encoding, callback) { callback(); } });
      engines.push(child);
      return child;
    },
    setTimer: (callback, delay) => { const id = ++nextTimer; timers.set(id, { callback, delay }); return id; },
    clearTimer: id => timers.delete(id)
  });
  client.start();
  const pending = client.call('status');
  engines[0].emit('exit', 1, null);
  await assert.rejects(pending, /ponawianie uruchomienia/);
  assert.equal(timers.size, 1);
  const [firstId, firstRetry] = timers.entries().next().value;
  assert.equal(firstRetry.delay, 1000);
  timers.delete(firstId);
  firstRetry.callback();
  engines[1].emit('exit', 2, null);
  assert.equal([...timers.values()][0].delay, 2000);
  client.dispose();
  assert.equal(timers.size, 0);
  assert.equal(client.status, 'stopped');
});

test('records a safe .NET exception type without exposing stderr contents', () => {
  const child = makeEngine();
  const client = new EngineClient('engine.exe', { spawnProcess: () => child });
  client.start();
  child.stderr.write('Unhandled exception. System.InvalidOperationException: private path or token\n   at C:\\private\\user\\path');
  assert.equal(client.stderrObserved, true);
  assert.deepEqual(client.diagnostics(), { status: 'starting', lastExitCode: null, stderrObserved: true, stderrExceptionType: 'System.InvalidOperationException' });
  assert.equal(JSON.stringify(client.diagnostics()).includes('private path'), false);
  assert.equal(JSON.stringify(client.diagnostics()).includes('user'), false);
  assert.equal(JSON.stringify(client.status).includes('private path'), false);
  client.dispose();
});

test('updates the diagnostic exception type after a later engine crash', () => {
  const engines = [];
  const timers = new Map();
  let nextTimer = 0;
  const client = new EngineClient('engine.exe', {
    spawnProcess: () => { const child = makeEngine(); engines.push(child); return child; },
    setTimer: (callback, delay) => { const id = ++nextTimer; timers.set(id, { callback, delay }); return id; },
    clearTimer: id => timers.delete(id)
  });

  client.start();
  engines[0].stderr.write('Unhandled exception. System.InvalidOperationException: private first message\n');
  engines[0].emit('exit', 1, null);
  assert.equal(client.diagnostics().stderrExceptionType, 'System.InvalidOperationException');

  const [restartId, restart] = timers.entries().next().value;
  timers.delete(restartId);
  restart.callback();
  engines[1].stderr.write('Unhandled exception. System.IO.IOException: private second message\n');

  const diagnostics = client.diagnostics();
  assert.equal(diagnostics.stderrExceptionType, 'System.IO.IOException');
  assert.equal(JSON.stringify(diagnostics).includes('private'), false);
  client.dispose();
});

test('kills and restarts a hung engine after a request timeout', async () => {
  const timers = new Map();
  let nextTimer = 0;
  const child = makeEngine();
  child.stdin = new Writable({ write(_chunk, _encoding, callback) { callback(); } });
  const client = new EngineClient('engine.exe', {
    spawnProcess: () => child,
    setTimer: (callback, delay) => { const id = ++nextTimer; timers.set(id, { callback, delay }); return id; },
    clearTimer: id => timers.delete(id)
  });
  client.start();
  const pending = client.call('collect');
  const [timeoutId, timeout] = [...timers.entries()].find(([, value]) => value.delay === 45000);
  timers.delete(timeoutId);
  timeout.callback();
  await assert.rejects(pending, /Przekroczono czas odpowiedzi/);
  assert.equal(child.exitCode, 0);
  assert.equal(client.status, 'restarting');
  assert.ok([...timers.values()].some(value => value.delay === 1000));
  client.dispose();
});
