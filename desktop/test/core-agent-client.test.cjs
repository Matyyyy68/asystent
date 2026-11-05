const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const test = require('node:test');
const { CoreAgentClient, PIPE_PATH, resolvePipePath, sanitizeCoreEngineDiagnostics } = require('../electron/core-agent-client.cjs');

class MockPipe extends EventEmitter {
  write(line) {
    const request = JSON.parse(line);
    const result = request.method === 'coreEngineDiagnostics'
      ? { engineProcessRunning: false, engineLastExitCode: -532462766, engineStderrObserved: true,
        engineExceptionType: 'System.IO.IOException', message: 'private path C:\\Users\\Alice\\secret.txt' }
      : { engine: 'ready' };
    queueMicrotask(() => this.emit('data', Buffer.from(JSON.stringify({ id: request.id, ok: true, result }) + '\n')));
  }
  destroy() { this.destroyed = true; }
}

test('Core Agent client launches the detached user agent and sends versioned IPC through the named pipe', async () => {
  const launches = [];
  const client = new CoreAgentClient('Sentinel.Agent.exe', {
    spawnProcess: (...args) => { launches.push(args); return { unref() { launches[0].unreferenced = true; } }; },
    connectPipe: () => { const pipe = new MockPipe(); queueMicrotask(() => pipe.emit('connect')); return pipe; }
  });
  client.start();
  assert.equal(launches.length, 1);
  assert.equal(launches[0][0], 'Sentinel.Agent.exe');
  assert.deepEqual(launches[0][2], { detached: true, windowsHide: true, stdio: 'ignore' });
  assert.equal(launches[0].unreferenced, true);
  assert.equal(PIPE_PATH, resolvePipePath());
  assert.equal(resolvePipePath('RDP-Tcp#0'), '\\\\.\\pipe\\SentinelAI.Engine.v1.RDP-Tcp_0');
  assert.deepEqual(await client.call('status'), { engine: 'ready' });
  assert.equal(client.diagnostics().status, 'ready');
  client.dispose();
  assert.equal(client.diagnostics().status, 'stopped');
});

test('Core Agent client returns only sanitized Engine failure diagnostics', async () => {
  const client = new CoreAgentClient('Sentinel.Agent.exe', {
    spawnProcess: () => ({ unref() {} }),
    connectPipe: () => { const pipe = new MockPipe(); queueMicrotask(() => pipe.emit('connect')); return pipe; }
  });
  assert.deepEqual(await client.call('coreEngineDiagnostics'), {
    engineProcessRunning: false,
    engineLastExitCode: '-532462766',
    engineStderrObserved: true,
    engineExceptionType: 'System.IO.IOException'
  });
  client.dispose();
});

test('Core Agent client permits a retry after an asynchronous process launch error', () => {
  const children = [];
  let nowMs = 0;
  const client = new CoreAgentClient('Sentinel.Agent.exe', {
    nowMs: () => nowMs,
    spawnProcess: () => { const child = new EventEmitter(); child.unref = () => {}; children.push(child); return child; }
  });
  client.start();
  children[0].emit('error', Object.assign(new Error('spawn failed'), { code: 'ENOENT' }));
  client.start();
  assert.equal(children.length, 1, 'launch retries must respect backoff');
  nowMs = 1000;
  client.start();
  assert.equal(children.length, 2);
  assert.equal(client.diagnostics().status, 'restarting');
  client.dispose();
});

test('Core Agent client does not retry completed engine errors', async () => {
  let attempts = 0;
  const client = new CoreAgentClient('Sentinel.Agent.exe', {
    spawnProcess: () => ({ unref() {} }),
    connectPipe: () => {
      attempts++;
      const pipe = new EventEmitter();
      pipe.write = line => {
        const request = JSON.parse(line);
        queueMicrotask(() => pipe.emit('data', Buffer.from(JSON.stringify({ id: request.id, ok: false, error: 'Invalid file path' }) + '\n')));
      };
      pipe.destroy = () => {};
      queueMicrotask(() => pipe.emit('connect'));
      return pipe;
    }
  });
  await assert.rejects(client.call('file'), /Invalid file path/);
  assert.equal(attempts, 1);
  client.dispose();
});

test('sanitizes Agent Engine diagnostics to bounded, non-sensitive status fields', () => {
  assert.deepEqual(sanitizeCoreEngineDiagnostics({
    engineProcessRunning: false,
    engineLastExitCode: -532462766,
    engineStderrObserved: true,
    engineExceptionType: 'System.IO.IOException',
    message: 'private path C:\\Users\\Alice\\secret.txt'
  }), {
    engineProcessRunning: false,
    engineLastExitCode: '-532462766',
    engineStderrObserved: true,
    engineExceptionType: 'System.IO.IOException'
  });
  assert.deepEqual(sanitizeCoreEngineDiagnostics({
    engineLastExitCode: 0x1_0000_0000,
    engineExceptionType: 'System.Exception C:\\private'
  }), {
    engineProcessRunning: null,
    engineLastExitCode: null,
    engineStderrObserved: false,
    engineExceptionType: null
  });
});
