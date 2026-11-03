const net = require('node:net');

const PIPE_PATH = String.raw`\\.\pipe\SentinelAI.Service.Status.v1`;

function parseServiceStatusLine(line, now = Date.now()) {
  if (typeof line !== 'string' || line.length > 4096) return { available: false, reason: 'invalid-response' };
  try {
    const response = JSON.parse(line);
    if (response?.version !== 1 || response?.id !== 'desktop-health' || response?.ok !== true ||
        response?.result?.state !== 'running' || typeof response?.result?.lastCollectionAtUtc !== 'string')
      return { available: false, reason: 'invalid-response' };
    const timestamp = Date.parse(response.result.lastCollectionAtUtc);
    if (!Number.isFinite(timestamp) || timestamp > now || now - timestamp > 30000)
      return { available: false, reason: 'stale-heartbeat' };
    return { available: true, state: 'running', lastCollectionAtUtc: new Date(timestamp).toISOString() };
  } catch {
    return { available: false, reason: 'invalid-response' };
  }
}

function readServiceStatus({ platform = process.platform, connect = net.createConnection, timeoutMs = 2500 } = {}) {
  if (platform !== 'win32') return Promise.resolve({ available: false, reason: 'unsupported-platform' });
  return new Promise(resolve => {
    let settled = false;
    let buffer = '';
    const finish = value => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(value);
    };
    const socket = connect(PIPE_PATH);
    const timer = setTimeout(() => finish({ available: false, reason: 'timeout' }), timeoutMs);
    socket.setEncoding('utf8');
    socket.on('connect', () => socket.write('{"id":"desktop-health","version":1,"method":"status"}\n'));
    socket.on('data', chunk => {
      buffer += chunk;
      if (buffer.length > 4096) return finish({ available: false, reason: 'invalid-response' });
      const newline = buffer.indexOf('\n');
      if (newline >= 0) finish(parseServiceStatusLine(buffer.slice(0, newline).replace(/\r$/, '')));
    });
    socket.on('error', () => finish({ available: false, reason: 'unavailable' }));
    socket.on('end', () => finish(parseServiceStatusLine(buffer.replace(/\r?\n$/, ''))));
  });
}

module.exports = { PIPE_PATH, parseServiceStatusLine, readServiceStatus };
