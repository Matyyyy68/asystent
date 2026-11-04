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

function parseServiceEventsLine(line) {
  if (typeof line !== 'string' || line.length > 32768) return { available: false, reason: 'invalid-response', events: [] };
  try {
    const response = JSON.parse(line);
    const events = response?.result?.events;
    if (response?.version !== 1 || response?.id !== 'desktop-events' || response?.ok !== true ||
        !Array.isArray(events) || events.length > 12 || events.some(event =>
          !Number.isSafeInteger(event?.id) || event.id <= 0 || typeof event?.timestamp !== 'string' ||
          event.timestamp.length > 64 ||
          !Number.isFinite(Date.parse(event.timestamp)) ||
          !['Information', 'Low', 'Moderate', 'High', 'Critical'].includes(event?.risk) ||
          !['New', 'Reviewed', 'FalsePositive'].includes(event?.status) ||
          typeof event?.category !== 'string' || typeof event?.application !== 'string' ||
          typeof event?.explanation !== 'string' || typeof event?.recommendation !== 'string'))
      return { available: false, reason: 'invalid-response', events: [] };
    const truncate = (value, limit) => typeof value === 'string' ? value.slice(0, limit) : undefined;
    const guid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value) ? value : undefined;
    const stringList = (value, count, length) => Array.isArray(value)
      ? value.filter(item => typeof item === 'string').slice(0, count).map(item => item.slice(0, length)) : [];
    const safeEvents = events.map(event => ({
      id: event.id,
      timestamp: event.timestamp,
      risk: event.risk,
      status: event.status,
      category: truncate(event.category, 128),
      application: truncate(event.application, 128),
      explanation: truncate(event.explanation, 768),
      recommendation: truncate(event.recommendation, 512),
      eventId: guid(event.eventId),
      source: truncate(event.source, 64),
      ruleVersion: truncate(event.ruleVersion, 64),
      confidence: Number.isInteger(event.confidence) && event.confidence >= 0 && event.confidence <= 100 ? event.confidence : undefined,
      schemaVersion: Number.isInteger(event.schemaVersion) && event.schemaVersion > 0 ? event.schemaVersion : 1,
      processId: Number.isSafeInteger(event.processId) && event.processId > 0 ? event.processId : undefined,
      processName: truncate(event.processName, 128),
      correlationId: guid(event.correlationId),
      evidenceCodes: stringList(event.evidenceCodes, 12, 96),
      analysisLimitations: stringList(event.analysisLimitations, 8, 96)
    }));
    return { available: true, events: safeEvents };
  } catch {
    return { available: false, reason: 'invalid-response', events: [] };
  }
}

function queryServicePipe({ platform, connect, timeoutMs, request, maxResponseChars, parse }) {
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
    socket.on('connect', () => socket.write(request));
    socket.on('data', chunk => {
      buffer += chunk;
      if (buffer.length > maxResponseChars) return finish({ available: false, reason: 'invalid-response' });
      const newline = buffer.indexOf('\n');
      if (newline >= 0) finish(parse(buffer.slice(0, newline).replace(/\r$/, '')));
    });
    socket.on('error', () => finish({ available: false, reason: 'unavailable' }));
    socket.on('end', () => finish(parse(buffer.replace(/\r?\n$/, ''))));
  });
}

function readServiceStatus(options = {}) {
  return queryServicePipe({ platform: options.platform ?? process.platform, connect: options.connect ?? net.createConnection,
    timeoutMs: options.timeoutMs ?? 2500, request: '{"id":"desktop-health","version":1,"method":"status"}\n',
    maxResponseChars: 4096, parse: line => parseServiceStatusLine(line, options.now ?? Date.now()) });
}

function readServiceEvents(options = {}) {
  return queryServicePipe({ platform: options.platform ?? process.platform, connect: options.connect ?? net.createConnection,
    timeoutMs: options.timeoutMs ?? 2500, request: '{"id":"desktop-events","version":1,"method":"recentEvents"}\n',
    maxResponseChars: 32768, parse: parseServiceEventsLine });
}

function updateServiceEventStatus(eventId, status, options = {}) {
  if (!Number.isSafeInteger(eventId) || eventId <= 0 || !['Reviewed', 'FalsePositive'].includes(status))
    return Promise.resolve({ available: false, reason: 'invalid-request' });
  const request = JSON.stringify({ id: 'desktop-event-status', version: 1, method: 'eventStatus', eventId, status }) + '\n';
  const parse = line => {
    if (typeof line !== 'string' || line.length > 4096) return { available: false, reason: 'invalid-response' };
    try {
      const response = JSON.parse(line);
      if (response?.version !== 1 || response?.id !== 'desktop-event-status' || response?.ok !== true || response?.result?.updated !== true)
        return { available: false, reason: 'update-failed' };
      return { available: true };
    } catch { return { available: false, reason: 'invalid-response' }; }
  };
  return queryServicePipe({ platform: options.platform ?? process.platform, connect: options.connect ?? net.createConnection,
    timeoutMs: options.timeoutMs ?? 2500, request, maxResponseChars: 4096, parse });
}

module.exports = { PIPE_PATH, parseServiceStatusLine, parseServiceEventsLine, readServiceStatus, readServiceEvents, updateServiceEventStatus };
