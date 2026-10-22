const fs = require('node:fs');
const path = require('node:path');

const MAX_FAILURES = 64;
const EXCEPTION_TYPE = /^[A-Za-z][A-Za-z0-9_.+`]{0,159}Exception$/;

function safeFailure(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const occurredAt = new Date(value.occurredAtUtc);
  if (!Number.isFinite(occurredAt.getTime())) return null;
  const reasonCode = Number.isSafeInteger(value.reasonCode)
    ? String(value.reasonCode)
    : typeof value.reasonCode === 'string' && /^[A-Za-z0-9_-]{1,40}$/.test(value.reasonCode)
      ? value.reasonCode : 'unknown';
  const exceptionType = typeof value.exceptionType === 'string' && EXCEPTION_TYPE.test(value.exceptionType)
    ? value.exceptionType : null;
  return {
    occurredAtUtc: occurredAt.toISOString(),
    reasonCode,
    stderrObserved: value.stderrObserved === true,
    exceptionType
  };
}

function logPath(directory) {
  return path.join(directory, 'engine-lifecycle.jsonl');
}

function readFailures(directory) {
  try {
    return fs.readFileSync(logPath(directory), 'utf8').split(/\r?\n/)
      .map(line => { try { return safeFailure(JSON.parse(line)); } catch { return null; } })
      .filter(Boolean).slice(-MAX_FAILURES);
  } catch { return []; }
}

function recordFailure(directory, failure) {
  const safe = safeFailure(failure);
  if (!safe) return false;
  try {
    fs.mkdirSync(directory, { recursive: true });
    const retained = [...readFailures(directory), safe].slice(-MAX_FAILURES);
    fs.writeFileSync(logPath(directory), retained.map(item => JSON.stringify(item)).join('\n') + '\n', 'utf8');
    return true;
  } catch { return false; }
}

module.exports = { MAX_FAILURES, readFailures, recordFailure };
