'use strict';

const MAX_BATCH_SIZE = 15;

function createFileCheckBatcher(onBatch, { delayMs = 350 } = {}) {
  if (typeof onBatch !== 'function') throw new TypeError('onBatch must be a function');
  if (!Number.isInteger(delayMs) || delayMs < 0 || delayMs > 5000) throw new RangeError('Invalid batch delay');

  let pending = new Map();
  let timer = null;
  let running = false;
  let closed = false;

  const schedule = delay => {
    if (closed || timer || pending.size === 0) return;
    timer = setTimeout(() => { timer = null; void flush(); }, delay);
  };

  async function flush() {
    if (closed || running || pending.size === 0) return;
    if (timer) { clearTimeout(timer); timer = null; }
    running = true;
    const batch = [...pending.entries()].slice(0, MAX_BATCH_SIZE);
    for (const [filePath] of batch) pending.delete(filePath);
    let result;
    try { result = await onBatch(batch.map(([filePath]) => filePath)); }
    catch (error) { result = { error: String(error?.message || 'Błąd sprawdzania').slice(0, 500) }; }
    for (const [, resolvers] of batch) for (const resolve of resolvers) resolve(result);
    running = false;
    schedule(pending.size ? 0 : delayMs);
  }

  return {
    enqueue(filePath) {
      if (closed || typeof filePath !== 'string' || filePath.length === 0 || filePath.length > 32760 || filePath.startsWith('--'))
        return Promise.resolve(false);
      return new Promise(resolve => {
        const resolvers = pending.get(filePath) || [];
        resolvers.push(resolve);
        pending.set(filePath, resolvers);
        schedule(pending.size >= MAX_BATCH_SIZE ? 0 : delayMs);
      });
    },
    flush,
    isIdle() { return !running && pending.size === 0; },
    dispose() {
      closed = true;
      if (timer) clearTimeout(timer);
      timer = null;
      for (const resolvers of pending.values()) for (const resolve of resolvers) resolve(false);
      pending.clear();
    }
  };
}

module.exports = { createFileCheckBatcher, MAX_BATCH_SIZE };
