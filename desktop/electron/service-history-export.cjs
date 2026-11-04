const fs = require('node:fs/promises');
const { randomUUID } = require('node:crypto');

const PAGE_SIZE = 12;
const SERVICE_HISTORY_LIMIT = 500;

async function readRetainedServiceHistory(readPage, { pageSize = PAGE_SIZE, maxItems = SERVICE_HISTORY_LIMIT } = {}) {
  const events = [];
  const seen = new Set();
  let beforeEventId;
  while (events.length < maxItems) {
    let page;
    try { page = await readPage(beforeEventId === undefined ? {} : { beforeEventId }); }
    catch { return { available: false, events: [] }; }
    if (!page?.available || !Array.isArray(page.events)) return { available: false, events: [] };
    for (const event of page.events) {
      if (!Number.isSafeInteger(event?.id) || event.id <= 0 || seen.has(event.id)) continue;
      seen.add(event.id);
      events.push(event);
      if (events.length >= maxItems) break;
    }
    if (page.events.length < pageSize || page.events.length === 0) break;
    const lastId = page.events.at(-1)?.id;
    if (!Number.isSafeInteger(lastId) || lastId <= 0 || lastId === beforeEventId) break;
    beforeEventId = lastId;
  }
  return { available: true, events };
}

async function includeServiceHistoryInJsonExport(filePath, readPage) {
  const history = await readRetainedServiceHistory(readPage);
  if (!history.available || history.events.length === 0) return { included: false, count: 0, available: history.available };
  const localEvents = JSON.parse(await fs.readFile(filePath, 'utf8'));
  if (!Array.isArray(localEvents)) throw new Error('Nieprawidłowy format eksportu historii.');
  const serviceEvents = history.events.map(event => ({
    id: `service-${event.id}`,
    timestamp: event.timestamp,
    processedAt: null,
    risk: event.risk,
    category: event.category,
    application: event.application,
    explanation: event.explanation,
    recommendation: event.recommendation,
    status: event.status,
    eventId: event.eventId ?? null,
    source: event.source ?? null,
    ruleVersion: event.ruleVersion ?? null,
    confidence: event.confidence ?? null,
    schemaVersion: event.schemaVersion ?? 1,
    processId: event.processId ?? null,
    processName: event.processName ?? null,
    correlationId: event.correlationId ?? null,
    evidenceCodes: event.evidenceCodes ?? [],
    analysisLimitations: event.analysisLimitations ?? [],
    observations: [],
    origin: 'system-service'
  }));
  const combined = [...localEvents.map(event => ({ ...event, origin: 'user-engine' })), ...serviceEvents];
  combined.sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
  const temporaryPath = `${filePath}.${randomUUID()}.tmp`;
  try {
    await fs.writeFile(temporaryPath, JSON.stringify(combined), { flag: 'wx' });
    await fs.rename(temporaryPath, filePath);
  } catch (error) {
    await fs.rm(temporaryPath, { force: true }).catch(() => {});
    throw error;
  }
  return { included: true, count: serviceEvents.length, available: true };
}

function csvField(value) {
  let text = value == null ? '' : String(value);
  if (/^[\s\u0000-\u001f]*[=+@-]/u.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}

async function includeServiceHistoryInCsvExport(filePath, readPage) {
  const history = await readRetainedServiceHistory(readPage);
  if (!history.available || history.events.length === 0) return { included: false, count: 0, available: history.available };
  const original = await fs.readFile(filePath);
  const text = original.toString('utf8').replace(/^\uFEFF/u, '');
  const expectedHeader = 'id,timestamp_utc,processed_at_utc,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,analysis_limitations,observations,origin';
  if (text.slice(0, text.indexOf('\n')).replace(/\r$/u, '') !== expectedHeader)
    throw new Error('Nieprawidłowy nagłówek eksportu CSV.');
  const rows = history.events.map(event => [
    `service-${event.id}`, event.timestamp, '', event.risk, event.category, event.application, event.explanation,
    event.recommendation, event.status, event.eventId, event.source, event.ruleVersion, event.confidence,
    event.schemaVersion ?? 1, event.processId, event.processName, event.correlationId,
    (event.evidenceCodes ?? []).join('|'), JSON.stringify(event.analysisLimitations ?? []), '[]', 'system-service'
  ].map(csvField).join(','));
  const separator = text.endsWith('\n') ? '' : '\r\n';
  const output = Buffer.concat([Buffer.from('\uFEFF', 'utf8'), Buffer.from(text + separator + rows.join('\r\n') + '\r\n', 'utf8')]);
  const temporaryPath = `${filePath}.${randomUUID()}.tmp`;
  try {
    await fs.writeFile(temporaryPath, output, { flag: 'wx' });
    await fs.rename(temporaryPath, filePath);
  } catch (error) {
    await fs.rm(temporaryPath, { force: true }).catch(() => {});
    throw error;
  }
  return { included: true, count: rows.length, available: true };
}

module.exports = { PAGE_SIZE, SERVICE_HISTORY_LIMIT, readRetainedServiceHistory, includeServiceHistoryInJsonExport, includeServiceHistoryInCsvExport };
