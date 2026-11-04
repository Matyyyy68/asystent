function isDomainEvent(event) {
  return event.source === 'browser-extension' ||
    (event.evidenceCodes?.some(code => code.startsWith('dns.') || code.startsWith('url.') || code.startsWith('reputation.cert')) ?? false);
}

export function groupHistoryEvents(events, query = '') {
  const groups = new Map();
  const eventOrigins = new Map();
  for (const event of events) {
    if (typeof event.eventId !== 'string' || !event.eventId) continue;
    const eventId = event.eventId.toLocaleLowerCase();
    const origins = eventOrigins.get(eventId) ?? new Set();
    origins.add(Number.isSafeInteger(event.serviceEventId) ? 'service' : 'user');
    eventOrigins.set(eventId, origins);
  }
  const crossStoreDuplicates = new Set([...eventOrigins]
    .filter(([, origins]) => origins.has('service') && origins.has('user'))
    .map(([eventId]) => eventId));
  for (const event of events) {
    const duplicateId = typeof event.eventId === 'string' ? event.eventId.toLocaleLowerCase() : null;
    const correlationId = typeof event.correlationId === 'string' && event.correlationId.length > 0
      ? event.correlationId : null;
    const duplicate = duplicateId && crossStoreDuplicates.has(duplicateId);
    const key = duplicate ? `duplicate:${duplicateId}` : correlationId ? `correlation:${correlationId}` : `event:${event.id}`;
    let group = groups.get(key);
    if (!group) {
      group = { key, kind: duplicate ? 'duplicate' : correlationId ? (isDomainEvent(event) ? 'domain' : 'process') : 'single', events: [] };
      groups.set(key, group);
    }
    group.events.push(event);
  }

  const normalizedQuery = query.trim().toLocaleLowerCase();
  return [...groups.values()].filter(group => !normalizedQuery ||
    group.events.some(event => JSON.stringify(event).toLocaleLowerCase().includes(normalizedQuery)));
}
