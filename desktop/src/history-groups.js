function isDomainEvent(event) {
  return event.source === 'browser-extension' ||
    (event.evidenceCodes?.some(code => code.startsWith('dns.') || code.startsWith('url.') || code.startsWith('reputation.cert')) ?? false);
}

export function groupHistoryEvents(events, query = '') {
  const groups = new Map();
  for (const event of events) {
    const correlationId = typeof event.correlationId === 'string' && event.correlationId.length > 0
      ? event.correlationId : null;
    const key = correlationId ? `correlation:${correlationId}` : `event:${event.id}`;
    let group = groups.get(key);
    if (!group) {
      group = { key, kind: correlationId ? (isDomainEvent(event) ? 'domain' : 'process') : 'single', events: [] };
      groups.set(key, group);
    }
    group.events.push(event);
  }

  const normalizedQuery = query.trim().toLocaleLowerCase();
  return [...groups.values()].filter(group => !normalizedQuery ||
    group.events.some(event => JSON.stringify(event).toLocaleLowerCase().includes(normalizedQuery)));
}
