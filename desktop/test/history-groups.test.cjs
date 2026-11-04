const test = require('node:test');
const assert = require('node:assert/strict');

test('groups domain observations from different sources without dropping events', async () => {
  const { groupHistoryEvents } = await import('../src/history-groups.js');
  const shared = 'correlation-domain-1';
  const events = [
    { id: 3, correlationId: shared, source: 'browser-extension', evidenceCodes: ['url.brand'], explanation: 'browser observation' },
    { id: 2, correlationId: shared, source: 'dns-cache', evidenceCodes: ['dns.windows-cache-entry'], explanation: 'DNS observation' },
    { id: 1, source: 'manual-analysis', evidenceCodes: ['text.credentials'], explanation: 'unrelated observation' }
  ];

  const groups = groupHistoryEvents(events);

  assert.equal(groups.length, 2);
  assert.equal(groups[0].kind, 'domain');
  assert.deepEqual(groups[0].events.map(event => event.id), [3, 2]);
  assert.equal(groups[1].kind, 'single');
  assert.equal(groups.flatMap(group => group.events).length, events.length);
});

test('groups process correlations separately from domain correlations', async () => {
  const { groupHistoryEvents } = await import('../src/history-groups.js');
  const events = [
    { id: 2, correlationId: 'process-1', source: 'tcp-connection-snapshot', evidenceCodes: ['network.tcp.connection-snapshot'] },
    { id: 1, correlationId: 'process-1', source: 'process-snapshot', evidenceCodes: ['process.snapshot.new-pid'] }
  ];

  const groups = groupHistoryEvents(events);

  assert.equal(groups.length, 1);
  assert.equal(groups[0].kind, 'process');
  assert.equal(groups[0].events.length, 2);
});

test('a search match keeps its entire correlated group available', async () => {
  const { groupHistoryEvents } = await import('../src/history-groups.js');
  const events = [
    { id: 2, correlationId: 'domain-2', source: 'browser-extension', explanation: 'URL warning' },
    { id: 1, correlationId: 'domain-2', source: 'dns-cache', explanation: 'DNS warning' },
    { id: 0, source: 'manual-analysis', explanation: 'different alert' }
  ];

  const groups = groupHistoryEvents(events, 'dns warning');

  assert.equal(groups.length, 1);
  assert.deepEqual(groups[0].events.map(event => event.id), [2, 1]);
});

test('groups matching event ids from user and service stores without dropping either record', async () => {
  const { groupHistoryEvents } = await import('../src/history-groups.js');
  const eventId = 'ba5b4950-bd6a-4c82-bb7b-479a9e26827d';
  const events = [
    { id: 'service-12', serviceEventId: 12, eventId, source: 'dns-operational', status: 'New' },
    { id: 44, eventId: eventId.toUpperCase(), source: 'dns-operational', status: 'Reviewed' },
    { id: 45, eventId: '4bd9c089-1f98-40ec-9bb0-22e88e7a47e2', source: 'dns-operational' }
  ];
  const groups = groupHistoryEvents(events);
  assert.equal(groups.length, 2);
  assert.equal(groups[0].kind, 'duplicate');
  assert.deepEqual(groups[0].events.map(event => event.id), ['service-12', 44]);
  assert.deepEqual(groups[1].events.map(event => event.id), [45]);
  assert.equal(groups.flatMap(group => group.events).length, events.length);
});

