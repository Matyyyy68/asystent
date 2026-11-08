const test = require('node:test');
const assert = require('node:assert/strict');

test('incident analysis sends bounded normalized signals and excludes private event fields', async () => {
  const { buildIncidentAnalysisContext } = await import('../src/incident-ai-context.js');
  const context = buildIncidentAnalysisContext({
    kind: 'process',
    events: [{
      id: 'event-1', eventId: 'same-event', risk: 'Moderate', riskScore: 42,
      evidenceCodes: ['process.wmi.start-event', 'network.tcp.connection-snapshot', 'ignore this text'],
      application: 'private-app.exe', processImagePath: 'C:\\Users\\Mateusz\\private.exe',
      processImageSha256: 'A'.repeat(64), explanation: 'Private explanation containing secret.test',
      recommendation: 'Private recommendation'
    }]
  });
  assert.match(context, /process\.wmi\.start-event/);
  assert.match(context, /"ruleRisk":"Moderate"/);
  assert.match(context, /"ruleScore":42/);
  for (const secret of ['private-app.exe', 'Mateusz', 'private.exe', 'A'.repeat(64), 'secret.test', 'Private recommendation'])
    assert.equal(context.includes(secret), false, secret);
  assert.equal(context.includes('ignore this text'), false);
});

test('incident analysis deduplicates cross-store events and bounds count and evidence', async () => {
  const { buildIncidentAnalysisContext } = await import('../src/incident-ai-context.js');
  const events = Array.from({ length: 20 }, (_, index) => ({
    id: index, eventId: index < 2 ? 'duplicate' : `event-${index}`,
    risk: 'Critical', riskScore: 100,
    evidenceCodes: Array.from({ length: 40 }, (_, code) => `process.signal-${code}`)
  }));
  const payload = JSON.parse(buildIncidentAnalysisContext({ kind: 'process', events }).split('\n').at(-1));
  assert.equal(payload.events.length, 12);
  assert.equal(payload.omittedEventCount, 7);
  assert.equal(payload.events[0].evidenceCodes.length, 24);
  assert.equal(payload.events[0].sequence, 1);
});

test('invalid risk and arbitrary fields are discarded', async () => {
  const { buildIncidentAnalysisContext } = await import('../src/incident-ai-context.js');
  const payload = JSON.parse(buildIncidentAnalysisContext({ events: [{
    id: 1, risk: 'Critical! secret', riskScore: 101, evidenceCodes: ['bad code', { secret: true }]
  }]}).split('\n').at(-1));
  assert.equal('ruleRisk' in payload.events[0], false);
  assert.equal('ruleScore' in payload.events[0], false);
  assert.deepEqual(payload.events[0].evidenceCodes, []);
});

test('CERT reputation evidence is classified as web context', async () => {
  const { buildIncidentAnalysisContext } = await import('../src/incident-ai-context.js');
  const payload = JSON.parse(buildIncidentAnalysisContext({ kind: 'domain', events: [{
    id: 7, evidenceCodes: ['reputation.cert.match']
  }]}).split('\n').at(-1));
  assert.equal(payload.events[0].sourceFamily, 'web');
});
