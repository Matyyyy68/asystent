const test = require('node:test');
const assert = require('node:assert/strict');
const { requestEnterpriseContextConsent } = require('../electron/enterprise-context-consent.cjs');

test('does not show a native consent dialog when Enterprise sharing is unavailable', async () => {
  let prompts = 0;
  const allowed = await requestEnterpriseContextConsent(
    async () => ({ paired: true, sharingMetadata: false, server: 'https://sentinel.example' }),
    async () => { prompts++; return true; });
  assert.equal(allowed, false);
  assert.equal(prompts, 0);
});

test('requires a separate affirmative response for every Enterprise context send', async () => {
  let prompts = 0;
  const status = async () => ({ paired: true, sharingMetadata: true, server: 'https://sentinel.example' });
  const allowed = await requestEnterpriseContextConsent(status, async server => {
    prompts++;
    assert.equal(server, 'https://sentinel.example');
    return false;
  });
  assert.equal(allowed, false);
  assert.equal(prompts, 1);
});

test('allows Enterprise context only after native dialog confirmation', async () => {
  const allowed = await requestEnterpriseContextConsent(
    async () => ({ paired: true, sharingMetadata: true, server: 'https://sentinel.example' }),
    async () => true);
  assert.equal(allowed, true);
});

test('does not ask for Enterprise consent when the user declines in native UI', async () => {
  const allowed = await requestEnterpriseContextConsent(
    async () => ({ paired: false, sharingMetadata: false, server: null }),
    async () => { throw new Error('The dialog must not appear for an unpaired device.'); });
  assert.equal(allowed, false);
});
