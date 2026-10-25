const test = require('node:test');
const assert = require('node:assert/strict');

test('formats unsigned and signed Windows CLR exception exit codes as the same hex value', async () => {
  const { formatExitCode } = await import('../src/diagnostics-format.js');
  assert.equal(formatExitCode('3762504530'), '3762504530 (0xE0434352)');
  assert.equal(formatExitCode('-532462766'), '-532462766 (0xE0434352)');
});

test('keeps symbolic, missing, and out-of-range exit values readable', async () => {
  const { formatExitCode } = await import('../src/diagnostics-format.js');
  assert.equal(formatExitCode('response-timeout'), 'response-timeout');
  assert.equal(formatExitCode(null), 'brak');
  assert.equal(formatExitCode('4294967296'), '4294967296');
});
