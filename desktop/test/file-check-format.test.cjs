'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { formatFileCheckResult } = require('../electron/file-check-format.cjs');

test('reports reputation and Authenticode as separate observations', () => {
  assert.equal(formatFileCheckResult({ name: 'installer.exe', matched: false, signatureStatus: 'Valid' }),
    'brak dopasowania lokalnej listy; podpis prawidłowy — installer.exe');
  assert.equal(formatFileCheckResult({ name: 'dropper.exe', matched: true, signatureStatus: 'NotSigned' }),
    'dopasowanie lokalnej listy; brak podpisu — dropper.exe');
});

test('does not describe untrusted or mismatched signatures as safe', () => {
  assert.equal(formatFileCheckResult({ name: 'sample.exe', matched: false, signatureStatus: 'NotTrusted' }),
    'brak dopasowania lokalnej listy; certyfikat podpisu niezaufany — sample.exe');
  assert.equal(formatFileCheckResult({ name: 'sample.exe', matched: false, signatureStatus: 'HashMismatch' }),
    'brak dopasowania lokalnej listy; podpis niezgodny z plikiem — sample.exe');
});

test('bounds and sanitizes the displayed filename and handles unavailable results', () => {
  assert.equal(formatFileCheckResult({ name: 'bad\nname.exe', matched: false, signatureStatus: 'Unexpected' }),
    'brak dopasowania lokalnej listy; stan podpisu nieznany — bad name.exe');
  assert.equal(formatFileCheckResult({ name: 'x'.repeat(200), error: 'failure' }), `Nie sprawdzono — ${'x'.repeat(160)}`);
});
