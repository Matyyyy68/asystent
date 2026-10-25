const assert = require('node:assert/strict');
const test = require('node:test');
const { shouldShowInitialWindow } = require('../electron/window-visibility.cjs');

test('normal launch shows the main window', () => {
  assert.equal(shouldShowInitialWindow(['electron', 'main.cjs']), true);
});

test('Windows autostart with --minimized never creates a visible window', () => {
  assert.equal(shouldShowInitialWindow(['electron', 'main.cjs', '--minimized']), false);
});

test('headless smoke mode remains hidden', () => {
  assert.equal(shouldShowInitialWindow(['electron', 'main.cjs', '--smoke-test']), false);
});
