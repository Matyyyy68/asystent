const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const warningSource = readFileSync(path.resolve(__dirname, '../../browser-extension/warning.js'), 'utf8');

function bootWarning(details, stopResult = { ok: true }) {
  const elements = new Map();
  const requests = [];
  for (const id of ['signals', 'rule-version', 'warning-title', 'warning-description', 'warning-footnote',
    'continue', 'stop-download', 'download-action-status', 'close']) {
    elements.set(id, {
      hidden: id === 'stop-download' || id === 'download-action-status',
      disabled: false,
      textContent: '',
      children: [],
      listeners: {},
      append(child) { this.children.push(child); },
      addEventListener(event, listener) { this.listeners[event] = listener; }
    });
  }
  const chrome = {
    runtime: {
      sendMessage: async (message) => {
        requests.push(message);
        if (message.type === 'details') return details;
        if (message.type === 'stop-download') return stopResult;
        return { ok: true };
      }
    }
  };
  vm.runInNewContext(warningSource, {
    chrome,
    document: { getElementById: (id) => elements.get(id), createElement: () => ({ textContent: '' }) },
    location: { search: '?token=warning-token' },
    URLSearchParams,
    Promise
  }, { filename: 'browser-extension/warning.js' });
  return { elements, requests };
}

test('download warning exposes the stop action and reports when the browser cannot cancel', async () => {
  const { elements, requests } = bootWarning({ kind: 'download', canStopDownload: true, indicators: [] }, { ok: false });
  await new Promise((resolve) => setImmediate(resolve));

  const stop = elements.get('stop-download');
  assert.equal(stop.hidden, false);
  assert.equal(elements.get('continue').hidden, true);
  await stop.listeners.click();
  assert.equal(stop.disabled, true);
  assert.equal(elements.get('download-action-status').hidden, false);
  assert.match(elements.get('download-action-status').textContent, /Sprawdź stan pobierania/);
  assert.deepEqual(requests.map((request) => request.type), ['details', 'stop-download']);
  assert.equal(requests[1].token, 'warning-token');
});

test('download warning confirms the browser accepted a cancellation request', async () => {
  const { elements } = bootWarning({ kind: 'download', canStopDownload: true, indicators: [] });
  await new Promise((resolve) => setImmediate(resolve));
  await elements.get('stop-download').listeners.click();
  assert.match(elements.get('download-action-status').textContent, /przyjęła polecenie zatrzymania/);
  assert.match(elements.get('download-action-status').textContent, /plik trzeba usunąć ręcznie/);
});

test('navigation warning does not expose the download cancellation action', async () => {
  const { elements } = bootWarning({ kind: 'navigation', canStopDownload: false, indicators: [] });
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(elements.get('stop-download').hidden, true);
  assert.equal(elements.get('continue').hidden, false);
});
