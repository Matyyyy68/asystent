const SMOKE_TEST_TIMEOUT_MS = 60_000;

function watchSmokeTestWindow(webContents, reportFailure, options = {}) {
  const schedule = options.setTimeout ?? setTimeout;
  const cancel = options.clearTimeout ?? clearTimeout;
  const timeoutMs = options.timeoutMs ?? SMOKE_TEST_TIMEOUT_MS;
  let settled = false;
  let testTimer;

  const removeListeners = () => {
    webContents.removeListener('did-fail-load', onFailLoad);
    webContents.removeListener('render-process-gone', onRendererGone);
  };
  const fail = message => {
    if (settled) return;
    settled = true;
    cancel(testTimer);
    removeListeners();
    reportFailure(message);
  };
  const onFailLoad = (_event, errorCode, _description, _url, isMainFrame) => {
    if (isMainFrame !== true) return;
    const code = Number.isInteger(errorCode) ? String(errorCode) : 'unknown';
    fail(`Smoke test failed to load its main frame (net error ${code}).`);
  };
  const onRendererGone = (_event, details = {}) => {
    const reason = typeof details.reason === 'string' && /^[a-z-]{1,32}$/i.test(details.reason)
      ? details.reason : 'unknown';
    const exitCode = Number.isInteger(details.exitCode) ? String(details.exitCode) : 'unknown';
    fail(`Smoke test renderer exited (reason ${reason}, code ${exitCode}).`);
  };

  webContents.on('did-fail-load', onFailLoad);
  webContents.on('render-process-gone', onRendererGone);
  testTimer = schedule(() => fail('Smoke test did not complete within the 60-second limit.'), timeoutMs);

  return () => {
    if (settled) return;
    settled = true;
    cancel(testTimer);
    removeListeners();
  };
}

module.exports = { SMOKE_TEST_TIMEOUT_MS, watchSmokeTestWindow };
