const { readServiceStatus, readServiceEvents } = require('../desktop/electron/service-status.cjs');

readServiceStatus({ timeoutMs: 5000 }).then(async status => {
  if (!status.available) {
    console.error(`FAIL: Electron named-pipe client could not confirm Sentinel Service (${status.reason}).`);
    process.exitCode = 1;
    return;
  }
  const history = await readServiceEvents({ timeoutMs: 5000 });
  if (!history.available || !Array.isArray(history.events) || history.events.length > 12) {
    console.error(`FAIL: Electron named-pipe client could not read bounded Service history (${history.reason || 'invalid response'}).`);
    process.exitCode = 1;
    return;
  }
  const pagedHistory = await readServiceEvents({ timeoutMs: 5000, afterEventId: 0 });
  if (!pagedHistory.available || !Array.isArray(pagedHistory.events) || pagedHistory.events.length > 12 ||
      pagedHistory.events.some(event => event.id <= 0)) {
    console.error(`FAIL: Electron named-pipe client could not read cursor-bounded Service history (${pagedHistory.reason || 'invalid response'}).`);
    process.exitCode = 1;
    return;
  }
  console.log(`PASS: Electron named-pipe client received a fresh Service heartbeat (${status.state}), ${history.events.length} recent events, and ${pagedHistory.events.length} cursor-filtered events.`);
}).catch(error => {
  console.error(`FAIL: Electron named-pipe client failed (${error.name}).`);
  process.exitCode = 1;
});
