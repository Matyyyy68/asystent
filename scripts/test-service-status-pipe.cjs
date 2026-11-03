const { readServiceStatus } = require('../desktop/electron/service-status.cjs');

readServiceStatus({ timeoutMs: 5000 }).then(status => {
  if (!status.available) {
    console.error(`FAIL: Electron named-pipe client could not confirm Sentinel Service (${status.reason}).`);
    process.exitCode = 1;
    return;
  }
  console.log(`PASS: Electron named-pipe client received a fresh Service heartbeat (${status.state}).`);
}).catch(error => {
  console.error(`FAIL: Electron named-pipe client failed (${error.name}).`);
  process.exitCode = 1;
});
