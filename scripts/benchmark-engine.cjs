const { spawn } = require('node:child_process');
const { createInterface } = require('node:readline');
const { mkdtempSync, rmSync } = require('node:fs');
const os = require('node:os');
const net = require('node:net');
const { tmpdir } = os;
const path = require('node:path');
const root = mkdtempSync(path.join(tmpdir(), 'sentinel-engine-benchmark-'));
const durationArgument = process.argv.find(argument => argument.startsWith('--duration='));
const durationSeconds = durationArgument ? Number(durationArgument.slice('--duration='.length)) : 30;
if (!Number.isInteger(durationSeconds) || durationSeconds < 30 || durationSeconds > 900) throw new Error('Use --duration=SECONDS in range 30–900.');
const intervalArgument = process.argv.find(argument => argument.startsWith('--interval-ms='));
const intervalMs = intervalArgument ? Number(intervalArgument.slice('--interval-ms='.length)) : 5000;
if (!Number.isInteger(intervalMs) || intervalMs < 250 || intervalMs > 60000) throw new Error('Use --interval-ms=MILLISECONDS in range 250–60000.');
const sampleCount = Math.floor(durationSeconds * 1000 / intervalMs);
const tcpMonitor = process.argv.includes('--tcp-monitor');
const connectionCountArgument = process.argv.find(argument => argument.startsWith('--tcp-connections='));
const tcpConnectionCount = connectionCountArgument ? Number(connectionCountArgument.slice('--tcp-connections='.length)) : 1;
if (!Number.isInteger(tcpConnectionCount) || tcpConnectionCount < 1 || tcpConnectionCount > 512)
  throw new Error('Use --tcp-connections=COUNT in range 1–512.');
if (!tcpMonitor && connectionCountArgument)
  throw new Error('--tcp-connections requires --tcp-monitor.');
let tcpServer, tcpClients = [], tcpTarget, tcpBurstStartedAt = 0;
const observedClientPorts = new Set();
const connectionObservationLatencyMs = new Map();
const child = spawn(path.resolve('artifacts/engine/Sentinel.Engine.exe'), [], { windowsHide: true,
  env: { ...process.env, SENTINEL_DATA_ROOT: root }, stdio: ['pipe', 'pipe', 'inherit'] });
const lines = createInterface({ input: child.stdout });
const pending = new Map(); let id = 0, finished = false;
lines.on('line', line => { const response = JSON.parse(line); pending.get(response.id)?.(response); pending.delete(response.id); });
function call(method, data = {}) { return new Promise((resolve, reject) => { const key = String(++id); pending.set(key, response => response.ok ? resolve(response.result) : reject(new Error(response.error))); child.stdin.write(JSON.stringify({ ...data, id: key, version: 1, method }) + '\n'); }); }
const timeout = setTimeout(() => { console.error('Benchmark timeout'); finish(1); }, (durationSeconds + 90) * 1000);
function finish(code) { if (finished) return; finished = true; clearTimeout(timeout); for (const client of tcpClients) client.destroy(); if (tcpServer) tcpServer.close(); child.stdin.end(); child.kill(); child.once('exit', () => { rmSync(root, { recursive: true, force: true }); process.exitCode = code; }); }
(async () => {
  try {
    await call('status'); await call('pause', { paused: false });
    if (tcpMonitor) {
      const address = Object.values(os.networkInterfaces()).flat().find(item => item.family === 'IPv4' && !item.internal && !item.address.startsWith('169.254.'))?.address;
      if (!address) throw new Error('TCP soak requires a non-loopback IPv4 interface.');
      tcpServer = net.createServer(socket => socket.on('data', () => {}));
      await new Promise((resolve, reject) => { tcpServer.once('error', reject); tcpServer.listen(0, address, resolve); });
      tcpTarget = `${address}:${tcpServer.address().port}`;
      await call('settings', { retentionDays: 30, notifications: false, dnsPollIntervalSeconds: 60, monitorNetworkConnections: true });
    }
    await call('collect');
    if (tcpMonitor) {
      tcpClients = await Promise.all(Array.from({ length: tcpConnectionCount }, () => new Promise((resolve, reject) => {
        const client = net.createConnection({ host: tcpTarget.split(':')[0], port: tcpServer.address().port });
        client.once('connect', () => resolve(client));
        client.once('error', reject);
      })));
    }
    const baseline = (await call('status')).runtime;
    const observations = [], latencies = [];
    const start = performance.now();
    if (tcpMonitor) tcpBurstStartedAt = start;
    for (let index = 1; index <= sampleCount; index++) {
      const due = start + index * intervalMs;
      await new Promise(resolve => setTimeout(resolve, Math.max(0, due - performance.now())));
      const before = performance.now(); await call('collect'); latencies.push(performance.now() - before);
      if (tcpMonitor && observedClientPorts.size < tcpClients.length && index <= Math.ceil(10000 / intervalMs)) {
        const recentHistory = await call('history');
        for (const client of tcpClients) {
          const localPortMarker = `:${client.localPort} → ${tcpTarget}`;
          if (!observedClientPorts.has(client.localPort) && recentHistory.some(event =>
            event.source === 'tcp-connection-snapshot' && event.explanation.includes(localPortMarker))) {
            observedClientPorts.add(client.localPort);
            connectionObservationLatencyMs.set(client.localPort, performance.now() - tcpBurstStartedAt);
          }
        }
      }
      observations.push((await call('status')).runtime);
    }
    const elapsedMs = performance.now() - start;
    const last = observations.at(-1);
    const cpuPercent = Math.max(0, last.cpuTimeMilliseconds - baseline.cpuTimeMilliseconds) / elapsedMs / baseline.processorCount * 100;
    const peakWorkingSet = Math.max(...observations.map(sample => sample.workingSetBytes));
    const sorted = [...latencies].sort((a, b) => a - b);
    const finalStatus = await call('status');
    const history = tcpMonitor ? await call('history') : null;
    if (tcpMonitor) {
      if (!finalStatus.tcpConnections.includes('Ciągła migawka TCP/UDP działa')) throw new Error(`TCP observer was not healthy: ${finalStatus.tcpConnections}`);
      if (observedClientPorts.size !== tcpClients.length)
        throw new Error(`Only ${observedClientPorts.size}/${tcpClients.length} controlled TCP connections were observed within the first ${Math.ceil(10000 / intervalMs)} samples.`);
    }
    console.log(JSON.stringify({
      samples: observations.length, elapsedSeconds: +(elapsedMs / 1000).toFixed(1),
      engineCpuPercentOfTotalCapacity: +cpuPercent.toFixed(3),
      startingWorkingSetMiB: +(baseline.workingSetBytes / 1048576).toFixed(1), peakWorkingSetMiB: +(peakWorkingSet / 1048576).toFixed(1),
      collectLatencyMs: { median: +sorted[Math.floor(sorted.length / 2)].toFixed(1), max: +Math.max(...sorted).toFixed(1) },
      processSource: finalStatus.processes,
      ...(tcpMonitor ? {
        tcpObserver: finalStatus.tcpConnections,
        tcpEventsVisibleInHistory: history.filter(event => event.source === 'tcp-connection-snapshot').length,
        controlledTarget: tcpTarget,
        tcpConnectionsRequested: tcpClients.length,
        tcpConnectionsObserved: observedClientPorts.size,
        observedConnectionRatePerSecond: +(observedClientPorts.size / (Math.max(1, Math.max(...connectionObservationLatencyMs.values())) / 1000)).toFixed(1),
        connectionDetectionLatencyMs: {
          median: +[...connectionObservationLatencyMs.values()].sort((a, b) => a - b)[Math.floor(connectionObservationLatencyMs.size / 2)].toFixed(1),
          max: +Math.max(...connectionObservationLatencyMs.values()).toFixed(1)
        }
      } : {}),
      note: `Single isolated Windows session; ${durationSeconds}-second profile with ${intervalMs}-ms collection intervals${tcpMonitor ? ` and a controlled burst of ${tcpConnectionCount} TCP connections` : ''}; rates and latency include snapshot polling delay and are not fleet guarantees.`
    }, null, 2));
    finish(0);
  } catch (error) { console.error(error); finish(1); }
})();
