const { spawn } = require('node:child_process');
const { createInterface } = require('node:readline');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');
const root = mkdtempSync(path.join(tmpdir(), 'sentinel-engine-benchmark-'));
const durationArgument = process.argv.find(argument => argument.startsWith('--duration='));
const durationSeconds = durationArgument ? Number(durationArgument.slice('--duration='.length)) : 30;
if (!Number.isInteger(durationSeconds) || durationSeconds < 30 || durationSeconds > 900) throw new Error('Use --duration=SECONDS in range 30–900.');
const sampleCount = Math.floor(durationSeconds / 5);
const child = spawn(path.resolve('artifacts/engine/Sentinel.Engine.exe'), [], { windowsHide: true,
  env: { ...process.env, SENTINEL_DATA_ROOT: root }, stdio: ['pipe', 'pipe', 'inherit'] });
const lines = createInterface({ input: child.stdout });
const pending = new Map(); let id = 0, finished = false;
lines.on('line', line => { const response = JSON.parse(line); pending.get(response.id)?.(response); pending.delete(response.id); });
function call(method, data = {}) { return new Promise((resolve, reject) => { const key = String(++id); pending.set(key, response => response.ok ? resolve(response.result) : reject(new Error(response.error))); child.stdin.write(JSON.stringify({ ...data, id: key, version: 1, method }) + '\n'); }); }
const timeout = setTimeout(() => { console.error('Benchmark timeout'); finish(1); }, (durationSeconds + 90) * 1000);
function finish(code) { if (finished) return; finished = true; clearTimeout(timeout); child.stdin.end(); child.kill(); child.once('exit', () => { rmSync(root, { recursive: true, force: true }); process.exitCode = code; }); }
(async () => {
  try {
    await call('status'); await call('pause', { paused: false }); await call('collect');
    const baseline = (await call('status')).runtime;
    const observations = [], latencies = [];
    const start = performance.now();
    for (let index = 1; index <= sampleCount; index++) {
      const due = start + index * 5000;
      await new Promise(resolve => setTimeout(resolve, Math.max(0, due - performance.now())));
      const before = performance.now(); await call('collect'); latencies.push(performance.now() - before);
      observations.push((await call('status')).runtime);
    }
    const elapsedMs = performance.now() - start;
    const last = observations.at(-1);
    const cpuPercent = Math.max(0, last.cpuTimeMilliseconds - baseline.cpuTimeMilliseconds) / elapsedMs / baseline.processorCount * 100;
    const peakWorkingSet = Math.max(...observations.map(sample => sample.workingSetBytes));
    const sorted = [...latencies].sort((a, b) => a - b);
    console.log(JSON.stringify({
      samples: observations.length, elapsedSeconds: +(elapsedMs / 1000).toFixed(1),
      engineCpuPercentOfTotalCapacity: +cpuPercent.toFixed(3),
      startingWorkingSetMiB: +(baseline.workingSetBytes / 1048576).toFixed(1), peakWorkingSetMiB: +(peakWorkingSet / 1048576).toFixed(1),
      collectLatencyMs: { median: +sorted[Math.floor(sorted.length / 2)].toFixed(1), max: +Math.max(...sorted).toFixed(1) },
      processSource: (await call('status')).processes,
      note: `Single local Windows session; ${durationSeconds}-second profile with 5-second collect intervals; not a fleet or long-duration performance guarantee.`
    }, null, 2));
    finish(0);
  } catch (error) { console.error(error); finish(1); }
})();
