const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const timeoutMs = 120_000;

function tail(value, maxLines = 40) {
  return value.trim().split(/\r?\n/).slice(-maxLines).join('\n');
}

function killProcessTree(child) {
  if (!child.pid || child.exitCode !== null) return;
  if (process.platform === 'win32') {
    spawnSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
  }
  if (child.exitCode === null) child.kill();
}

async function main() {
  if (process.platform !== 'win32') throw new Error('The installed-app smoke test requires Windows.');

  const repoRoot = path.resolve(__dirname, '..');
  const desktopRoot = path.join(repoRoot, 'desktop');
  const electron = path.join(desktopRoot, 'node_modules', 'electron', 'dist', 'electron.exe');
  const appEntry = path.join(desktopRoot, 'electron', 'main.cjs');
  const renderer = path.join(desktopRoot, 'dist', 'index.html');
  const engine = path.join(repoRoot, 'artifacts', 'engine', 'Sentinel.Engine.exe');
  for (const file of [electron, appEntry, renderer, engine]) {
    if (!fs.existsSync(file)) throw new Error(`Smoke-test prerequisite is missing: ${path.relative(repoRoot, file)}`);
  }

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-electron-smoke-'));
  const dataRoot = path.join(tempRoot, 'data');
  fs.mkdirSync(dataRoot);
  let child;
  let stdout = '';
  let stderr = '';
  let timer;
  try {
    child = spawn(electron, [appEntry, '--smoke-test', '--disable-gpu'], {
      cwd: desktopRoot,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, SENTINEL_DATA_ROOT: dataRoot }
    });
    child.stdout.setEncoding('utf8').on('data', chunk => { stdout = (stdout + chunk).slice(-32_000); });
    child.stderr.setEncoding('utf8').on('data', chunk => { stderr = (stderr + chunk).slice(-32_000); });

    const exit = await Promise.race([
      new Promise((resolve, reject) => {
        child.once('error', reject);
        child.once('close', (code, signal) => resolve({ code, signal }));
      }),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          killProcessTree(child);
          reject(new Error(`Electron smoke test exceeded ${timeoutMs / 1000} seconds.`));
        }, timeoutMs);
      })
    ]);
    if (exit.code !== 0) throw new Error(`Electron exited with code ${exit.code} (signal ${exit.signal ?? 'none'}).`);

    const marker = path.join(dataRoot, 'smoke-test.passed');
    if (!fs.existsSync(marker) || fs.readFileSync(marker, 'utf8') !== 'renderer and engine checks passed')
      throw new Error('Electron exited without the renderer-to-engine smoke-test marker.');
    if (!stdout.includes('PASS: Electron renderer → isolated preload → IPC → .NET → SQLite'))
      throw new Error('Electron smoke-test success message was not observed.');
    process.stdout.write('PASS: installed Electron app → renderer → preload → IPC → .NET engine → SQLite\n');
  } catch (error) {
    killProcessTree(child);
    if (stdout) process.stderr.write(`Electron stdout (tail):\n${tail(stdout)}\n`);
    if (stderr) process.stderr.write(`Electron stderr (tail):\n${tail(stderr)}\n`);
    throw error;
  } finally {
    clearTimeout(timer);
    killProcessTree(child);
    const temp = path.resolve(os.tmpdir());
    if (!tempRoot.startsWith(temp + path.sep) || !path.basename(tempRoot).startsWith('sentinel-electron-smoke-'))
      throw new Error('Refusing to remove an unexpected smoke-test directory.');
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

main().catch(error => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});
