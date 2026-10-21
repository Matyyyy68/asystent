const { spawn } = require('node:child_process');
const { createInterface } = require('node:readline');

const INITIAL_RESTART_DELAY_MS = 1000;
const MAX_RESTART_DELAY_MS = 30000;
const REQUEST_TIMEOUT_MS = 45000;

class EngineClient {
  constructor(executable, options = {}) {
    this.executable = executable;
    this.spawnProcess = options.spawnProcess ?? spawn;
    this.setTimer = options.setTimer ?? setTimeout;
    this.clearTimer = options.clearTimer ?? clearTimeout;
    this.onState = options.onState ?? (() => {});
    this.engine = null;
    this.pending = new Map();
    this.sequence = 0;
    this.restartTimer = null;
    this.restartAttempt = 0;
    this.disposed = false;
    this.status = 'starting';
    this.lastExitCode = null;
    this.stderrObserved = false;
    this.stderrExceptionType = null;
    this.stderrExceptionCaptured = false;
    this.stderrPrefix = '';
    this.state('starting');
  }

  start() {
    if (!this.disposed && !this.engine && !this.restartTimer) this.launch();
  }

  state(value) {
    this.status = value;
    try { this.onState({ status: value, lastExitCode: this.lastExitCode, stderrObserved: this.stderrObserved }); }
    catch { /* State reporting must not destabilize the engine lifecycle. */ }
  }

  diagnostics() {
    return {
      status: this.status,
      lastExitCode: this.lastExitCode === null ? null : String(this.lastExitCode).slice(0, 40),
      stderrObserved: this.stderrObserved,
      stderrExceptionType: this.stderrExceptionType
    };
  }

  launch() {
    if (this.disposed || this.engine) return;
    this.restartTimer = null;
    this.state(this.restartAttempt ? 'restarting' : 'starting');
    let child;
    try {
      child = this.spawnProcess(this.executable, [], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    } catch (error) {
      this.lastExitCode = null;
      this.scheduleRestart(error?.code ?? 'spawn-error');
      return;
    }
    this.engine = child;
    this.stderrObserved = false;
    this.stderrExceptionCaptured = false;
    this.stderrPrefix = '';
    child.on('error', error => this.failed(child, error?.code ?? 'spawn-error'));
    child.on('exit', (code, signal) => this.failed(child, code ?? signal ?? 'unknown'));
    child.stdin?.on('error', error => this.failed(child, error?.code ?? 'stdin-error'));
    child.stderr?.on('data', chunk => {
      this.stderrObserved = true;
      if (this.stderrExceptionCaptured) return;
      const text = this.stderrPrefix + chunk.toString('utf8');
      const lines = text.split(/\r?\n/);
      this.stderrPrefix = lines.pop().slice(0, 256);
      for (const line of [...lines, this.stderrPrefix]) {
        const match = /^Unhandled exception\.\s+([A-Za-z_][A-Za-z0-9_.+`]{0,159})(?::|$)/.exec(line);
        if (match) {
          this.stderrExceptionType = match[1];
          this.stderrExceptionCaptured = true;
          this.stderrPrefix = '';
          break;
        }
      }
    });
    createInterface({ input: child.stdout }).on('line', line => {
      let response;
      try { response = JSON.parse(line); }
      catch { this.failed(child, 'invalid-response'); child.kill(); return; }
      const request = this.pending.get(response.id);
      if (!request) return;
      this.pending.delete(response.id);
      this.clearTimer(request.timer);
      if (response.ok) {
        this.restartAttempt = 0;
        this.state('ready');
        request.resolve(response.result);
      } else request.reject(new Error(response.error));
    });
  }

  failed(child, reason) {
    if (this.engine !== child) return;
    this.engine = null;
    this.lastExitCode = reason;
    this.rejectPending(new Error('Silnik jest niedostępny. Trwa ponawianie uruchomienia.'));
    this.scheduleRestart(reason);
  }

  scheduleRestart(reason) {
    if (this.disposed || this.restartTimer) return;
    const delay = Math.min(INITIAL_RESTART_DELAY_MS * (2 ** this.restartAttempt), MAX_RESTART_DELAY_MS);
    this.restartAttempt = Math.min(this.restartAttempt + 1, 16);
    this.state('restarting');
    // Log only a bounded reason code, never the child's stderr or request data.
    console.warn(`[Sentinel] Engine unavailable (${String(reason).slice(0, 40)}); retry in ${delay} ms.`);
    this.restartTimer = this.setTimer(() => this.launch(), delay);
  }

  rejectPending(error) {
    for (const request of this.pending.values()) {
      this.clearTimer(request.timer);
      request.reject(error);
    }
    this.pending.clear();
  }

  call(method, data = {}) {
    const child = this.engine;
    if (!child?.pid || child.exitCode !== null || child.stdin.destroyed) return Promise.reject(new Error('Silnik niedostępny'));
    return new Promise((resolve, reject) => {
      const id = String(++this.sequence);
      const timer = this.setTimer(() => {
        if (!this.pending.delete(id)) return;
        reject(new Error('Przekroczono czas odpowiedzi silnika; trwa ponowne uruchamianie.'));
        if (this.engine === child) {
          this.failed(child, 'response-timeout');
          child.kill();
        }
      }, REQUEST_TIMEOUT_MS);
      this.pending.set(id, { resolve, reject, timer });
      try { child.stdin.write(JSON.stringify({ ...data, id, version: 1, method }) + '\n'); }
      catch (error) {
        this.pending.delete(id);
        this.clearTimer(timer);
        reject(new Error('Nie można wysłać żądania do silnika: ' + (error?.code ?? 'błąd IPC')));
      }
    });
  }

  dispose() {
    if (this.disposed) return;
    this.disposed = true;
    if (this.restartTimer) this.clearTimer(this.restartTimer);
    this.restartTimer = null;
    this.rejectPending(new Error('Aplikacja Sentinel AI jest zamykana.'));
    const child = this.engine;
    this.engine = null;
    this.state('stopped');
    child?.kill();
  }
}

module.exports = { EngineClient };
