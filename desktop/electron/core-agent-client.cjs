'use strict';

const net = require('node:net');
const { spawn } = require('node:child_process');

function resolvePipePath(sessionName = process.env.SESSIONNAME) {
  const suffix = typeof sessionName === 'string' ? sessionName.replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 40) : '';
  return `\\\\.\\pipe\\SentinelAI.Engine.v1.${suffix || 'Default'}`;
}
const PIPE_PATH = resolvePipePath();
const REQUEST_TIMEOUT_MS = 45000;
const MAX_RESPONSE_BYTES = 1024 * 1024;

class CoreAgentClient {
  constructor(agentExecutable, options = {}) {
    this.agentExecutable = agentExecutable;
    this.spawnProcess = options.spawnProcess ?? spawn;
    this.connectPipe = options.connectPipe ?? (() => net.createConnection(PIPE_PATH));
    this.setTimer = options.setTimer ?? setTimeout;
    this.clearTimer = options.clearTimer ?? clearTimeout;
    this.onDiagnostic = options.onDiagnostic ?? (() => {});
    this.now = options.now ?? (() => new Date());
    this.nowMs = options.nowMs ?? (() => Date.now());
    this.status = 'starting';
    this.lastFailure = null;
    this.disposed = false;
    this.agentLaunchAttempted = false;
    this.nextAgentLaunchAt = 0;
    this.agentLaunchBackoffMs = 1000;
  }

  start() {
    if (this.disposed || this.agentLaunchAttempted || this.nowMs() < this.nextAgentLaunchAt) return;
    this.agentLaunchAttempted = true;
    this.nextAgentLaunchAt = this.nowMs() + this.agentLaunchBackoffMs;
    this.agentLaunchBackoffMs = Math.min(this.agentLaunchBackoffMs * 2, 30000);
    try {
      const child = this.spawnProcess(this.agentExecutable, [], { detached: true, windowsHide: true, stdio: 'ignore' });
      child.once?.('error', error => {
        this.agentLaunchAttempted = false;
        this.recordFailure(error?.code ?? 'agent-spawn-error');
      });
      child.once?.('exit', code => {
        if (code !== 0 && !this.disposed) {
          this.agentLaunchAttempted = false;
          this.recordFailure('agent-exit-error');
        }
      });
      child.unref?.();
    } catch (error) {
      this.agentLaunchAttempted = false;
      this.recordFailure(error?.code ?? 'agent-spawn-error');
    }
  }

  diagnostics() {
    return { status: this.status, lastExitCode: null, stderrObserved: false, stderrExceptionType: null, lastFailure: this.lastFailure };
  }

  recordFailure(reason) {
    const safeReason = typeof reason === 'string' && /^[A-Za-z0-9_-]{1,40}$/.test(reason) ? reason : 'unknown';
    this.lastFailure = { occurredAtUtc: this.now().toISOString(), reasonCode: safeReason, stderrObserved: false, exceptionType: null };
    try { this.onDiagnostic(this.lastFailure); } catch { /* Diagnostics must not interrupt reconnection. */ }
    this.status = 'restarting';
  }

  async call(method, data = {}) {
    if (this.disposed) throw new Error('Aplikacja Sentinel AI jest zamykana.');
    this.start();
    const id = String(Date.now()) + '-' + Math.random().toString(36).slice(2, 10);
    const request = JSON.stringify({ ...data, id, version: 1, method }) + '\n';
    if (Buffer.byteLength(request, 'utf8') > 24000) throw new Error('Żądanie przekracza limit.');
    const deadline = Date.now() + REQUEST_TIMEOUT_MS;
    let lastError;
    while (!this.disposed && Date.now() < deadline) {
      try {
        const response = await this.requestOnce(request, Math.max(1, deadline - Date.now()));
        if (response.id !== id) throw new Error('Nieprawidłowy identyfikator odpowiedzi silnika.');
        this.status = 'ready';
        this.lastFailure = null;
        this.agentLaunchBackoffMs = 1000;
        if (!response.ok) {
          const error = new Error(response.error || 'Operacja silnika nie powiodła się.');
          error.permanent = true;
          throw error;
        }
        return response.result;
      } catch (error) {
        if (error?.permanent) throw error;
        lastError = error;
        const reason = error?.code ?? (error?.message?.includes('timeout') ? 'response-timeout' : 'pipe-unavailable');
        this.recordFailure(reason);
        if (!this.agentLaunchAttempted) this.start();
        if (this.disposed) break;
        await new Promise(resolve => this.setTimer(resolve, 300));
      }
    }
    throw lastError ?? new Error('Silnik Sentinel AI jest niedostępny.');
  }

  requestOnce(request, timeoutMs) {
    return new Promise((resolve, reject) => {
      let socket;
      let settled = false;
      let buffer = '';
      const timer = this.setTimer(() => finish(new Error('Sentinel Core response-timeout')), timeoutMs);
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        this.clearTimer(timer);
        socket?.destroy();
        if (error) reject(error); else resolve(value);
      };
      try { socket = this.connectPipe(); }
      catch (error) { finish(error); return; }
      socket.once('connect', () => socket.write(request));
      socket.on('data', chunk => {
        buffer += chunk.toString('utf8');
        if (Buffer.byteLength(buffer, 'utf8') > MAX_RESPONSE_BYTES) { finish(new Error('Oversized Sentinel Core response')); return; }
        const newline = buffer.indexOf('\n');
        if (newline < 0) return;
        try { finish(null, JSON.parse(buffer.slice(0, newline))); }
        catch { finish(new Error('Invalid Sentinel Core response')); }
      });
      socket.once('error', error => finish(error));
      socket.once('end', () => { if (!settled) finish(new Error('Sentinel Core pipe closed without a response')); });
      socket.setTimeout?.(timeoutMs, () => finish(new Error('Sentinel Core response-timeout')));
    });
  }

  dispose() {
    this.disposed = true;
    this.status = 'stopped';
    // Core belongs to the per-user background agent; closing the UI leaves it running.
  }
}

module.exports = { CoreAgentClient, PIPE_PATH, resolvePipePath };
