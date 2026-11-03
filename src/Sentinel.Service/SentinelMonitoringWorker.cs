using System.Diagnostics;
using System.Text.Json;

namespace Sentinel.Service;

internal sealed class SentinelMonitoringWorker : IDisposable
{
    private const string CollectRequest = "{\"id\":\"service-collect\",\"version\":1,\"method\":\"collect\"}";
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(20);
    private readonly string serviceRoot = SecureServiceDataDirectory.GetPath();
    private readonly string dataRoot = Path.Combine(SecureServiceDataDirectory.GetPath(), "Data");
    private string downloadsPath = string.Empty;
    private EngineProcess? engine;
    private int restartDelaySeconds = 1;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Sentinel Service wymaga Windows.");
        SecureServiceDataDirectory.Prepare(serviceRoot);
        Directory.CreateDirectory(dataRoot);
        downloadsPath = Path.Combine(dataRoot, "service-profile-downloads");
        Directory.CreateDirectory(downloadsPath);
        engine = StartEngine();
        await CollectAsync(cancellationToken);
        ServiceLog.Write("CORE_FIRST_COLLECTION_COMPLETED");
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                engine ??= StartEngine();
                await CollectAsync(cancellationToken);
                restartDelaySeconds = 1;
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            {
                ServiceLog.Write($"CORE_COLLECTION_FAILED type={exception.GetType().Name} retrySeconds={restartDelaySeconds}");
                StopEngine();
                try { await Task.Delay(TimeSpan.FromSeconds(restartDelaySeconds), cancellationToken); }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
                restartDelaySeconds = Math.Min(restartDelaySeconds * 2, 30);
            }
        }
        StopEngine();
    }

    private EngineProcess StartEngine()
    {
        var executable = Path.Combine(AppContext.BaseDirectory, "Sentinel.Engine.exe");
        if (!File.Exists(executable)) throw new FileNotFoundException("Sentinel.Engine.exe is missing from the service directory.");
        var process = new EngineProcess(executable, dataRoot, downloadsPath);
        ServiceLog.Write("ENGINE_STARTED under service account");
        return process;
    }

    private async Task CollectAsync(CancellationToken cancellationToken)
    {
        var process = engine ?? throw new InvalidOperationException("Engine process is not available.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(RequestTimeout);
        var response = await process.SendAsync(CollectRequest, timeout.Token);
        using var document = JsonDocument.Parse(response, new JsonDocumentOptions { MaxDepth = 16 });
        if (!document.RootElement.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True)
            throw new InvalidDataException("Sentinel Engine rejected a service collection cycle.");
    }

    private void StopEngine()
    {
        engine?.Dispose();
        engine = null;
    }

    public void Dispose() => StopEngine();

    private sealed class EngineProcess(string executable, string dataRoot, string downloadsPath) : IDisposable
    {
        private readonly SemaphoreSlim gate = new(1, 1);
        private Process? process;
        private StreamWriter? input;
        private StreamReader? output;

        public async Task<string> SendAsync(string request, CancellationToken cancellationToken)
        {
            await gate.WaitAsync(cancellationToken);
            try
            {
                EnsureStarted();
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(RequestTimeout);
                await input!.WriteLineAsync(request.AsMemory(), timeout.Token);
                await input.FlushAsync(timeout.Token);
                var line = await output!.ReadLineAsync(timeout.Token)
                    ?? throw new EndOfStreamException("Sentinel Engine closed its response stream.");
                if (line.Length > 1_000_000) throw new InvalidDataException("Sentinel Engine response exceeded the service limit.");
                return line;
            }
            catch
            {
                Stop();
                throw;
            }
            finally { gate.Release(); }
        }

        private void EnsureStarted()
        {
            if (process is { HasExited: false }) return;
            Stop();
            var start = new ProcessStartInfo(executable)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(executable)!
            };
            start.Environment["SENTINEL_DATA_ROOT"] = dataRoot;
            start.Environment["SENTINEL_DOWNLOADS_PATH"] = downloadsPath;
            process = Process.Start(start) ?? throw new IOException("Unable to start Sentinel Engine.");
            input = process.StandardInput;
            output = process.StandardOutput;
            process.ErrorDataReceived += (_, line) =>
            {
                if (!string.IsNullOrWhiteSpace(line.Data)) ServiceLog.Write("ENGINE_DIAGNOSTIC_AVAILABLE");
            };
            process.BeginErrorReadLine();
        }

        private void Stop()
        {
            try { if (process is { HasExited: false }) process.Kill(entireProcessTree: true); } catch { }
            process?.Dispose();
            process = null;
            input = null;
            output = null;
        }

        public void Dispose()
        {
            try { input?.Close(); } catch { }
            try { if (process is { HasExited: false }) process.WaitForExit(3000); } catch { }
            Stop();
            gate.Dispose();
        }
    }
}
