using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Service;

internal sealed class SentinelMonitoringWorker : IDisposable
{
    private const string CollectRequest = "{\"id\":\"service-collect\",\"version\":1,\"method\":\"collect\"}";
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(20);
    private readonly string serviceRoot = SecureServiceDataDirectory.GetPath();
    private readonly string dataRoot = Path.Combine(SecureServiceDataDirectory.GetPath(), "Data");
    private readonly SecurityIdentifier? allowedUserSid;
    private readonly ServiceHealthSnapshot health = new();
    private string downloadsPath = string.Empty;
    private EngineProcess? engine;
    private ServiceStatusPipeServer? statusPipe;
    private Task? statusPipeTask;
    private readonly ServiceRestartBackoff restartBackoff = new();
    private DateTimeOffset engineStartedAt;

    public SentinelMonitoringWorker(SecurityIdentifier? allowedUserSid = null) => this.allowedUserSid = allowedUserSid;

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
        if (allowedUserSid is not null)
        {
            statusPipe = new ServiceStatusPipeServer(allowedUserSid, health,
                readRecentEvents: ReadRecentEventsAsync, updateEventStatus: UpdateEventStatusAsync);
            statusPipeTask = statusPipe.RunAsync(cancellationToken);
        }
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                engine ??= StartEngine();
                await CollectAsync(cancellationToken);
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            {
                var uptime = engineStartedAt == default ? TimeSpan.Zero : DateTimeOffset.UtcNow - engineStartedAt;
                var retrySeconds = restartBackoff.DelayForFailure(uptime);
                ServiceLog.Write($"CORE_COLLECTION_FAILED type={exception.GetType().Name} retrySeconds={retrySeconds}");
                StopEngine();
                try { await Task.Delay(TimeSpan.FromSeconds(retrySeconds), cancellationToken); }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
            }
        }
        StopEngine();
        if (statusPipeTask is not null)
        {
            try { await statusPipeTask; }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        }
    }

    private EngineProcess StartEngine()
    {
        var executable = Path.Combine(AppContext.BaseDirectory, "Sentinel.Engine.exe");
        if (!File.Exists(executable)) throw new FileNotFoundException("Sentinel.Engine.exe is missing from the service directory.");
        var process = new EngineProcess(executable, dataRoot, downloadsPath);
        engineStartedAt = DateTimeOffset.UtcNow;
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
        health.MarkCollectionSucceeded(DateTimeOffset.UtcNow);
    }

    private async Task<IReadOnlyList<ServiceEventSummary>> ReadRecentEventsAsync(long? afterEventId, long? beforeEventId, CancellationToken cancellationToken)
    {
        var process = engine ?? throw new IOException("Sentinel Engine is not available.");
        var response = await process.SendAsync("{\"id\":\"service-history\",\"version\":1,\"method\":\"history\"}", cancellationToken);
        using var document = JsonDocument.Parse(response, new JsonDocumentOptions { MaxDepth = 16 });
        if (!document.RootElement.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True ||
            !document.RootElement.TryGetProperty("result", out var result) || result.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Sentinel Engine returned an invalid history response.");

        var history = result.EnumerateArray().ToArray();
        var page = afterEventId is { } after
            ? history.Where(item => item.TryGetProperty("id", out var id) && id.TryGetInt64(out var value) && value > after)
                .OrderBy(item => item.GetProperty("id").GetInt64()).Take(12).ToArray()
            : beforeEventId is { } before
                ? history.Where(item => item.TryGetProperty("id", out var id) && id.TryGetInt64(out var value) && value < before)
                    .OrderByDescending(item => item.GetProperty("id").GetInt64()).Take(12).ToArray()
                : history.Take(12).ToArray();
        var events = new List<ServiceEventSummary>(page.Length);
        foreach (var item in page)
        {
            if (!item.TryGetProperty("id", out var id) || !id.TryGetInt64(out var eventId) || eventId <= 0 ||
                !item.TryGetProperty("timestamp", out var timestamp) || !timestamp.TryGetDateTimeOffset(out var observedAt) ||
                !TryText(item, "risk", 32, out var risk) || !TryText(item, "status", 32, out var status) ||
                !TryText(item, "category", 128, out var category) || !TryText(item, "application", 128, out var application) ||
                !TryText(item, "explanation", 768, out var explanation) || !TryText(item, "recommendation", 512, out var recommendation))
                continue;
            if (risk is not ("Information" or "Low" or "Moderate" or "High" or "Critical") ||
                status is not ("New" or "Reviewed" or "FalsePositive")) continue;

            events.Add(new ServiceEventSummary(eventId, observedAt, risk, category, application, explanation,
                recommendation, status, ReadGuid(item, "eventId"), ReadText(item, "source", 64), ReadText(item, "ruleVersion", 64),
                ReadNullableInt(item, "confidence"), ReadInt(item, "schemaVersion", 1), ReadNullableInt(item, "processId"),
                ReadText(item, "processName", 128), ReadGuid(item, "correlationId"), ReadStringArray(item, "evidenceCodes", 12, 96),
                ReadStringArray(item, "analysisLimitations", 8, 96)));
        }
        return events;
    }

    private async Task<bool> UpdateEventStatusAsync(long eventId, string status, CancellationToken cancellationToken)
    {
        if (eventId <= 0 || status is not ("Reviewed" or "FalsePositive")) return false;
        var process = engine ?? throw new IOException("Sentinel Engine is not available.");
        var request = JsonSerializer.Serialize(new { id = "service-event-status", version = 1, method = "eventStatus", eventId, status },
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var response = await process.SendAsync(request, cancellationToken);
        using var document = JsonDocument.Parse(response, new JsonDocumentOptions { MaxDepth = 8 });
        return document.RootElement.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.True;
    }

    private static bool TryText(JsonElement element, string property, int maxLength, out string value)
    {
        value = ReadText(element, property, maxLength) ?? string.Empty;
        return value.Length > 0;
    }

    private static string? ReadText(JsonElement element, string property, int maxLength) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() is { } text ? text[..Math.Min(text.Length, maxLength)] : null
            : null;

    private static int ReadInt(JsonElement element, string property, int fallback) =>
        element.TryGetProperty(property, out var value) && value.TryGetInt32(out var parsed) ? parsed : fallback;

    private static int? ReadNullableInt(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.TryGetInt32(out var parsed) ? parsed : null;

    private static Guid? ReadGuid(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String && value.TryGetGuid(out var parsed) ? parsed : null;

    private static IReadOnlyList<string> ReadStringArray(JsonElement element, string property, int maxItems, int maxLength) =>
        element.TryGetProperty(property, out var values) && values.ValueKind == JsonValueKind.Array
            ? values.EnumerateArray().Where(value => value.ValueKind == JsonValueKind.String).Take(maxItems)
                .Select(value => value.GetString() is { } text ? text[..Math.Min(text.Length, maxLength)] : string.Empty).ToArray()
            : Array.Empty<string>();

    private void StopEngine()
    {
        engine?.Dispose();
        engine = null;
        engineStartedAt = default;
        health.MarkCollectionFailed();
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
