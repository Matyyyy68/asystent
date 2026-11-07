using Sentinel.Core;
using Sentinel.Engine;
using Xunit;

namespace Sentinel.Tests;

public sealed class ProtectionEngineCorrelationTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "sentinel-engine-correlation-" + Guid.NewGuid());

    [Fact]
    public async Task DownloadHashWmiProcessInspectionAndTcpObservationShareOneIncidentId()
    {
        var store = new LocalStore(directory);
        await store.InitializeAsync();
        var eventAt = DateTimeOffset.UtcNow;
        var hash = string.Concat(Enumerable.Repeat("AB", 32));
        var downloadEventId = Guid.NewGuid();
        await store.AddLocalOnlyAsync(new SecurityEvent(0, eventAt, RiskLevel.Information,
            "Pobrany plik pasuje do lokalnej listy hashy", "Monitoring Downloads",
            "Syntetyczne dopasowanie testowe; nie jest potwierdzeniem malware.",
            "Test bez reakcji automatycznej.", EventStatus.New, EventId: downloadEventId,
            Source: "downloads-local-hash", EvidenceCodes: ["file.sha256.matches-local-list"], SignalHash: hash));

        var processSnapshot = new Dictionary<int, string> { [1234] = "test-child" };
        var imagePath = Path.Combine(directory, "test-child.exe");
        var processMonitor = new ProcessSnapshotMonitor(() => new(processSnapshot), (_, _) => imagePath,
            (_, _) => true, null);
        Assert.Equal(1, await processMonitor.CollectAsync(store, paused: false, excludedApplications: "",
            traceEvents: [new WindowsProcessTraceEvent(eventAt, "Proces zaobserwowany", 1234, "test-child", 1)]));

        var processEvent = Assert.Single(await store.ReadAsync(), item => item.Source == "process-wmi");
        Assert.NotNull(processEvent.EventId);
        await store.UpdateProcessImageInspectionAsync(processEvent.EventId!.Value, hash, "Valid", true);
        var downloadEvent = Assert.Single(await store.ReadAsync(), item => item.EventId == downloadEventId);
        processEvent = Assert.Single(await store.ReadAsync(), item => item.Source == "process-wmi");
        Assert.NotNull(downloadEvent.CorrelationId);
        Assert.Equal(downloadEvent.CorrelationId, processEvent.CorrelationId);
        Assert.Contains("correlation.download-process.same-sha256", downloadEvent.EvidenceCodes!);
        Assert.Contains("correlation.download-process.same-sha256", processEvent.EvidenceCodes!);

        var clock = new TestTimeProvider(eventAt);
        IReadOnlyCollection<ConnectionSnapshot> connections = [];
        var networkMonitor = new TcpConnectionSnapshotMonitor(_ => Task.FromResult(connections), clock,
            processMonitor.WasRecentlyObservedStart);
        Assert.Equal(0, await networkMonitor.CollectAsync(store, enabled: true, paused: false, ""));
        connections = [new ConnectionSnapshot("TCP", "192.0.2.10", 51000, "198.51.100.20", 443,
            "Established", 1234, "test-child")];
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(1, await networkMonitor.CollectAsync(store, enabled: true, paused: false, ""));

        var tcpEvent = Assert.Single(await store.ReadAsync(), item => item.Source == "tcp-connection-snapshot");
        Assert.Equal(downloadEvent.CorrelationId, tcpEvent.CorrelationId);
        Assert.Contains("korelacja czasowa", tcpEvent.Explanation);
        Assert.Equal(3, (await store.ReadAsync()).Count);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); } catch { }
    }

    private sealed class TestTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset current = now;
        public override DateTimeOffset GetUtcNow() => current;
        public void Advance(TimeSpan delta) => current += delta;
    }
}
