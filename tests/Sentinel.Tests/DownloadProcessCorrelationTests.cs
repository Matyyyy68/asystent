using System.Security.Cryptography;
using System.Text.Json;
using Sentinel.Core;
using Sentinel.Core.Analysis;
using Sentinel.Engine;
using Xunit;

namespace Sentinel.Tests;

public sealed class DownloadProcessCorrelationTests : IDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), "sentinel-download-process-correlation-" + Guid.NewGuid());

    [Fact]
    public async Task DownloadedPeAndLaterExecutionAreCorrelatedWithoutRiskEscalation()
    {
        var downloads = Path.Combine(root, "Downloads");
        var data = Path.Combine(root, "data");
        Directory.CreateDirectory(downloads);
        var store = new LocalStore(data);
        await store.InitializeAsync();
        var reputation = new FileHashReputation(Path.Combine(data, "reputation"));
        using var monitor = new DownloadedFileMonitor(downloads);
        await monitor.SetEnabledAsync(store, true);

        var path = Path.Combine(downloads, "sample.exe");
        var pe = MinimalPe();
        var hash = Convert.ToHexString(SHA256.HashData(pe));
        await File.WriteAllBytesAsync(path, pe);
        await Task.Delay(900);

        for (var attempt = 0; attempt < 30; attempt++)
        {
            await monitor.CollectAsync(store, reputation);
            if ((await store.ReadAsync()).Any(item => item.Source == "downloads-executable-observed")) break;
            await Task.Delay(100);
        }

        var download = Assert.Single((await store.ReadAsync()).Where(item => item.Source == "downloads-executable-observed"));
        Assert.Equal(RiskLevel.Information, download.Risk);
        Assert.Equal(0, download.RiskScore);
        Assert.Equal(hash, download.SignalHash);
        Assert.Contains("file.downloads.pe-observed", download.EvidenceCodes!);
        Assert.DoesNotContain(path, JsonSerializer.Serialize(download), StringComparison.OrdinalIgnoreCase);

        var correlationId = Guid.NewGuid();
        var processEventId = Guid.NewGuid();
        var processEvent = new SecurityEvent(0, DateTimeOffset.UtcNow, RiskLevel.Information,
            "Proces zaobserwowany", "sample", "Syntetyczny test integracyjny.", "Brak automatycznego działania.",
            EventStatus.New, EventId: processEventId, Source: "process-snapshot",
            RuleVersion: ThreatAnalysisEngine.RulesVersion, ProcessId: 4242, ProcessName: "sample",
            CorrelationId: correlationId, EvidenceCodes: ["process.snapshot.new-pid"],
            ProcessImagePath: path, ProcessImageSignatureStatus: "Pending", RiskScore: 0);
        await store.AddLocalOnlyAsync(processEvent);
        await store.UpdateProcessImageInspectionAsync(processEventId, hash, "NotSigned", localHashMatch: null);

        var linked = await store.ReadAsync();
        var linkedDownload = linked.Single(item => item.Source == "downloads-executable-observed");
        var linkedProcess = linked.Single(item => item.EventId == processEventId);
        Assert.Equal(correlationId, linkedDownload.CorrelationId);
        Assert.Equal(linkedDownload.CorrelationId, linkedProcess.CorrelationId);
        Assert.Contains("correlation.download-process.same-sha256", linkedDownload.EvidenceCodes!);
        Assert.Contains("correlation.download-process.same-sha256", linkedProcess.EvidenceCodes!);
        Assert.Equal(RiskLevel.Information, linkedProcess.Risk);
        Assert.Equal(0, linkedProcess.RiskScore);
        Assert.Equal(path, linkedProcess.ProcessImagePath);
    }

    private static byte[] MinimalPe()
    {
        var pe = new byte[128];
        pe[0] = (byte)'M';
        pe[1] = (byte)'Z';
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(pe.AsSpan(0x3c, 4), 64);
        "PE\0\0"u8.CopyTo(pe.AsSpan(64));
        return pe;
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
            Directory.Delete(root, recursive: true);
    }
}
