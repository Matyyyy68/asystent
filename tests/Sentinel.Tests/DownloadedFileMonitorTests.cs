using System.Security.Cryptography;
using System.Text;
using Sentinel.Core;
using Sentinel.Core.Analysis;
using Xunit;

namespace Sentinel.Tests;

public sealed class DownloadedFileMonitorTests : IDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), "sentinel-download-monitor-" + Guid.NewGuid());

    [Fact]
    public async Task QueueOverflowReconcilesNewFilesWithoutScanningPreexistingFiles()
    {
        var downloads = Path.Combine(root, "Downloads");
        var data = Path.Combine(root, "data");
        Directory.CreateDirectory(downloads);
        var payload = "synthetic matching download";
        var payloadHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
        var reputation = new FileHashReputation(Path.Combine(data, "reputation"));
        reputation.Import(payloadHash, DateTimeOffset.UtcNow);
        var store = new LocalStore(data);
        await store.InitializeAsync();

        await File.WriteAllTextAsync(Path.Combine(downloads, "preexisting.bin"), payload);
        using var monitor = new DownloadedFileMonitor(downloads, maximumPendingFiles: 2);
        monitor.SetEnabled(true);
        Assert.Contains("działa", monitor.State, StringComparison.OrdinalIgnoreCase);

        const int newFiles = 5;
        for (var index = 0; index < newFiles; index++)
            await File.WriteAllTextAsync(Path.Combine(downloads, $"new-{index}.bin"), payload);

        await Task.Delay(TimeSpan.FromMilliseconds(900));
        var recorded = 0;
        for (var attempt = 0; attempt < 40 && recorded < newFiles; attempt++)
        {
            recorded += await monitor.CollectAsync(store, reputation);
            if (recorded < newFiles) await Task.Delay(TimeSpan.FromMilliseconds(100));
        }

        Assert.Equal(newFiles, recorded);
        var events = await store.ReadAsync();
        Assert.Equal(newFiles, events.Count(item => item.Source == "downloads-local-hash"));
        Assert.DoesNotContain(events, item => item.Application == "preexisting.bin");
        Assert.Contains("odtworzyło", monitor.State, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task BaselineGrowthStopsMonitoringAtConfiguredBound()
    {
        var downloads = Path.Combine(root, "Downloads");
        var data = Path.Combine(root, "data");
        Directory.CreateDirectory(downloads);
        var payload = "bounded baseline sample";
        var payloadHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
        var reputation = new FileHashReputation(Path.Combine(data, "reputation"));
        reputation.Import(payloadHash, DateTimeOffset.UtcNow);
        var store = new LocalStore(data);
        await store.InitializeAsync();
        await File.WriteAllTextAsync(Path.Combine(downloads, "old-1.bin"), payload);
        await File.WriteAllTextAsync(Path.Combine(downloads, "old-2.bin"), payload);

        using var monitor = new DownloadedFileMonitor(downloads, maximumBaselineFiles: 2);
        monitor.SetEnabled(true);
        await File.WriteAllTextAsync(Path.Combine(downloads, "new.bin"), payload);
        await Task.Delay(TimeSpan.FromMilliseconds(900));

        Assert.Equal(0, await monitor.CollectAsync(store, reputation));
        Assert.Contains("osiągnięto limit 2", monitor.State, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(await store.ReadAsync());
    }

    public void Dispose()
    {
        if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
    }
}
