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
        await monitor.SetEnabledAsync(store, true);
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
        await monitor.SetEnabledAsync(store, true);
        await File.WriteAllTextAsync(Path.Combine(downloads, "new.bin"), payload);
        var detected = 0;
        for (var attempt = 0; attempt < 50 && !monitor.State.Contains("osiągnięto limit 2", StringComparison.OrdinalIgnoreCase); attempt++)
        {
            detected += await monitor.CollectAsync(store, reputation);
            if (!monitor.State.Contains("osiągnięto limit 2", StringComparison.OrdinalIgnoreCase))
                await Task.Delay(TimeSpan.FromMilliseconds(100));
        }

        Assert.Equal(0, detected);
        Assert.Contains("osiągnięto limit 2", monitor.State, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(await store.ReadAsync());
    }

    [Fact]
    public async Task RestartFindsNewMatchingFilesWithoutRescanningOldFiles()
    {
        var downloads = Path.Combine(root, "Downloads");
        var data = Path.Combine(root, "data");
        Directory.CreateDirectory(downloads);
        var payload = "synthetic matching download after restart";
        var payloadHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
        var reputation = new FileHashReputation(Path.Combine(data, "reputation"));
        reputation.Import(payloadHash, DateTimeOffset.UtcNow);
        var store = new LocalStore(data); await store.InitializeAsync();
        await File.WriteAllTextAsync(Path.Combine(downloads, "old.bin"), payload);

        using (var firstSession = new DownloadedFileMonitor(downloads))
        {
            await firstSession.SetEnabledAsync(store, true);
            Assert.Single((await store.ReadDownloadedFileMonitorSnapshotAsync()).Files);
        }

        await File.WriteAllTextAsync(Path.Combine(downloads, "arrived-while-stopped.bin"), payload);
        await Task.Delay(TimeSpan.FromMilliseconds(900));
        using var restarted = new DownloadedFileMonitor(downloads);
        await restarted.SetEnabledAsync(store, true);
        var detected = 0;
        for (var attempt = 0; attempt < 40 && detected == 0; attempt++)
        {
            detected += await restarted.CollectAsync(store, reputation);
            if (detected == 0) await Task.Delay(TimeSpan.FromMilliseconds(100));
        }

        Assert.Equal(1, detected);
        var events = await store.ReadAsync();
        Assert.Single(events);
        Assert.Equal("arrived-while-stopped.bin", events[0].Application);
        var baseline = await store.ReadDownloadedFileMonitorSnapshotAsync();
        Assert.True(baseline.Initialized);
        Assert.Equal(2, baseline.Files.Count);
    }

    [Fact]
    public async Task MonitorRetriesStartupAfterDatabaseFailure()
    {
        var downloads = Path.Combine(root, "Downloads");
        var data = Path.Combine(root, "data");
        Directory.CreateDirectory(downloads);
        var store = new LocalStore(data);
        using var monitor = new DownloadedFileMonitor(downloads);

        await monitor.SetEnabledAsync(store, true);
        Assert.Contains("niedostępny", monitor.State, StringComparison.OrdinalIgnoreCase);

        await store.InitializeAsync();
        await monitor.CollectAsync(store, new FileHashReputation(Path.Combine(data, "reputation")));
        Assert.Contains("zaimportuj lokalną listę hashy", monitor.State, StringComparison.OrdinalIgnoreCase);
        Assert.True((await store.ReadDownloadedFileMonitorSnapshotAsync()).Initialized);
    }

    [Fact]
    public async Task DisablingMonitorClearsPersistedBaselineAndResumeExcludesExistingFiles()
    {
        var downloads = Path.Combine(root, "Downloads");
        var data = Path.Combine(root, "data");
        Directory.CreateDirectory(downloads);
        var payload = "synthetic matching download during pause";
        var payloadHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
        var reputation = new FileHashReputation(Path.Combine(data, "reputation"));
        reputation.Import(payloadHash, DateTimeOffset.UtcNow);
        var store = new LocalStore(data); await store.InitializeAsync();
        using var monitor = new DownloadedFileMonitor(downloads);
        await monitor.SetEnabledAsync(store, true);
        await File.WriteAllTextAsync(Path.Combine(downloads, "paused.bin"), payload);
        await monitor.SetEnabledAsync(store, false);
        Assert.False((await store.ReadDownloadedFileMonitorSnapshotAsync()).Initialized);

        await monitor.SetEnabledAsync(store, true);
        await Task.Delay(TimeSpan.FromMilliseconds(900));
        Assert.Equal(0, await monitor.CollectAsync(store, reputation));
        Assert.Empty(await store.ReadAsync());
    }

    [Fact]
    public async Task DeletingFileReleasesPersistedBaselineEntry()
    {
        var downloads = Path.Combine(root, "Downloads");
        var data = Path.Combine(root, "data");
        Directory.CreateDirectory(downloads);
        var reputation = new FileHashReputation(Path.Combine(data, "reputation"));
        reputation.Import(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("any known file"))), DateTimeOffset.UtcNow);
        var store = new LocalStore(data); await store.InitializeAsync();
        var file = Path.Combine(downloads, "delete-me.bin"); await File.WriteAllTextAsync(file, "existing");
        using var monitor = new DownloadedFileMonitor(downloads);
        await monitor.SetEnabledAsync(store, true);
        Assert.Single((await store.ReadDownloadedFileMonitorSnapshotAsync()).Files);

        File.Delete(file);
        for (var attempt = 0; attempt < 30 && (await store.ReadDownloadedFileMonitorSnapshotAsync()).Files.Count > 0; attempt++)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(100));
            await monitor.CollectAsync(store, reputation);
        }

        Assert.Empty((await store.ReadDownloadedFileMonitorSnapshotAsync()).Files);
    }

    public void Dispose()
    {
        if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
    }
}
