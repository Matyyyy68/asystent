using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
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
        var preexistingFolder = Path.Combine(downloads, "existing-folder");
        Directory.CreateDirectory(preexistingFolder);
        await File.WriteAllTextAsync(Path.Combine(preexistingFolder, "preexisting-nested.bin"), payload);
        using var monitor = new DownloadedFileMonitor(downloads, maximumPendingFiles: 2);
        await monitor.SetEnabledAsync(store, true);
        Assert.Contains("działa", monitor.State, StringComparison.OrdinalIgnoreCase);

        const int newFiles = 5;
        for (var index = 0; index < newFiles; index++)
            await File.WriteAllTextAsync(Path.Combine(downloads, $"new-{index}.bin"), payload);
        var newFolder = Path.Combine(downloads, "new-folder");
        Directory.CreateDirectory(newFolder);
        await File.WriteAllTextAsync(Path.Combine(newFolder, "nested-new.bin"), payload);

        await Task.Delay(TimeSpan.FromMilliseconds(900));
        var recorded = 0;
        for (var attempt = 0; attempt < 40 && recorded < newFiles + 1; attempt++)
        {
            recorded += await monitor.CollectAsync(store, reputation);
            if (recorded < newFiles + 1) await Task.Delay(TimeSpan.FromMilliseconds(100));
        }

        Assert.Equal(newFiles + 1, recorded);
        var events = await store.ReadAsync();
        Assert.Equal(newFiles + 1, events.Count(item => item.Source == "downloads-local-hash"));
        Assert.DoesNotContain(events, item => item.Application == "preexisting.bin");
        Assert.DoesNotContain(events, item => item.Application == "preexisting-nested.bin");
        Assert.DoesNotContain("nested-new.bin", System.Text.Json.JsonSerializer.Serialize(events), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("odtworzył", monitor.State, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DeletingNestedFolderPrunesItsPersistedFilesFromBaseline()
    {
        var downloads = Path.Combine(root, "Downloads");
        var data = Path.Combine(root, "data");
        var nested = Path.Combine(downloads, "nested");
        Directory.CreateDirectory(nested);
        var store = new LocalStore(data);
        await store.InitializeAsync();
        await File.WriteAllTextAsync(Path.Combine(nested, "old.bin"), "existing nested file");

        using var monitor = new DownloadedFileMonitor(downloads, reconciliationInterval: TimeSpan.FromMilliseconds(100));
        await monitor.SetEnabledAsync(store, true);
        Assert.Single((await store.ReadDownloadedFileMonitorSnapshotAsync()).Files);

        Directory.Delete(nested, recursive: true);
        for (var attempt = 0; attempt < 40 && (await store.ReadDownloadedFileMonitorSnapshotAsync()).Files.Count > 0; attempt++)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(100));
            await monitor.CollectAsync(store, new FileHashReputation(Path.Combine(data, "reputation")));
        }

        Assert.Empty((await store.ReadDownloadedFileMonitorSnapshotAsync()).Files);
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
        Assert.Equal("Monitoring Downloads", events[0].Application);
        Assert.DoesNotContain("arrived-while-stopped.bin", System.Text.Json.JsonSerializer.Serialize(events), StringComparison.OrdinalIgnoreCase);
        var baseline = await store.ReadDownloadedFileMonitorSnapshotAsync();
        Assert.True(baseline.Initialized);
        Assert.Equal(2, baseline.Files.Count);
    }

    [Fact]
    public async Task JunctionInsideDownloadsDoesNotExpandScanScopeOutsideDownloads()
    {
        if (!OperatingSystem.IsWindows()) return;
        var downloads = Path.Combine(root, "Downloads");
        var outside = Path.Combine(root, "outside");
        var data = Path.Combine(root, "data");
        Directory.CreateDirectory(downloads);
        Directory.CreateDirectory(outside);
        var junction = Path.Combine(downloads, "linked-folder");
        CreateJunction(junction, outside);

        try
        {
            var payload = "matching file outside the selected Downloads tree";
            var payloadHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
            var reputation = new FileHashReputation(Path.Combine(data, "reputation"));
            reputation.Import(payloadHash, DateTimeOffset.UtcNow);
            var store = new LocalStore(data);
            await store.InitializeAsync();
            await File.WriteAllTextAsync(Path.Combine(outside, "already-there.bin"), payload);

            using var monitor = new DownloadedFileMonitor(downloads);
            await monitor.SetEnabledAsync(store, true);
            Assert.Empty((await store.ReadDownloadedFileMonitorSnapshotAsync()).Files);

            await File.WriteAllTextAsync(Path.Combine(outside, "arrived-later.bin"), payload);
            await File.WriteAllTextAsync(Path.Combine(downloads, "inside.bin"), payload);
            await Task.Delay(TimeSpan.FromMilliseconds(900));
            var detected = 0;
            for (var attempt = 0; attempt < 40 && detected == 0; attempt++)
            {
                detected += await monitor.CollectAsync(store, reputation);
                if (detected == 0) await Task.Delay(TimeSpan.FromMilliseconds(100));
            }

            Assert.Equal(1, detected);
            var events = await store.ReadAsync();
            Assert.Single(events);
            Assert.DoesNotContain("linked-folder", System.Text.Json.JsonSerializer.Serialize(events), StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("already-there.bin", System.Text.Json.JsonSerializer.Serialize(events), StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("arrived-later.bin", System.Text.Json.JsonSerializer.Serialize(events), StringComparison.OrdinalIgnoreCase);
            Assert.All((await store.ReadDownloadedFileMonitorSnapshotAsync()).Files,
                item => Assert.DoesNotContain("linked-folder", item.Key, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            if (Directory.Exists(junction)) Directory.Delete(junction);
        }
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

    private static void CreateJunction(string path, string target)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add("/d");
        start.ArgumentList.Add("/c");
        start.ArgumentList.Add("mklink");
        start.ArgumentList.Add("/J");
        start.ArgumentList.Add(path);
        start.ArgumentList.Add(target);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Nie uruchomiono tworzenia junction testowego.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        Assert.True(process.ExitCode == 0 && Directory.Exists(path), $"Nie utworzono junction testowego. {output} {error}");
    }
}
