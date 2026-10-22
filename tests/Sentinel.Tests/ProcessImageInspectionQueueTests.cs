using System.Security.Cryptography;
using Sentinel.Core;
using Sentinel.Core.Analysis;
using Xunit;

namespace Sentinel.Tests;

public sealed class ProcessImageInspectionQueueTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "sentinel-process-image-queue-" + Guid.NewGuid());

    [Fact]
    public async Task QueueHashesLocalImageChecksFeedAndPersistsSignatureResult()
    {
        Directory.CreateDirectory(directory);
        var store = new LocalStore(directory);
        await store.InitializeAsync();
        var imagePath = Path.Combine(directory, "synthetic-process.exe");
        var imageBytes = Enumerable.Range(0, 4096).Select(index => (byte)(index % 251)).ToArray();
        await File.WriteAllBytesAsync(imagePath, imageBytes);
        var expectedHash = Convert.ToHexString(SHA256.HashData(imageBytes));
        var reputation = new FileHashReputation(directory);
        reputation.Import(expectedHash, DateTimeOffset.UtcNow);
        var eventId = Guid.NewGuid();
        await store.AddLocalOnlyAsync(new SecurityEvent(0, DateTimeOffset.UtcNow, RiskLevel.Information,
            "Proces zaobserwowany", "synthetic-process", "Test-only process", "No action", EventStatus.New,
            EventId: eventId, Source: "process-snapshot", ProcessId: 123, ProcessName: "synthetic-process",
            EvidenceCodes: ["process.snapshot.new-pid", "process.image.path-available"],
            ProcessImagePath: imagePath, ProcessImageSignatureStatus: "Pending"));

        await using var queue = new ProcessImageInspectionQueue(store, reputation,
            (_, _) => Task.FromResult(new AuthenticodeSignatureInfo("Valid", "Synthetic signer", "TEST")));
        Assert.True(queue.TryEnqueue(eventId, imagePath));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (queue.Completed == 0)
            await Task.Delay(10, timeout.Token);

        var inspected = Assert.Single(await store.ReadAsync());
        Assert.Equal(expectedHash, inspected.ProcessImageSha256);
        Assert.Equal("Valid", inspected.ProcessImageSignatureStatus);
        Assert.True(inspected.ProcessImageLocalHashMatch);
        Assert.Contains("process.image.sha256.available", inspected.EvidenceCodes!);
        Assert.Contains("process.image.local-hash-match", inspected.EvidenceCodes!);

        var exportPath = Path.Combine(directory, "events.json");
        await store.ExportAsync(exportPath);
        var export = await File.ReadAllTextAsync(exportPath);
        Assert.DoesNotContain(imagePath, export, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(expectedHash, export, StringComparison.OrdinalIgnoreCase);
    }

    public void Dispose()
    {
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }
}
