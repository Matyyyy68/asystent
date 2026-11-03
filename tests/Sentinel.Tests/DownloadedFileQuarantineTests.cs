using System.Security.Cryptography;
using Sentinel.Core.Analysis;
using Xunit;

namespace Sentinel.Tests;

public sealed class DownloadedFileQuarantineTests : IDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), "sentinel-quarantine-" + Guid.NewGuid().ToString("N"));
    private readonly string downloads;
    private readonly string data;
    private readonly DownloadedFileQuarantine quarantine;

    public DownloadedFileQuarantineTests()
    {
        downloads = Path.Combine(root, "Downloads");
        data = Path.Combine(root, "Data");
        Directory.CreateDirectory(downloads);
        Directory.CreateDirectory(data);
        quarantine = new DownloadedFileQuarantine(data, downloads);
        quarantine.InitializeAsync().GetAwaiter().GetResult();
    }

    [Fact]
    public async Task MovesOnlyTheMatchingDownloadsFileAndCanRestoreIt()
    {
        var content = "harmless quarantine fixture"u8.ToArray();
        var source = Path.Combine(downloads, "fixture.exe");
        await File.WriteAllBytesAsync(source, content);
        var hash = Convert.ToHexString(SHA256.HashData(content));
        var eventId = Guid.NewGuid();

        var moved = await quarantine.QuarantineAsync(eventId, source, hash);

        Assert.Equal("fixture.exe", moved.FileName);
        Assert.Equal(eventId, moved.EventId);
        Assert.Equal("Quarantined", moved.State);
        Assert.False(File.Exists(source));
        Assert.Contains(eventId, await quarantine.ReadQuarantinedEventIdsAsync());
        var quarantinedFile = Directory.GetFiles(Path.Combine(data, "Quarantine"), "*.quarantined").Single();
        Assert.Equal(hash, Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(quarantinedFile))));

        var restored = await quarantine.RestoreAsync(eventId);

        Assert.Equal("Restored", restored.State);
        Assert.Equal(content, await File.ReadAllBytesAsync(source));
        Assert.DoesNotContain(eventId, await quarantine.ReadQuarantinedEventIdsAsync());
    }

    [Fact]
    public async Task RejectsHashMismatchAndFilesOutsideDownloadsWithoutMovingAnything()
    {
        var source = Path.Combine(downloads, "fixture.exe");
        var outside = Path.Combine(root, "outside.exe");
        await File.WriteAllTextAsync(source, "fixture");
        await File.WriteAllTextAsync(outside, "fixture");
        var correctHash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(source)));
        var wrongHash = new string('A', 64);

        await Assert.ThrowsAsync<InvalidOperationException>(() => quarantine.QuarantineAsync(Guid.NewGuid(), source, wrongHash));
        await Assert.ThrowsAsync<InvalidOperationException>(() => quarantine.QuarantineAsync(Guid.NewGuid(), outside, correctHash));

        Assert.True(File.Exists(source));
        Assert.True(File.Exists(outside));
        Assert.Empty(await quarantine.ReadQuarantinedEventIdsAsync());
    }

    [Fact]
    public async Task RestoreNeverOverwritesAFileCreatedAtTheOriginalPath()
    {
        var source = Path.Combine(downloads, "fixture.exe");
        await File.WriteAllTextAsync(source, "original");
        var hash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(source)));
        var eventId = Guid.NewGuid();
        await quarantine.QuarantineAsync(eventId, source, hash);
        await File.WriteAllTextAsync(source, "user replacement");

        await Assert.ThrowsAsync<IOException>(() => quarantine.RestoreAsync(eventId));

        Assert.Equal("user replacement", await File.ReadAllTextAsync(source));
        Assert.Contains(eventId, await quarantine.ReadQuarantinedEventIdsAsync());
    }

    public void Dispose()
    {
        try { Directory.Delete(root, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
