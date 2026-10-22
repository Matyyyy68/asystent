using Sentinel.Core.Analysis;
using Xunit;

namespace Sentinel.Tests;

public sealed class FileHashReputationTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "sentinel-file-reputation-" + Guid.NewGuid());

    [Fact]
    public void EmptyFeedDoesNotClaimFilesAreReputable()
    {
        var reputation = new FileHashReputation(directory);

        Assert.Equal(new FileHashReputationStatus(0, null), reputation.Status());
        Assert.Equal(new FileHashReputationCheck(false, false), reputation.Check(new string('a', 64)));
    }

    [Fact]
    public void ImportNormalizesDeduplicatesAndMatchesExactSha256()
    {
        var reputation = new FileHashReputation(directory);
        const string hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        reputation.Import($"# user-provided test feed\n{hash}\n{hash.ToUpperInvariant()}\n", DateTimeOffset.Parse("2026-10-20T12:00:00Z"));

        Assert.Equal(1, reputation.Status().HashCount);
        Assert.Equal(new FileHashReputationCheck(true, true), reputation.Check(hash));
        Assert.Equal(new FileHashReputationCheck(true, false), reputation.Check(new string('f', 64)));
    }

    [Fact]
    public void InvalidImportDoesNotReplaceExistingHashes()
    {
        var reputation = new FileHashReputation(directory);
        var validHash = new string('a', 64);
        reputation.Import(validHash, DateTimeOffset.UtcNow);

        Assert.Throws<InvalidDataException>(() => reputation.Import(validHash + "\nnot-a-sha256", DateTimeOffset.UtcNow));

        Assert.Equal(new FileHashReputationCheck(true, true), reputation.Check(validHash));
        Assert.Equal(1, reputation.Status().HashCount);
    }

    [Fact]
    public void ImportRejectsEmptyOrOversizedHashLists()
    {
        var reputation = new FileHashReputation(directory);

        Assert.Throws<InvalidDataException>(() => reputation.Import("# no indicators", DateTimeOffset.UtcNow));
        Assert.Throws<InvalidDataException>(() => reputation.Import(new string('a', FileHashReputation.MaximumFeedBytes + 1), DateTimeOffset.UtcNow));
        Assert.Equal(0, reputation.Status().HashCount);
    }

    [Fact]
    public void ClearingFeedRemovesHashesAndImportMetadataAcrossRestart()
    {
        var reputation = new FileHashReputation(directory);
        var hash = new string('b', 64);
        reputation.Import(hash, DateTimeOffset.Parse("2026-10-22T12:00:00Z"));

        var status = reputation.Clear();

        Assert.Equal(new FileHashReputationStatus(0, null), status);
        Assert.Equal(new FileHashReputationCheck(false, false), reputation.Check(hash));
        var reopened = new FileHashReputation(directory);
        Assert.Equal(new FileHashReputationStatus(0, null), reopened.Status());
        Assert.Equal(new FileHashReputationCheck(false, false), reopened.Check(hash));
    }

    public void Dispose()
    {
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }
}
