using Sentinel.Core.Analysis;
using Xunit;
namespace Sentinel.Tests;
public sealed class ReputationTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "sentinel-reputation-" + Guid.NewGuid());
    [Fact]
    public void MatchesOnlyExactFreshDomainAndDeduplicates()
    {
        var store = new DomainReputation(directory); var now = DateTimeOffset.UtcNow;
        store.Import("EVIL.test\nevil.test\nżółw.test", now);
        Assert.Equal(2, store.Status(now).Count);
        Assert.True(store.Contains("evil.test.", now));
        Assert.True(store.Contains(DomainReputation.Normalize("żółw.test"), now));
        Assert.False(store.Contains("notevil.test", now));
        Assert.False(store.Contains("evil.test.example.test", now));
        Assert.False(store.Contains("192.0.2.1", now));
        Assert.False(store.Contains("evil.test", now.AddDays(3)));
    }
    [Fact]
    public void FailedImportPreservesSnapshotAndRollbackRestoresPrevious()
    {
        var store = new DomainReputation(directory); var now = DateTimeOffset.UtcNow;
        store.Import("old.test", now);
        Assert.Throws<InvalidDataException>(() => store.Import("<html>error</html>", now));
        Assert.True(store.Contains("old.test", now));
        store.Import("new.test", now);
        Assert.False(store.Contains("old.test", now));
        store.Rollback();
        Assert.True(store.Contains("old.test", now));
        Assert.False(store.Contains("new.test", now));
    }
    [Fact]
    public void BrowserUrlUsesReputationWithoutBroadIpBlocking()
    {
        var store = new DomainReputation(directory); store.Import("fraud.test", DateTimeOffset.UtcNow);
        var processor = new Sentinel.UrlHost.UrlRequestProcessor(store);
        var flagged = processor.Process(new Sentinel.UrlHost.BrowserRequest("1", "analyze", "https://fraud.test/login"));
        var unflagged = processor.Process(new Sentinel.UrlHost.BrowserRequest("2", "analyze", "https://other.test/login"));
        Assert.True(flagged.ShouldWarn);
        Assert.Contains(flagged.Indicators, indicator => indicator.Id == "reputation.cert");
        Assert.DoesNotContain(unflagged.Indicators, indicator => indicator.Id == "reputation.cert");
        Assert.False(store.Contains("192.0.2.20", DateTimeOffset.UtcNow));
    }
    public void Dispose() { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
}
