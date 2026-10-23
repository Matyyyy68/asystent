using Sentinel.Core.Analysis;
using Xunit;
namespace Sentinel.Tests;
public sealed class ReputationTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "sentinel-reputation-" + Guid.NewGuid());
    [Fact]
    public void MatchesListedDomainAndSubdomainsButNotParentsOrLookalikes()
    {
        var store = new DomainReputation(directory); var now = DateTimeOffset.UtcNow;
        store.Import("EVIL.test\nevil.test\nżółw.test\nlogin.only.test\nco.uk", now);
        Assert.Equal(4, store.Status(now).Count);
        Assert.True(store.Contains("evil.test.", now));
        Assert.True(store.Contains("www.evil.test", now));
        Assert.True(store.Contains(DomainReputation.Normalize("żółw.test"), now));
        Assert.False(store.Contains("notevil.test", now));
        Assert.False(store.Contains("evil.test.example.test", now));
        Assert.True(store.Contains("child.login.only.test", now));
        Assert.False(store.Contains("only.test", now));
        Assert.False(store.Contains("tenant.co.uk", now));
        Assert.False(store.Contains("192.0.2.1", now));
        Assert.False(store.Contains("evil.test", now.AddDays(3)));
    }
    [Fact]
    public void FindMatchesIncludesSubdomainsWithoutLeakingParentOrLookalikeMatches()
    {
        var store = new DomainReputation(directory); var now = DateTimeOffset.UtcNow;
        store.Import("evil.test\nlogin.only.test", now);

        var matches = store.FindMatches([
            "www.evil.test", "notevil.test", "only.test", "child.login.only.test", "safe.test"
        ], now);

        Assert.Equal(new[] { "www.evil.test", "child.login.only.test" }, matches);
    }
    [Fact]
    public void EmptyImportedDomainTableIsNeverReportedAsCurrent()
    {
        var now = DateTimeOffset.UtcNow;
        var store = new DomainReputation(directory);
        store.Import("example.test\nmalware.test\n", now);
        using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={Path.Combine(directory, "reputation.db")};Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM domains";
            command.ExecuteNonQuery();
        }

        var status = store.Status(now);

        Assert.Equal(0, status.Count);
        Assert.Equal(now, status.FetchedAt);
        Assert.True(status.Expired);
        Assert.False(store.Contains("example.test", now));
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
    [Fact]
    public async Task LiveCertFeedCanBeFetchedOnlyWhenExplicitlyEnabled()
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("SENTINEL_LIVE_CERT_FEED"), "1", StringComparison.Ordinal)) return;
        var store = new DomainReputation(directory);

        await store.UpdateAsync();

        var status = store.Status(DateTimeOffset.UtcNow);
        Assert.True(status.Count > 0);
        Assert.False(status.Expired);
        Assert.Matches("^[A-F0-9]{64}$", status.Version!);
        Assert.NotNull(status.FetchedAt);
    }
    public void Dispose() { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
}
