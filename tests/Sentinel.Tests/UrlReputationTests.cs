using Microsoft.Data.Sqlite;
using Sentinel.Core.Analysis;
using Xunit;

namespace Sentinel.Tests;

public sealed class UrlReputationTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "sentinel-url-reputation-" + Guid.NewGuid());

    [Fact]
    public void ExactUrlFeedMatchesLocallyAndPersistsOnlyHashes()
    {
        var importedAt = DateTimeOffset.Parse("2026-10-23T10:00:00Z");
        var reputation = new UrlReputation(directory);
        reputation.Import("# user supplied URL list\nhttps://bad.example.test/account?token=fixture#ignored\n", importedAt);

        Assert.True(reputation.Check("https://bad.example.test/account?token=fixture", importedAt.AddHours(1)).Match);
        Assert.False(reputation.Check("https://bad.example.test/other?token=fixture", importedAt.AddHours(1)).Match);
        Assert.False(reputation.Check("https://bad.example.test/account?token=other", importedAt.AddHours(1)).Match);
        Assert.True(reputation.Check("https://bad.example.test/account?token=fixture", importedAt.AddHours(49)).FeedImported is false);

        var database = File.ReadAllBytes(Path.Combine(directory, "url-reputation.db"));
        var databaseText = System.Text.Encoding.UTF8.GetString(database);
        Assert.DoesNotContain("bad.example.test", databaseText, StringComparison.Ordinal);
        Assert.DoesNotContain("token=fixture", databaseText, StringComparison.Ordinal);
        Assert.Equal(1, reputation.Status(importedAt.AddHours(1)).UrlCount);
    }

    [Fact]
    public async Task ImportsOnlyVerifiedOnlinePhishTankCsvRowsAndPreservesFeedOnInvalidCsv()
    {
        var now = DateTimeOffset.Parse("2026-10-23T10:00:00Z");
        var reputation = new UrlReputation(directory);
        var csvPath = Path.Combine(directory, "phish-feed.CSV");
        var csv = "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\r\n" +
                  "1,\"https://bad.example.test/pay,roll?case=1\",https://phishtank.example/detail/1,2026-10-23T09:00:00Z,yes,2026-10-23T09:10:00Z,yes,\"Mega, Inc.\"\r\n" +
                  "2,https://offline.example.test/,https://phishtank.example/detail/2,2026-10-23T09:00:00Z,yes,2026-10-23T09:10:00Z,no,Other\r\n" +
                  "3,https://unverified.example.test/,https://phishtank.example/detail/3,2026-10-23T09:00:00Z,no,,yes,Other\r\n";
        await File.WriteAllTextAsync(csvPath, csv, new System.Text.UTF8Encoding(false));

        var imported = await reputation.ImportFileAsync(csvPath, now);

        Assert.Equal(1, imported.UrlCount);
        Assert.True(reputation.Check("https://bad.example.test/pay,roll?case=1", now.AddMinutes(1)).Match);
        Assert.False(reputation.Check("https://offline.example.test/", now.AddMinutes(1)).Match);
        Assert.False(reputation.Check("https://unverified.example.test/", now.AddMinutes(1)).Match);

        var invalidCsvPath = Path.Combine(directory, "invalid.csv");
        await File.WriteAllTextAsync(invalidCsvPath,
            "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n" +
            "4,javascript:alert(1),https://phishtank.example/detail/4,2026-10-23T09:00:00Z,yes,2026-10-23T09:10:00Z,yes,Other\n",
            new System.Text.UTF8Encoding(false));
        await Assert.ThrowsAsync<InvalidDataException>(() => reputation.ImportFileAsync(invalidCsvPath, now.AddHours(1)));
        Assert.True(reputation.Check("https://bad.example.test/pay,roll?case=1", now.AddHours(1)).Match);
        Assert.Equal(1, reputation.Status(now.AddHours(1)).UrlCount);
    }

    [Fact]
    public void InvalidOrEmptyReplacementKeepsCommittedFeedAndRollbackRestoresPreviousFeed()
    {
        var importedAt = DateTimeOffset.Parse("2026-10-23T10:00:00Z");
        var reputation = new UrlReputation(directory);
        reputation.Import("https://first.example.test/path\n", importedAt);
        Assert.Throws<InvalidDataException>(() => reputation.Import("https://valid.example.test/\nfile:///private\n", importedAt.AddHours(1)));
        Assert.Throws<InvalidDataException>(() => reputation.Import("# empty\n", importedAt.AddHours(1)));
        Assert.True(reputation.Check("https://first.example.test/path", importedAt.AddHours(1)).Match);

        reputation.Import("https://second.example.test/path\n", importedAt.AddHours(2));
        reputation.Rollback();
        Assert.True(reputation.Check("https://first.example.test/path", importedAt.AddHours(3)).Match);
        Assert.False(reputation.Check("https://second.example.test/path", importedAt.AddHours(3)).Match);
    }

    [Fact]
    public void FeedClearRemovesCurrentAndPreviousSignalsAndFreshnessMetadata()
    {
        var reputation = new UrlReputation(directory);
        var now = DateTimeOffset.UtcNow;
        reputation.Import("https://first.example.test/\n", now);
        reputation.Import("https://second.example.test/\n", now.AddMinutes(1));

        var cleared = reputation.Clear();

        Assert.Equal(new UrlReputationStatus(0, null, null, true), cleared);
        Assert.False(reputation.Check("https://second.example.test/", now.AddMinutes(2)).FeedImported);
        Assert.Throws<InvalidDataException>(reputation.Rollback);
        Assert.Equal(new UrlReputationStatus(0, null, null, true), new UrlReputation(directory).Status(now.AddMinutes(2)));
    }

    [Fact]
    public void NormalizesFragmentsButKeepsCaseSensitivePathAndQuery()
    {
        Assert.Equal(UrlReputation.CreateSignalHash("https://example.test/path?q=one"),
            UrlReputation.CreateSignalHash("https://EXAMPLE.test:443/path?q=one#fragment"));
        Assert.NotEqual(UrlReputation.CreateSignalHash("https://example.test/path?q=one"),
            UrlReputation.CreateSignalHash("https://example.test/Path?q=one"));
        Assert.NotEqual(UrlReputation.CreateSignalHash("https://example.test/path?q=one"),
            UrlReputation.CreateSignalHash("https://example.test/path?q=ONE"));
        Assert.Throws<InvalidDataException>(() => UrlReputation.CreateSignalHash("javascript:alert(1)"));
        Assert.Throws<InvalidDataException>(() => UrlReputation.CreateSignalHash("https://example.test/" + new string('x', 4100)));
    }

    [Fact]
    public void DuplicateAndCommentLinesCannotBypassFeedSizeBounds()
    {
        var reputation = new UrlReputation(directory);
        var duplicateLines = string.Join('\n', Enumerable.Repeat("https://same.example.test/", UrlReputation.MaximumUrls + 1));
        Assert.Throws<InvalidDataException>(() => reputation.Import(duplicateLines, DateTimeOffset.UtcNow));
        var commentLines = string.Join('\n', Enumerable.Repeat("# comment", UrlReputation.MaximumFeedLines + 1));
        Assert.Throws<InvalidDataException>(() => reputation.Import(commentLines, DateTimeOffset.UtcNow));
        Assert.Equal(0, reputation.Status(DateTimeOffset.UtcNow).UrlCount);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }
}
