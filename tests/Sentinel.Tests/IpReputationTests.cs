using System.Net;
using Microsoft.Data.Sqlite;
using Sentinel.Core.Analysis;
using Xunit;

namespace Sentinel.Tests;

public sealed class IpReputationTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "sentinel-ip-reputation-" + Guid.NewGuid());

    [Fact]
    public void ImportsCanonicalIpv4AndIpv6NetworksAndMatchesWithoutNetworkAccess()
    {
        var reputation = new IpReputation(directory);
        reputation.Import("192.0.2.7\n198.51.100.9/24 # example block\n2001:db8:1234::/48\n", DateTimeOffset.UtcNow);

        Assert.True(reputation.Contains("192.0.2.7"));
        Assert.True(reputation.Contains("198.51.100.42"));
        Assert.False(reputation.Contains("198.51.101.42"));
        Assert.True(reputation.Contains("2001:db8:1234::abcd"));
        Assert.False(reputation.Contains("2001:db8:1235::1"));
        Assert.Equal(3, reputation.Status().NetworkCount);
    }

    [Fact]
    public void InvalidReplacementDoesNotEraseTheLastCommittedFeedAndFeedSurvivesRestart()
    {
        var reputation = new IpReputation(directory);
        reputation.Import("203.0.113.10/32\n", DateTimeOffset.Parse("2026-10-22T12:00:00Z"));
        Assert.Throws<InvalidDataException>(() => reputation.Import("198.51.100.0/99\n", DateTimeOffset.UtcNow));

        var reopened = new IpReputation(directory);
        Assert.True(reopened.Contains("203.0.113.10"));
        Assert.False(reopened.Contains("198.51.100.1"));
        Assert.Equal(DateTimeOffset.Parse("2026-10-22T12:00:00Z"), reopened.Status().ImportedAt);
    }

    [Fact]
    public void RejectsMalformedAndEmptyFeedsInsteadOfTreatingThemAsAReplacement()
    {
        var reputation = new IpReputation(directory);
        Assert.Throws<InvalidDataException>(() => reputation.Import("not-an-address\n", DateTimeOffset.UtcNow));
        Assert.Throws<InvalidDataException>(() => reputation.Import("# no indicators\n", DateTimeOffset.UtcNow));
        Assert.Equal(0, reputation.Status().NetworkCount);
    }

    [Fact]
    public void NormalizesIpv4MappedIpv6AddressToIpv4ForExactMatches()
    {
        var reputation = new IpReputation(directory);
        reputation.Import("192.0.2.44\n", DateTimeOffset.UtcNow);
        var mapped = IPAddress.Parse("::ffff:192.0.2.44").ToString();
        Assert.True(reputation.Contains(mapped));
    }

    [Fact]
    public void ClearingFeedRemovesNetworksAndImportMetadataAcrossRestart()
    {
        var reputation = new IpReputation(directory);
        reputation.Import("203.0.113.0/24\n", DateTimeOffset.Parse("2026-10-22T12:00:00Z"));

        var status = reputation.Clear();

        Assert.Equal(new IpReputationStatus(0, null), status);
        Assert.False(reputation.Contains("203.0.113.42"));
        var reopened = new IpReputation(directory);
        Assert.Equal(new IpReputationStatus(0, null), reopened.Status());
        Assert.False(reopened.Contains("203.0.113.42"));
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }
}
