using Sentinel.Core;
using Sentinel.Core.Configuration;
using Xunit;

namespace Sentinel.Tests;

public sealed class ConfigurationTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "sentinel-profile-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task FirstInstallProfileIsPersistedAndUpdateCannotChangeVariant()
    {
        var store = new LocalStore(directory);
        await store.InitializeAsync(new InstalledProductProfile(ProductVariant.EnterpriseClient, "https://sentinel.example"));
        var reopened = new LocalStore(directory);
        await reopened.InitializeAsync(new InstalledProductProfile(ProductVariant.User));
        Assert.Equal(new InstalledProductProfile(ProductVariant.EnterpriseClient, "https://sentinel.example"), await reopened.GetInstallationProfileAsync());
    }

    [Fact]
    public async Task ExistingUserDatabaseRemainsUserOnUpgrade()
    {
        var store = new LocalStore(directory);
        await store.InitializeAsync();
        await store.InitializeAsync(new InstalledProductProfile(ProductVariant.EnterpriseClient, "https://other.example"));
        Assert.Equal(ProductVariant.User, (await store.GetInstallationProfileAsync()).Variant);
    }

    [Fact]
    public async Task VersionOneDatabaseMigratesWithoutLosingSettingsOrHistory()
    {
        var store = new LocalStore(directory);
        await using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={store.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync();
            using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE settings(id INTEGER PRIMARY KEY CHECK(id=1), json TEXT NOT NULL);
                CREATE TABLE events(id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, risk INTEGER NOT NULL, category TEXT NOT NULL, application TEXT NOT NULL, explanation TEXT NOT NULL, recommendation TEXT NOT NULL, status INTEGER NOT NULL);
                CREATE VIRTUAL TABLE knowledge USING fts5(source UNINDEXED, content);
                INSERT INTO settings VALUES(1, '{"RetentionDays":11,"Notifications":false,"Paused":true}');
                PRAGMA user_version=1;
                """;
            await command.ExecuteNonQueryAsync();
        }
        await store.InitializeAsync();
        Assert.Equal(11, (await store.LoadSettingsAsync()).RetentionDays);
        Assert.Equal(ProductVariant.User, (await store.GetInstallationProfileAsync()).Variant);
    }

    [Theory]
    [InlineData("http://server.example", ProductVariant.EnterpriseClient)]
    [InlineData("https://user:password@server.example", ProductVariant.EnterpriseClient)]
    [InlineData("https://server.example/api", ProductVariant.EnterpriseClient)]
    [InlineData("https://server.example", ProductVariant.User)]
    public void InvalidProductProfilesAreRejected(string address, ProductVariant variant) =>
        Assert.Throws<ArgumentException>(() => new InstalledProductProfile(variant, address).Validate());

    [Theory]
    [InlineData("--sentinel-variant=user", ProductVariant.User)]
    [InlineData("--sentinel-variant=enterprise-client", ProductVariant.EnterpriseClient)]
    public void InstallerVariantArgumentsAreValidated(string argument, ProductVariant expected) =>
        Assert.Equal(expected, ProductProfileArguments.Parse([argument]).Variant);

    [Fact]
    public void UnknownInstallerArgumentsFailClosed() => Assert.Throws<ArgumentException>(() => ProductProfileArguments.Parse(["--sentinel-variant=admin"]));

    [Fact]
    public void DuplicateInstallerVariantIsRejected() => Assert.Throws<ArgumentException>(() => ProductProfileArguments.Parse(["--sentinel-variant=user", "--sentinel-variant=enterprise-client"]));

    [Fact]
    public void RecommendationOnlySelectsImplementedOfflineCapabilities()
    {
        var system = new SystemSnapshot("Windows", "Pro", "X64", "CPU", 8, 8UL << 30, 4UL << 30,
            20L << 30, ["Example GPU"], NpuAvailability.Unknown, false, [], true, true);
        var recommendation = new ConfigurationRecommendationEngine().Recommend(system, ProductVariant.User);
        Assert.False(recommendation.RequiresNetworkForBasicAnalysis);
        Assert.Contains("Lokalny silnik reguł", recommendation.AvailableModules);
        Assert.Contains("Lokalna baza pełnotekstowa FTS5 (TXT, MD, DOCX)", recommendation.AvailableModules);
        Assert.Contains(recommendation.UnavailableModules, item => item.Contains("dobór modelu", StringComparison.Ordinal));
        Assert.Contains(recommendation.Notices, item => item.Contains("zgodność z modelem", StringComparison.Ordinal));
    }

    [Fact]
    public void EnterpriseRecommendationDoesNotClaimSynchronizationExists()
    {
        var system = new SystemSnapshot("Windows", null, "X64", null, null, null, null, null, null,
            NpuAvailability.Unknown, null, [], true, true);
        var recommendation = new ConfigurationRecommendationEngine().Recommend(system, ProductVariant.EnterpriseClient);
        Assert.Contains(recommendation.UnavailableModules, item => item.Contains("synchronizacji polityk", StringComparison.Ordinal));
        Assert.Contains(recommendation.Notices, item => item.Contains("nie może jeszcze połączyć", StringComparison.Ordinal));
    }

    public void Dispose() { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
}
