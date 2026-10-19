using Sentinel.Core;
using Sentinel.Core.Enterprise;
using Xunit;
namespace Sentinel.Tests;
public sealed class StoreTests : IDisposable
{
    private readonly string dir = Path.Combine(Path.GetTempPath(), "sentinel-test-" + Guid.NewGuid());
    private async Task<LocalStore> Store() { var s = new LocalStore(dir); await s.InitializeAsync(); return s; }
    private static SecurityEvent Event(DateTimeOffset? time = null) => new(0,time ?? DateTimeOffset.UtcNow,RiskLevel.Information,"Test","Synthetic","Synthetic test only","No action",EventStatus.New);
    [Fact] public async Task SettingsSurviveReopening() { var s = await Store(); await s.SaveSettingsAsync(new(7,false)); var next = await Store(); Assert.Equal(new AppSettings(7,false), await next.LoadSettingsAsync()); }
    [Fact] public async Task EventsAndFeedbackPersist() { var s = await Store(); var id = await s.AddAsync(Event()); await s.SetStatusAsync(id,EventStatus.FalsePositive); var next = await Store(); Assert.Equal(EventStatus.FalsePositive,Assert.Single(await next.ReadAsync()).Status); }
    [Fact] public async Task ConcurrentEventWritesPersistEveryUniqueEvent()
    {
        var store = await Store();
        var writes = Enumerable.Range(0, 32).Select(index => store.AddLocalOnlyAsync(
            Event() with { Category = $"Concurrent-{index}" }));

        var ids = await Task.WhenAll(writes);
        var events = await store.ReadAsync();

        Assert.Equal(32, events.Count);
        Assert.Equal(32, ids.Distinct().Count());
        Assert.Equal(32, events.Select(item => item.EventId).Distinct().Count());
    }
    [Fact] public async Task NewEventsPersistStableIdentityAndProvenance()
    {
        var s = await Store();
        var id = await s.AddLocalOnlyAsync(Event() with { Source = "process-snapshot", RuleVersion = "2026.10.1", ProcessId = 4242, ProcessName = "synthetic-process" });
        var item = Assert.Single(await (await Store()).ReadAsync());
        Assert.Equal(id, item.Id); Assert.NotEqual(Guid.Empty, item.EventId);
        Assert.Equal("process-snapshot", item.Source); Assert.Equal("2026.10.1", item.RuleVersion);
        Assert.Equal(4242, item.ProcessId); Assert.Equal("synthetic-process", item.ProcessName);
        Assert.Null(item.Confidence); // No calibrated confidence is claimed by deterministic rules.
        var export = Path.Combine(dir, "provenance.json"); await s.ExportAsync(export);
        var exported = Assert.Single(System.Text.Json.JsonSerializer.Deserialize<SecurityEvent[]>(await File.ReadAllTextAsync(export))!);
        Assert.Equal(item.EventId, exported.EventId); Assert.Equal(item.Source, exported.Source); Assert.Equal(item.RuleVersion, exported.RuleVersion);
        Assert.Equal(item.ProcessId, exported.ProcessId); Assert.Equal(item.ProcessName, exported.ProcessName);
    }
    [Fact] public async Task VersionThreeHistoryMigratesWithoutLosingEvents()
    {
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "sentinel.db");
        await using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path};Pooling=False"))
        {
            await connection.OpenAsync(); await using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE events(id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, risk INTEGER NOT NULL, category TEXT NOT NULL,
                  application TEXT NOT NULL, explanation TEXT NOT NULL, recommendation TEXT NOT NULL, status INTEGER NOT NULL);
                INSERT INTO events VALUES(7,'2026-10-01T00:00:00.0000000+00:00',2,'Legacy','Test','Existing event','Keep it',0);
                PRAGMA user_version=3;
                """;
            await command.ExecuteNonQueryAsync();
        }
        var s = await Store();
        var old = Assert.Single(await s.ReadAsync());
        Assert.Equal(7, old.Id); Assert.Equal("Existing event", old.Explanation);
        Assert.Null(old.EventId); Assert.Null(old.Source); Assert.Null(old.RuleVersion); Assert.Null(old.ProcessId); Assert.Null(old.ProcessName);
        await s.AddAsync(Event() with { Source = "manual-analysis", RuleVersion = "2026.10.1" });
        Assert.Equal(2, (await s.ReadAsync()).Count);
    }
    [Fact] public async Task VersionFiveHistoryAddsOptionalProcessMetadata()
    {
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "sentinel.db");
        await using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path};Pooling=False"))
        {
            await connection.OpenAsync(); await using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE events(id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, risk INTEGER NOT NULL, category TEXT NOT NULL,
                  application TEXT NOT NULL, explanation TEXT NOT NULL, recommendation TEXT NOT NULL, status INTEGER NOT NULL,
                  event_id TEXT, source TEXT, rule_version TEXT, confidence INTEGER, schema_version INTEGER NOT NULL DEFAULT 1);
                INSERT INTO events VALUES(9,'2026-10-01T00:00:00.0000000+00:00',0,'Legacy','Test','Keep','Review',0,'00000000-0000-0000-0000-000000000009','legacy','rules-1',NULL,1);
                PRAGMA user_version=5;
                """;
            await command.ExecuteNonQueryAsync();
        }
        var s = await Store();
        var old = Assert.Single(await s.ReadAsync());
        Assert.Equal(Guid.Parse("00000000-0000-0000-0000-000000000009"), old.EventId);
        Assert.Null(old.ProcessId); Assert.Null(old.ProcessName);
        await s.AddLocalOnlyAsync(Event() with { Source = "process-snapshot", ProcessId = 4242, ProcessName = "synthetic-process" });
        var rows = await s.ReadAsync(); Assert.Equal(4242, Assert.Single(rows, row => row.ProcessId is not null).ProcessId);
    }
    [Fact] public async Task EnterpriseQueueContainsOnlyRiskMetadataAndAcknowledgesBatch()
    {
        var s = await Store();
        await s.SetEnterpriseProfileAsync("https://sentinel.example", shareSecurityMetadata: true);
        await s.AddAsync(new(0, DateTimeOffset.UtcNow, RiskLevel.High, "URL", "Synthetic", "private text and URL", "local advice", EventStatus.New));
        var queued = await s.ReadPendingEnterpriseEventsAsync();
        var item = Assert.Single(queued); Assert.Equal("url", item.Category); Assert.Equal(3, item.RiskLevel); Assert.Equal("local.url", item.RuleCode);
        Assert.DoesNotContain("private", System.Text.Json.JsonSerializer.Serialize(item));
        Assert.Equal(Assert.Single(await s.ReadAsync()).EventId, item.EventId);
        await s.MarkEnterpriseEventsSentAsync([item.EventId]); Assert.Empty(await s.ReadPendingEnterpriseEventsAsync());
    }
    [Fact] public async Task EnterpriseMetadataQueueRequiresExplicitOptIn()
    {
        var s = await Store();
        await s.AddAsync(new(0, DateTimeOffset.UtcNow, RiskLevel.High, "URL", "Synthetic", "private text", "local advice", EventStatus.New));
        Assert.Empty(await s.ReadPendingEnterpriseEventsAsync());
        await Assert.ThrowsAsync<InvalidOperationException>(() => s.EnqueueEnterpriseEventAsync(
            new PendingEnterpriseEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, "url", 3, "local.url")));
        await s.SetEnterpriseProfileAsync("https://sentinel.example", shareSecurityMetadata: false);
        await Assert.ThrowsAsync<InvalidOperationException>(() => s.EnqueueEnterpriseEventAsync(
            new PendingEnterpriseEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, "url", 3, "local.url")));
        await s.SetEnterpriseProfileAsync("https://sentinel.example", shareSecurityMetadata: true);
        await s.EnqueueEnterpriseEventAsync(new PendingEnterpriseEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, "url", 3, "local.url"));
        Assert.Single(await s.ReadPendingEnterpriseEventsAsync());
    }
    [Fact] public async Task EnterpriseOfflineQueueIsBoundedWithoutEvictingPendingEvents()
    {
        var s = await Store(); await s.SetEnterpriseProfileAsync("https://sentinel.example", shareSecurityMetadata: true);
        await using (var c = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={s.DatabasePath};Pooling=False"))
        {
            await c.OpenAsync(); using var seed = c.CreateCommand();
            seed.CommandText = "WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x<10000) INSERT INTO enterprise_event_queue(event_id,occurred_at,category,risk_level,rule_code) SELECT lower(hex(randomblob(16))),strftime('%Y-%m-%dT%H:%M:%fZ','now'),'url',3,'local.url' FROM seq";
            await seed.ExecuteNonQueryAsync();
        }
        Assert.False(await s.EnqueueEnterpriseEventAsync(new PendingEnterpriseEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, "url", 3, "local.url")));
        Assert.Equal(10000, await s.CountPendingEnterpriseEventsAsync());
    }
    [Fact] public async Task RevokingEnterpriseConsentClearsPendingMetadataWithoutDeletingLocalHistory()
    {
        var s = await Store(); await s.SetEnterpriseProfileAsync("https://sentinel.example", shareSecurityMetadata: true);
        var localEvent = new SecurityEvent(0, DateTimeOffset.UtcNow, RiskLevel.High, "URL", "Synthetic", "private local evidence", "local advice", EventStatus.New, EventId: Guid.NewGuid());
        await s.AddLocalOnlyAsync(localEvent);
        Assert.True(await s.EnqueueEnterpriseEventAsync(new PendingEnterpriseEvent(localEvent.EventId!.Value, localEvent.Timestamp, "url", 3, "local.url")));
        await s.SetEnterpriseProfileAsync("https://sentinel.example", shareSecurityMetadata: false);
        await s.ClearEnterpriseEventQueueAsync();
        Assert.Empty(await s.ReadPendingEnterpriseEventsAsync());
        Assert.Equal("private local evidence", Assert.Single(await s.ReadAsync()).Explanation);
    }
    [Fact] public async Task RetentionRemovesOnlyOldEvents() { var s = await Store(); await s.AddAsync(Event(DateTimeOffset.UtcNow.AddDays(-60))); await s.AddAsync(Event()); await s.ApplyRetentionAsync(30); Assert.Single(await s.ReadAsync()); }
    [Fact] public async Task InvalidRetentionRejected() { var s = await Store(); await Assert.ThrowsAsync<ArgumentOutOfRangeException>(()=>s.SaveSettingsAsync(new(0))); }
    [Fact] public async Task BackupCanReopenAndExportIsValid() { var s = await Store(); await s.AddAsync(Event()); var export = Path.Combine(dir,"events.json"); await s.ExportAsync(export); Assert.Contains("Synthetic",await File.ReadAllTextAsync(export)); var backupDir = Path.Combine(dir,"backup"); Directory.CreateDirectory(backupDir); await s.BackupAsync(Path.Combine(backupDir,"sentinel.db")); var backup = new LocalStore(backupDir); await backup.InitializeAsync(); Assert.Single(await backup.ReadAsync()); }
    [Fact] public async Task RestoreReplacesHistoryAndSettingsButPreservesInstalledIdentity()
    {
        var backupDirectory = Path.Combine(dir, "backup-source"); Directory.CreateDirectory(backupDirectory);
        var source = new LocalStore(backupDirectory);
        await source.InitializeAsync(new Sentinel.Core.Configuration.InstalledProductProfile(Sentinel.Core.Configuration.ProductVariant.EnterpriseClient, "https://sentinel.example"));
        await source.AddAsync(Event() with { Category = "BackupEvent" });
        var restoredSettings = new AppSettings(RetentionDays: 30, Notifications: false, Paused: false);
        await source.SaveSettingsAsync(restoredSettings);
        var backupPath = Path.Combine(dir, "restore.db"); await source.BackupAsync(backupPath);

        var target = await Store();
        await target.AddAsync(Event() with { Category = "DiscardedEvent" });
        Assert.Equal(1, await target.RestoreAsync(backupPath));

        Assert.Equal("BackupEvent", Assert.Single(await target.ReadAsync()).Category);
        Assert.Equal(restoredSettings, await target.LoadSettingsAsync());
        Assert.Equal(Sentinel.Core.Configuration.ProductVariant.User, (await target.GetInstallationProfileAsync()).Variant);
    }
    [Fact] public async Task InvalidRestoreSourceDoesNotChangeCurrentEvents()
    {
        var target = await Store(); await target.AddAsync(Event() with { Category = "KeepCurrentEvent" });
        var corrupt = Path.Combine(dir, "corrupt.db"); await File.WriteAllTextAsync(corrupt, "not a SQLite database");
        await Assert.ThrowsAsync<Microsoft.Data.Sqlite.SqliteException>(() => target.RestoreAsync(corrupt));
        Assert.Equal("KeepCurrentEvent", Assert.Single(await target.ReadAsync()).Category);
    }
    [Fact] public async Task DeleteClearsHistory() { var s = await Store(); await s.AddAsync(Event()); await s.DeleteHistoryAsync(); Assert.Empty(await s.ReadAsync()); }
    [Fact] public async Task CorruptDatabaseFailsWithoutReset() { Directory.CreateDirectory(dir); var path=Path.Combine(dir,"sentinel.db"); await File.WriteAllTextAsync(path,"not a sqlite database"); var s=new LocalStore(dir); await Assert.ThrowsAsync<Microsoft.Data.Sqlite.SqliteException>(()=>s.InitializeAsync()); Assert.Equal("not a sqlite database",await File.ReadAllTextAsync(path)); }
    [Fact] public void FileInsteadOfDirectoryFails() { Directory.CreateDirectory(dir); var p=Path.Combine(dir,"file"); File.WriteAllText(p,"x"); Assert.Throws<IOException>(()=>new LocalStore(p)); }
    [Fact] public async Task MigrationIsRepeatableAndFutureSchemaRejected() { var s = await Store(); await s.AddAsync(Event()); await s.InitializeAsync(); var item=Assert.Single(await s.ReadAsync()); Assert.NotEqual(Guid.Empty,item.EventId); await using var c = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={s.DatabasePath};Pooling=False"); await c.OpenAsync(); using var cmd=c.CreateCommand(); cmd.CommandText="PRAGMA user_version=99"; await cmd.ExecuteNonQueryAsync(); await Assert.ThrowsAsync<InvalidDataException>(()=>s.InitializeAsync()); }
    [Fact] public async Task MonitoringSettingsSurviveReopening()
    {
        var s = await Store();
        var settings = new AppSettings(Paused: false, MinimumIntervalSeconds: 25,
            ExcludedApplications: "example;private", ExcludedWindowTitles: "sekret",
            ExcludeBrowsers: true, ExcludeMessaging: true, CollectStaticText: false, MonitorForegroundChanges: true);
        await s.SaveSettingsAsync(settings);
        Assert.Equal(settings, await (await Store()).LoadSettingsAsync());
    }
    [Fact] public async Task StageOneSettingsReceiveSafeDefaults()
    {
        var s = await Store();
        await using var c = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={s.DatabasePath};Pooling=False");
        await c.OpenAsync(); using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO settings VALUES(1, $json)";
        cmd.Parameters.AddWithValue("$json", "{\"RetentionDays\":7,\"Notifications\":false,\"Paused\":true}");
        await cmd.ExecuteNonQueryAsync();
        var settings = await s.LoadSettingsAsync();
        Assert.True(settings.Paused); Assert.False(settings.MonitorForegroundChanges);
        Assert.Equal(10, settings.MinimumIntervalSeconds); Assert.Contains("bitwarden",settings.ExcludedApplications);
    }
    [Theory] [InlineData(0)] [InlineData(301)]
    public async Task InvalidCollectionIntervalIsRejected(int seconds)
    {
        var s = await Store(); await Assert.ThrowsAsync<ArgumentOutOfRangeException>(()=>s.SaveSettingsAsync(new(MinimumIntervalSeconds:seconds)));
    }
    public void Dispose() { if(Directory.Exists(dir)) Directory.Delete(dir,true); }
}
