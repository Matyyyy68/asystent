using Sentinel.Core;
using Xunit;
namespace Sentinel.Tests;
public sealed class StoreTests : IDisposable
{
    private readonly string dir = Path.Combine(Path.GetTempPath(), "sentinel-test-" + Guid.NewGuid());
    private async Task<LocalStore> Store() { var s = new LocalStore(dir); await s.InitializeAsync(); return s; }
    private static SecurityEvent Event(DateTimeOffset? time = null) => new(0,time ?? DateTimeOffset.UtcNow,RiskLevel.Information,"Test","Synthetic","Synthetic test only","No action",EventStatus.New);
    [Fact] public async Task SettingsSurviveReopening() { var s = await Store(); await s.SaveSettingsAsync(new(7,false)); var next = await Store(); Assert.Equal(new AppSettings(7,false), await next.LoadSettingsAsync()); }
    [Fact] public async Task EventsAndFeedbackPersist() { var s = await Store(); var id = await s.AddAsync(Event()); await s.SetStatusAsync(id,EventStatus.FalsePositive); var next = await Store(); Assert.Equal(EventStatus.FalsePositive,Assert.Single(await next.ReadAsync()).Status); }
    [Fact] public async Task EnterpriseQueueContainsOnlyRiskMetadataAndAcknowledgesBatch()
    {
        var s = await Store();
        await s.AddAsync(new(0, DateTimeOffset.UtcNow, RiskLevel.High, "URL", "Synthetic", "private text and URL", "local advice", EventStatus.New));
        var queued = await s.ReadPendingEnterpriseEventsAsync();
        var item = Assert.Single(queued); Assert.Equal("url", item.Category); Assert.Equal(3, item.RiskLevel); Assert.Equal("local.url", item.RuleCode);
        Assert.DoesNotContain("private", System.Text.Json.JsonSerializer.Serialize(item));
        await s.MarkEnterpriseEventsSentAsync([item.EventId]); Assert.Empty(await s.ReadPendingEnterpriseEventsAsync());
    }
    [Fact] public async Task RetentionRemovesOnlyOldEvents() { var s = await Store(); await s.AddAsync(Event(DateTimeOffset.UtcNow.AddDays(-60))); await s.AddAsync(Event()); await s.ApplyRetentionAsync(30); Assert.Single(await s.ReadAsync()); }
    [Fact] public async Task InvalidRetentionRejected() { var s = await Store(); await Assert.ThrowsAsync<ArgumentOutOfRangeException>(()=>s.SaveSettingsAsync(new(0))); }
    [Fact] public async Task BackupCanReopenAndExportIsValid() { var s = await Store(); await s.AddAsync(Event()); var export = Path.Combine(dir,"events.json"); await s.ExportAsync(export); Assert.Contains("Synthetic",await File.ReadAllTextAsync(export)); var backupDir = Path.Combine(dir,"backup"); Directory.CreateDirectory(backupDir); await s.BackupAsync(Path.Combine(backupDir,"sentinel.db")); var backup = new LocalStore(backupDir); await backup.InitializeAsync(); Assert.Single(await backup.ReadAsync()); }
    [Fact] public async Task DeleteClearsHistory() { var s = await Store(); await s.AddAsync(Event()); await s.DeleteHistoryAsync(); Assert.Empty(await s.ReadAsync()); }
    [Fact] public async Task CorruptDatabaseFailsWithoutReset() { Directory.CreateDirectory(dir); var path=Path.Combine(dir,"sentinel.db"); await File.WriteAllTextAsync(path,"not a sqlite database"); var s=new LocalStore(dir); await Assert.ThrowsAsync<Microsoft.Data.Sqlite.SqliteException>(()=>s.InitializeAsync()); Assert.Equal("not a sqlite database",await File.ReadAllTextAsync(path)); }
    [Fact] public void FileInsteadOfDirectoryFails() { Directory.CreateDirectory(dir); var p=Path.Combine(dir,"file"); File.WriteAllText(p,"x"); Assert.Throws<IOException>(()=>new LocalStore(p)); }
    [Fact] public async Task MigrationIsRepeatableAndFutureSchemaRejected() { var s = await Store(); await s.InitializeAsync(); await using var c = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={s.DatabasePath};Pooling=False"); await c.OpenAsync(); using var cmd=c.CreateCommand(); cmd.CommandText="PRAGMA user_version=99"; await cmd.ExecuteNonQueryAsync(); await Assert.ThrowsAsync<InvalidDataException>(()=>s.InitializeAsync()); }
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
