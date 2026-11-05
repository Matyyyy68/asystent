Warning: truncated output (original token count: 23513)
Total output lines: 1398

using Sentinel.Core;
using Sentinel.Core.Analysis;
using Sentinel.Core.Enterprise;
using Microsoft.Data.Sqlite;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;
using Xunit;
namespace Sentinel.Tests;
public sealed class StoreTests : IDisposable
{
    private readonly string dir = Path.Combine(Path.GetTempPath(), "sentinel-test-" + Guid.NewGuid());
    private async Task<LocalStore> Store() { var s = new LocalStore(dir); await s.InitializeAsync(); return s; }
    private static SecurityEvent Event(DateTimeOffset? time = null) => new(0,time ?? DateTimeOffset.UtcNow,RiskLevel.Information,"Test","Synthetic","Synthetic test only","No action",EventStatus.New);
    [Fact] public async Task CertFeedAutomaticRefreshDefaultsOnAndAnExplicitOptOutSurvivesRestart()
    {
        var store = await Store();
        Assert.True((await store.LoadSettingsAsync()).AutoUpdateCertFeed);

        await store.SaveSettingsAsync(new AppSettings(AutoUpdateCertFeed: false));

        Assert.False((await (await Store()).LoadSettingsAsync()).AutoUpdateCertFeed);
    }

    [Fact] public async Task EventHistoryCanBeReadInBoundedAscendingPagesAfterStableRowId()
    {
        var store = await Store();
        var first = await store.AddLocalOnlyAsync(Event());
        var second = await store.AddLocalOnlyAsync(Event());
        var third = await store.AddLocalOnlyAsync(Event());

        var page = await store.ReadAfterAsync(first, limit: 1);
        var next = await store.ReadAfterAsync(page[^1].Id);

        Assert.Equal(second, Assert.Single(page).Id);
        Assert.Equal(third, Assert.Single(next).Id);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => store.ReadAfterAsync(-1));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => store.ReadAfterAsync(0, 33));
    }

    [Fact] public async Task ForwardedEventImportIsBoundedAndIdempotentByEventId()
    {
        var store = await Store();
        var item = new ForwardedSecurityEvent(41, DateTimeOffset.UtcNow, RiskLevel.Moderate,
            "Synthetic", "Synthetic", "Test event", "Review", EventStatus.New, Guid.NewGuid(),
            "agent-test", "test-v1", null, 1, null, null, Guid.NewGuid(), ["test.signal"], []);

        Assert.Equal(new long[] { 41 }, await store.ImportForwardedEventsAsync([item]));
        Assert.Equal(new long[] { 41 }, await store.ImportForwardedEventsAsync([item]));
        Assert.Equal(1, await store.CountEventsAsync());
        await Assert.ThrowsAsync<ArgumentException>(() => store.ImportForwardedEventsAsync(Enumerable.Repeat(item, 9).ToArray()));
        await Assert.ThrowsAsync<ArgumentException>(() => store.ImportForwardedEventsAsync([item with { SourceRowId = 0 }]));
    }

    [Fact] public async Task ForwardedEventImportRejectsMalformedPageBeforePersistingAnyRow()
    {
        var store = await Store();
        var first = new ForwardedSecurityEvent(41, DateTimeOffset.UtcNow, RiskLevel.Moderate,
            "Synthetic", "Synthetic", "Test event", "Review", EventStatus.New, Guid.NewGuid(),
            "agent-test", "test-v1", null, 1, null, null, Guid.NewGuid(), ["test.signal"], []);
        var invalidSecond = first with { SourceRowId = 42, EventId = Guid.NewGuid(), Category = "" };

        await Assert.ThrowsAsync<ArgumentException>(() => store.ImportForwardedEventsAsync([first, invalidSecond]));

        Assert.Equal(0, await store.CountEventsAsync());
    }

    [Fact] public async Task DataDirectoryPointerBoundsReadsAndRejectsInvalidOrNonLocalPaths()
    {
        Directory.CreateDirectory(dir);
        var pointer = Path.Combine(dir, "data-path.txt");
        var fallback = Path.Combine(dir, "data");
        Assert.Equal(Path.GetFullPath(fallback), await DataDirectoryPointer.ReadAsync(pointer, fallback));

        await File.WriteAllTextAsync(pointer, fallback);
        Assert.Equal(Path.GetFullPath(fallback), await DataDirectoryPointer.ReadAsync(pointer, fallback));

        var bom = new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: true).GetPreamble();
        await File.WriteAllBytesAsync(pointer, [.. bom, .. System.Text.Encoding.UTF8.GetBytes(fallback)]);
        Assert.Equal(Path.GetFullPath(fallback), await DataDirectoryPointer.ReadAsync(pointer, fallback));

        await File.WriteAllTextAsync(pointer, new string('x', DataDirectoryPointer.MaximumPointerBytes + 1));
        await Assert.ThrowsAsync<InvalidDataException>(() => DataDirectoryPointer.ReadAsync(pointer, fallback));

        await File.WriteAllBytesAsync(pointer, [0xFF]);
        await Assert.ThrowsAsync<InvalidDataException>(() => DataDirectoryPointer.ReadAsync(pointer, fallback));

        await File.WriteAllTextAsync(pointer, fallback);
        using (var locked = new FileStream(pointer, FileMode.Open, FileAccess.Read, FileShare.None))
            await Assert.ThrowsAsync<IOException>(() => DataDirectoryPointer.ReadAsync(pointer, fallback));

        Assert.Throws<InvalidDataException>(() => DataDirectoryPointer.Validate("relative-data"));
        Assert.Throws<InvalidDataException>(() => DataDirectoryPointer.Validate(Path.GetPathRoot(dir)!));
        if (OperatingSystem.IsWindows())
            Assert.Throws<InvalidDataException>(() => DataDirectoryPointer.Validate(@"\\server\share\sentinel"));
    }
    [Fact] public async Task SettingsSurviveReopening() { var s = await Store(); await s.SaveSettingsAsync(new(7,false)); var next = await Store(); Assert.Equal(new AppSettings(7,false), await next.LoadSettingsAsync()); }
    [Fact] public async Task DnsOperationalRecordCursorPersistsAndCanResetAfterLogClear()
    {
        var store = await Store();
        Assert.Null(await store.GetDnsOperationalRecordCursorAsync());
        await store.SetDnsOperationalRecordCursorAsync(42);
        Assert.Equal(42, await (await Store()).GetDnsOperationalRecordCursorAsync());
        await store.SetDnsOperationalRecordCursorAsync(3);
        Assert.Equal(3, await (await Store()).GetDnsOperationalRecordCursorAsync());
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => store.SetDnsOperationalRecordCursorAsync(-1));
    }
    [Fact] public async Task VersionTwentyOneDatabaseMigratesDnsOperationalCursorWithoutLosingHistory()
    {
        var store = await Store();
        await store.AddLocalOnlyAsync(Event() with { Category = "BeforeDnsCursorMigration" });
        await using (var connection = new SqliteConnection($"Data Source={store.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync(); using var command = connection.CreateCommand();
            command.CommandText = "DROP TABLE dns_operational_monitor_metadata; PRAGMA user_version=21;";
            await command.ExecuteNonQueryAsync();
        }
        await store.InitializeAsync();
        Assert.Equal("BeforeDnsCursorMigration", Assert.Single(await store.ReadAsync()).Category);
        Assert.Null(await store.GetDnsOperationalRecordCursorAsync());
        await using var verify = new SqliteConnection($"Data Source={store.DatabasePath};Pooling=False");
        await verify.OpenAsync(); using var version = verify.CreateCommand(); version.CommandText = "PRAGMA user_version";
        Assert.Equal(40L, (long)(await version.ExecuteScalarAsync())!);
    }

    [Fact] public async Task VersionThirtyNineDatabaseMigratesHashFeedRecheckCheckpointWithoutLosingDownloadsBaseline()
    {
        var store = await Store();
        var file = new DownloadFileFingerprint(Path.Combine(dir, "Downloads", "sample.bin"), 17, 638900000000000000);
        await store.InitializeDownloadedFileMonitorSnapshotAsync([file]);
        await store.AddLocalOnlyAsync(Event() with { Category = "BeforeHashFeedCheckpointMigration" });
        await using (var connection = new SqliteConnection($"Data Source={store.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync();
            using var command = connection.CreateCommand();
            command.CommandText = "ALTER TABLE downloaded_file_monitor_metadata DROP COLUMN hash_feed_state_initialized; ALTER TABLE downloaded_file_monitor_metadata DROP COLUMN hash_feed_recheck_at; ALTER TABLE downloaded_file_monitor_metadata DROP COLUMN hash_feed_imported_at; PRAGMA user_version=39;";
            await command.ExecuteNonQueryAsync();
        }

        await store.InitializeAsync();

        Assert.Equal("BeforeHashFeedCheckpointMigration", Assert.Single(await store.ReadAsync()).Category);
        Assert.Equal(file, Assert.Single((await store.ReadDownloadedFileMonitorSnapshotAsync()).Files.Values));
        var checkpoint = DateTimeOffset.UtcNow;
        await store.BeginDownloadedFileHashFeedRecheckAsync(checkpoint);
        Assert.Equal(checkpoint, (await store.ReadDownloadedFileMonitorSnapshotAsync()).HashFeedRecheckAtUtc);
        await store.CompleteDownloadedFileHashFeedRecheckAsync(checkpoint);
        var migrated = await store.ReadDownloadedFileMonitorSnapshotAsync();
        Assert.True(migrated.HashFeedStateInitialized);
        Assert.Equal(checkpoint, migrated.HashFeedImportedAtUtc);
        Assert.Null(migrated.HashFeedRecheckAtUtc);
    }

    [Fact] public async Task VersionThirtyFourDatabaseMigratesProcessBacklogWithoutLosingHistoryOrBaseline()
    {
        var store = await Store();
        await store.AddAsync(Event());
        await store.CommitProcessMonitorChangesAsync([], [new KeyValuePair<int, string>(77, "existing-process")], []);
        await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = store.DatabasePath, Pooling = false }.ToString()))
        {
            await connection.OpenAsync();
            using var command = connection.CreateCommand(); command.CommandText = "DROP TABLE process_change_backlog; ALTER TABLE process_monitor_metadata DROP COLUMN dropped_changes; PRAGMA user_version=34";
            await command.ExecuteNonQueryAsync();
        }

        await store.InitializeAsync();
        Assert.Single(await store.ReadAsync());
        Assert.Equal("existing-process", (await store.ReadProcessMonitorSnapshotAsync()).Processes[77]);
        Assert.Equal(0, (await store.ReadPendingProcessChangesAsync()).Count);
        await using var verify = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = store.DatabasePath, Pooling = false }.ToString());
        await verify.OpenAsync(); using var version = verify.CreateCommand(); version.CommandText = "PRAGMA user_version";
        Assert.Equal(40L, (long)(await version.ExecuteScalarAsync())!);
    }

    [Fact] public async Task ProcessBacklogAcceptsWmiExitEventsWithoutStartCorrelation()
    {
        var store = await Store();
        var exitEvent = new ProcessChangeQueueItem(0, Guid.NewGuid(), DateTimeOffset.UtcNow,
            "Proces zakończony", 89, "short-lived-process", null);

        await store.CommitProcessMonitorChangesAsync([], [], [], backlogToAdd: [exitEvent]);
        var queued = Assert.Single((await store.ReadPendingProcessChangesAsync()).Items);

        Assert.Equal("Proces zakończony", queued.Action);
        Assert.Equal(89, queued.ProcessId);
        Assert.Null(queued.CorrelationId);
    }

    [Fact] public async Task VersionThirtyFiveMigrationAddsDurableDroppedChangeCounterWithoutLosingData()
    {
        var store = await Store();
        await store.AddAsync(Event());
        await store.CommitProcessMonitorChangesAsync([], [new KeyValuePair<int, string>(88, "existing-process")], [],
            backlogToAdd: [new ProcessChangeQueueItem(0, Guid.NewGuid(), DateTimeOffset.UtcNow,
                "Proces zaobserwowany", 89, "pending-process", Guid.NewGuid())]);
        await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = store.DatabasePath, Pooling = false }.ToString()))
        {
            await connection.OpenAsync();
            using var command = connection.CreateCommand(); command.CommandText = "ALTER TABLE process_monitor_metadata DROP COLUMN dropped_changes; PRAGMA user_version=35";
            await command.ExecuteNonQueryAsync();
        }

        await store.InitializeAsync();
        Assert.Single(await store.ReadAsync());
        Assert.Equal("existing-process", (await store.ReadProcessMonitorSnapshotAsync()).Processes[88]);
        Assert.Equal(1, (await store.ReadPendingProcessChangesAsync()).Count);
        Assert.Equal(0L, (await store.ReadProcessMonitorSnapshotAsync()).DroppedChanges);
        await using var verify = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = store.DatabasePath, Pooling = false }.ToString());
        await verify.OpenAsync(); using var version = verify.CreateCommand(); version.CommandText = "PRAGMA user_version";
        Assert.Equal(40L, (long)(await version.ExecuteScalarAsync())!);
    }
    [Fact] public async Task VersionTwentyTwoMigrationAddsProcessingTimesWithoutInventingLegacyValuesAndPreservesNewValues()
    {
        var store = await Store();
        var legacyId = Guid.NewGuid();
        await store.AddLocalOnlyAsync(Event() with { EventId = legacyId, Source = "legacy" });
        await using (var connection = new SqliteConnection($"Data Source={store.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync(); using var command = connection.CreateCommand();
            command.CommandText = "DROP TRIGGER trg_events_add_observation; ALTER TABLE events DROP COLUMN analysis_limitations; ALTER TABLE event_observations DROP COLUMN analysis_limitations; ALTER TABLE events DROP COLUMN processed_at; ALTER TABLE event_observations DROP COLUMN processed_at; PRAGMA user_version=22;";
            await command.ExecuteNonQueryAsync();
        }
        await store.InitializeAsync();
        var legacy = Assert.Single(await store.ReadAsync());
        Assert.Null(legacy.ProcessedAt);
        Assert.Null(Assert.Single(legacy.Observations!).ProcessedAt);

        var processedAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        var at = DateTimeOffset.UtcNow;
        var signal = LocalStore.CreateHostSignalHash("clock.example.test");
        var limitations = new[] { "analysis.sender-intent-unverified", "analysis.ai-unavailable-rule-only" };
        await store.AddLocalOnlyAsync(Event(at) with { EventId = Guid.NewGuid(), Source = "browser-extension", Risk = RiskLevel.High, EvidenceCodes = ["reputation.cert"], SignalHash = signal, ProcessedAt = processedAt, AnalysisLimitations = limitations });
        await store.AddLocalOnlyAsync(Event(at.AddSeconds(1)) with { EventId = Guid.NewGuid(), Source = "dns-cache", Risk = RiskLevel.High, EvidenceCodes = ["reputation.cert"], SignalHash = signal, AnalysisLimitations = ["analysis.navigation-target-unverified"] });
        var merged = (await store.ReadAsync()).Single(item => item.Source == "browser-extension");
        Assert.Equal(processedAt, merged.ProcessedAt);
        Assert.Equal(limitations, merged.AnalysisLimitations);
        Assert.Equal(2, merged.Observations!.Count);
        Assert.Contains(merged.Observations, observation => observation.Source == "dns-cache" && observation.ProcessedAt is not null && observation.AnalysisLimitations!.Contains("analysis.navigation-target-unverified"));

        var backup = Path.Combine(dir, "v23-processing-times.db");
        await store.BackupAsync(backup);
        var restored = await Store();
        await restored.RestoreAsync(backup);
        var restoredMerged = (await restored.ReadAsync()).Single(item => item.Source == "browser-extension");
        Assert.Equal(processedAt, restoredMerged.ProcessedAt);
        Assert.Equal(limitations, restoredMerged.AnalysisLimitations);
        Assert.All(restoredMerged.Observations!, observation => Assert.NotNull(observation.ProcessedAt));

        var v23Backup = Path.Combine(dir, "legacy-v23-processing-times.db");
        File.Copy(backup, v23Backup);
        await using (var connection = new SqliteConnection($"Data Source={v23Backup};Pooling=False"))
        {
            await connection.OpenAsync(); using var command = connection.CreateCommand();
            command.CommandText = "DROP TRIGGER trg_events_add_observation; ALTER TABLE events DROP COLUMN analysis_limitations; ALTER TABLE event_observations DROP COLUMN analysis_limitations; PRAGMA user_version=23;";
            await command.ExecuteNonQueryAsync();
        }
        var restoredV23 = await Store();
        await restoredV23.RestoreAsync(v23Backup);
        var fromV23 = (await restoredV23.ReadAsync()).Single(item => item.Source == "browser-extension");
        Assert.Equal(processedAt, fromV23.ProcessedAt);
        Assert.Null(fromV23.AnalysisLimitations);
        Assert.All(fromV23.Observations!, observation => Assert.Null(observation.AnalysisLimitations));

        var json = Path.Combine(dir, "processing-times.json");
        await restored.ExportAsync(json);
        Assert.Contains("ProcessedAt", await File.ReadAllTextAsync(json));
        var csv = Path.Combine(dir, "processing-times.csv");
        await restored.ExportCsvAsync(csv);
        Assert.Contains("processed_at_utc", await File.ReadAllTextAsync(csv));
        Assert.Contains("analysis_limitations", await File.ReadAllTextAsync(csv));
    }
    [Fact] public async Task ContinuousTcpMonitoringOptInSurvivesReopening()
    {
        var store = await Store();
        var settings = new AppSettings(Paused: false, MonitorNetworkConnections: true);
        await store.SaveSettingsAsync(settings);
        Assert.True((await (await Store()).LoadSettingsAsync()).MonitorNetworkConnections);
    }
    [Fact] public async Task EventsAndFeedbackPersist() { var s = await Store(); var id = await s.AddAsync(Event()); await s.SetStatusAsync(id,EventStatus.FalsePositive); var next = await Store(); Assert.Equal(EventStatus.FalsePositive,Assert.Single(await next.ReadAsync()).Status); }
    [Fact] public async Task RepeatedEventIdReturnsExistingRecordWithoutCreatingDuplicate()
    {
        var store = await Store();
        var eventId = Guid.NewGuid();
        var item = Event() with { EventId = eventId, Source = "test.retry" };

        var firstId = await store.AddLocalOnlyAsync(item);
        var retryId = await store.AddLocalOnlyAsync(item);

        Assert.Equal(firstId, retryId);
        var saved = Assert.Single(await store.ReadAsync());
        Assert.Equal(eventId, saved.EventId);
        Assert.Equal("test.retry", saved.Source);
    }
    [Fact] public async Task PersistentSourceSignalDeduplicationSurvivesStoreReopenAndRespectsSourceHashAndWindow()
    {
        var store = await Store();
        var at = DateTimeOffset.UtcNow;
        var hash = new string('A', 64);
        var basis = new SecurityEvent(0, at, RiskLevel.High, "Domena na liście", "DNS", "Synthetic match", "Review", EventStatus.New,
            EventId: Guid.NewGuid(), Source: "dns-cache", EvidenceCodes: ["dns.windows-cache-entry"], SignalHash: hash);

        var first = await store.AddWithEnterpriseMetadataDeduplicatedAsync(basis, "url", "reputation.cert", TimeSpan.FromMinutes(10));
        Assert.False(first.Duplicate);
        var reopened = await Store();
        var repeated = await reopened.AddWithEnterpriseMetadataDeduplicatedAsync(
            basis with { EventId = Guid.NewGuid(), Timestamp = at.AddMinutes(5) }, "url", "reputation.cert", TimeSpan.FromMinutes(10));
        Assert.True(repeated.Duplicate);

        var operational = await reopened.AddWithEnterpriseMetadataDeduplicatedAsync(
            basis with { EventId = Guid.NewGuid(), Source = "dns-operational", Timestamp = at.AddMinutes(5) }, "url", "reputation.cert", TimeSpan.FromMinutes(10));
        var repeatedOperational = await reopened.AddWithEnterpriseMetadataDeduplicatedAsync(
            basis with { EventId = Guid.NewGuid(), Source = "dns-operational", Timestamp = at.AddMinutes(6) }, "url", "reputation.cert", TimeSpan.FromMinutes(10));
        var otherSource = await reopened.AddWithEnterpriseMetadataDeduplicatedAsync(
            basis with { EventId = Guid.NewGuid(), Source = "dns-other", Timestamp = at.AddMinutes(5) }, "url", "reputation.cert", TimeSpan.FromMinutes(10));
        var otherSignal = await reopened.AddWithEnterpriseMetadataDeduplicatedAsync(
            basis with { EventId = Guid.NewGuid(), SignalHash = new string('B', 64), Timestamp = at.AddMinutes(5) }, "url", "reputation.cert", TimeSpan.FromMinutes(10));
        var changedRisk = await reopened.AddWithEnterpriseMetadataDeduplicatedAsync(
            basis with { EventId = Guid.NewGuid(), Risk = RiskLevel.Moderate, Timestamp = at.AddMinutes(6) }, "url", "reputation.cert", TimeSpan.FromMinutes(10));
        var afterWindow = await reopened.AddWithEnterpriseMetadataDeduplicatedAsync(
            basis with { EventId = Guid.NewGuid(), Timestamp = at.AddMinutes(11) }, "url", "reputation.cert", TimeSpan.FromMinutes(10));

        Assert.False(operational.Duplicate);
        Assert.True(repeatedOperational.Duplicate);
        Assert.False(otherSource.Duplicate);
        Assert.False(otherSignal.Duplicate);
        Assert.False(changedRisk.Duplicate);
        Assert.False(afterWindow.Duplicate);
        Assert.Equal(6, await reopened.CountEventsAsync());
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => reopened.AddWithEnterpriseMetadataDeduplicatedAsync(
            basis, "url", "reputation.cert", TimeSpan.Zero));
    }
    [Fact] public async Task PersistentLocalOnlySignalDeduplicationSurvivesStoreReopenAndValidatesInputs()
    {
        var store = await Store();
        var at = DateTimeOffset.UtcNow;
        var basis = Event(at) with { Risk = RiskLevel.Moderate, EventId = Guid.NewGuid(), Source = "browser-extension", SignalHash = new string('A', 64) };

        Assert.True(await store.AddLocalOnlyDeduplicatedAsync(basis, TimeSpan.FromMinutes(10)));
        var reopened = await Store();
        Assert.False(await reopened.AddLocalOnlyDeduplicatedAsync(basis with { EventId = Guid.NewGuid(), Timestamp = at.AddMinutes(5) }, TimeSpan.FromMinutes(10)));
        Assert.True(await reopened.AddLocalOnlyDeduplicatedAsync(basis with { EventId = Guid.NewGuid(), SignalHash = new string('B', 64) }, TimeSpan.FromMinutes(10)));
        Assert.True(await reopened.AddLocalOnlyDeduplicatedAsync(basis with { EventId = Guid.NewGuid(), Source = "manual-analysis" }, TimeSpan.FromMinutes(10)));
        Assert.True(await reopened.AddLocalOnlyDeduplicatedAsync(basis with { EventId = Guid.NewGuid(), Timestamp = at.AddMinutes(11) }, TimeSpan.FromMinutes(10)));

        Assert.Equal(4, await reopened.CountEventsAsync());
        await Assert.ThrowsAsync<ArgumentException>(() => reopened.AddLocalOnlyDeduplicatedAsync(
            basis with { SignalHash = "not-a-hash" }, TimeSpan.FromMinutes(10)));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => reopened.AddLocalOnlyDeduplicatedAsync(basis, TimeSpan.Zero));
    }
    [Fact] public async Task PersistentLocalOnlySignalDeduplicationIsAtomicForConcurrentWriters()
    {
        var store = await Store();
        var at = DateTimeOffset.UtcNow;
        var hash = new string('C', 64);
        var writes = Enumerable.Range(0, 8).Select(index => store.AddLocalOnlyDeduplicatedAsync(
            Event(at) with { Risk = RiskLevel.Moderate, EventId = Guid.NewGuid(), Source = "browser-extension", SignalHash = hash },
            TimeSpan.FromMinutes(10)));

        var results = await Task.WhenAll(writes);

        Assert.Single(results, recorded => recorded);
        Assert.Equal(1, await store.CountEventsAsync());
    }
    [Fa…11513 tokens truncated…act] public async Task RetentionRemovesOnlyOldEvents() { var s = await Store(); await s.AddAsync(Event(DateTimeOffset.UtcNow.AddDays(-60))); await s.AddAsync(Event()); await s.ApplyRetentionAsync(30); Assert.Single(await s.ReadAsync()); }
    [Fact] public async Task RetentionRemovesObservationsForExpiredMergedEvents()
    {
        var store = await Store();
        var at = DateTimeOffset.UtcNow.AddDays(-60);
        var signalHash = LocalStore.CreateHostSignalHash("expired.example.test");
        var oldDetection = new SecurityEvent(0, at, RiskLevel.High, "URL", "Browser", "Synthetic CERT match", "Review", EventStatus.New,
            EventId: Guid.NewGuid(), Source: "browser-extension", EvidenceCodes: ["reputation.cert"], SignalHash: signalHash);
        await store.AddLocalOnlyAsync(oldDetection);
        await store.AddLocalOnlyAsync(oldDetection with
        {
            EventId = Guid.NewGuid(),
            Timestamp = at.AddSeconds(5),
            Source = "dns-cache",
            EvidenceCodes = ["reputation.cert.current-feed-match"]
        });

        var merged = Assert.Single(await store.ReadAsync());
        Assert.Equal(2, merged.Observations!.Count);

        await store.ApplyRetentionAsync(30);

        Assert.Empty(await store.ReadAsync());
        await using var connection = new SqliteConnection($"Data Source={store.DatabasePath};Pooling=False");
        await connection.OpenAsync();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM event_observations";
        Assert.Equal(0L, (long)(await command.ExecuteScalarAsync())!);
    }
    [Fact] public async Task InvalidRetentionRejected() { var s = await Store(); await Assert.ThrowsAsync<ArgumentOutOfRangeException>(()=>s.SaveSettingsAsync(new(0))); }
    [Fact] public async Task BackupCanReopenAndExportIsValid() { var s = await Store(); await s.AddAsync(Event()); var export = Path.Combine(dir,"events.json"); await s.ExportAsync(export); Assert.Contains("Synthetic",await File.ReadAllTextAsync(export)); var backupDir = Path.Combine(dir,"backup"); Directory.CreateDirectory(backupDir); await s.BackupAsync(Path.Combine(backupDir,"sentinel.db")); var backup = new LocalStore(backupDir); await backup.InitializeAsync(); Assert.Single(await backup.ReadAsync()); }
    [Fact] public async Task ProcessImageInspectionPersistsAndRestoresLocallyButNeverExportsPathOrHash()
    {
        var store = await Store();
        var path = Path.Combine(dir, "private-process-image.exe");
        const string hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        var eventId = Guid.NewGuid();
        await store.AddLocalOnlyAsync(Event() with { EventId = eventId, Source = "process-snapshot", ProcessId = 123,
            ProcessName = "private-process-image", ProcessImagePath = path, ProcessImageSignatureStatus = "Pending",
            EvidenceCodes = ["process.snapshot.new-pid", "process.image.path-available"] });
        Assert.Equal((eventId, path), Assert.Single(await store.ReadPendingProcessImageInspectionsAsync()));

        await store.UpdateProcessImageInspectionAsync(eventId, hash, "Valid", true);
        Assert.Empty(await store.ReadPendingProcessImageInspectionsAsync());
        var inspected = Assert.Single(await store.ReadAsync());
        Assert.Equal(path, inspected.ProcessImagePath);
        Assert.Equal(hash, inspected.ProcessImageSha256);
        Assert.Equal("Valid", inspected.ProcessImageSignatureStatus);
        Assert.True(inspected.ProcessImageLocalHashMatch);
        Assert.Contains("process.image.sha256.available", inspected.EvidenceCodes!);

        var backupPath = Path.Combine(dir, "process-image-backup.db");
        await store.BackupAsync(backupPath);
        var restored = await Store();
        await restored.RestoreAsync(backupPath);
        var restoredEvent = Assert.Single(await restored.ReadAsync());
        Assert.Equal(path, restoredEvent.ProcessImagePath);
        Assert.Equal(hash, restoredEvent.ProcessImageSha256);
        Assert.True(restoredEvent.ProcessImageLocalHashMatch);

        var jsonPath = Path.Combine(dir, "process-image-export.json");
        await restored.ExportAsync(jsonPath);
        var json = await File.ReadAllTextAsync(jsonPath);
        Assert.DoesNotContain(path, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(hash, json, StringComparison.OrdinalIgnoreCase);
    }
    [Fact] public async Task ProcessImageWithExactDownloadedSha256SharesIncidentCorrelation()
    {
        var store = await Store();
        const string hash = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        var observedAt = DateTimeOffset.UtcNow;
        var downloadEventId = Guid.NewGuid();
        var processEventId = Guid.NewGuid();
        await store.AddLocalOnlyAsync(Event(observedAt) with { EventId = downloadEventId, Source = "downloads-local-hash",
            Category = "Pobrany plik pasuje do lokalnej listy hashy", SignalHash = hash,
            EvidenceCodes = ["file.sha256.matches-local-list"] });
        await store.AddLocalOnlyAsync(Event(observedAt.AddSeconds(40)) with { EventId = processEventId, Source = "process-snapshot",
            ProcessId = 123, ProcessName = "downloaded-program", ProcessImagePath = Path.Combine(dir, "downloaded-program.exe"),
            ProcessImageSignatureStatus = "Pending", EvidenceCodes = ["process.snapshot.new-pid"] });

        await store.UpdateProcessImageInspectionAsync(processEventId, hash, "NotSigned", null);

        var events = await store.ReadAsync();
        var download = Assert.Single(events, item => item.EventId == downloadEventId);
        var process = Assert.Single(events, item => item.EventId == processEventId);
        Assert.NotNull(download.CorrelationId);
        Assert.Equal(download.CorrelationId, process.CorrelationId);
        Assert.Contains("correlation.download-process.same-sha256", download.EvidenceCodes!);
        Assert.Contains("correlation.download-process.same-sha256", process.EvidenceCodes!);
    }
    [Fact] public async Task ProcessImageDoesNotCorrelateToDifferentHashOrOldDownload()
    {
        var store = await Store();
        var observedAt = DateTimeOffset.UtcNow;
        var downloadEventId = Guid.NewGuid();
        var processEventId = Guid.NewGuid();
        await store.AddLocalOnlyAsync(Event(observedAt.AddMinutes(-11)) with { EventId = downloadEventId, Source = "downloads-local-hash",
            SignalHash = new string('C', 64), EvidenceCodes = ["file.sha256.matches-local-list"] });
        await store.AddLocalOnlyAsync(Event(observedAt) with { EventId = processEventId, Source = "process-snapshot",
            ProcessId = 123, ProcessName = "different-program", ProcessImagePath = Path.Combine(dir, "different-program.exe"),
            ProcessImageSignatureStatus = "Pending", EvidenceCodes = ["process.snapshot.new-pid"] });

        await store.UpdateProcessImageInspectionAsync(processEventId, new string('D', 64), "Valid", false);

        var events = await store.ReadAsync();
        Assert.Null(Assert.Single(events, item => item.EventId == downloadEventId).CorrelationId);
        var process = Assert.Single(events, item => item.EventId == processEventId);
        Assert.Null(process.CorrelationId);
        Assert.DoesNotContain("correlation.download-process.same-sha256", process.EvidenceCodes!);
    }
    [Fact] public async Task CsvExportQuotesFieldsAndPreventsSpreadsheetFormulas()
    {
        var s = await Store();
        var correlationId = Guid.NewGuid();
        await s.AddLocalOnlyAsync(Event() with { Explanation = "=HYPERLINK(\"https://evil.test\")", Recommendation = "quoted, value\nand second line", Application = " \t=HYPERLINK(\"https://evil.test\")", ProcessName = "-SUM(A1:A2)", CorrelationId = correlationId, EvidenceCodes = ["url.brand", "text.credentials"] });
        var export = Path.Combine(dir, "events.csv"); await s.ExportCsvAsync(export);
        var bytes = await File.ReadAllBytesAsync(export);
        Assert.True(bytes.AsSpan().StartsWith(new byte[] { 0xEF, 0xBB, 0xBF }));
        var csv = await File.ReadAllTextAsync(export);
        Assert.Contains(",origin", csv.Split('\n')[0]);
        Assert.Contains("\"user-engine\"", csv);
        Assert.Contains("\"'=HYPERLINK(\"\"https://evil.test\"\")\"", csv);
        Assert.Contains("\"'-SUM(A1:A2)\"", csv);
        Assert.Contains("\"' \t=HYPERLINK(\"\"https://evil.test\"\")\"", csv);
        Assert.Contains("\"quoted, value\nand second line\"", csv);
        Assert.Contains(correlationId.ToString("D"), csv);
        Assert.Contains("url.brand|text.credentials", csv);
    }
    [Fact] public async Task RestoreReplacesHistoryAndSettingsButPreservesInstalledIdentity()
    {
        var backupDirectory = Path.Combine(dir, "backup-source"); Directory.CreateDirectory(backupDirectory);
        var source = new LocalStore(backupDirectory);
        await source.InitializeAsync(new Sentinel.Core.Configuration.InstalledProductProfile(Sentinel.Core.Configuration.ProductVariant.EnterpriseClient,
            "https://sentinel.example", ShareSecurityMetadata: true));
        var correlationId = Guid.NewGuid();
        var evidence = new[] { "process.snapshot.new-pid", "network.tcp.connection-snapshot" };
        await source.AddAsync(Event() with { Risk = RiskLevel.High, Category = "BackupEvent", Source = "process-snapshot", RuleVersion = "2026.10.1", CorrelationId = correlationId, EvidenceCodes = evidence });
        var restoredSettings = new AppSettings(RetentionDays: 30, Notifications: false, Paused: false);
        await source.SaveSettingsAsync(restoredSettings);
        var backupPath = Path.Combine(dir, "restore.db"); await source.BackupAsync(backupPath);

        var target = await Store();
        await target.AddAsync(Event() with { Category = "DiscardedEvent" });
        Assert.Equal(1, await target.RestoreAsync(backupPath));

        Assert.Equal("BackupEvent", Assert.Single(await target.ReadAsync()).Category);
        Assert.Equal(correlationId, Assert.Single(await target.ReadAsync()).CorrelationId);
        Assert.Equal(evidence, Assert.Single(await target.ReadAsync()).EvidenceCodes);
        var restoredQueueItem = Assert.Single(await target.ReadPendingEnterpriseEventsAsync());
        Assert.Equal("process-snapshot", restoredQueueItem.Source);
        Assert.Equal("2026.10.1", restoredQueueItem.RuleVersion);
        Assert.Equal(1, restoredQueueItem.SchemaVersion);
        Assert.Equal(restoredSettings, await target.LoadSettingsAsync());
        Assert.Equal(Sentinel.Core.Configuration.ProductVariant.User, (await target.GetInstallationProfileAsync()).Variant);
    }
    [Fact] public async Task RestorePreservesDeferredEnterpriseEvents()
    {
        var sourceDirectory = Path.Combine(dir, "deferred-backup-source"); Directory.CreateDirectory(sourceDirectory);
        var source = new LocalStore(sourceDirectory);
        await source.InitializeAsync(new Sentinel.Core.Configuration.InstalledProductProfile(Sentinel.Core.Configuration.ProductVariant.EnterpriseClient,
            "https://sentinel.example", ShareSecurityMetadata: true));
        await using (var c = new SqliteConnection($"Data Source={source.DatabasePath};Pooling=False"))
        {
            await c.OpenAsync(); using var seed = c.CreateCommand();
            seed.CommandText = "WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x<10000) INSERT INTO enterprise_event_queue(event_id,occurred_at,category,risk_level,rule_code) SELECT lower(hex(randomblob(4)))||'-'||lower(hex(randomblob(2)))||'-'||lower(hex(randomblob(2)))||'-'||lower(hex(randomblob(2)))||'-'||lower(hex(randomblob(6))),strftime('%Y-%m-%dT%H:%M:%fZ','now'),'url',3,'local.url' FROM seq";
            await seed.ExecuteNonQueryAsync();
        }
        var deferred = new PendingEnterpriseEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, "url", 3, "local.url");
        Assert.False(await source.EnqueueEnterpriseEventAsync(deferred));
        var backupPath = Path.Combine(dir, "deferred-backup.db"); await source.BackupAsync(backupPath);

        var target = await Store();
        Assert.Equal(0, await target.RestoreAsync(backupPath));
        Assert.Equal(10001, await target.CountPendingEnterpriseEventsAsync());
        await using var restored = new SqliteConnection($"Data Source={target.DatabasePath};Pooling=False");
        await restored.OpenAsync(); using var verify = restored.CreateCommand();
        verify.CommandText = "SELECT COUNT(*) FROM enterprise_event_deferred WHERE event_id=$id";
        verify.Parameters.AddWithValue("$id", deferred.EventId.ToString("D"));
        Assert.Equal(1L, await verify.ExecuteScalarAsync());
    }
    [Theory] [InlineData(6)] [InlineData(7)]
    public async Task RestoreAcceptsLegacyV6AndV7Backups(int version)
    {
        var sourceDirectory = Path.Combine(dir, $"legacy-v{version}-source");
        var source = new LocalStore(sourceDirectory);
        await source.InitializeAsync();
        await source.AddAsync(Event() with { Category = $"LegacyV{version}Event" });
        var backupPath = Path.Combine(dir, $"legacy-v{version}.db");
        await source.BackupAsync(backupPath);

        await using (var legacy = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = backupPath, Pooling = false }.ToString()))
        {
            await legacy.OpenAsync();
            using var shape = legacy.CreateCommand();
            shape.CommandText = version == 6
                ? "DROP TABLE process_snapshot; DROP TABLE process_monitor_metadata; DROP TABLE network_endpoint_snapshot; DROP TABLE network_monitor_metadata; PRAGMA user_version=6;"
                : "DROP TABLE process_snapshot; DROP TABLE process_monitor_metadata; PRAGMA user_version=7;";
            await shape.ExecuteNonQueryAsync();
        }

        var target = await Store();
        await target.AddAsync(Event() with { Category = "DiscardedEvent" });
        Assert.Equal(1, await target.RestoreAsync(backupPath));
        Assert.Equal($"LegacyV{version}Event", Assert.Single(await target.ReadAsync()).Category);
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
    [Fact] public async Task VersionEightDatabaseMigratesToPersistentDownloadsBaselineWithoutLosingHistory()
    {
        var store = await Store(); await store.AddAsync(Event());
        await using (var c = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={store.DatabasePath};Pooling=False"))
        {
            await c.OpenAsync(); using var command = c.CreateCommand();
            command.CommandText = "DROP TRIGGER IF EXISTS trg_events_add_observation; DROP INDEX IF EXISTS ix_process_start_recent_correlation; DROP INDEX IF EXISTS ix_process_start_recent_correlation_v2; DROP TABLE downloaded_file_snapshot; DROP TABLE downloaded_file_monitor_metadata; ALTER TABLE events DROP COLUMN correlation_id; DROP TRIGGER IF EXISTS trg_events_add_observation; ALTER TABLE events DROP COLUMN evidence_codes; PRAGMA user_version=8;";
            await command.ExecuteNonQueryAsync();
        }
        await store.InitializeAsync();
        Assert.Single(await store.ReadAsync());
        Assert.Null(Assert.Single(await store.ReadAsync()).CorrelationId);
        Assert.False((await store.ReadDownloadedFileMonitorSnapshotAsync()).Initialized);
        await using var verify = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={store.DatabasePath};Pooling=False");
        await verify.OpenAsync(); using var version = verify.CreateCommand(); version.CommandText = "PRAGMA user_version";
        Assert.Equal(40L, (long)(await version.ExecuteScalarAsync())!);
    }
    [Fact] public async Task VersionTenHistoryMigratesCorrelationColumnWithoutLosingEvents()
    {
        var store = await Store();
        await store.AddLocalOnlyAsync(Event() with { Category = "BeforeCorrelationMigration" });
        await using (var connection = new SqliteConnection($"Data Source={store.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync(); using var command = connection.CreateCommand();
            command.CommandText = "DROP TRIGGER IF EXISTS trg_events_add_observation; DROP INDEX IF EXISTS ix_process_start_recent_correlation; DROP INDEX IF EXISTS ix_process_start_recent_correlation_v2; ALTER TABLE events DROP COLUMN correlation_id; DROP TRIGGER IF EXISTS trg_events_add_observation; ALTER TABLE events DROP COLUMN evidence_codes; PRAGMA user_version=10;";
            await command.ExecuteNonQueryAsync();
        }

        await store.InitializeAsync();
        var migrated = Assert.Single(await store.ReadAsync());
        Assert.Equal("BeforeCorrelationMigration", migrated.Category);
        Assert.Null(migrated.CorrelationId);
        await using var verify = new SqliteConnection($"Data Source={store.DatabasePath};Pooling=False");
        await verify.OpenAsync(); using var version = verify.CreateCommand(); version.CommandText = "PRAGMA user_version";
        Assert.Equal(40L, (long)(await version.ExecuteScalarAsync())!);
    }
    [Fact] public async Task RestoreAcceptsVersionTenBackupWithoutCorrelationColumn()
    {
        var source = await Store();
        await source.AddLocalOnlyAsync(Event() with { Category = "LegacyV10Event" });
        var backupPath = Path.Combine(dir, "legacy-v10.db");
        await source.BackupAsync(backupPath);
        await using (var backup = new SqliteConnection($"Data Source={backupPath};Pooling=False"))
        {
            await backup.OpenAsync(); using var command = backup.CreateCommand();
            command.CommandText = "DROP TRIGGER IF EXISTS trg_events_add_observation; DROP INDEX IF EXISTS ix_process_start_recent_correlation; DROP INDEX IF EXISTS ix_process_start_recent_correlation_v2; ALTER TABLE events DROP COLUMN correlation_id; DROP TRIGGER IF EXISTS trg_events_add_observation; ALTER TABLE events DROP COLUMN evidence_codes; PRAGMA user_version=10;";
            await command.ExecuteNonQueryAsync();
        }

        var target = await Store();
        Assert.Equal(1, await target.RestoreAsync(backupPath));
        var restored = Assert.Single(await target.ReadAsync());
        Assert.Equal("LegacyV10Event", restored.Category);
        Assert.Null(restored.CorrelationId);
        Assert.Empty(restored.EvidenceCodes!);
    }
    [Fact] public async Task RestoreAcceptsVersionElevenBackupWithoutEvidenceCodes()
    {
        var source = await Store();
        await source.AddLocalOnlyAsync(Event() with { Category = "LegacyV11Event" });
        var backupPath = Path.Combine(dir, "legacy-v11.db");
        await source.BackupAsync(backupPath);
        await using (var backup = new SqliteConnection($"Data Source={backupPath};Pooling=False"))
        {
            await backup.OpenAsync(); using var command = backup.CreateCommand();
            command.CommandText = "DROP TRIGGER IF EXISTS trg_events_add_observation; ALTER TABLE events DROP COLUMN evidence_codes; PRAGMA user_version=11;";
            await command.ExecuteNonQueryAsync();
        }

        var target = await Store();
        Assert.Equal(1, await target.RestoreAsync(backupPath));
        var restored = Assert.Single(await target.ReadAsync());
        Assert.Equal("LegacyV11Event", restored.Category);
        Assert.Empty(restored.EvidenceCodes!);
    }
    [Fact] public async Task MonitoringSettingsSurviveReopening()
    {
        var s = await Store();
        var settings = new AppSettings(Paused: false, MinimumIntervalSeconds: 25,
            ExcludedApplications: "example;private", ExcludedWindowTitles: "sekret",
            ExcludeBrowsers: true, ExcludeMessaging: true, CollectStaticText: false, MonitorForegroundChanges: true,
            MonitorDownloadedFiles: true);
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
        Assert.True(settings.MonitorNetworkConnections);
        Assert.True(settings.MonitorDownloadedFiles);
        Assert.True(settings.MonitorPersistenceChanges);
        Assert.True(settings.AutoUpdateCertFeed);
        Assert.Equal(10, settings.MinimumIntervalSeconds); Assert.Contains("bitwarden",settings.ExcludedApplications);
    }
    [Fact] public async Task FreshSettingsEnableLocalMonitoringWithoutCapturingForegroundText()
    {
        var settings = await (await Store()).LoadSettingsAsync();
        Assert.False(settings.Paused);
        Assert.True(settings.MonitorNetworkConnections);
        Assert.True(settings.MonitorDownloadedFiles);
        Assert.True(settings.MonitorPersistenceChanges);
        Assert.False(settings.MonitorForegroundChanges);
        Assert.False(settings.CollectStaticText);
        Assert.True(settings.AutoUpdateCertFeed);
    }
    [Theory] [InlineData(0)] [InlineData(301)]
    public async Task InvalidCollectionIntervalIsRejected(int seconds)
    {
        var s = await Store(); await Assert.ThrowsAsync<ArgumentOutOfRangeException>(()=>s.SaveSettingsAsync(new(MinimumIntervalSeconds:seconds)));
    }
    public void Dispose() { if(Directory.Exists(dir)) Directory.Delete(dir,true); }
}


