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
        Assert.Equal(27L, (long)(await version.ExecuteScalarAsync())!);
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
    [Fact] public async Task PersistentSourceSignalDeduplicationIsAtomicForConcurrentWriters()
    {
        var store = await Store();
        var at = DateTimeOffset.UtcNow;
        var hash = new string('C', 64);
        var writes = Enumerable.Range(0, 8).Select(index => store.AddWithEnterpriseMetadataDeduplicatedAsync(
            new SecurityEvent(0, at, RiskLevel.High, "Domena na liście", "DNS", "Synthetic match", "Review", EventStatus.New,
                EventId: Guid.NewGuid(), Source: "dns-cache", EvidenceCodes: ["dns.windows-cache-entry"], SignalHash: hash),
            "url", "reputation.cert", TimeSpan.FromMinutes(10)));

        var results = await Task.WhenAll(writes);

        Assert.Single(results, result => !result.Duplicate);
        Assert.Equal(1, await store.CountEventsAsync());
    }
    [Fact] public async Task CERTDetectionsFromDifferentSourcesMergeAndKeepEveryObservation()
    {
        var store = await Store();
        var signal = LocalStore.CreateHostSignalHash("login.example.com");
        Assert.NotNull(signal);
        var observedAt = DateTimeOffset.UtcNow;
        var browserId = Guid.NewGuid();
        var dnsId = Guid.NewGuid();
        var browser = new SecurityEvent(0, observedAt, RiskLevel.High, "URL", "Browser", "CERT feed match", "Review", EventStatus.New,
            EventId: browserId, Source: "browser-extension", EvidenceCodes: ["reputation.cert"], SignalHash: signal);
        var dns = browser with { EventId = dnsId, Source = "dns-cache", Timestamp = observedAt.AddSeconds(8),
            EvidenceCodes = ["dns.windows-cache-entry", "reputation.cert.current-feed-match"] };

        var canonicalId = await store.AddLocalOnlyAsync(browser);
        await store.InitializeAsync(); // Opening a current v17 database must retain its insert trigger.
        Assert.Equal(canonicalId, await store.AddLocalOnlyAsync(dns));
        var repeatedBrowser = await store.AddLocalOnlyAsync(browser with { EventId = Guid.NewGuid(), Timestamp = observedAt.AddSeconds(12) });
        Assert.NotEqual(canonicalId, repeatedBrowser); // A previously seen source is never absorbed into the cross-source merge.

        Assert.Equal(2, await store.CountEventsAsync());
        var saved = (await store.ReadAsync()).Single(eventItem => eventItem.Id == canonicalId);
        var observations = saved.Observations!;
        Assert.Equal(browserId, saved.EventId);
        Assert.Equal(new[] { "browser-extension", "dns-cache" }, observations.Select(observation => observation.Source));
        Assert.Contains(dnsId, observations.Select(observation => observation.EventId));
        Assert.Contains("reputation.cert.current-feed-match", observations.Single(observation => observation.EventId == dnsId).EvidenceCodes);
    }
    [Fact] public async Task CERTDetectionDeduplicationRequiresDistinctSourceAndSameRiskAndWindow()
    {
        var store = await Store();
        var at = DateTimeOffset.UtcNow;
        var hash = LocalStore.CreateHostSignalHash("login.example.com");
        var basis = new SecurityEvent(0, at, RiskLevel.High, "URL", "Synthetic", "CERT feed match", "Review", EventStatus.New,
            EventId: Guid.NewGuid(), Source: "browser-extension", EvidenceCodes: ["reputation.cert"], SignalHash: hash);
        await store.AddLocalOnlyAsync(basis);
        await store.AddLocalOnlyAsync(basis with { EventId = Guid.NewGuid() }); // Same source remains a separate observation.
        await store.AddLocalOnlyAsync(basis with { EventId = Guid.NewGuid(), Source = "dns-cache", Risk = RiskLevel.Moderate });
        await store.AddLocalOnlyAsync(basis with { EventId = Guid.NewGuid(), Source = "dns-cache", Timestamp = at.AddMinutes(2) });
        await store.AddLocalOnlyAsync(basis with { EventId = Guid.NewGuid(), Source = "downloads-local-hash",
            EvidenceCodes = ["file.sha256.matches-local-list"] }); // A file digest never aliases a host digest.

        Assert.Equal(5, await store.CountEventsAsync());
    }
    [Fact] public async Task MatchingManualAndBrowserUrlSignalsMergeWithoutStoringHostOrRuleHash()
    {
        var store = await Store();
        var at = DateTimeOffset.UtcNow;
        var evidence = new[] { "url.brand", "url.userinfo" };
        var hash = LocalStore.CreateUrlEvidenceSignalHash("login.example.com", evidence);
        Assert.NotNull(hash);
        Assert.Equal(hash, LocalStore.CreateUrlEvidenceSignalHash("LOGIN.example.com", evidence.Reverse()));
        Assert.Null(LocalStore.CreateUrlEvidenceSignalHash("login.example.com", ["text.credential"]));

        var manual = new SecurityEvent(0, at, RiskLevel.Moderate, "SuspiciousNavigation", "Manual analysis", "Synthetic URL warning", "Review", EventStatus.New,
            EventId: Guid.NewGuid(), Source: "manual-analysis", EvidenceCodes: evidence, SignalHash: hash);
        var canonicalId = await store.AddLocalOnlyAsync(manual);
        var browser = manual with { EventId = Guid.NewGuid(), Timestamp = at.AddSeconds(8), Source = "browser-extension",
            Application = "Browser extension", EvidenceCodes = evidence.Reverse().ToArray() };
        Assert.Equal(canonicalId, await store.AddLocalOnlyAsync(browser));

        var sameSource = manual with { EventId = Guid.NewGuid(), Timestamp = at.AddSeconds(10) };
        Assert.NotEqual(canonicalId, await store.AddLocalOnlyAsync(sameSource));
        var otherSignal = browser with { EventId = Guid.NewGuid(), Timestamp = at.AddSeconds(11), EvidenceCodes = ["url.brand"],
            SignalHash = LocalStore.CreateUrlEvidenceSignalHash("login.example.com", ["url.brand"]) };
        Assert.NotEqual(canonicalId, await store.AddLocalOnlyAsync(otherSignal));

        Assert.Equal(3, await store.CountEventsAsync());
        var saved = (await store.ReadAsync()).Single(item => item.Id == canonicalId);
        Assert.Equal(new[] { "manual-analysis", "browser-extension" }, saved.Observations!.Select(item => item.Source));
        var serialized = System.Text.Json.JsonSerializer.Serialize(await store.ReadAsync());
        Assert.DoesNotContain("login.example.com", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(hash, serialized, StringComparison.OrdinalIgnoreCase);
    }
    [Fact] public async Task MatchingManualAndBrowserExactUrlFeedSignalsMergeWithoutStoringUrlOrSignalHash()
    {
        var store = await Store();
        var at = DateTimeOffset.UtcNow;
        const string url = "https://bad.example.test/login?campaign=synthetic";
        var hash = UrlReputation.CreateSignalHash(url);
        var evidence = new[] { "reputation.url-feed" };
        var manual = new SecurityEvent(0, at, RiskLevel.High, "SuspiciousNavigation", "Manual analysis", "Exact URL feed match", "Review", EventStatus.New,
            EventId: Guid.NewGuid(), Source: "manual-analysis", EvidenceCodes: evidence, SignalHash: hash);
        var canonicalId = await store.AddLocalOnlyAsync(manual);
        var browser = manual with { EventId = Guid.NewGuid(), Timestamp = at.AddSeconds(8), Source = "browser-extension",
            Application = "Browser extension" };

        Assert.Equal(canonicalId, await store.AddLocalOnlyAsync(browser));
        Assert.Equal(1, await store.CountEventsAsync());
        var serialized = System.Text.Json.JsonSerializer.Serialize(await store.ReadAsync());
        Assert.DoesNotContain(url, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("bad.example.test", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(hash, serialized, StringComparison.OrdinalIgnoreCase);
    }
    [Fact] public async Task MatchingManualAndDownloadsFileSignalsMergeWithoutPersistingFileNames()
    {
        var store = await Store();
        var at = DateTimeOffset.UtcNow;
        var codes = new[] { "file.sha256.matches-local-list", "file.local-list-source-unverified" };
        var downloads = new SecurityEvent(0, at, RiskLevel.Information, "Pobrany plik pasuje do lokalnej listy hashy", "Monitoring Downloads",
            "Nowy plik z Downloads pasuje do lokalnej listy SHA-256.", "Sprawdź źródło listy.", EventStatus.New,
            EventId: Guid.NewGuid(), Source: "downloads-local-hash", EvidenceCodes: codes,
            SignalHash: "A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF0123456789ABCDEF0");
        await store.AddLocalOnlyAsync(downloads);
        var manual = downloads with { EventId = Guid.NewGuid(), Timestamp = at.AddSeconds(11),
            Category = "Plik · dopasowanie lokalnej listy SHA-256", Application = "Ręczna analiza pliku",
            Source = "manual-file-analysis", Explanation = "SHA-256 pasuje do lokalnej listy." };
        var canonical = await store.AddLocalOnlyAsync(manual);

        Assert.Equal(1, await store.CountEventsAsync());
        var saved = Assert.Single(await store.ReadAsync());
        Assert.Equal(downloads.EventId, saved.EventId);
        Assert.Equal(new[] { "downloads-local-hash", "manual-file-analysis" }, saved.Observations!.Select(observation => observation.Source));
        Assert.DoesNotContain("A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF0123456789ABCDEF0", System.Text.Json.JsonSerializer.Serialize(saved), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(saved.Id, canonical);
    }
    [Fact] public async Task BackupRestorePreservesMergedCERTObservations()
    {
        var store = await Store();
        var at = DateTimeOffset.UtcNow;
        var first = new SecurityEvent(0, at, RiskLevel.High, "URL", "Browser", "CERT match", "Review", EventStatus.New,
            EventId: Guid.NewGuid(), Source: "browser-extension", EvidenceCodes: ["reputation.cert"], SignalHash: LocalStore.CreateHostSignalHash("login.example.com"));
        await store.AddLocalOnlyAsync(first);
        await store.AddLocalOnlyAsync(first with { EventId = Guid.NewGuid(), Source = "dns-cache", Timestamp = at.AddSeconds(3),
            EvidenceCodes = ["reputation.cert.current-feed-match"] });
        var backup = Path.Combine(Path.GetTempPath(), "sentinel-backup-" + Guid.NewGuid() + ".db");
        try
        {
            await store.BackupAsync(backup);
            var target = new LocalStore(Path.Combine(Path.GetTempPath(), "sentinel-restore-" + Guid.NewGuid()));
            await target.InitializeAsync();
            Assert.Equal(1, await target.RestoreAsync(backup));
            var restored = Assert.Single(await target.ReadAsync());
            Assert.Equal(2, restored.Observations!.Count);
            Assert.Contains("dns-cache", restored.Observations.Select(observation => observation.Source));
        }
        finally { File.Delete(backup); }
    }
    [Fact] public async Task DomainCorrelationsShareRegistrableDomainAndExpireAfterSlidingWindow()
    {
        var store = await Store();
        var firstSeen = DateTimeOffset.UtcNow;
        var first = await store.GetDomainCorrelationIdAsync("login.example.com", firstSeen);
        var continued = await store.GetDomainCorrelationIdAsync("example.com", firstSeen.AddSeconds(59));
        var continuedAgain = await store.GetDomainCorrelationIdAsync("www.example.com", firstSeen.AddSeconds(118));
        var expired = await store.GetDomainCorrelationIdAsync("example.com", firstSeen.AddSeconds(179));
        var otherDomain = await store.GetDomainCorrelationIdAsync("example.net", firstSeen.AddSeconds(179));

        Assert.Equal(first, continued);
        Assert.Equal(first, continuedAgain);
        Assert.NotEqual(first, expired);
        Assert.NotEqual(expired, otherDomain);
    }
    [Fact] public async Task OutOfOrderDomainEventsDoNotMoveCorrelationWindowBackward()
    {
        var store = await Store();
        var firstSeen = DateTimeOffset.UtcNow;
        var first = await store.GetDomainCorrelationIdAsync("example.test", firstSeen);
        var recent = await store.GetDomainCorrelationIdAsync("example.test", firstSeen.AddSeconds(30));
        var lateWithinWindow = await store.GetDomainCorrelationIdAsync("example.test", firstSeen.AddSeconds(15));
        var lateOutsideWindow = await store.GetDomainCorrelationIdAsync("example.test", firstSeen.AddSeconds(-61));
        var current = await store.GetDomainCorrelationIdAsync("example.test", firstSeen.AddSeconds(45));

        Assert.Equal(first, recent);
        Assert.Equal(first, lateWithinWindow);
        Assert.NotEqual(first, lateOutsideWindow);
        Assert.Equal(first, current);
    }
    [Fact] public async Task DomainCorrelationRejectsIpAddressAndMalformedHost()
    {
        var store = await Store();
        await Assert.ThrowsAsync<ArgumentException>(() => store.GetDomainCorrelationIdAsync("192.0.2.1", DateTimeOffset.UtcNow));
        await Assert.ThrowsAsync<ArgumentException>(() => store.GetDomainCorrelationIdAsync("bad..example.test", DateTimeOffset.UtcNow));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => store.GetDomainCorrelationIdAsync("example.test", DateTimeOffset.UtcNow, TimeSpan.FromHours(1)));
    }
    [Fact] public async Task DomainCorrelationStoresOnlyHashedDomainAndRestoreClearsTransientIds()
    {
        var source = await Store();
        var observedAt = DateTimeOffset.UtcNow;
        var originalId = await source.GetDomainCorrelationIdAsync("login.example.test", observedAt);
        await source.AddLocalOnlyAsync(Event() with { CorrelationId = originalId, Source = "browser-extension" });
        await using (var connection = new SqliteConnection($"Data Source={source.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync(); using var command = connection.CreateCommand();
            command.CommandText = "SELECT domain_key FROM domain_correlation";
            var storedKey = (string)(await command.ExecuteScalarAsync())!;
            Assert.Equal(64, storedKey.Length);
            Assert.DoesNotContain("example.test", storedKey, StringComparison.OrdinalIgnoreCase);
        }

        var backup = Path.Combine(dir, "domain-correlation.db");
        await source.BackupAsync(backup);
        var restored = await Store();
        Assert.Equal(1, await restored.RestoreAsync(backup));
        var afterRestore = await restored.GetDomainCorrelationIdAsync("www.example.test", observedAt.AddSeconds(1));
        Assert.NotEqual(originalId, afterRestore);
        Assert.Equal(originalId, Assert.Single(await restored.ReadAsync()).CorrelationId);
    }
    [Fact] public async Task VersionTwelveDatabaseMigratesDomainCorrelationWithoutLosingHistory()
    {
        var store = await Store();
        await store.AddLocalOnlyAsync(Event() with { Category = "BeforeDomainCorrelationMigration" });
        await using (var connection = new SqliteConnection($"Data Source={store.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync(); using var command = connection.CreateCommand();
            command.CommandText = "DROP TRIGGER IF EXISTS trg_events_add_observation; DROP INDEX ix_domain_correlation_last_seen; DROP TABLE domain_correlation; PRAGMA user_version=12;";
            await command.ExecuteNonQueryAsync();
        }

        await store.InitializeAsync();
        Assert.Equal("BeforeDomainCorrelationMigration", Assert.Single(await store.ReadAsync()).Category);
        Assert.NotEqual(Guid.Empty, await store.GetDomainCorrelationIdAsync("example.test", DateTimeOffset.UtcNow));
        await using var verify = new SqliteConnection($"Data Source={store.DatabasePath};Pooling=False");
        await verify.OpenAsync(); using var version = verify.CreateCommand(); version.CommandText = "PRAGMA user_version";
        Assert.Equal(27L, (long)(await version.ExecuteScalarAsync())!);
    }
    [Fact] public async Task StorageMetricsIncludeHistoryCountAndSQLiteFileSize()
    {
        var store = await Store();
        await store.AddLocalOnlyAsync(Event());

        var metrics = await store.GetStorageMetricsAsync();

        Assert.Equal(1, metrics.RecordCount);
        Assert.True(metrics.DatabaseBytes > 0);
        Assert.True(metrics.TotalBytes >= metrics.DatabaseBytes);
        Assert.True(metrics.PageCount > 0);
        Assert.InRange(metrics.FreePages, 0, metrics.PageCount);
    }
    [Fact] public async Task HistoryDatabaseLimitRejectsGrowthWithoutLosingExistingEvents()
    {
        const long maximumBytes = 1024 * 1024;
        var store = new LocalStore(dir, maximumBytes);
        await store.InitializeAsync();
        var fullEvent = Event() with { Explanation = new string('x', 1800), Recommendation = new string('y', 1800) };
        var batchFailed = false;
        for (var batch = 0; batch < 100; batch++)
        {
            var countBeforeBatch = await store.CountEventsAsync();
            try
            {
                await store.AddLocalOnlyBatchAsync(Enumerable.Range(0, 100).Select(_ => fullEvent with { EventId = Guid.NewGuid() }).ToArray());
            }
            catch (SqliteException exception) when (exception.SqliteErrorCode == 13)
            {
                batchFailed = true;
                Assert.Equal(countBeforeBatch, await store.CountEventsAsync());
                break;
            }
        }

        Assert.True(batchFailed);
        Assert.True(await store.CountEventsAsync() > 0);
        var writeFailed = false;
        for (var attempt = 0; attempt < 100; attempt++)
        {
            var countBeforeWrite = await store.CountEventsAsync();
            try { await store.AddLocalOnlyAsync(fullEvent with { EventId = Guid.NewGuid() }); }
            catch (SqliteException exception) when (exception.SqliteErrorCode == 13)
            {
                writeFailed = true;
                Assert.Equal(countBeforeWrite, await store.CountEventsAsync());
                break;
            }
        }
        Assert.True(writeFailed);
        Assert.NotEmpty(await store.ReadAsync()); // The database remains queryable.
        var metrics = await store.GetStorageMetricsAsync();
        Assert.InRange(metrics.TotalBytes, 1, maximumBytes);
    }
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
    [WindowsFact]
    [SupportedOSPlatform("windows")]
    public async Task HistoryStoreFailsClosedWhenCurrentUserCannotCreateFilesInDirectory()
    {
        Directory.CreateDirectory(dir);
        var directory = new DirectoryInfo(dir);
        var originalAcl = FileSystemAclExtensions.GetAccessControl(directory);
        var sid = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("Current Windows user SID is unavailable.");
        var deniedAcl = FileSystemAclExtensions.GetAccessControl(directory);
        deniedAcl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.CreateFiles,
            InheritanceFlags.None, PropagationFlags.None, AccessControlType.Deny));

        Exception? error;
        try
        {
            FileSystemAclExtensions.SetAccessControl(directory, deniedAcl);
            error = await Record.ExceptionAsync(() => new LocalStore(dir).InitializeAsync());
        }
        finally
        {
            FileSystemAclExtensions.SetAccessControl(directory, originalAcl);
        }

        Assert.NotNull(error);
        Assert.True(error is UnauthorizedAccessException || error is SqliteException,
            $"Unexpected ACL failure type: {error.GetType().FullName}");
        Assert.False(File.Exists(Path.Combine(dir, "sentinel.db")));
    }
    [Fact] public async Task LocalEventBatchIsAtomicWhenAnEntryIsInvalid()
    {
        var store = await Store();
        var batch = new[] { Event(), Event() with { ProcessName = new string('x', 261) } };

        await Assert.ThrowsAsync<ArgumentException>(() => store.AddLocalOnlyBatchAsync(batch));

        Assert.Empty(await store.ReadAsync());
        Assert.Equal(2, await store.AddLocalOnlyBatchAsync([Event(), Event()]));
        Assert.Equal(2, (await store.ReadAsync()).Count);
    }
    [Fact] public async Task NetworkMonitorSnapshotAdvancesAtomicallyWithEventBatch()
    {
        var store = await Store();
        var duplicateId = Guid.NewGuid();
        await Assert.ThrowsAsync<SqliteException>(() => store.CommitNetworkMonitorChangesAsync(
            [Event() with { EventId = duplicateId }, Event() with { EventId = duplicateId }], ["TCP:valid-key"], []));

        var snapshot = await store.ReadNetworkMonitorSnapshotAsync();
        Assert.False(snapshot.Initialized);
        Assert.Empty(snapshot.EndpointKeys);
        Assert.Empty(await store.ReadAsync());

        await store.CommitNetworkMonitorChangesAsync([Event()], ["TCP:valid-key"], []);
        var committed = await store.ReadNetworkMonitorSnapshotAsync();
        Assert.True(committed.Initialized);
        Assert.Contains("TCP:valid-key", committed.EndpointKeys);
        Assert.Single(await store.ReadAsync());
    }
    [Fact] public async Task ProcessMonitorSnapshotAdvancesAtomicallyWithEventBatch()
    {
        var store = await Store();
        var duplicateId = Guid.NewGuid();
        await Assert.ThrowsAsync<SqliteException>(() => store.CommitProcessMonitorChangesAsync(
            [Event() with { EventId = duplicateId }, Event() with { EventId = duplicateId }], [new(412, "synthetic")], []));

        var snapshot = await store.ReadProcessMonitorSnapshotAsync();
        Assert.False(snapshot.Initialized);
        Assert.Empty(snapshot.Processes);
        Assert.Empty(await store.ReadAsync());

        await store.CommitProcessMonitorChangesAsync([Event()], [new(412, "synthetic")], []);
        var committed = await store.ReadProcessMonitorSnapshotAsync();
        Assert.True(committed.Initialized);
        Assert.Equal("synthetic", committed.Processes[412]);
        Assert.Single(await store.ReadAsync());
    }
    [Fact] public async Task ProcessSnapshotTruncationMetadataMigratesFromV13WithoutLosingBaseline()
    {
        var store = await Store();
        await store.CommitProcessMonitorChangesAsync([], [new(512, "synthetic")], [], truncated: true);
        await using (var connection = new SqliteConnection($"Data Source={store.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync();
            using var command = connection.CreateCommand();
            command.CommandText = "ALTER TABLE process_monitor_metadata DROP COLUMN truncated; PRAGMA user_version=13;";
            await command.ExecuteNonQueryAsync();
        }

        await store.InitializeAsync();
        var snapshot = await store.ReadProcessMonitorSnapshotAsync();
        Assert.True(snapshot.Initialized);
        Assert.False(snapshot.Truncated);
        Assert.Equal("synthetic", snapshot.Processes[512]);
    }
    [Fact] public async Task NetworkSnapshotTruncationMetadataMigratesFromV14WithoutLosingBaseline()
    {
        var store = await Store();
        await store.CommitNetworkMonitorChangesAsync([], ["TCP:synthetic", "UDP:synthetic"], [], tcpTruncated: true, udpTruncated: true);
        await using (var connection = new SqliteConnection($"Data Source={store.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync();
            using var command = connection.CreateCommand();
            command.CommandText = "ALTER TABLE network_monitor_metadata DROP COLUMN tcp_truncated; ALTER TABLE network_monitor_metadata DROP COLUMN udp_truncated; PRAGMA user_version=14;";
            await command.ExecuteNonQueryAsync();
        }

        await store.InitializeAsync();
        var snapshot = await store.ReadNetworkMonitorSnapshotAsync();
        Assert.True(snapshot.Initialized);
        Assert.False(snapshot.TcpTruncated);
        Assert.False(snapshot.UdpTruncated);
        Assert.Contains("TCP:synthetic", snapshot.EndpointKeys);
        Assert.Contains("UDP:synthetic", snapshot.EndpointKeys);
    }
    [Fact] public async Task NewEventsPersistStableIdentityAndProvenance()
    {
        var s = await Store();
        var correlationId = Guid.NewGuid();
        var evidence = new[] { "process.snapshot.new-pid", "network.tcp.connection-snapshot" };
        var id = await s.AddLocalOnlyAsync(Event() with { Source = "process-snapshot", RuleVersion = "2026.10.1", ProcessId = 4242, ProcessName = "synthetic-process", CorrelationId = correlationId, EvidenceCodes = evidence });
        var item = Assert.Single(await (await Store()).ReadAsync());
        Assert.Equal(id, item.Id); Assert.NotEqual(Guid.Empty, item.EventId);
        Assert.Equal("process-snapshot", item.Source); Assert.Equal("2026.10.1", item.RuleVersion);
        Assert.Equal(4242, item.ProcessId); Assert.Equal("synthetic-process", item.ProcessName);
        Assert.Equal(correlationId, item.CorrelationId);
        Assert.Equal(evidence, item.EvidenceCodes);
        Assert.Null(item.Confidence); // No calibrated confidence is claimed by deterministic rules.
        var export = Path.Combine(dir, "provenance.json"); await s.ExportAsync(export);
        var exported = Assert.Single(System.Text.Json.JsonSerializer.Deserialize<SecurityEvent[]>(await File.ReadAllTextAsync(export))!);
        Assert.Equal(item.EventId, exported.EventId); Assert.Equal(item.Source, exported.Source); Assert.Equal(item.RuleVersion, exported.RuleVersion);
        Assert.Equal(item.ProcessId, exported.ProcessId); Assert.Equal(item.ProcessName, exported.ProcessName);
        Assert.Equal(correlationId, exported.CorrelationId);
        Assert.Equal(evidence, exported.EvidenceCodes);
    }
    [Fact] public async Task EvidenceCodesAreValidatedAndStayOutOfEnterprisePayload()
    {
        var store = await Store();
        await Assert.ThrowsAsync<ArgumentException>(() => store.AddLocalOnlyAsync(Event() with { EvidenceCodes = ["contains spaces"] }));
        await Assert.ThrowsAsync<ArgumentException>(() => store.AddLocalOnlyAsync(Event() with { EvidenceCodes = ["rule.alpha", "rule.alpha"] }));

        await store.SetEnterpriseProfileAsync("https://sentinel.example", shareSecurityMetadata: true);
        await store.AddAsync(Event() with { Risk = RiskLevel.High, EvidenceCodes = ["text.credentials", "url.brand"] });
        var queued = Assert.Single(await store.ReadPendingEnterpriseEventsAsync());
        Assert.DoesNotContain("EvidenceCodes", System.Text.Json.JsonSerializer.Serialize(queued));
        Assert.Equal(new[] { "text.credentials", "url.brand" }, Assert.Single(await store.ReadAsync()).EvidenceCodes);
    }
    [Fact] public async Task CorruptPersistedEvidenceCodesFailClosed()
    {
        var store = await Store();
        var id = await store.AddLocalOnlyAsync(Event() with { EvidenceCodes = ["rule.safe"] });
        await using (var connection = new SqliteConnection($"Data Source={store.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync(); using var command = connection.CreateCommand();
            command.CommandText = "UPDATE events SET evidence_codes='[\"contains spaces\"]' WHERE id=$id";
            command.Parameters.AddWithValue("$id", id); await command.ExecuteNonQueryAsync();
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => store.ReadAsync());
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
                CREATE UNIQUE INDEX ux_events_event_id ON events(event_id) WHERE event_id IS NOT NULL;
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
        await s.AddAsync(new(0, DateTimeOffset.UtcNow, RiskLevel.High, "URL", "Synthetic", "private text and URL", "local advice", EventStatus.New,
            Source: "process-snapshot", RuleVersion: "2026.10.1"));
        var queued = await s.ReadPendingEnterpriseEventsAsync();
        var item = Assert.Single(queued); Assert.Equal("url", item.Category); Assert.Equal(3, item.RiskLevel); Assert.Equal("local.url", item.RuleCode);
        Assert.Equal("process-snapshot", item.Source); Assert.Equal("2026.10.1", item.RuleVersion); Assert.Equal(1, item.SchemaVersion);
        Assert.DoesNotContain("private", System.Text.Json.JsonSerializer.Serialize(item));
        Assert.Equal(Assert.Single(await s.ReadAsync()).EventId, item.EventId);
        await s.MarkEnterpriseEventsSentAsync([item.EventId]); Assert.Empty(await s.ReadPendingEnterpriseEventsAsync());
    }
    [Fact] public async Task EnterpriseEventAndOfflineQueueEntryCommitAtomically()
    {
        var store = await Store();
        await store.SetEnterpriseProfileAsync("https://sentinel.example", shareSecurityMetadata: true);
        await using (var connection = new SqliteConnection($"Data Source={store.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync();
            using var trigger = connection.CreateCommand();
            trigger.CommandText = "CREATE TRIGGER reject_enterprise_queue BEFORE INSERT ON enterprise_event_queue BEGIN SELECT RAISE(ABORT, 'synthetic queue write failure'); END";
            await trigger.ExecuteNonQueryAsync();
        }

        var item = Event() with { Risk = RiskLevel.High, EventId = Guid.NewGuid(), Source = "manual-analysis" };
        await Assert.ThrowsAsync<SqliteException>(() => store.AddWithEnterpriseMetadataAsync(item, "url", "local.url"));

        Assert.Empty(await store.ReadAsync());
        Assert.Empty(await store.ReadPendingEnterpriseEventsAsync());
    }
    [Fact] public async Task EnterpriseDetectionMetadataIsPersistedWithItsEvent()
    {
        var store = await Store();
        await store.SetEnterpriseProfileAsync("https://sentinel.example", shareSecurityMetadata: true);
        var item = Event() with { Risk = RiskLevel.High, EventId = Guid.NewGuid(), Source = "manual-analysis" };

        Assert.False(await store.AddWithEnterpriseMetadataAsync(item, "url", "local.url"));

        Assert.Single(await store.ReadAsync());
        var queued = Assert.Single(await store.ReadPendingEnterpriseEventsAsync());
        Assert.Equal(item.EventId, queued.EventId);
        Assert.Equal("url", queued.Category);
        Assert.Equal("local.url", queued.RuleCode);
    }
    [Fact] public async Task EnterpriseCategoryMappingUsesStableCategoryOrKnownSourceNotDisplayText()
    {
        var store = await Store();
        await store.SetEnterpriseProfileAsync("https://sentinel.example", shareSecurityMetadata: true);
        var cases = new (string Category, string Source, string Expected)[]
        {
            ("SuspiciousNavigation", "manual-analysis", "url"),
            ("CredentialPhishing", "manual-analysis", "login"),
            ("PaymentFraud", "manual-analysis", "message"),
            ("UnsafeExecution", "manual-analysis", "attachment"),
            ("Domena na liście CERT Polska", "dns-cache", "url"),
            ("File hash match", "downloads-local-hash", "attachment"),
            ("The word URL in a display label", "manual-analysis", "message"),
            ("1", "manual-analysis", "message")
        };

        foreach (var (category, source, _) in cases)
            await store.AddAsync(Event() with { Risk = RiskLevel.High, Category = category, Source = source });

        var queued = await store.ReadPendingEnterpriseEventsAsync();
        Assert.Equal(cases.Select(item => item.Expected), queued.Select(item => item.Category));
    }
    [Fact] public async Task VersionNineDatabaseMigratesPendingEnterpriseQueueWithSafeDefaults()
    {
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "sentinel.db");
        await using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path};Pooling=False"))
        {
            await connection.OpenAsync(); await using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE enterprise_event_queue(event_id TEXT PRIMARY KEY, occurred_at TEXT NOT NULL,
                  category TEXT NOT NULL, risk_level INTEGER NOT NULL, rule_code TEXT NOT NULL, sent INTEGER NOT NULL DEFAULT 0);
                INSERT INTO enterprise_event_queue(event_id,occurred_at,category,risk_level,rule_code)
                  VALUES('00000000-0000-0000-0000-000000000123','2026-10-20T10:00:00.0000000+00:00','url',3,'local.url');
                PRAGMA user_version=9;
                """;
            await command.ExecuteNonQueryAsync();
        }

        var store = new LocalStore(dir); await store.InitializeAsync();
        var item = Assert.Single(await store.ReadPendingEnterpriseEventsAsync());
        Assert.Equal("unknown", item.Source); Assert.Null(item.RuleVersion); Assert.Equal(1, item.SchemaVersion);
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
    [Fact] public async Task EnterpriseQueueRejectsUnsupportedEventSchema()
    {
        var s = await Store(); await s.SetEnterpriseProfileAsync("https://sentinel.example", shareSecurityMetadata: true);
        var item = new PendingEnterpriseEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, "url", 3, "local.url", SchemaVersion: 2);
        await Assert.ThrowsAsync<ArgumentException>(() => s.EnqueueEnterpriseEventAsync(item));
        Assert.Empty(await s.ReadPendingEnterpriseEventsAsync());
    }
    [Fact] public async Task EnterpriseOfflineQueueIsBoundedWithoutEvictingPendingEvents()
    {
        var s = await Store(); await s.SetEnterpriseProfileAsync("https://sentinel.example", shareSecurityMetadata: true);
        await using (var c = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={s.DatabasePath};Pooling=False"))
        {
            await c.OpenAsync(); using var seed = c.CreateCommand();
            seed.CommandText = "WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x<10000) INSERT INTO enterprise_event_queue(event_id,occurred_at,category,risk_level,rule_code) SELECT lower(hex(randomblob(4)))||'-'||lower(hex(randomblob(2)))||'-'||lower(hex(randomblob(2)))||'-'||lower(hex(randomblob(2)))||'-'||lower(hex(randomblob(6))),strftime('%Y-%m-%dT%H:%M:%fZ','now'),'url',3,'local.url' FROM seq";
            await seed.ExecuteNonQueryAsync();
        }
        Assert.False(await s.EnqueueEnterpriseEventAsync(new PendingEnterpriseEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, "url", 3, "local.url")));
        var localDetection = Event() with { Risk = RiskLevel.High, EventId = Guid.NewGuid(), Source = "manual-analysis" };
        Assert.True(await s.AddWithEnterpriseMetadataAsync(localDetection, "url", "local.url"));
        Assert.Equal(10002, await s.CountPendingEnterpriseEventsAsync());
        Assert.Equal(localDetection.EventId, Assert.Single(await s.ReadAsync()).EventId);
        await using (var c = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={s.DatabasePath};Pooling=False"))
        {
            await c.OpenAsync(); using var deferred = c.CreateCommand(); deferred.CommandText = "SELECT COUNT(*) FROM enterprise_event_deferred";
            Assert.Equal(2L, await deferred.ExecuteScalarAsync());
        }
        var batch = await s.ReadPendingEnterpriseEventsAsync();
        await s.MarkEnterpriseEventsSentAsync(batch.Select(item => item.EventId));
        await using (var c = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={s.DatabasePath};Pooling=False"))
        {
            await c.OpenAsync(); using var sent = c.CreateCommand(); sent.CommandText = "SELECT COUNT(*) FROM enterprise_event_queue WHERE sent=1";
            Assert.True(Convert.ToInt32(await sent.ExecuteScalarAsync()) > 0);
        }
        await s.ReadPendingEnterpriseEventsAsync(); // Frees sent slots and refills them from durable deferred storage.
        await using (var c = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={s.DatabasePath};Pooling=False"))
        {
            await c.OpenAsync(); using var promoted = c.CreateCommand(); promoted.CommandText = "SELECT COUNT(*) FROM enterprise_event_queue WHERE event_id=$id";
            promoted.Parameters.AddWithValue("$id", localDetection.EventId!.Value.ToString("D"));
            Assert.Equal(1L, await promoted.ExecuteScalarAsync());
        }
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
    [Fact] public async Task RevokingEnterpriseConsentAtomicallyClearsDeferredEvents()
    {
        var s = await Store(); await s.SetEnterpriseProfileAsync("https://sentinel.example", shareSecurityMetadata: true);
        await using (var c = new SqliteConnection($"Data Source={s.DatabasePath};Pooling=False"))
        {
            await c.OpenAsync(); using var seed = c.CreateCommand();
            seed.CommandText = "WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x<10000) INSERT INTO enterprise_event_queue(event_id,occurred_at,category,risk_level,rule_code) SELECT lower(hex(randomblob(4)))||'-'||lower(hex(randomblob(2)))||'-'||lower(hex(randomblob(2)))||'-'||lower(hex(randomblob(2)))||'-'||lower(hex(randomblob(6))),strftime('%Y-%m-%dT%H:%M:%fZ','now'),'url',3,'local.url' FROM seq";
            await seed.ExecuteNonQueryAsync();
            using var trigger = c.CreateCommand(); trigger.CommandText = "CREATE TRIGGER fail_deferred_delete BEFORE DELETE ON enterprise_event_deferred BEGIN SELECT RAISE(ABORT,'simulated revoke failure'); END";
            await trigger.ExecuteNonQueryAsync();
        }
        var detection = Event() with { Risk = RiskLevel.High, EventId = Guid.NewGuid(), Source = "manual-analysis" };
        Assert.True(await s.AddWithEnterpriseMetadataAsync(detection, "url", "local.url"));
        Assert.Equal(10001, await s.CountPendingEnterpriseEventsAsync());

        await Assert.ThrowsAsync<SqliteException>(() => s.SetEnterpriseProfileAsync("https://sentinel.example", shareSecurityMetadata: false));
        Assert.True((await s.GetInstallationProfileAsync()).ShareSecurityMetadata);
        Assert.Equal(10001, await s.CountPendingEnterpriseEventsAsync());
        await using (var c = new SqliteConnection($"Data Source={s.DatabasePath};Pooling=False"))
        {
            await c.OpenAsync(); using var drop = c.CreateCommand(); drop.CommandText = "DROP TRIGGER fail_deferred_delete";
            await drop.ExecuteNonQueryAsync();
        }
        await s.SetEnterpriseProfileAsync("https://sentinel.example", shareSecurityMetadata: false);
        Assert.False((await s.GetInstallationProfileAsync()).ShareSecurityMetadata);
        Assert.Equal(0, await s.CountPendingEnterpriseEventsAsync());
        Assert.Equal(detection.EventId, Assert.Single(await s.ReadAsync()).EventId);
    }
    [Fact] public async Task RetentionRemovesOnlyOldEvents() { var s = await Store(); await s.AddAsync(Event(DateTimeOffset.UtcNow.AddDays(-60))); await s.AddAsync(Event()); await s.ApplyRetentionAsync(30); Assert.Single(await s.ReadAsync()); }
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
    [Fact] public async Task CsvExportQuotesFieldsAndPreventsSpreadsheetFormulas()
    {
        var s = await Store();
        var correlationId = Guid.NewGuid();
        await s.AddLocalOnlyAsync(Event() with { Explanation = "=HYPERLINK(\"https://evil.test\")", Recommendation = "quoted, value\nand second line", Application = " \t=HYPERLINK(\"https://evil.test\")", ProcessName = "-SUM(A1:A2)", CorrelationId = correlationId, EvidenceCodes = ["url.brand", "text.credentials"] });
        var export = Path.Combine(dir, "events.csv"); await s.ExportCsvAsync(export);
        var bytes = await File.ReadAllBytesAsync(export);
        Assert.True(bytes.AsSpan().StartsWith(new byte[] { 0xEF, 0xBB, 0xBF }));
        var csv = await File.ReadAllTextAsync(export);
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
            command.CommandText = "DROP TRIGGER IF EXISTS trg_events_add_observation; DROP INDEX IF EXISTS ix_process_start_recent_correlation; DROP TABLE downloaded_file_snapshot; DROP TABLE downloaded_file_monitor_metadata; ALTER TABLE events DROP COLUMN correlation_id; DROP TRIGGER IF EXISTS trg_events_add_observation; ALTER TABLE events DROP COLUMN evidence_codes; PRAGMA user_version=8;";
            await command.ExecuteNonQueryAsync();
        }
        await store.InitializeAsync();
        Assert.Single(await store.ReadAsync());
        Assert.Null(Assert.Single(await store.ReadAsync()).CorrelationId);
        Assert.False((await store.ReadDownloadedFileMonitorSnapshotAsync()).Initialized);
        await using var verify = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={store.DatabasePath};Pooling=False");
        await verify.OpenAsync(); using var version = verify.CreateCommand(); version.CommandText = "PRAGMA user_version";
        Assert.Equal(27L, (long)(await version.ExecuteScalarAsync())!);
    }
    [Fact] public async Task VersionTenHistoryMigratesCorrelationColumnWithoutLosingEvents()
    {
        var store = await Store();
        await store.AddLocalOnlyAsync(Event() with { Category = "BeforeCorrelationMigration" });
        await using (var connection = new SqliteConnection($"Data Source={store.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync(); using var command = connection.CreateCommand();
            command.CommandText = "DROP TRIGGER IF EXISTS trg_events_add_observation; DROP INDEX IF EXISTS ix_process_start_recent_correlation; ALTER TABLE events DROP COLUMN correlation_id; DROP TRIGGER IF EXISTS trg_events_add_observation; ALTER TABLE events DROP COLUMN evidence_codes; PRAGMA user_version=10;";
            await command.ExecuteNonQueryAsync();
        }

        await store.InitializeAsync();
        var migrated = Assert.Single(await store.ReadAsync());
        Assert.Equal("BeforeCorrelationMigration", migrated.Category);
        Assert.Null(migrated.CorrelationId);
        await using var verify = new SqliteConnection($"Data Source={store.DatabasePath};Pooling=False");
        await verify.OpenAsync(); using var version = verify.CreateCommand(); version.CommandText = "PRAGMA user_version";
        Assert.Equal(27L, (long)(await version.ExecuteScalarAsync())!);
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
            command.CommandText = "DROP TRIGGER IF EXISTS trg_events_add_observation; DROP INDEX IF EXISTS ix_process_start_recent_correlation; ALTER TABLE events DROP COLUMN correlation_id; DROP TRIGGER IF EXISTS trg_events_add_observation; ALTER TABLE events DROP COLUMN evidence_codes; PRAGMA user_version=10;";
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
        Assert.False(settings.MonitorNetworkConnections);
        Assert.False(settings.MonitorDownloadedFiles);
        Assert.Equal(10, settings.MinimumIntervalSeconds); Assert.Contains("bitwarden",settings.ExcludedApplications);
    }
    [Theory] [InlineData(0)] [InlineData(301)]
    public async Task InvalidCollectionIntervalIsRejected(int seconds)
    {
        var s = await Store(); await Assert.ThrowsAsync<ArgumentOutOfRangeException>(()=>s.SaveSettingsAsync(new(MinimumIntervalSeconds:seconds)));
    }
    public void Dispose() { if(Directory.Exists(dir)) Directory.Delete(dir,true); }
}
