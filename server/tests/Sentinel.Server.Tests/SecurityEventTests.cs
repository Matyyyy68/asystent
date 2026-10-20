using Sentinel.Server.Core;
using Sentinel.Server.Infrastructure;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Sentinel.Server.Tests;

public sealed class SecurityEventTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "sentinel-event-tests", Guid.NewGuid().ToString("N"));
    private readonly SqliteServerStore _store;
    private readonly string _deviceId;

    public SecurityEventTests()
    {
        _store = new(Path.Combine(_directory, "server.db"));
        _store.InitializeAsync().GetAwaiter().GetResult();
        var now = DateTimeOffset.UtcNow;
        var invitation = _store.CreateInvitationAsync(new("Events", now.AddDays(1), 1), "invite-hash", "admin", now).GetAwaiter().GetResult();
        var enrollment = _store.EnrollAsync(new("invite", "EVENT-PC", "1.0", "device-token"), "invite-hash", "device-hash", now).GetAwaiter().GetResult();
        Assert.NotNull(enrollment);
        _deviceId = enrollment.DeviceId;
    }

    [Fact]
    public async Task EventIngestionIsIdempotentAndStatusChangesAreAudited()
    {
        var now = DateTimeOffset.UtcNow;
        var item = new SecurityEventInput(Guid.NewGuid().ToString(), now, "url", 3, "url.suspicious_domain",
            "process-snapshot", "2026.10.1", 1);
        var first = await _store.IngestEventsAsync(_deviceId, [item], now);
        var replay = await _store.IngestEventsAsync(_deviceId, [item], now.AddSeconds(1));

        Assert.Equal(new EventBatchResult(1, 0), first);
        Assert.Equal(new EventBatchResult(0, 1), replay);
        var saved = Assert.Single(await _store.ListEventsAsync(100));
        Assert.Equal(item.EventId.ToLowerInvariant(), saved.EventId);
        Assert.Equal("open", saved.Status);
        Assert.Equal("process-snapshot", saved.Source);
        Assert.Equal("2026.10.1", saved.RuleVersion);
        Assert.Equal(1, saved.SchemaVersion);
        Assert.True(await _store.SetEventStatusAsync(saved.EventId, _deviceId, "false_positive", "admin", now));
        Assert.False(await _store.SetEventStatusAsync(saved.EventId, _deviceId, "false_positive", "admin", now));
        Assert.Equal("false_positive", Assert.Single(await _store.ListEventsAsync(100)).Status);
        Assert.Contains(await _store.ReadAuditAsync(20), entry => entry.Action == "event.status_changed" && entry.TargetId == saved.EventId);
    }

    [Fact]
    public async Task IngestionPurgesEventsOlderThanTheConfiguredNinetyDayRetention()
    {
        var firstReceived = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var old = new SecurityEventInput(Guid.NewGuid().ToString(), firstReceived, "login", 1, "login.known_location");
        Assert.Equal(1, (await _store.IngestEventsAsync(_deviceId, [old], firstReceived)).Accepted);

        var later = firstReceived.AddDays(91);
        var fresh = new SecurityEventInput(Guid.NewGuid().ToString(), later, "login", 2, "login.new_location");
        await _store.IngestEventsAsync(_deviceId, [fresh], later);
        Assert.Equal(fresh.EventId.ToLowerInvariant(), Assert.Single(await _store.ListEventsAsync(100)).EventId);
    }

    [Fact]
    public void EventRulesRejectRawCategoriesRiskAndInvalidRuleIdentifiers()
    {
        var now = DateTimeOffset.UtcNow;
        Assert.Null(SecurityEventRules.Validate(new(Guid.NewGuid().ToString(), now, "url", 2, "url.malware"), now));
        Assert.NotNull(SecurityEventRules.Validate(new(Guid.NewGuid().ToString(), now, "screen", 2, "url.malware"), now));
        Assert.NotNull(SecurityEventRules.Validate(new(Guid.NewGuid().ToString(), now, "url", 5, "url.malware"), now));
        Assert.NotNull(SecurityEventRules.Validate(new(Guid.NewGuid().ToString(), now, "url", 1, "unsafe value"), now));
        Assert.NotNull(SecurityEventRules.Validate(new(Guid.NewGuid().ToString(), now, "url", 1, "url.ok", "private-app.exe"), now));
        Assert.NotNull(SecurityEventRules.Validate(new(Guid.NewGuid().ToString(), now, "url", 1, "url.ok", RuleVersion: "bad version"), now));
        Assert.NotNull(SecurityEventRules.Validate(new(Guid.NewGuid().ToString(), now, "url", 1, "url.ok", SchemaVersion: 2), now));
    }

    [Fact]
    public async Task SchemaV7MigrationPreservesEventsAndAddsDefaultProvenance()
    {
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, "legacy-server.db");
        await using (var connection = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE security_events(
                  event_id TEXT NOT NULL, device_id TEXT NOT NULL, occurred_at TEXT NOT NULL, received_at TEXT NOT NULL,
                  category TEXT NOT NULL, risk_level INTEGER NOT NULL, rule_code TEXT NOT NULL,
                  status TEXT NOT NULL DEFAULT 'open', PRIMARY KEY(device_id,event_id));
                INSERT INTO security_events(event_id,device_id,occurred_at,received_at,category,risk_level,rule_code)
                  VALUES('legacy-event','legacy-device','2026-10-20T10:00:00.0000000+00:00','2026-10-20T10:00:01.0000000+00:00','url',2,'url.legacy');
                PRAGMA user_version=7;
                """;
            await command.ExecuteNonQueryAsync();
        }

        var upgraded = new SqliteServerStore(path);
        await upgraded.InitializeAsync();
        var saved = Assert.Single(await upgraded.ListEventsAsync(10));
        Assert.Equal("legacy-event", saved.EventId);
        Assert.Equal("unknown", saved.Source);
        Assert.Null(saved.RuleVersion);
        Assert.Equal(1, saved.SchemaVersion);
        await using (var verify = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            await verify.OpenAsync();
            await using var version = verify.CreateCommand(); version.CommandText = "PRAGMA user_version";
            Assert.Equal(8L, (long)(await version.ExecuteScalarAsync())!);
        }
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);
}
