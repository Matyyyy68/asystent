using Sentinel.Server.Core;
using Sentinel.Server.Infrastructure;
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
        var item = new SecurityEventInput(Guid.NewGuid().ToString(), now, "url", 3, "url.suspicious_domain");
        var first = await _store.IngestEventsAsync(_deviceId, [item], now);
        var replay = await _store.IngestEventsAsync(_deviceId, [item], now.AddSeconds(1));

        Assert.Equal(new EventBatchResult(1, 0), first);
        Assert.Equal(new EventBatchResult(0, 1), replay);
        var saved = Assert.Single(await _store.ListEventsAsync(100));
        Assert.Equal(item.EventId.ToLowerInvariant(), saved.EventId);
        Assert.Equal("open", saved.Status);
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
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);
}
