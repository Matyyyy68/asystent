using Sentinel.Server.Core;
using Sentinel.Server.Infrastructure;
using Xunit;

namespace Sentinel.Server.Tests;

public sealed class PolicyRulesTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "sentinel-policy-tests", Guid.NewGuid().ToString("N"));
    private readonly SqliteServerStore _store;

    public PolicyRulesTests()
    {
        _store = new(Path.Combine(_directory, "server.db"));
        _store.InitializeAsync().GetAwaiter().GetResult();
    }

    [Fact]
    public void ValidateAcceptsPartialPolicyAndRejectsUnsupportedValues()
    {
        Assert.Null(PolicyRules.Validate(new(AnalysisIntervalSeconds: 60, SelectedEventCategories: ["url", "login"])));
        Assert.NotNull(PolicyRules.Validate(new(AnalysisMode: "remote")));
        Assert.NotNull(PolicyRules.Validate(new(AnalysisIntervalSeconds: 2)));
        Assert.NotNull(PolicyRules.Validate(new(TrustedDomains: ["https://example.com/path"])));
    }

    [Fact]
    public void ResolveUsesDeviceThenGroupThenGlobalThenDefaultsAndTracksSource()
    {
        var resolved = PolicyRules.Resolve("Sales", 1, new(AnalysisIntervalSeconds: 60, DetailLevel: 2),
            2, new(DetailLevel: 3, RiskThreshold: 4), 1, new(AnalysisIntervalSeconds: 90));

        Assert.Equal(90, resolved.Effective.AnalysisIntervalSeconds);
        Assert.Equal("device", resolved.Sources["analysisIntervalSeconds"]);
        Assert.Equal(3, resolved.Effective.DetailLevel);
        Assert.Equal("group", resolved.Sources["detailLevel"]);
        Assert.Equal(4, resolved.Effective.RiskThreshold);
        Assert.Equal("group", resolved.Sources["riskThreshold"]);
        Assert.Equal("local", resolved.Effective.AnalysisMode);
        Assert.Equal("default", resolved.Sources["analysisMode"]);
    }

    [Fact]
    public async Task StorePersistsLayerVersionsAndRejectsStaleWrites()
    {
        var now = DateTimeOffset.UtcNow;
        var group = await _store.CreateGroupAsync("Sales", "admin", now);
        Assert.True(await _store.WriteGlobalPolicyAsync(new(new(AnalysisIntervalSeconds: 60), 0), "admin", now));
        Assert.False(await _store.WriteGlobalPolicyAsync(new(new(AnalysisIntervalSeconds: 75), 0), "admin", now));
        Assert.True(await _store.WriteGroupPolicyAsync(group.Id, new(new(DetailLevel: 3), 0), "admin", now));

        var invite = await _store.CreateInvitationAsync(new("Sales", now.AddHours(1), 1), "invite-hash", "admin", now);
        var enrolled = await _store.EnrollAsync(new("invite", "PC-01", "1.0", "device-secret"), "invite-hash", "device-hash", now);
        Assert.NotNull(enrolled);
        Assert.True(await _store.WriteDevicePolicyAsync(enrolled.DeviceId, new(new(AnalysisIntervalSeconds: 90), 0), "admin", now));

        var effective = await _store.GetEffectivePolicyAsync(enrolled.DeviceId);
        Assert.NotNull(effective);
        Assert.Equal(1, effective.GlobalVersion);
        Assert.Equal(1, effective.GroupVersion);
        Assert.Equal(1, effective.DeviceVersion);
        Assert.Equal(90, effective.Effective.AnalysisIntervalSeconds);
        Assert.Equal(3, effective.Effective.DetailLevel);
        Assert.Equal("device", effective.Sources["analysisIntervalSeconds"]);
        Assert.Equal("group", effective.Sources["detailLevel"]);
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);
}
