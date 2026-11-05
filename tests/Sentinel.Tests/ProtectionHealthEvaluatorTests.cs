using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests;

public sealed class ProtectionHealthEvaluatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 5, 12, 0, 0, TimeSpan.Zero);
    private static readonly IReadOnlyDictionary<string, string?> HealthySources = new Dictionary<string, string?>
    {
        ["processes"] = "Snapshot procesów działa",
        ["processEvents"] = "WMI process trace is receiving events",
        ["downloadedFiles"] = "Monitoring Downloads działa",
        ["persistence"] = "Monitor zmian autostartu działa",
        ["tcpConnections"] = "Ciągła migawka TCP/UDP działa",
        ["dns"] = "Odczyt cache DNS działa"
    };

    [Fact]
    public void ReportsPausedBeforeCollectionState()
    {
        var result = ProtectionHealthEvaluator.Evaluate(new AppSettings(Paused: true), null, Now,
            HealthySources, "stan dobry", "stan dobry");

        Assert.Equal("DISABLED", result.State);
        Assert.Contains("monitoring-paused", result.Limitations);
    }

    [Fact]
    public void ReportsInitializingUntilFirstCollection()
    {
        var result = ProtectionHealthEvaluator.Evaluate(new AppSettings(), null, Now,
            HealthySources, "stan dobry", "stan dobry");

        Assert.Equal("INITIALIZING", result.State);
    }

    [Fact]
    public void ReportsUnavailableProcessEventsAsLimited()
    {
        var sources = new Dictionary<string, string?>(HealthySources)
        {
            ["processEvents"] = "Zdarzenia procesów WMI niedostępne; działa awaryjny snapshot PID"
        };

        var result = ProtectionHealthEvaluator.Evaluate(new AppSettings(), Now.AddSeconds(-5), Now,
            sources, "stan dobry", "stan dobry");

        Assert.Equal("LIMITED_PROTECTION", result.State);
        Assert.Contains("Zdarzenia startu procesów", result.Description);
    }

    [Fact]
    public void ReportsStaleCollectionAndWindowsSecurityAttention()
    {
        var stale = ProtectionHealthEvaluator.Evaluate(new AppSettings(), Now.AddMinutes(-2), Now,
            HealthySources, "stan dobry", "stan dobry");
        Assert.Equal("ATTENTION_REQUIRED", stale.State);
        Assert.Contains("collection-stale", stale.Limitations);

        var security = ProtectionHealthEvaluator.Evaluate(new AppSettings(), Now.AddSeconds(-5), Now,
            HealthySources, "stan dobry", "wymaga uwagi");
        Assert.Equal("ATTENTION_REQUIRED", security.State);
        Assert.Contains("Windows Security Center", security.Description);
    }

    [Fact]
    public void NeverClaimsCompleteProtectionWhenMonitorsAreHealthy()
    {
        var result = ProtectionHealthEvaluator.Evaluate(new AppSettings(), Now.AddSeconds(-5), Now,
            HealthySources, "stan dobry", "stan dobry");

        Assert.Equal("LIMITED_PROTECTION", result.State);
        Assert.Contains("no-process-or-network-blocking", result.Limitations);
    }
}
