using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests;

public sealed class ProtectionHealthEvaluatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 5, 12, 0, 0, TimeSpan.Zero);
    private static readonly IReadOnlyDictionary<string, string?> HealthySources = new Dictionary<string, string?>
    {
        ["processes"] = "Snapshot procesów działa",
        ["processEvents"] = "Odbieranie zdarzeń startu i zakończenia procesów przez WMI; kolejka ograniczona do 4096.",
        ["downloadedFiles"] = "Monitoring Downloads działa",
        ["persistence"] = "Monitor zmian autostartu działa",
        ["tcpConnections"] = "Ciągła migawka TCP/UDP działa",
        ["dns"] = "Odczyt cache DNS działa",
        ["reputation"] = "Baza reputacji domen aktualna (500000 wpisów)"
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
    public void ReportsExpiredOrMissingDomainReputationAsLimited()
    {
        var expiredSources = new Dictionary<string, string?>(HealthySources)
        {
            ["reputation"] = "Baza reputacji domen nieaktualna (0 wpisów)"
        };
        var expired = ProtectionHealthEvaluator.Evaluate(new AppSettings(), Now.AddSeconds(-5), Now,
            expiredSources, "stan dobry", "stan dobry");
        Assert.Equal("LIMITED_PROTECTION", expired.State);
        Assert.Contains("Baza reputacji domen", expired.Description);

        var missingSources = new Dictionary<string, string?>(HealthySources);
        missingSources.Remove("reputation");
        var missing = ProtectionHealthEvaluator.Evaluate(new AppSettings(), Now.AddSeconds(-5), Now,
            missingSources, "stan dobry", "stan dobry");
        Assert.Equal("LIMITED_PROTECTION", missing.State);
        Assert.Contains("Baza reputacji domen", missing.Description);
    }

    [Fact]
    public void FreshDomainReputationDoesNotAddAFeedLimitation()
    {
        var result = ProtectionHealthEvaluator.Evaluate(new AppSettings(), Now.AddSeconds(-5), Now,
            HealthySources, "stan dobry", "stan dobry");

        Assert.DoesNotContain("Baza reputacji domen", result.Limitations);
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

    [Theory]
    [InlineData("dns", "Jeszcze nie wykonano odczytu cache DNS", "Cache DNS")]
    [InlineData("tcpConnections", "Ciągła migawka TCP/UDP działa; Osiągnięto limit tabeli; alerty z niepełnej próbki są wstrzymane.", "Połączenia sieciowe")]
    [InlineData("persistence", "Monitor zmian autostartu wymaga Windows.", "Zmiany autostartu")]
    [InlineData("downloadedFiles", "Monitoring Downloads: kolejka jest pełna; pominięto zdarzenia.", "Pobrane pliki")]
    [InlineData("processEvents", "Zdarzenia procesów WMI są ograniczone: przepełniono kolejkę 4096; pominięto zdarzenia, snapshot PID pozostaje fallbackiem.", "Zdarzenia startu procesów")]
    public void FailsClosedForUnknownOrDegradedCollectorStates(string key, string state, string limitation)
    {
        var sources = new Dictionary<string, string?>(HealthySources) { [key] = state };

        var result = ProtectionHealthEvaluator.Evaluate(new AppSettings(), Now.AddSeconds(-5), Now,
            sources, "stan dobry", "stan dobry");

        Assert.Equal("LIMITED_PROTECTION", result.State);
        Assert.Contains(limitation, result.Description);
    }
}
