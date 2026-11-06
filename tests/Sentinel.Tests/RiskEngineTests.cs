using Sentinel.Core;
using Sentinel.Core.Analysis;
using Xunit;

namespace Sentinel.Tests;

public sealed class RiskEngineTests
{
    private static ThreatIndicator Indicator(string id, int weight) =>
        new(id, id, weight, ThreatCategory.UnsafeExecution);

    [Fact]
    public void EmptyEvidenceHasZeroInformationRisk()
    {
        var result = RiskEngine.Evaluate([]);

        Assert.Equal(0, result.Score);
        Assert.Equal(RiskLevel.Information, result.Level);
    }

    [Theory]
    [InlineData(1, 25, RiskLevel.Low)]
    [InlineData(2, 30, RiskLevel.Low)]
    [InlineData(4, 44, RiskLevel.Moderate)]
    public void SingleSignalUsesBoundedWeightedScore(int weight, int expectedScore, RiskLevel expectedLevel)
    {
        var result = RiskEngine.Evaluate([Indicator("signal", weight)]);

        Assert.Equal(expectedScore, result.Score);
        Assert.Equal(expectedLevel, result.Level);
    }

    [Fact]
    public void IndependentSignalsIncreaseSeverityAndDuplicateEvidenceDoesNot()
    {
        var indicators = new[] { Indicator("a", 4), Indicator("b", 4), Indicator("c", 4) };

        var result = RiskEngine.Evaluate(indicators);
        var duplicate = RiskEngine.Evaluate([indicators[0], indicators[0]]);

        Assert.Equal(80, result.Score);
        Assert.Equal(RiskLevel.Critical, result.Level);
        Assert.Equal(44, duplicate.Score);
        Assert.Equal(RiskLevel.Moderate, duplicate.Level);
    }

    [Fact]
    public void ScoreIsClampedToSupportedInputBounds()
    {
        var low = RiskEngine.Evaluate([Indicator("low", -10)]);
        var high = RiskEngine.Evaluate([Indicator("high", 100)]);

        Assert.Equal(0, low.Score);
        Assert.Equal(44, high.Score);
    }

    [Fact]
    public void MonitoredEventScoresUseKnownEvidenceAndIgnoreUnknownCodes()
    {
        var oneSignal = RiskEngine.EvaluateEvidenceCodes([
            "reputation.cert.current-feed-match", "dns.windows-operational-query"]);
        var correlated = RiskEngine.EvaluateEvidenceCodes([
            "process.behavior.office-spawned-script-host", "correlation.process-network.office-spawned-script-host"]);
        var unknown = RiskEngine.EvaluateEvidenceCodes(["made-up.signal"]);

        Assert.Equal(63, oneSignal.Score);
        Assert.Equal(RiskLevel.High, oneSignal.Level);
        Assert.Equal(52, correlated.Score);
        Assert.Equal(RiskLevel.Moderate, correlated.Level);
        Assert.Equal(0, unknown.Score);
        Assert.Equal(RiskLevel.Information, unknown.Level);
    }

    [Fact]
    public void UnverifiedLocalIpFeedDoesNotProduceNumericRisk()
    {
        var result = RiskEngine.EvaluateEvidenceCodes([
            "network.tcp.connection-snapshot", "reputation.ip-feed.match",
            "reputation.local-ip-feed-source-unverified"]);

        Assert.Equal(0, result.Score);
        Assert.Equal(RiskLevel.Information, result.Level);
    }

    [Fact]
    public void UnverifiedLocalHashFeedDoesNotProduceNumericRisk()
    {
        var result = RiskEngine.EvaluateEvidenceCodes([
            "file.sha256.matches-local-list", "file.local-list-source-unverified"]);

        Assert.Equal(0, result.Score);
        Assert.Equal(RiskLevel.Information, result.Level);
    }
}
