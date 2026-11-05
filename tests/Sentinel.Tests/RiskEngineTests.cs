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
}
