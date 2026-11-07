using Sentinel.Core;
using Sentinel.Core.Analysis;
using Xunit;

namespace Sentinel.Tests;

public sealed class EnterpriseAssessmentCombinerTests
{
    private static ThreatIndicator Signal(string id, int weight, ThreatCategory category) => new(id, id, weight, category);

    [Fact]
    public void RemoteRiskWithoutSupportingEvidenceDoesNotEscalateCombinedAssessment()
    {
        var local = new ThreatAssessment(ThreatCategory.UnsafeExecution, RiskLevel.Moderate,
            [Signal("local.script", 4, ThreatCategory.UnsafeExecution)], [], [], "local finding", 44);
        var remote = new ThreatAssessment(ThreatCategory.CredentialPhishing, RiskLevel.Critical,
            [], [], [], "remote claim", 0);

        var combined = EnterpriseAssessmentCombiner.Combine(local, remote);

        Assert.Equal(44, combined.RiskScore);
        Assert.Equal(RiskLevel.Moderate, combined.Risk);
        Assert.Equal(ThreatCategory.UnsafeExecution, combined.Category);
    }

    [Fact]
    public void DistinctLocalAndRemoteEvidenceProduceConsistentCombinedScoreAndLevel()
    {
        var local = new ThreatAssessment(ThreatCategory.UnsafeExecution, RiskLevel.Moderate,
            [Signal("local.script", 4, ThreatCategory.UnsafeExecution)], [], ["review"], "local finding");
        var remote = new ThreatAssessment(ThreatCategory.CredentialPhishing, RiskLevel.High,
            [Signal("remote.credentials", 4, ThreatCategory.CredentialPhishing)], ["remote uncertainty"], [], "remote finding");

        var combined = EnterpriseAssessmentCombiner.Combine(local, remote, "confirmed context sharing");

        Assert.Equal(63, combined.RiskScore);
        Assert.Equal(RiskLevel.High, combined.Risk);
        Assert.Equal(combined.Risk, RiskEngine.LevelForScore(combined.RiskScore));
        Assert.Equal(2, combined.Indicators.Count);
        Assert.Contains("review", combined.Recommendations);
        Assert.Contains("confirmed context sharing", combined.Uncertainties);
    }
}
