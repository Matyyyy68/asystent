using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests;

public sealed class ServiceEventNotificationPolicyTests
{
    [Theory]
    [InlineData("Information", false)]
    [InlineData("Low", false)]
    [InlineData("Moderate", true)]
    [InlineData("High", true)]
    [InlineData("Critical", true)]
    [InlineData("Unknown", false)]
    [InlineData(null, false)]
    public void OnlyResponseDecisionsThatRecommendAlertsNotify(string? risk, bool expected)
        => Assert.Equal(expected, ServiceEventNotificationPolicy.ShouldNotify(risk));

    [Theory]
    [InlineData("Information", false)]
    [InlineData("Low", false)]
    [InlineData("Moderate", true)]
    [InlineData("High", true)]
    [InlineData("Critical", true)]
    public void NotificationPolicyMatchesCentralResponseActions(string risk, bool expected)
    {
        var level = Enum.Parse<RiskLevel>(risk);
        var action = Sentinel.Core.Analysis.RiskEngine.DecideResponse(level).Action;
        var recommendsNotification = action is Sentinel.Core.Analysis.RiskEngine.ResponseAction.NotifyForReview or Sentinel.Core.Analysis.RiskEngine.ResponseAction.UrgentReview;

        Assert.Equal(expected, recommendsNotification);
        Assert.Equal(recommendsNotification, ServiceEventNotificationPolicy.ShouldNotify(risk));
    }
}
