using Sentinel.Core.Analysis;

namespace Sentinel.Core;

/// <summary>Uses the central response decision to suppress history-only service events from notifications.</summary>
public static class ServiceEventNotificationPolicy
{
    public static bool ShouldNotify(string? risk)
    {
        if (!Enum.TryParse<RiskLevel>(risk, ignoreCase: false, out var level) || !Enum.IsDefined(level))
            return false;

        return RiskEngine.DecideResponse(level).Action is RiskEngine.ResponseAction.NotifyForReview or RiskEngine.ResponseAction.UrgentReview;
    }
}
