namespace Sentinel.Core;

/// <summary>Suppresses routine informational service events from user-facing notifications.</summary>
public static class ServiceEventNotificationPolicy
{
    public static bool ShouldNotify(string? risk) => risk is "Low" or "Moderate" or "High" or "Critical";
}
