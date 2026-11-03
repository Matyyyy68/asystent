namespace Sentinel.Core.Analysis;

public static class SecurityCenterAlertPolicy
{
    public static bool RequiresAttention(string? health) => !string.IsNullOrWhiteSpace(health) &&
        (health.Contains("wymaga uwagi", StringComparison.OrdinalIgnoreCase) ||
         health.Contains("wstrzymane", StringComparison.OrdinalIgnoreCase) ||
         health.Contains("nie jest monitorowane", StringComparison.OrdinalIgnoreCase) ||
         health.Contains("niedostępne", StringComparison.OrdinalIgnoreCase));
}
