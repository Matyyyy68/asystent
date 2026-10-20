using Sentinel.Contracts;

namespace Sentinel.Server.Core;

public sealed record SecurityEvent(string EventId, string DeviceId, DateTimeOffset OccurredAt, DateTimeOffset ReceivedAt,
    string Category, int RiskLevel, string RuleCode, string Status, string Source, string? RuleVersion, int SchemaVersion);
public static class SecurityEventRules
{
    public static string? Validate(EnterpriseEventV1? item, DateTimeOffset now) => EnterpriseEventV1Rules.Validate(item, now);
}
