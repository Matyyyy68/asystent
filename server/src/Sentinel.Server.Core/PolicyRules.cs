using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace Sentinel.Server.Core;

public static partial class PolicyRules
{
    private static readonly string[] AnalysisModes = ["local", "server", "hybrid"];
    private static readonly string[] Providers = ["disabled", "ollama"];
    private static readonly string[] NotificationLevels = ["history", "important", "all"];
    private static readonly string[] EventCategories = ["url", "message", "document", "attachment", "sender", "login"];

    public static PolicyDocument Defaults { get; } = new("local", false, 30, 1, "disabled", 15, 1, false, "important", 2, [], [], [], 300);

    public static string? Validate(PolicyDocument policy)
    {
        if (policy.AnalysisMode is not null && !AnalysisModes.Contains(policy.AnalysisMode, StringComparer.Ordinal)) return "analysisMode musi mieć wartość local, server lub hybrid.";
        if (policy.AiProvider is not null && !Providers.Contains(policy.AiProvider, StringComparer.Ordinal)) return "aiProvider musi mieć wartość disabled lub ollama.";
        if (policy.NotificationLevel is not null && !NotificationLevels.Contains(policy.NotificationLevel, StringComparer.Ordinal)) return "notificationLevel musi mieć wartość history, important lub all.";
        if (policy.AnalysisIntervalSeconds is < 3 or > 3600) return "analysisIntervalSeconds musi mieć wartość 3–3600.";
        if (policy.DetailLevel is < 0 or > 3) return "detailLevel musi mieć wartość 0–3.";
        if (policy.AiTimeoutSeconds is < 1 or > 120) return "aiTimeoutSeconds musi mieć wartość 1–120.";
        if (policy.MaxParallelAnalyses is < 1 or > 16) return "maxParallelAnalyses musi mieć wartość 1–16.";
        if (policy.RiskThreshold is < 0 or > 4) return "riskThreshold musi mieć wartość 0–4.";
        if (policy.SyncIntervalSeconds is < 30 or > 86400) return "syncIntervalSeconds musi mieć wartość 30–86400.";
        if (policy.ExcludedApplications is { } apps && (apps.Count > 200 || apps.Any(app => app.Length is < 1 or > 64 || !ApplicationName().IsMatch(app))))
            return "excludedApplications może zawierać maksymalnie 200 nazw procesów (1–64 znaków: litery, cyfry, kropka, podkreślenie lub myślnik).";
        if (policy.TrustedDomains is { } domains && (domains.Count > 200 || domains.Any(domain => !IsValidDomain(domain))))
            return "trustedDomains może zawierać maksymalnie 200 prawidłowych nazw domen ASCII/IDN.";
        if (policy.SelectedEventCategories is { } categories && (categories.Count > EventCategories.Length || categories.Any(category => !EventCategories.Contains(category, StringComparer.Ordinal)) || categories.Distinct(StringComparer.Ordinal).Count() != categories.Count))
            return "selectedEventCategories zawiera nieobsługiwaną lub powtórzoną kategorię.";
        return null;
    }

    public static bool ExposesContext(PolicyDocument policy) => policy.IncludeContext == true || policy.AnalysisMode is "server" or "hybrid";

    public static PolicyLayer Resolve(string? groupName, long globalVersion, PolicyDocument global,
        long groupVersion, PolicyDocument? group, long deviceVersion, PolicyDocument? device)
    {
        var sources = new Dictionary<string, string>(StringComparer.Ordinal);
        T ResolveValue<T>(string key, T? deviceValue, T? groupValue, T? globalValue, T fallback) where T : class
        {
            if (deviceValue is not null) { sources[key] = "device"; return deviceValue; }
            if (groupValue is not null) { sources[key] = "group"; return groupValue; }
            if (globalValue is not null) { sources[key] = "global"; return globalValue; }
            sources[key] = "default"; return fallback;
        }
        T? ResolveStruct<T>(string key, T? deviceValue, T? groupValue, T? globalValue, T fallback) where T : struct
        {
            if (deviceValue.HasValue) { sources[key] = "device"; return deviceValue; }
            if (groupValue.HasValue) { sources[key] = "group"; return groupValue; }
            if (globalValue.HasValue) { sources[key] = "global"; return globalValue; }
            sources[key] = "default"; return fallback;
        }
        var effective = new PolicyDocument(
            ResolveValue("analysisMode", device?.AnalysisMode, group?.AnalysisMode, global.AnalysisMode, Defaults.AnalysisMode!),
            ResolveStruct("includeContext", device?.IncludeContext, group?.IncludeContext, global.IncludeContext, Defaults.IncludeContext!.Value),
            ResolveStruct("analysisIntervalSeconds", device?.AnalysisIntervalSeconds, group?.AnalysisIntervalSeconds, global.AnalysisIntervalSeconds, Defaults.AnalysisIntervalSeconds!.Value),
            ResolveStruct("detailLevel", device?.DetailLevel, group?.DetailLevel, global.DetailLevel, Defaults.DetailLevel!.Value),
            ResolveValue("aiProvider", device?.AiProvider, group?.AiProvider, global.AiProvider, Defaults.AiProvider!),
            ResolveStruct("aiTimeoutSeconds", device?.AiTimeoutSeconds, group?.AiTimeoutSeconds, global.AiTimeoutSeconds, Defaults.AiTimeoutSeconds!.Value),
            ResolveStruct("maxParallelAnalyses", device?.MaxParallelAnalyses, group?.MaxParallelAnalyses, global.MaxParallelAnalyses, Defaults.MaxParallelAnalyses!.Value),
            ResolveStruct("ragEnabled", device?.RagEnabled, group?.RagEnabled, global.RagEnabled, Defaults.RagEnabled!.Value),
            ResolveValue("notificationLevel", device?.NotificationLevel, group?.NotificationLevel, global.NotificationLevel, Defaults.NotificationLevel!),
            ResolveStruct("riskThreshold", device?.RiskThreshold, group?.RiskThreshold, global.RiskThreshold, Defaults.RiskThreshold!.Value),
            ResolveValue("excludedApplications", device?.ExcludedApplications, group?.ExcludedApplications, global.ExcludedApplications, Defaults.ExcludedApplications!),
            ResolveValue("trustedDomains", device?.TrustedDomains, group?.TrustedDomains, global.TrustedDomains, Defaults.TrustedDomains!),
            ResolveValue("selectedEventCategories", device?.SelectedEventCategories, group?.SelectedEventCategories, global.SelectedEventCategories, Defaults.SelectedEventCategories!),
            ResolveStruct("syncIntervalSeconds", device?.SyncIntervalSeconds, group?.SyncIntervalSeconds, global.SyncIntervalSeconds, Defaults.SyncIntervalSeconds!.Value));
        return new(groupName, globalVersion, groupVersion, deviceVersion, effective, sources);
    }

    private static bool IsValidDomain(string domain)
    {
        if (domain.Length is < 1 or > 253 || domain.Contains('/') || domain.Contains(':') || domain.Any(char.IsWhiteSpace)) return false;
        try
        {
            var ascii = new IdnMapping { UseStd3AsciiRules = true }.GetAscii(domain.TrimEnd('.'));
            return IPAddress.TryParse(ascii, out _) || Uri.CheckHostName(ascii) == UriHostNameType.Dns;
        }
        catch (ArgumentException) { return false; }
    }

    [GeneratedRegex("^[a-zA-Z0-9._-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex ApplicationName();
}
