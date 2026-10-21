namespace Sentinel.Core;
public enum RiskLevel { Information, Low, Moderate, High, Critical }
public enum EventStatus { New, Reviewed, FalsePositive }
// Never persist page text, credentials or screenshots in this model.
public sealed record SecurityEvent(long Id, DateTimeOffset Timestamp, RiskLevel Risk,
    string Category, string Application, string Explanation, string Recommendation, EventStatus Status,
    Guid? EventId = null, string? Source = null, string? RuleVersion = null, int? Confidence = null, int SchemaVersion = 1,
    int? ProcessId = null, string? ProcessName = null, Guid? CorrelationId = null,
    IReadOnlyList<string>? EvidenceCodes = null);
public sealed record AppSettings(int RetentionDays = 30, bool Notifications = true, bool Paused = true,
    int MinimumIntervalSeconds = 10,
    string ExcludedApplications = "1password;bitwarden;keepass;keepassxc;credentialuibroker;logonui",
    string ExcludedWindowTitles = "",
    bool ExcludeBrowsers = false,
    bool ExcludeMessaging = false,
    bool CollectStaticText = true,
    bool MonitorForegroundChanges = false,
    string Theme = "System",
    bool StartMinimized = false,
    bool UseLocalAI = false,
    string LocalAIEndpoint = "http://127.0.0.1:11434",
    string LocalAIModel = "",
    int LocalAITimeoutSeconds = 30,
    bool StartWithWindows = false,
    int DnsPollIntervalSeconds = 15,
    bool MonitorNetworkConnections = false,
    bool MonitorDownloadedFiles = false);
public sealed record NetworkMonitorSnapshot(bool Initialized, IReadOnlySet<string> EndpointKeys,
    bool TcpTruncated = false, bool UdpTruncated = false);
public sealed record ProcessMonitorSnapshot(bool Initialized, IReadOnlyDictionary<int, string> Processes, bool Truncated = false);
public sealed record DownloadFileFingerprint(string Path, long Length, long LastWriteTicks);
public sealed record DownloadMonitorSnapshot(bool Initialized, IReadOnlyDictionary<string, DownloadFileFingerprint> Files);
public interface IEventRepository
{
    Task<IReadOnlyList<SecurityEvent>> ReadAsync(CancellationToken cancellationToken = default);
    Task<long> AddAsync(SecurityEvent item, CancellationToken cancellationToken = default);
    Task SetStatusAsync(long id, EventStatus status, CancellationToken cancellationToken = default);
    Task DeleteHistoryAsync(CancellationToken cancellationToken = default);
}
public interface ISettingsRepository
{
    Task<AppSettings> LoadSettingsAsync(CancellationToken cancellationToken = default);
    Task SaveSettingsAsync(AppSettings settings, CancellationToken cancellationToken = default);
}
