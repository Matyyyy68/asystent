namespace Sentinel.Server.Core;

public sealed record InvitationRequest(string Group, DateTimeOffset ExpiresAt, int MaximumRegistrations, bool RequiresApproval = false);
public sealed record Invitation(string Id, string Group, DateTimeOffset ExpiresAt, int MaximumRegistrations, int RegistrationCount, bool Revoked, bool RequiresApproval = false);
public sealed record EnrollmentRequest(string InvitationCode, string DeviceName, string ClientVersion, string DeviceToken);
public sealed record EnrollmentResult(string DeviceId, string DeviceToken, string Group, DateTimeOffset RegisteredAt);
public sealed record Device(string Id, string Name, string Group, string ClientVersion, DateTimeOffset RegisteredAt, DateTimeOffset? LastSeenAt, bool Revoked, string? LastError, bool Approved = true);
public enum AdminRole { SystemAdministrator, SecurityAdministrator, Operator, ReadOnly }
public sealed record AdminIdentity(string Id, string Username, AdminRole Role, string SessionId);
public sealed record AdminCredential(string Id, string Username, string PasswordHash, AdminRole Role, bool Disabled);
public sealed record AuditEntry(long Id, DateTimeOffset Timestamp, string? ActorUsername, string Action, string? TargetId);
public sealed record DeviceGroup(string Id, string Name, DateTimeOffset CreatedAt, long PolicyVersion);
public sealed record ServerAIConfiguration(string Endpoint, string Model, bool Enabled, int TimeoutSeconds, long Version);
public sealed record PolicyDocument(string? AnalysisMode = null, bool? IncludeContext = null, int? AnalysisIntervalSeconds = null,
    int? DetailLevel = null, string? AiProvider = null, int? AiTimeoutSeconds = null, int? MaxParallelAnalyses = null,
    bool? RagEnabled = null, string? NotificationLevel = null, int? RiskThreshold = null, IReadOnlyList<string>? ExcludedApplications = null,
    IReadOnlyList<string>? TrustedDomains = null, IReadOnlyList<string>? SelectedEventCategories = null, int? SyncIntervalSeconds = null);
public sealed record VersionedPolicy(PolicyDocument Policy, long Version);
public sealed record PolicyLayer(string? GroupName, long GlobalVersion, long GroupVersion, long DeviceVersion, PolicyDocument Effective,
    IReadOnlyDictionary<string, string> Sources);
public sealed record PolicyWrite(PolicyDocument Policy, long ExpectedVersion);

public interface IServerStore
{
    Task InitializeAsync(CancellationToken cancellationToken = default);
    Task<bool> CheckReadyAsync(CancellationToken cancellationToken = default);
    Task<bool> TryBootstrapAdminAsync(string username, string passwordHash, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<AdminCredential?> FindAdminAsync(string username, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AdminCredential>> ListAdminsAsync(CancellationToken cancellationToken = default);
    Task<AdminCredential> CreateAdminAsync(string username, string passwordHash, AdminRole role, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<bool> SetAdminDisabledAsync(string id, bool disabled, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<bool> SetAdminRoleAsync(string id, AdminRole role, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<bool> ChangeAdminPasswordAsync(string id, string passwordHash, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<AdminIdentity> CreateAdminSessionAsync(string adminId, string sessionHash, DateTimeOffset now, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);
    Task<AdminIdentity?> AuthenticateAdminSessionAsync(string sessionHash, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<bool> RevokeAdminSessionAsync(string sessionId, string adminId, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AuditEntry>> ReadAuditAsync(int limit, CancellationToken cancellationToken = default);
    Task RecordAdminActionAsync(string actorUsername, string action, string? targetId, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<ServerAIConfiguration> ReadServerAIConfigurationAsync(CancellationToken cancellationToken = default);
    Task<bool> WriteServerAIConfigurationAsync(ServerAIConfiguration configuration, long expectedVersion, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<DeviceGroup> CreateGroupAsync(string name, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<DeviceGroup>> ListGroupsAsync(CancellationToken cancellationToken = default);
    Task<DeviceGroup?> FindGroupByNameAsync(string name, CancellationToken cancellationToken = default);
    Task<bool> SetDeviceGroupAsync(string deviceId, string groupId, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<VersionedPolicy> ReadGlobalPolicyAsync(CancellationToken cancellationToken = default);
    Task<bool> WriteGlobalPolicyAsync(PolicyWrite write, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<VersionedPolicy?> ReadGroupPolicyAsync(string groupId, CancellationToken cancellationToken = default);
    Task<bool> WriteGroupPolicyAsync(string groupId, PolicyWrite write, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<VersionedPolicy?> ReadDevicePolicyAsync(string deviceId, CancellationToken cancellationToken = default);
    Task<bool> WriteDevicePolicyAsync(string deviceId, PolicyWrite write, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<PolicyLayer?> GetEffectivePolicyAsync(string deviceId, CancellationToken cancellationToken = default);
    Task<Invitation> CreateInvitationAsync(InvitationRequest request, string codeHash, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<bool> RevokeInvitationAsync(string id, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<EnrollmentResult?> EnrollAsync(EnrollmentRequest request, string codeHash, string deviceTokenHash, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<Device?> AuthenticateDeviceAsync(string tokenHash, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<Device>> ListDevicesAsync(CancellationToken cancellationToken = default);
    Task<bool> RevokeDeviceAsync(string id, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<bool> SetDeviceApprovalAsync(string id, bool approved, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<bool> StageDeviceCredentialRotationAsync(string id, string currentTokenHash, string candidateTokenHash, CancellationToken cancellationToken = default);
    Task<bool> HeartbeatAsync(string id, DateTimeOffset now, string? lastError, CancellationToken cancellationToken = default);
    Task<EventBatchResult> IngestEventsAsync(string deviceId, IReadOnlyList<SecurityEventInput> events, DateTimeOffset receivedAt, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<SecurityEvent>> ListEventsAsync(int limit, string? deviceId = null, CancellationToken cancellationToken = default);
    Task<bool> SetEventStatusAsync(string eventId, string deviceId, string status, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<int> PurgeExpiredEventsAsync(DateTimeOffset now, CancellationToken cancellationToken = default);
}
