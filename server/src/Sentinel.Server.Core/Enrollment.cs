namespace Sentinel.Server.Core;

public sealed record InvitationRequest(string Group, DateTimeOffset ExpiresAt, int MaximumRegistrations);
public sealed record Invitation(string Id, string Group, DateTimeOffset ExpiresAt, int MaximumRegistrations, int RegistrationCount, bool Revoked);
public sealed record EnrollmentRequest(string InvitationCode, string DeviceName, string ClientVersion, string DeviceToken);
public sealed record EnrollmentResult(string DeviceId, string DeviceToken, string Group, DateTimeOffset RegisteredAt);
public sealed record Device(string Id, string Name, string Group, string ClientVersion, DateTimeOffset RegisteredAt, DateTimeOffset? LastSeenAt, bool Revoked, string? LastError);
public enum AdminRole { SystemAdministrator, SecurityAdministrator, Operator, ReadOnly }
public sealed record AdminIdentity(string Id, string Username, AdminRole Role, string SessionId);
public sealed record AdminCredential(string Id, string Username, string PasswordHash, AdminRole Role, bool Disabled);
public sealed record AuditEntry(long Id, DateTimeOffset Timestamp, string? ActorUsername, string Action, string? TargetId);

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
    Task<Invitation> CreateInvitationAsync(InvitationRequest request, string codeHash, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<bool> RevokeInvitationAsync(string id, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<EnrollmentResult?> EnrollAsync(EnrollmentRequest request, string codeHash, string deviceTokenHash, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<Device?> AuthenticateDeviceAsync(string tokenHash, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<Device>> ListDevicesAsync(CancellationToken cancellationToken = default);
    Task<bool> RevokeDeviceAsync(string id, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<bool> HeartbeatAsync(string id, DateTimeOffset now, string? lastError, CancellationToken cancellationToken = default);
}
