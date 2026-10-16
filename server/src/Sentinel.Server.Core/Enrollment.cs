namespace Sentinel.Server.Core;

public sealed record InvitationRequest(string Group, DateTimeOffset ExpiresAt, int MaximumRegistrations);
public sealed record Invitation(string Id, string Group, DateTimeOffset ExpiresAt, int MaximumRegistrations, int RegistrationCount, bool Revoked);
public sealed record EnrollmentRequest(string InvitationCode, string DeviceName, string ClientVersion, string DeviceToken);
public sealed record EnrollmentResult(string DeviceId, string DeviceToken, string Group, DateTimeOffset RegisteredAt);
public sealed record Device(string Id, string Name, string Group, string ClientVersion, DateTimeOffset RegisteredAt, DateTimeOffset? LastSeenAt, bool Revoked, string? LastError);

public interface IServerStore
{
    Task InitializeAsync(CancellationToken cancellationToken = default);
    Task<bool> CheckReadyAsync(CancellationToken cancellationToken = default);
    Task<Invitation> CreateInvitationAsync(InvitationRequest request, string codeHash, CancellationToken cancellationToken = default);
    Task<bool> RevokeInvitationAsync(string id, CancellationToken cancellationToken = default);
    Task<EnrollmentResult?> EnrollAsync(EnrollmentRequest request, string codeHash, string deviceTokenHash, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<Device?> AuthenticateDeviceAsync(string tokenHash, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<Device>> ListDevicesAsync(CancellationToken cancellationToken = default);
    Task<bool> RevokeDeviceAsync(string id, CancellationToken cancellationToken = default);
    Task<bool> HeartbeatAsync(string id, DateTimeOffset now, string? lastError, CancellationToken cancellationToken = default);
}
