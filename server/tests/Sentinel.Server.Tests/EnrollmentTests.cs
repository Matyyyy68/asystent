using System.Security.Cryptography;
using System.Text;
using Sentinel.Server.Core;
using Sentinel.Server.Infrastructure;
using Xunit;

namespace Sentinel.Server.Tests;

public sealed class EnrollmentTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "sentinel-server-tests", Guid.NewGuid().ToString("N"));
    private readonly SqliteServerStore _store;

    public EnrollmentTests()
    {
        _store = new(Path.Combine(_directory, "server.db"));
        _store.InitializeAsync().GetAwaiter().GetResult();
    }

    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    private Task<Invitation> CreateInviteAsync(string code, int maximum = 1, DateTimeOffset? expires = null) =>
        _store.CreateInvitationAsync(new("Testowe", expires ?? DateTimeOffset.UtcNow.AddHours(1), maximum), Hash(code));

    [Fact]
    public async Task EnrollmentReturnsUniqueDeviceCredentialAndHeartbeatUpdatesPresence()
    {
        await CreateInviteAsync("one-use-code");
        var now = DateTimeOffset.UtcNow;
        var enrolled = await _store.EnrollAsync(new("one-use-code", "PC-01", "1.2.3", "device-secret"),
            Hash("one-use-code"), Hash("device-secret"), now);

        Assert.NotNull(enrolled);
        Assert.NotEqual(string.Empty, enrolled.DeviceId);
        Assert.Equal("device-secret", enrolled.DeviceToken);
        Assert.Equal("Testowe", enrolled.Group);
        Assert.NotNull(await _store.AuthenticateDeviceAsync(Hash("device-secret"), now));
        Assert.Null(await _store.AuthenticateDeviceAsync(Hash("invalid-secret"), now));

        var later = now.AddMinutes(1);
        Assert.True(await _store.HeartbeatAsync(enrolled.DeviceId, later, null));
        var device = Assert.Single(await _store.ListDevicesAsync());
        Assert.Equal(later, device.LastSeenAt);
        Assert.Equal("1.2.3", device.ClientVersion);
    }

    [Fact]
    public async Task InvitationCannotBeUsedMoreThanItsLimit()
    {
        await CreateInviteAsync("limited-code", maximum: 1);
        var first = await _store.EnrollAsync(new("limited-code", "PC-01", "1", "secret-1"), Hash("limited-code"), Hash("secret-1"), DateTimeOffset.UtcNow);
        var second = await _store.EnrollAsync(new("limited-code", "PC-02", "1", "secret-2"), Hash("limited-code"), Hash("secret-2"), DateTimeOffset.UtcNow);
        Assert.NotNull(first);
        Assert.Null(second);
        Assert.Single(await _store.ListDevicesAsync());
    }

    [Fact]
    public async Task ExpiredAndRevokedInvitationsCannotEnrollDevices()
    {
        var expired = DateTimeOffset.UtcNow.AddMinutes(-1);
        await CreateInviteAsync("expired-code", expires: expired);
        var now = DateTimeOffset.UtcNow;
        Assert.Null(await _store.EnrollAsync(new("expired-code", "PC", "1", "secret"), Hash("expired-code"), Hash("secret"), now));

        var invitation = await CreateInviteAsync("revoked-code");
        Assert.True(await _store.RevokeInvitationAsync(invitation.Id));
        Assert.Null(await _store.EnrollAsync(new("revoked-code", "PC", "1", "secret-2"), Hash("revoked-code"), Hash("secret-2"), now));
    }

    [Fact]
    public async Task RevokingDeviceImmediatelyInvalidatesItsCredential()
    {
        await CreateInviteAsync("revoke-code");
        var device = await _store.EnrollAsync(new("revoke-code", "PC", "1", "secret"), Hash("revoke-code"), Hash("secret"), DateTimeOffset.UtcNow);
        Assert.NotNull(device);
        Assert.True(await _store.RevokeDeviceAsync(device.DeviceId));
        Assert.Null(await _store.AuthenticateDeviceAsync(Hash("secret"), DateTimeOffset.UtcNow));
        Assert.True(Assert.Single(await _store.ListDevicesAsync()).Revoked);
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);
}
