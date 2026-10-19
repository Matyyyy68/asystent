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
        _store.CreateInvitationAsync(new("Testowe", expires ?? DateTimeOffset.UtcNow.AddHours(1), maximum), Hash(code), "test-admin", DateTimeOffset.UtcNow);

    private Task<Invitation> CreateApprovalInviteAsync(string code) =>
        _store.CreateInvitationAsync(new("Testowe", DateTimeOffset.UtcNow.AddHours(1), 1, true), Hash(code), "test-admin", DateTimeOffset.UtcNow);

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
    public async Task OnlineBackupIsAnIntegrityCheckedSnapshotOfTheServerDatabase()
    {
        await CreateInviteAsync("backup-test-code");
        var backupPath = Path.Combine(_directory, "Backups", "snapshot.db");
        await _store.CreateBackupAsync(backupPath);

        Assert.True(File.Exists(backupPath));
        await using var backup = new Microsoft.Data.Sqlite.SqliteConnection(new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder { DataSource = backupPath, Mode = Microsoft.Data.Sqlite.SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        await backup.OpenAsync();
        await using var integrity = backup.CreateCommand(); integrity.CommandText = "PRAGMA integrity_check";
        Assert.Equal("ok", await integrity.ExecuteScalarAsync());
        await using var rows = backup.CreateCommand(); rows.CommandText = "SELECT COUNT(*) FROM invitations";
        Assert.Equal(1L, (long)(await rows.ExecuteScalarAsync())!);
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
        Assert.True(await _store.RevokeInvitationAsync(invitation.Id, "test-admin", DateTimeOffset.UtcNow));
        Assert.Null(await _store.EnrollAsync(new("revoked-code", "PC", "1", "secret-2"), Hash("revoked-code"), Hash("secret-2"), now));
    }

    [Fact]
    public async Task RevokingDeviceImmediatelyInvalidatesItsCredential()
    {
        await CreateInviteAsync("revoke-code");
        var device = await _store.EnrollAsync(new("revoke-code", "PC", "1", "secret"), Hash("revoke-code"), Hash("secret"), DateTimeOffset.UtcNow);
        Assert.NotNull(device);
        Assert.True(await _store.RevokeDeviceAsync(device.DeviceId, "test-admin", DateTimeOffset.UtcNow));
        Assert.Null(await _store.AuthenticateDeviceAsync(Hash("secret"), DateTimeOffset.UtcNow));
        Assert.True(Assert.Single(await _store.ListDevicesAsync()).Revoked);
    }

    [Fact]
    public async Task ManualApprovalBlocksAgentAuthenticationUntilApprovedAndRejectInvalidatesCredential()
    {
        await CreateApprovalInviteAsync("approval-code");
        var pending = await _store.EnrollAsync(new("approval-code", "PC-pending", "1", "pending-secret"), Hash("approval-code"), Hash("pending-secret"), DateTimeOffset.UtcNow);
        Assert.NotNull(pending);
        Assert.False(Assert.Single(await _store.ListDevicesAsync()).Approved);
        Assert.Null(await _store.AuthenticateDeviceAsync(Hash("pending-secret"), DateTimeOffset.UtcNow));
        Assert.True(await _store.SetDeviceApprovalAsync(pending.DeviceId, true, "test-admin", DateTimeOffset.UtcNow));
        Assert.NotNull(await _store.AuthenticateDeviceAsync(Hash("pending-secret"), DateTimeOffset.UtcNow));

        await CreateApprovalInviteAsync("rejection-code");
        var rejected = await _store.EnrollAsync(new("rejection-code", "PC-rejected", "1", "rejected-secret"), Hash("rejection-code"), Hash("rejected-secret"), DateTimeOffset.UtcNow);
        Assert.NotNull(rejected);
        Assert.True(await _store.SetDeviceApprovalAsync(rejected.DeviceId, false, "test-admin", DateTimeOffset.UtcNow));
        Assert.Null(await _store.AuthenticateDeviceAsync(Hash("rejected-secret"), DateTimeOffset.UtcNow));
        Assert.False(await _store.SetDeviceApprovalAsync(rejected.DeviceId, true, "test-admin", DateTimeOffset.UtcNow));
    }

    [Fact]
    public async Task ExistingSchemaFiveDatabaseGetsApprovedDefaultsDuringMigration()
    {
        var path = Path.Combine(_directory, "legacy.db");
        await using (var legacy = new Microsoft.Data.Sqlite.SqliteConnection(new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
        {
            await legacy.OpenAsync();
            await using var setup = legacy.CreateCommand();
            setup.CommandText = """
                CREATE TABLE invitations(id TEXT PRIMARY KEY,code_hash TEXT NOT NULL UNIQUE,device_group TEXT NOT NULL,expires_at TEXT NOT NULL,max_registrations INTEGER NOT NULL,registration_count INTEGER NOT NULL DEFAULT 0,revoked INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE devices(id TEXT PRIMARY KEY,token_hash TEXT NOT NULL UNIQUE,name TEXT NOT NULL,device_group TEXT NOT NULL,client_version TEXT NOT NULL,registered_at TEXT NOT NULL,last_seen_at TEXT NULL,revoked INTEGER NOT NULL DEFAULT 0,last_error TEXT NULL);
                INSERT INTO devices(id,token_hash,name,device_group,client_version,registered_at) VALUES('legacy-device','legacy-hash','PC-old','Legacy','0.4.0','2026-01-01T00:00:00Z');
                PRAGMA user_version=5;
                """;
            await setup.ExecuteNonQueryAsync();
        }
        var migrated = new SqliteServerStore(path);
        await migrated.InitializeAsync();
        var device = Assert.Single(await migrated.ListDevicesAsync());
        Assert.True(device.Approved);
        await migrated.InitializeAsync();
        Assert.True(Assert.Single(await migrated.ListDevicesAsync()).Approved);
    }

    [Fact]
    public async Task CredentialRotationKeepsOldTokenUntilNewTokenIsFirstUsedThenInvalidatesIt()
    {
        await CreateInviteAsync("rotation-code");
        var enrollment = await _store.EnrollAsync(new("rotation-code", "PC-rotate", "1", "old-device-secret"), Hash("rotation-code"), Hash("old-device-secret"), DateTimeOffset.UtcNow);
        Assert.NotNull(enrollment);
        Assert.True(await _store.StageDeviceCredentialRotationAsync(enrollment.DeviceId, Hash("old-device-secret"), Hash("new-device-secret")));
        Assert.NotNull(await _store.AuthenticateDeviceAsync(Hash("old-device-secret"), DateTimeOffset.UtcNow));
        Assert.Null(await _store.AuthenticateDeviceAsync(Hash("unrelated-device-secret"), DateTimeOffset.UtcNow));
        Assert.NotNull(await _store.AuthenticateDeviceAsync(Hash("new-device-secret"), DateTimeOffset.UtcNow));
        Assert.Null(await _store.AuthenticateDeviceAsync(Hash("old-device-secret"), DateTimeOffset.UtcNow));
        Assert.False(await _store.StageDeviceCredentialRotationAsync(enrollment.DeviceId, Hash("old-device-secret"), Hash("another-device-secret")));
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);
}
