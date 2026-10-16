using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Sentinel.Server.Core;
using Sentinel.Server.Infrastructure;
using Xunit;

namespace Sentinel.Server.Tests;

public sealed class AdminSecurityTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "sentinel-admin-tests", Guid.NewGuid().ToString("N"));
    private readonly SqliteServerStore _store;
    private readonly DateTimeOffset _now = DateTimeOffset.UtcNow;

    public AdminSecurityTests()
    {
        _store = new(Path.Combine(_directory, "server.db"));
        _store.InitializeAsync().GetAwaiter().GetResult();
    }

    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    [Fact]
    public void PasswordHashUsesSaltAndRejectsIncorrectPasswords()
    {
        var hasher = new AdminPasswordHasher();
        var encoded = hasher.Hash("A-long-test-password-42!");
        Assert.True(hasher.Verify("A-long-test-password-42!", encoded));
        Assert.False(hasher.Verify("Another-long-password-42!", encoded));
        Assert.NotEqual(encoded, hasher.Hash("A-long-test-password-42!"));
        Assert.False(AdminPasswordHasher.IsValid("short"));
    }

    [Fact]
    public async Task BootstrapIsOneTimeAndAdminSessionsExpireAndCanBeRevoked()
    {
        var hasher = new AdminPasswordHasher(); var passwordHash = hasher.Hash("Initial-long-password-42!");
        Assert.True(await _store.TryBootstrapAdminAsync("root@example.test", passwordHash, _now));
        Assert.False(await _store.TryBootstrapAdminAsync("attacker", passwordHash, _now));
        var admin = Assert.Single(await _store.ListAdminsAsync());
        Assert.Equal(AdminRole.SystemAdministrator, admin.Role);

        var identity = await _store.CreateAdminSessionAsync(admin.Id, Hash("session-token"), _now, _now.AddHours(12));
        Assert.Equal(admin.Id, identity.Id);
        Assert.Equal(admin.Id, (await _store.AuthenticateAdminSessionAsync(Hash("session-token"), _now.AddHours(1)))?.Id);
        Assert.Null(await _store.AuthenticateAdminSessionAsync(Hash("session-token"), _now.AddHours(13)));
        Assert.True(await _store.RevokeAdminSessionAsync(identity.SessionId, identity.Id, identity.Username, _now.AddHours(2)));
        Assert.Null(await _store.AuthenticateAdminSessionAsync(Hash("session-token"), _now.AddHours(2)));

        var audit = await _store.ReadAuditAsync(100);
        Assert.Contains(audit, e => e.Action == "admin.bootstrap");
        Assert.Contains(audit, e => e.Action == "admin.login");
        Assert.Contains(audit, e => e.Action == "admin.logout");
    }

    [Fact]
    public async Task LastSystemAdministratorCannotBeDisabledOrDemoted()
    {
        var hasher = new AdminPasswordHasher();
        await _store.TryBootstrapAdminAsync("root", hasher.Hash("Initial-long-password-42!"), _now);
        var admin = Assert.Single(await _store.ListAdminsAsync());
        await Assert.ThrowsAsync<InvalidOperationException>(() => _store.SetAdminDisabledAsync(admin.Id, true, "root", _now));
        await Assert.ThrowsAsync<InvalidOperationException>(() => _store.SetAdminRoleAsync(admin.Id, AdminRole.ReadOnly, "root", _now));
        Assert.False((await _store.FindAdminAsync("root"))!.Disabled);
        Assert.Equal(AdminRole.SystemAdministrator, (await _store.FindAdminAsync("root"))!.Role);
    }

    [Fact]
    public async Task DisablingAccountRevokesItsLiveSessionsAndRoleChangesAreAudited()
    {
        var hasher = new AdminPasswordHasher();
        await _store.TryBootstrapAdminAsync("root", hasher.Hash("Initial-long-password-42!"), _now);
        var root = Assert.Single(await _store.ListAdminsAsync());
        var operatorAdmin = await _store.CreateAdminAsync("operator", hasher.Hash("Operator-long-password-42!"), AdminRole.Operator, "root", _now);
        var session = await _store.CreateAdminSessionAsync(operatorAdmin.Id, Hash("operator-session"), _now, _now.AddHours(12));
        Assert.True(await _store.SetAdminRoleAsync(operatorAdmin.Id, AdminRole.SecurityAdministrator, "root", _now.AddMinutes(1)));
        Assert.Equal(AdminRole.SecurityAdministrator, (await _store.AuthenticateAdminSessionAsync(Hash("operator-session"), _now.AddMinutes(1)))!.Role);
        Assert.True(await _store.SetAdminDisabledAsync(operatorAdmin.Id, true, "root", _now.AddMinutes(2)));
        Assert.Null(await _store.AuthenticateAdminSessionAsync(Hash("operator-session"), _now.AddMinutes(2)));
        Assert.Contains(await _store.ReadAuditAsync(100), e => e.Action == "admin.role_changed" && e.TargetId == operatorAdmin.Id);
        Assert.Contains(await _store.ReadAuditAsync(100), e => e.Action == "admin.disabled" && e.ActorUsername == "root");
        Assert.NotEqual(root.Id, session.Id);
    }

    [Fact]
    public async Task VersionOneDatabaseIsUpgradedWithoutLosingEnrollmentData()
    {
        var path = Path.Combine(_directory, "legacy.db");
        Directory.CreateDirectory(_directory);
        await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString()))
        {
            await connection.OpenAsync(); await using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE invitations(id TEXT PRIMARY KEY,code_hash TEXT NOT NULL UNIQUE,device_group TEXT NOT NULL,expires_at TEXT NOT NULL,
                  max_registrations INTEGER NOT NULL,registration_count INTEGER NOT NULL DEFAULT 0,revoked INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE devices(id TEXT PRIMARY KEY,token_hash TEXT NOT NULL UNIQUE,name TEXT NOT NULL,device_group TEXT NOT NULL,
                  client_version TEXT NOT NULL,registered_at TEXT NOT NULL,last_seen_at TEXT NULL,revoked INTEGER NOT NULL DEFAULT 0,last_error TEXT NULL);
                INSERT INTO invitations(id,code_hash,device_group,expires_at,max_registrations) VALUES('old','legacy-code-hash','IT',$expires,1);
                PRAGMA user_version=1;
                """;
            command.Parameters.AddWithValue("$expires", _now.AddHours(1).ToString("O"));
            await command.ExecuteNonQueryAsync();
        }
        var migrated = new SqliteServerStore(path);
        await migrated.InitializeAsync();
        Assert.True(await migrated.CheckReadyAsync());
        var enrollment = await migrated.EnrollAsync(new("legacy-code", "OLD-PC", "0.2.0", "legacy-device-token"),
            "legacy-code-hash", Hash("legacy-device-token"), _now);
        Assert.NotNull(enrollment);
        Assert.Equal("IT", enrollment.Group);
        Assert.Contains(await migrated.ListGroupsAsync(), group => group.Name == "IT");
        Assert.Single(await migrated.ListDevicesAsync());
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);
}
