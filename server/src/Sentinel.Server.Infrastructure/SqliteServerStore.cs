using Microsoft.Data.Sqlite;
using Sentinel.Server.Core;

namespace Sentinel.Server.Infrastructure;

public sealed class SqliteServerStore(string databasePath) : IServerStore
{
    private readonly string _databasePath = Path.GetFullPath(databasePath);
    private string ConnectionString => new SqliteConnectionStringBuilder { DataSource = _databasePath, Pooling = false, Mode = SqliteOpenMode.ReadWriteCreate }.ToString();

    private async Task<SqliteConnection> OpenAsync(CancellationToken ct)
    {
        var connection = new SqliteConnection(ConnectionString);
        try { await connection.OpenAsync(ct); return connection; }
        catch { await connection.DisposeAsync(); throw; }
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_databasePath)!);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version";
        var version = Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken), System.Globalization.CultureInfo.InvariantCulture);
        if (version > 2) throw new InvalidDataException("Baza serwera została utworzona przez nowszą wersję.");
        command.Parameters.Clear();
        command.CommandText = """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS invitations(
              id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, device_group TEXT NOT NULL,
              expires_at TEXT NOT NULL, max_registrations INTEGER NOT NULL CHECK(max_registrations BETWEEN 1 AND 1000),
              registration_count INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)));
            CREATE TABLE IF NOT EXISTS devices(
              id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, name TEXT NOT NULL, device_group TEXT NOT NULL,
              client_version TEXT NOT NULL, registered_at TEXT NOT NULL, last_seen_at TEXT NULL,
              revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)), last_error TEXT NULL);
            CREATE INDEX IF NOT EXISTS ix_devices_last_seen ON devices(last_seen_at);
            CREATE TABLE IF NOT EXISTS administrators(
              id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL,
              role TEXT NOT NULL CHECK(role IN ('SystemAdministrator','SecurityAdministrator','Operator','ReadOnly')),
              disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0,1)), created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS admin_sessions(
              id TEXT PRIMARY KEY, admin_id TEXT NOT NULL REFERENCES administrators(id), token_hash TEXT NOT NULL UNIQUE,
              created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT NULL);
            CREATE INDEX IF NOT EXISTS ix_admin_sessions_token ON admin_sessions(token_hash,expires_at);
            CREATE TABLE IF NOT EXISTS admin_audit(
              id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, actor_username TEXT NULL,
              action TEXT NOT NULL, target_id TEXT NULL);
            CREATE INDEX IF NOT EXISTS ix_admin_audit_time ON admin_audit(timestamp DESC);
            PRAGMA user_version=2;
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<bool> CheckReadyAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var command = connection.CreateCommand(); command.CommandText = "SELECT 1 FROM sqlite_master LIMIT 1";
            return await command.ExecuteScalarAsync(cancellationToken) is not null;
        }
        catch (SqliteException) { return false; }
        catch (IOException) { return false; }
    }

    public async Task<bool> TryBootstrapAdminAsync(string username, string passwordHash, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await using var count = connection.CreateCommand(); count.Transaction = (SqliteTransaction)transaction;
            count.CommandText = "SELECT COUNT(*) FROM administrators";
            if (Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken), System.Globalization.CultureInfo.InvariantCulture) != 0)
            { await transaction.RollbackAsync(cancellationToken); return false; }
            var id = Guid.NewGuid().ToString("N");
            await using var insert = connection.CreateCommand(); insert.Transaction = (SqliteTransaction)transaction;
            insert.CommandText = "INSERT INTO administrators(id,username,password_hash,role,created_at) VALUES($id,$username,$hash,'SystemAdministrator',$now)";
            insert.Parameters.AddWithValue("$id", id); insert.Parameters.AddWithValue("$username", username);
            insert.Parameters.AddWithValue("$hash", passwordHash); insert.Parameters.AddWithValue("$now", now.ToString("O"));
            await insert.ExecuteNonQueryAsync(cancellationToken);
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, username, "admin.bootstrap", id, cancellationToken);
            await transaction.CommitAsync(cancellationToken); return true;
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<AdminCredential?> FindAdminAsync(string username, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id,username,password_hash,role,disabled FROM administrators WHERE username=$username COLLATE NOCASE";
        command.Parameters.AddWithValue("$username", username); await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadAdmin(reader) : null;
    }

    public async Task<IReadOnlyList<AdminCredential>> ListAdminsAsync(CancellationToken cancellationToken = default)
    {
        var admins = new List<AdminCredential>(); await using var connection = await OpenAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id,username,password_hash,role,disabled FROM administrators ORDER BY username COLLATE NOCASE";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) admins.Add(ReadAdmin(reader)); return admins;
    }

    public async Task<AdminCredential> CreateAdminAsync(string username, string passwordHash, AdminRole role, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var admin = new AdminCredential(Guid.NewGuid().ToString("N"), username, passwordHash, role, false);
        await using var connection = await OpenAsync(cancellationToken); await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await using var command = connection.CreateCommand(); command.Transaction = (SqliteTransaction)transaction;
            command.CommandText = "INSERT INTO administrators(id,username,password_hash,role,created_at) VALUES($id,$username,$hash,$role,$now)";
            command.Parameters.AddWithValue("$id", admin.Id); command.Parameters.AddWithValue("$username", admin.Username);
            command.Parameters.AddWithValue("$hash", admin.PasswordHash); command.Parameters.AddWithValue("$role", admin.Role.ToString()); command.Parameters.AddWithValue("$now", now.ToString("O"));
            await command.ExecuteNonQueryAsync(cancellationToken);
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, actorUsername, "admin.created", admin.Id, cancellationToken);
            await transaction.CommitAsync(cancellationToken); return admin;
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<bool> SetAdminDisabledAsync(string id, bool disabled, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await using var update = connection.CreateCommand(); update.Transaction = (SqliteTransaction)transaction;
            update.CommandText = "UPDATE administrators SET disabled=$disabled WHERE id=$id AND disabled<>$disabled";
            update.Parameters.AddWithValue("$disabled", disabled ? 1 : 0); update.Parameters.AddWithValue("$id", id);
            if (await update.ExecuteNonQueryAsync(cancellationToken) != 1) { await transaction.RollbackAsync(cancellationToken); return false; }
            if (disabled)
            {
                await EnsureSystemAdministratorRemainsAsync(connection, (SqliteTransaction)transaction, cancellationToken);
                await using var sessions = connection.CreateCommand(); sessions.Transaction = (SqliteTransaction)transaction;
                sessions.CommandText = "UPDATE admin_sessions SET revoked_at=$now WHERE admin_id=$id AND revoked_at IS NULL";
                sessions.Parameters.AddWithValue("$now", now.ToString("O")); sessions.Parameters.AddWithValue("$id", id); await sessions.ExecuteNonQueryAsync(cancellationToken);
            }
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, actorUsername, disabled ? "admin.disabled" : "admin.enabled", id, cancellationToken);
            await transaction.CommitAsync(cancellationToken); return true;
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<bool> SetAdminRoleAsync(string id, AdminRole role, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await using var update = connection.CreateCommand(); update.Transaction = (SqliteTransaction)transaction;
            update.CommandText = "UPDATE administrators SET role=$role WHERE id=$id AND role<>$role";
            update.Parameters.AddWithValue("$role", role.ToString()); update.Parameters.AddWithValue("$id", id);
            if (await update.ExecuteNonQueryAsync(cancellationToken) != 1) { await transaction.RollbackAsync(cancellationToken); return false; }
            if (role != AdminRole.SystemAdministrator)
                await EnsureSystemAdministratorRemainsAsync(connection, (SqliteTransaction)transaction, cancellationToken);
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, actorUsername, "admin.role_changed", id, cancellationToken);
            await transaction.CommitAsync(cancellationToken); return true;
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<bool> ChangeAdminPasswordAsync(string id, string passwordHash, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await using var update = connection.CreateCommand(); update.Transaction = (SqliteTransaction)transaction;
            update.CommandText = "UPDATE administrators SET password_hash=$hash WHERE id=$id AND disabled=0";
            update.Parameters.AddWithValue("$hash", passwordHash); update.Parameters.AddWithValue("$id", id);
            if (await update.ExecuteNonQueryAsync(cancellationToken) != 1) { await transaction.RollbackAsync(cancellationToken); return false; }
            await using var sessions = connection.CreateCommand(); sessions.Transaction = (SqliteTransaction)transaction;
            sessions.CommandText = "UPDATE admin_sessions SET revoked_at=$now WHERE admin_id=$id AND revoked_at IS NULL";
            sessions.Parameters.AddWithValue("$now", now.ToString("O")); sessions.Parameters.AddWithValue("$id", id); await sessions.ExecuteNonQueryAsync(cancellationToken);
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, actorUsername, "admin.password_changed", id, cancellationToken);
            await transaction.CommitAsync(cancellationToken); return true;
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<AdminIdentity> CreateAdminSessionAsync(string adminId, string sessionHash, DateTimeOffset now, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        var admin = await FindAdminByIdAsync(adminId, cancellationToken) ?? throw new InvalidOperationException("Konto administratora nie istnieje.");
        var sessionId = Guid.NewGuid().ToString("N");
        await using var connection = await OpenAsync(cancellationToken); await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await using var command = connection.CreateCommand(); command.Transaction = (SqliteTransaction)transaction;
            command.CommandText = "INSERT INTO admin_sessions(id,admin_id,token_hash,created_at,expires_at) VALUES($id,$admin,$hash,$now,$expires)";
            command.Parameters.AddWithValue("$id", sessionId); command.Parameters.AddWithValue("$admin", adminId); command.Parameters.AddWithValue("$hash", sessionHash);
            command.Parameters.AddWithValue("$now", now.ToString("O")); command.Parameters.AddWithValue("$expires", expiresAt.ToString("O"));
            await command.ExecuteNonQueryAsync(cancellationToken);
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, admin.Username, "admin.login", sessionId, cancellationToken);
            await transaction.CommitAsync(cancellationToken); return new(admin.Id, admin.Username, admin.Role, sessionId);
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<AdminIdentity?> AuthenticateAdminSessionAsync(string sessionHash, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT a.id,a.username,a.role,s.id FROM admin_sessions s
            JOIN administrators a ON a.id=s.admin_id WHERE s.token_hash=$hash AND s.revoked_at IS NULL AND s.expires_at>$now AND a.disabled=0
            """;
        command.Parameters.AddWithValue("$hash", sessionHash); command.Parameters.AddWithValue("$now", now.ToString("O"));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return new(reader.GetString(0), reader.GetString(1), Enum.Parse<AdminRole>(reader.GetString(2)), reader.GetString(3));
    }

    public async Task<bool> RevokeAdminSessionAsync(string sessionId, string adminId, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await using var update = connection.CreateCommand(); update.Transaction = (SqliteTransaction)transaction;
            update.CommandText = "UPDATE admin_sessions SET revoked_at=$now WHERE id=$id AND admin_id=$admin AND revoked_at IS NULL";
            update.Parameters.AddWithValue("$now", now.ToString("O")); update.Parameters.AddWithValue("$id", sessionId); update.Parameters.AddWithValue("$admin", adminId);
            if (await update.ExecuteNonQueryAsync(cancellationToken) != 1) { await transaction.RollbackAsync(cancellationToken); return false; }
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, actorUsername, "admin.logout", sessionId, cancellationToken);
            await transaction.CommitAsync(cancellationToken); return true;
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<IReadOnlyList<AuditEntry>> ReadAuditAsync(int limit, CancellationToken cancellationToken = default)
    {
        limit = Math.Clamp(limit, 1, 500); var entries = new List<AuditEntry>();
        await using var connection = await OpenAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id,timestamp,actor_username,action,target_id FROM admin_audit ORDER BY id DESC LIMIT $limit";
        command.Parameters.AddWithValue("$limit", limit); await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) entries.Add(new(reader.GetInt64(0), DateTimeOffset.Parse(reader.GetString(1)),
            reader.IsDBNull(2) ? null : reader.GetString(2), reader.GetString(3), reader.IsDBNull(4) ? null : reader.GetString(4)));
        return entries;
    }

    private async Task<AdminCredential?> FindAdminByIdAsync(string id, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id,username,password_hash,role,disabled FROM administrators WHERE id=$id AND disabled=0";
        command.Parameters.AddWithValue("$id", id); await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadAdmin(reader) : null;
    }

    private static AdminCredential ReadAdmin(SqliteDataReader reader) => new(reader.GetString(0), reader.GetString(1), reader.GetString(2),
        Enum.Parse<AdminRole>(reader.GetString(3)), reader.GetInt32(4) != 0);

    private static async Task AddAuditAsync(SqliteConnection connection, SqliteTransaction transaction, DateTimeOffset now,
        string actorUsername, string action, string targetId, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "INSERT INTO admin_audit(timestamp,actor_username,action,target_id) VALUES($now,$actor,$action,$target)";
        command.Parameters.AddWithValue("$now", now.ToString("O")); command.Parameters.AddWithValue("$actor", actorUsername);
        command.Parameters.AddWithValue("$action", action); command.Parameters.AddWithValue("$target", targetId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task EnsureSystemAdministratorRemainsAsync(SqliteConnection connection, SqliteTransaction transaction, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "SELECT COUNT(*) FROM administrators WHERE role='SystemAdministrator' AND disabled=0";
        if (Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken), System.Globalization.CultureInfo.InvariantCulture) < 1)
            throw new InvalidOperationException("Nie można wyłączyć ani zdegradować ostatniego aktywnego administratora systemu.");
    }

    public async Task<Invitation> CreateInvitationAsync(InvitationRequest request, string codeHash, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var result = new Invitation(Guid.NewGuid().ToString("N"), request.Group, request.ExpiresAt.ToUniversalTime(), request.MaximumRegistrations, 0, false);
        await using var connection = await OpenAsync(cancellationToken); await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await using var command = connection.CreateCommand(); command.Transaction = (SqliteTransaction)transaction;
            command.CommandText = "INSERT INTO invitations(id,code_hash,device_group,expires_at,max_registrations) VALUES($id,$hash,$group,$expires,$max)";
            command.Parameters.AddWithValue("$id", result.Id); command.Parameters.AddWithValue("$hash", codeHash);
            command.Parameters.AddWithValue("$group", result.Group); command.Parameters.AddWithValue("$expires", result.ExpiresAt.ToString("O"));
            command.Parameters.AddWithValue("$max", result.MaximumRegistrations); await command.ExecuteNonQueryAsync(cancellationToken);
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, actorUsername, "invitation.created", result.Id, cancellationToken);
            await transaction.CommitAsync(cancellationToken); return result;
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<bool> RevokeInvitationAsync(string id, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await using var command = connection.CreateCommand(); command.Transaction = (SqliteTransaction)transaction;
            command.CommandText = "UPDATE invitations SET revoked=1 WHERE id=$id AND revoked=0";
            command.Parameters.AddWithValue("$id", id); if (await command.ExecuteNonQueryAsync(cancellationToken) != 1) { await transaction.RollbackAsync(cancellationToken); return false; }
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, actorUsername, "invitation.revoked", id, cancellationToken);
            await transaction.CommitAsync(cancellationToken); return true;
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<EnrollmentResult?> EnrollAsync(EnrollmentRequest request, string codeHash, string deviceTokenHash, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await using var invitationCommand = connection.CreateCommand(); invitationCommand.Transaction = (SqliteTransaction)transaction;
            invitationCommand.CommandText = "SELECT id,device_group,expires_at,max_registrations,registration_count FROM invitations WHERE code_hash=$hash AND revoked=0";
            invitationCommand.Parameters.AddWithValue("$hash", codeHash);
            await using var reader = await invitationCommand.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)) { await transaction.RollbackAsync(cancellationToken); return null; }
            var invitationId = reader.GetString(0); var group = reader.GetString(1); var expires = DateTimeOffset.Parse(reader.GetString(2));
            var maximum = reader.GetInt32(3); var count = reader.GetInt32(4); await reader.CloseAsync();
            if (expires <= now || count >= maximum) { await transaction.RollbackAsync(cancellationToken); return null; }
            var device = new EnrollmentResult(Guid.NewGuid().ToString("N"), request.DeviceToken, group, now);
            await using var updateInvitation = connection.CreateCommand(); updateInvitation.Transaction = (SqliteTransaction)transaction;
            updateInvitation.CommandText = "UPDATE invitations SET registration_count=registration_count+1 WHERE id=$id AND revoked=0 AND registration_count < max_registrations AND expires_at > $now";
            updateInvitation.Parameters.AddWithValue("$id", invitationId); updateInvitation.Parameters.AddWithValue("$now", now.ToString("O"));
            if (await updateInvitation.ExecuteNonQueryAsync(cancellationToken) != 1) { await transaction.RollbackAsync(cancellationToken); return null; }
            await using var insertDevice = connection.CreateCommand(); insertDevice.Transaction = (SqliteTransaction)transaction;
            insertDevice.CommandText = "INSERT INTO devices(id,token_hash,name,device_group,client_version,registered_at,last_seen_at) VALUES($id,$token,$name,$group,$version,$now,$now)";
            insertDevice.Parameters.AddWithValue("$id", device.DeviceId); insertDevice.Parameters.AddWithValue("$token", deviceTokenHash);
            insertDevice.Parameters.AddWithValue("$name", request.DeviceName); insertDevice.Parameters.AddWithValue("$group", group);
            insertDevice.Parameters.AddWithValue("$version", request.ClientVersion); insertDevice.Parameters.AddWithValue("$now", now.ToString("O"));
            await insertDevice.ExecuteNonQueryAsync(cancellationToken); await transaction.CommitAsync(cancellationToken); return device;
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<Device?> AuthenticateDeviceAsync(string tokenHash, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id,name,device_group,client_version,registered_at,last_seen_at,revoked,last_error FROM devices WHERE token_hash=$hash AND revoked=0";
        command.Parameters.AddWithValue("$hash", tokenHash);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return ReadDevice(reader);
    }

    public async Task<IReadOnlyList<Device>> ListDevicesAsync(CancellationToken cancellationToken = default)
    {
        var items = new List<Device>(); await using var connection = await OpenAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id,name,device_group,client_version,registered_at,last_seen_at,revoked,last_error FROM devices ORDER BY name COLLATE NOCASE";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) items.Add(ReadDevice(reader)); return items;
    }

    public async Task<bool> RevokeDeviceAsync(string id, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await using var command = connection.CreateCommand(); command.Transaction = (SqliteTransaction)transaction;
            command.CommandText = "UPDATE devices SET revoked=1,token_hash=$invalidated WHERE id=$id AND revoked=0";
            command.Parameters.AddWithValue("$id", id); command.Parameters.AddWithValue("$invalidated", Guid.NewGuid().ToString("N"));
            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1) { await transaction.RollbackAsync(cancellationToken); return false; }
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, actorUsername, "device.revoked", id, cancellationToken);
            await transaction.CommitAsync(cancellationToken); return true;
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<bool> HeartbeatAsync(string id, DateTimeOffset now, string? lastError, CancellationToken cancellationToken = default)
    {
        if (lastError is { Length: > 256 }) lastError = lastError[..256];
        await using var connection = await OpenAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE devices SET last_seen_at=$now,last_error=$error WHERE id=$id AND revoked=0";
        command.Parameters.AddWithValue("$id", id); command.Parameters.AddWithValue("$now", now.ToString("O"));
        command.Parameters.AddWithValue("$error", (object?)lastError ?? DBNull.Value);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    private static Device ReadDevice(SqliteDataReader reader) => new(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
        DateTimeOffset.Parse(reader.GetString(4)), reader.IsDBNull(5) ? null : DateTimeOffset.Parse(reader.GetString(5)), reader.GetInt32(6) != 0,
        reader.IsDBNull(7) ? null : reader.GetString(7));
}
