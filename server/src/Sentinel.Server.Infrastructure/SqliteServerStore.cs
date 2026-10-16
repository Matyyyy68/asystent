using Microsoft.Data.Sqlite;
using Sentinel.Server.Core;
using System.Text.Json;

namespace Sentinel.Server.Infrastructure;

public sealed class SqliteServerStore : IServerStore
{
    private readonly string _databasePath;
    private readonly int _eventRetentionDays;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public SqliteServerStore(string databasePath, int eventRetentionDays = 90)
    {
        if (eventRetentionDays is < 30 or > 3650) throw new ArgumentOutOfRangeException(nameof(eventRetentionDays), "Retencja zdarzeń musi wynosić 30–3650 dni.");
        _databasePath = Path.GetFullPath(databasePath);
        _eventRetentionDays = eventRetentionDays;
    }
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
        if (version > 6) throw new InvalidDataException("Baza serwera została utworzona przez nowszą wersję.");
        command.Parameters.Clear();
        command.CommandText = """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS invitations(
              id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, device_group TEXT NOT NULL,
              expires_at TEXT NOT NULL, max_registrations INTEGER NOT NULL CHECK(max_registrations BETWEEN 1 AND 1000),
              registration_count INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
              requires_approval INTEGER NOT NULL DEFAULT 0 CHECK(requires_approval IN (0,1)));
            CREATE TABLE IF NOT EXISTS devices(
              id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, name TEXT NOT NULL, device_group TEXT NOT NULL,
              client_version TEXT NOT NULL, registered_at TEXT NOT NULL, last_seen_at TEXT NULL,
              revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)), last_error TEXT NULL,
              approved INTEGER NOT NULL DEFAULT 1 CHECK(approved IN (0,1)));
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
            CREATE TABLE IF NOT EXISTS device_groups(
              id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, created_at TEXT NOT NULL,
              policy_json TEXT NULL, policy_version INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS server_policies(
              id INTEGER PRIMARY KEY CHECK(id=1), policy_json TEXT NOT NULL, version INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS server_ai_config(
              id INTEGER PRIMARY KEY CHECK(id=1), endpoint TEXT NOT NULL, model TEXT NOT NULL,
              enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), timeout_seconds INTEGER NOT NULL CHECK(timeout_seconds BETWEEN 3 AND 120),
              version INTEGER NOT NULL CHECK(version >= 0));
            INSERT OR IGNORE INTO server_ai_config(id,endpoint,model,enabled,timeout_seconds,version)
              VALUES(1,'http://127.0.0.1:11434','',0,30,0);
            CREATE TABLE IF NOT EXISTS device_policies(
              device_id TEXT PRIMARY KEY REFERENCES devices(id), policy_json TEXT NOT NULL, version INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS security_events(
              event_id TEXT NOT NULL, device_id TEXT NOT NULL REFERENCES devices(id), occurred_at TEXT NOT NULL, received_at TEXT NOT NULL,
              category TEXT NOT NULL, risk_level INTEGER NOT NULL CHECK(risk_level BETWEEN 0 AND 4), rule_code TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','resolved','false_positive')), PRIMARY KEY(device_id,event_id));
            CREATE INDEX IF NOT EXISTS ix_security_events_time ON security_events(occurred_at DESC);
            CREATE INDEX IF NOT EXISTS ix_security_events_device_time ON security_events(device_id,occurred_at DESC);
            INSERT OR IGNORE INTO device_groups(id,name,created_at)
              SELECT lower(hex(randomblob(16))),device_group,strftime('%Y-%m-%dT%H:%M:%fZ','now') FROM invitations WHERE length(device_group)>0;
            INSERT OR IGNORE INTO device_groups(id,name,created_at)
              SELECT lower(hex(randomblob(16))),device_group,strftime('%Y-%m-%dT%H:%M:%fZ','now') FROM devices WHERE length(device_group)>0;
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
        await EnsureColumnAsync(connection, "invitations", "requires_approval", "INTEGER NOT NULL DEFAULT 0 CHECK(requires_approval IN (0,1))", cancellationToken);
        await EnsureColumnAsync(connection, "devices", "approved", "INTEGER NOT NULL DEFAULT 1 CHECK(approved IN (0,1))", cancellationToken);
        await using var setVersion = connection.CreateCommand(); setVersion.CommandText = "PRAGMA user_version=6";
        await setVersion.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task EnsureColumnAsync(SqliteConnection connection, string table, string column, string definition, CancellationToken ct)
    {
        await using var inspect = connection.CreateCommand(); inspect.CommandText = $"PRAGMA table_info({table})";
        await using var reader = await inspect.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) if (string.Equals(reader.GetString(1), column, StringComparison.OrdinalIgnoreCase)) return;
        await reader.CloseAsync();
        await using var alter = connection.CreateCommand(); alter.CommandText = $"ALTER TABLE {table} ADD COLUMN {column} {definition}";
        await alter.ExecuteNonQueryAsync(ct);
    }

    public async Task CreateBackupAsync(string destinationPath, CancellationToken cancellationToken = default)
    {
        var destination = Path.GetFullPath(destinationPath);
        if (string.Equals(destination, _databasePath, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new ArgumentException("Kopia musi być zapisana w osobnym pliku.", nameof(destinationPath));
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        await using var source = await OpenAsync(cancellationToken);
        await using var target = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = destination, Pooling = false, Mode = SqliteOpenMode.ReadWriteCreate
        }.ToString());
        await target.OpenAsync(cancellationToken);
        source.BackupDatabase(target);
        await using var check = target.CreateCommand();
        check.CommandText = "PRAGMA integrity_check";
        var result = Convert.ToString(await check.ExecuteScalarAsync(cancellationToken), System.Globalization.CultureInfo.InvariantCulture);
        if (!string.Equals(result, "ok", StringComparison.OrdinalIgnoreCase))
        {
            await target.CloseAsync();
            File.Delete(destination);
            throw new InvalidDataException("Utworzona kopia bazy nie przeszła kontroli integralności.");
        }
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

    public async Task RecordAdminActionAsync(string actorUsername, string action, string? targetId, DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(actorUsername) || actorUsername.Length > 64 || string.IsNullOrWhiteSpace(action) || action.Length > 100 || targetId is { Length: > 200 })
            throw new ArgumentException("Nieprawidłowy wpis audytowy.");
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, actorUsername, action, targetId, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<ServerAIConfiguration> ReadServerAIConfigurationAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT endpoint,model,enabled,timeout_seconds,version FROM server_ai_config WHERE id=1";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) throw new InvalidDataException("Brak konfiguracji AI serwera.");
        return new(reader.GetString(0), reader.GetString(1), reader.GetInt32(2) != 0, reader.GetInt32(3), reader.GetInt64(4));
    }

    public async Task<bool> WriteServerAIConfigurationAsync(ServerAIConfiguration configuration, long expectedVersion,
        string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        if (configuration.Endpoint.Length > 2000 || !Uri.TryCreate(configuration.Endpoint, UriKind.Absolute, out var endpoint) ||
            endpoint.Scheme != Uri.UriSchemeHttp || endpoint.UserInfo.Length > 0 || endpoint.Query.Length > 0 || endpoint.Fragment.Length > 0 || endpoint.AbsolutePath != "/" ||
            !(endpoint.DnsSafeHost.Equals("localhost", StringComparison.OrdinalIgnoreCase) || System.Net.IPAddress.TryParse(endpoint.DnsSafeHost, out var ip) && System.Net.IPAddress.IsLoopback(ip)))
            throw new ArgumentException("Model serwera może działać wyłącznie na localhost/loopback; zdalne endpointy nie są obsługiwane.", nameof(configuration));
        if (configuration.Model.Length > 160 || configuration.Model.Any(char.IsControl) || configuration.Enabled && string.IsNullOrWhiteSpace(configuration.Model))
            throw new ArgumentException("Wybierz lokalny model albo pozostaw provider wyłączony.", nameof(configuration));
        if (configuration.TimeoutSeconds is < 3 or > 120 || expectedVersion < 0 || string.IsNullOrWhiteSpace(actorUsername))
            throw new ArgumentException("Nieprawidłowa wersja lub limit czasu konfiguracji AI.", nameof(configuration));

        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await using var update = connection.CreateCommand(); update.Transaction = (SqliteTransaction)transaction;
            update.CommandText = "UPDATE server_ai_config SET endpoint=$endpoint,model=$model,enabled=$enabled,timeout_seconds=$timeout,version=version+1 WHERE id=1 AND version=$version";
            update.Parameters.AddWithValue("$endpoint", endpoint.ToString().TrimEnd('/'));
            update.Parameters.AddWithValue("$model", configuration.Model.Trim());
            update.Parameters.AddWithValue("$enabled", configuration.Enabled ? 1 : 0);
            update.Parameters.AddWithValue("$timeout", configuration.TimeoutSeconds);
            update.Parameters.AddWithValue("$version", expectedVersion);
            if (await update.ExecuteNonQueryAsync(cancellationToken) != 1) { await transaction.RollbackAsync(cancellationToken); return false; }
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, actorUsername, "ai.config_changed", "server", cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return true;
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
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
        string actorUsername, string action, string? targetId, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "INSERT INTO admin_audit(timestamp,actor_username,action,target_id) VALUES($now,$actor,$action,$target)";
        command.Parameters.AddWithValue("$now", now.ToString("O")); command.Parameters.AddWithValue("$actor", actorUsername);
        command.Parameters.AddWithValue("$action", action); command.Parameters.AddWithValue("$target", targetId is null ? DBNull.Value : targetId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task EnsureSystemAdministratorRemainsAsync(SqliteConnection connection, SqliteTransaction transaction, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "SELECT COUNT(*) FROM administrators WHERE role='SystemAdministrator' AND disabled=0";
        if (Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken), System.Globalization.CultureInfo.InvariantCulture) < 1)
            throw new InvalidOperationException("Nie można wyłączyć ani zdegradować ostatniego aktywnego administratora systemu.");
    }

    public async Task<DeviceGroup> CreateGroupAsync(string name, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        name = name.Trim();
        if (name.Length is < 1 or > 80 || name.Any(char.IsControl)) throw new ArgumentException("Nazwa grupy musi mieć 1–80 znaków.", nameof(name));
        var group = new DeviceGroup(Guid.NewGuid().ToString("N"), name, now, 0);
        await using var connection = await OpenAsync(cancellationToken); await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await using var insert = connection.CreateCommand(); insert.Transaction = (SqliteTransaction)transaction;
            insert.CommandText = "INSERT INTO device_groups(id,name,created_at) VALUES($id,$name,$now)";
            insert.Parameters.AddWithValue("$id", group.Id); insert.Parameters.AddWithValue("$name", group.Name); insert.Parameters.AddWithValue("$now", now.ToString("O"));
            await insert.ExecuteNonQueryAsync(cancellationToken);
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, actorUsername, "group.created", group.Id, cancellationToken);
            await transaction.CommitAsync(cancellationToken); return group;
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<IReadOnlyList<DeviceGroup>> ListGroupsAsync(CancellationToken cancellationToken = default)
    {
        var groups = new List<DeviceGroup>(); await using var connection = await OpenAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id,name,created_at,policy_version FROM device_groups ORDER BY name COLLATE NOCASE";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) groups.Add(new(reader.GetString(0), reader.GetString(1), DateTimeOffset.Parse(reader.GetString(2)), reader.GetInt64(3)));
        return groups;
    }

    public async Task<DeviceGroup?> FindGroupByNameAsync(string name, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id,name,created_at,policy_version FROM device_groups WHERE name=$name COLLATE NOCASE";
        command.Parameters.AddWithValue("$name", name); await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? new(reader.GetString(0), reader.GetString(1), DateTimeOffset.Parse(reader.GetString(2)), reader.GetInt64(3)) : null;
    }

    public async Task<bool> SetDeviceGroupAsync(string deviceId, string groupId, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await using var update = connection.CreateCommand(); update.Transaction = (SqliteTransaction)transaction;
            update.CommandText = """
                UPDATE devices SET device_group=(SELECT name FROM device_groups WHERE id=$group)
                WHERE id=$device AND EXISTS(SELECT 1 FROM device_groups WHERE id=$group)
                """;
            update.Parameters.AddWithValue("$group", groupId); update.Parameters.AddWithValue("$device", deviceId);
            if (await update.ExecuteNonQueryAsync(cancellationToken) != 1) { await transaction.RollbackAsync(cancellationToken); return false; }
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, actorUsername, "device.group_changed", deviceId, cancellationToken);
            await transaction.CommitAsync(cancellationToken); return true;
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<VersionedPolicy> ReadGlobalPolicyAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = "SELECT policy_json,version FROM server_policies WHERE id=1";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return new(new PolicyDocument(), 0);
        return new(JsonSerializer.Deserialize<PolicyDocument>(reader.GetString(0), JsonOptions) ?? new(), reader.GetInt64(1));
    }

    public async Task<bool> WriteGlobalPolicyAsync(PolicyWrite write, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        ValidatePolicy(write.Policy); await using var connection = await OpenAsync(cancellationToken); await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            var current = await ReadVersionAsync(connection, (SqliteTransaction)transaction, "SELECT COALESCE((SELECT version FROM server_policies WHERE id=1),0)", cancellationToken);
            if (current != write.ExpectedVersion) { await transaction.RollbackAsync(cancellationToken); return false; }
            await using var update = connection.CreateCommand(); update.Transaction = (SqliteTransaction)transaction;
            update.CommandText = "INSERT INTO server_policies(id,policy_json,version) VALUES(1,$json,$version) ON CONFLICT(id) DO UPDATE SET policy_json=$json,version=$version";
            update.Parameters.AddWithValue("$json", JsonSerializer.Serialize(write.Policy, JsonOptions)); update.Parameters.AddWithValue("$version", current + 1);
            await update.ExecuteNonQueryAsync(cancellationToken);
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, actorUsername, "policy.global_changed", "global", cancellationToken);
            await transaction.CommitAsync(cancellationToken); return true;
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<VersionedPolicy?> ReadGroupPolicyAsync(string groupId, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = "SELECT policy_json,policy_version FROM device_groups WHERE id=$id"; command.Parameters.AddWithValue("$id", groupId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        var policy = reader.IsDBNull(0) ? new PolicyDocument() : JsonSerializer.Deserialize<PolicyDocument>(reader.GetString(0), JsonOptions) ?? new();
        return new(policy, reader.GetInt64(1));
    }

    public async Task<bool> WriteGroupPolicyAsync(string groupId, PolicyWrite write, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        ValidatePolicy(write.Policy); await using var connection = await OpenAsync(cancellationToken); await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            var current = await ReadVersionAsync(connection, (SqliteTransaction)transaction, "SELECT policy_version FROM device_groups WHERE id=$id", cancellationToken, ("$id", groupId));
            if (current < 0 || current != write.ExpectedVersion) { await transaction.RollbackAsync(cancellationToken); return false; }
            await using var update = connection.CreateCommand(); update.Transaction = (SqliteTransaction)transaction;
            update.CommandText = "UPDATE device_groups SET policy_json=$json,policy_version=$version WHERE id=$id";
            update.Parameters.AddWithValue("$json", JsonSerializer.Serialize(write.Policy, JsonOptions)); update.Parameters.AddWithValue("$version", current + 1); update.Parameters.AddWithValue("$id", groupId);
            await update.ExecuteNonQueryAsync(cancellationToken);
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, actorUsername, "policy.group_changed", groupId, cancellationToken);
            await transaction.CommitAsync(cancellationToken); return true;
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<VersionedPolicy?> ReadDevicePolicyAsync(string deviceId, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = "SELECT p.policy_json,p.version FROM devices d LEFT JOIN device_policies p ON p.device_id=d.id WHERE d.id=$id";
        command.Parameters.AddWithValue("$id", deviceId); await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return reader.IsDBNull(0) ? new(new PolicyDocument(), 0) : new(JsonSerializer.Deserialize<PolicyDocument>(reader.GetString(0), JsonOptions) ?? new(), reader.GetInt64(1));
    }

    public async Task<bool> WriteDevicePolicyAsync(string deviceId, PolicyWrite write, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        ValidatePolicy(write.Policy); await using var connection = await OpenAsync(cancellationToken); await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            var current = await ReadVersionAsync(connection, (SqliteTransaction)transaction, "SELECT COALESCE(p.version,0) FROM devices d LEFT JOIN device_policies p ON p.device_id=d.id WHERE d.id=$id", cancellationToken, ("$id", deviceId));
            if (current < 0 || current != write.ExpectedVersion) { await transaction.RollbackAsync(cancellationToken); return false; }
            await using var update = connection.CreateCommand(); update.Transaction = (SqliteTransaction)transaction;
            update.CommandText = "INSERT INTO device_policies(device_id,policy_json,version) VALUES($id,$json,$version) ON CONFLICT(device_id) DO UPDATE SET policy_json=$json,version=$version";
            update.Parameters.AddWithValue("$id", deviceId); update.Parameters.AddWithValue("$json", JsonSerializer.Serialize(write.Policy, JsonOptions)); update.Parameters.AddWithValue("$version", current + 1);
            await update.ExecuteNonQueryAsync(cancellationToken);
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, actorUsername, "policy.device_changed", deviceId, cancellationToken);
            await transaction.CommitAsync(cancellationToken); return true;
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<PolicyLayer?> GetEffectivePolicyAsync(string deviceId, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT d.device_group,COALESCE(g.policy_version,0),COALESCE(dp.version,0),gp.policy_json,dp.policy_json,sp.policy_json,COALESCE(sp.version,0)
            FROM devices d LEFT JOIN device_groups g ON g.name=d.device_group COLLATE NOCASE
            LEFT JOIN device_policies dp ON dp.device_id=d.id LEFT JOIN server_policies sp ON sp.id=1
            LEFT JOIN device_groups gp ON gp.id=g.id WHERE d.id=$id
            """;
        command.Parameters.AddWithValue("$id", deviceId); await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        PolicyDocument Parse(int ordinal) => reader.IsDBNull(ordinal) ? new() : JsonSerializer.Deserialize<PolicyDocument>(reader.GetString(ordinal), JsonOptions) ?? new();
        return PolicyRules.Resolve(reader.IsDBNull(0) ? null : reader.GetString(0), reader.GetInt64(6), Parse(5), reader.GetInt64(1), Parse(3), reader.GetInt64(2), Parse(4));
    }

    private static async Task<long> ReadVersionAsync(SqliteConnection connection, SqliteTransaction transaction, string sql,
        CancellationToken cancellationToken, params (string Key, object Value)[] parameters)
    {
        await using var command = connection.CreateCommand(); command.Transaction = transaction; command.CommandText = sql;
        foreach (var (key, value) in parameters) command.Parameters.AddWithValue(key, value);
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result is null or DBNull ? -1 : Convert.ToInt64(result, System.Globalization.CultureInfo.InvariantCulture);
    }

    private static void ValidatePolicy(PolicyDocument policy)
    {
        var error = PolicyRules.Validate(policy);
        if (error is not null) throw new ArgumentException(error, nameof(policy));
    }

    public async Task<Invitation> CreateInvitationAsync(InvitationRequest request, string codeHash, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var result = new Invitation(Guid.NewGuid().ToString("N"), request.Group, request.ExpiresAt.ToUniversalTime(), request.MaximumRegistrations, 0, false, request.RequiresApproval);
        await using var connection = await OpenAsync(cancellationToken); await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await using var command = connection.CreateCommand(); command.Transaction = (SqliteTransaction)transaction;
            command.CommandText = "INSERT INTO invitations(id,code_hash,device_group,expires_at,max_registrations,requires_approval) VALUES($id,$hash,$group,$expires,$max,$approval)";
            command.Parameters.AddWithValue("$id", result.Id); command.Parameters.AddWithValue("$hash", codeHash);
            command.Parameters.AddWithValue("$group", result.Group); command.Parameters.AddWithValue("$expires", result.ExpiresAt.ToString("O"));
            command.Parameters.AddWithValue("$max", result.MaximumRegistrations); command.Parameters.AddWithValue("$approval", result.RequiresApproval);
            await command.ExecuteNonQueryAsync(cancellationToken);
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
            invitationCommand.CommandText = "SELECT id,device_group,expires_at,max_registrations,registration_count,requires_approval FROM invitations WHERE code_hash=$hash AND revoked=0";
            invitationCommand.Parameters.AddWithValue("$hash", codeHash);
            await using var reader = await invitationCommand.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)) { await transaction.RollbackAsync(cancellationToken); return null; }
            var invitationId = reader.GetString(0); var group = reader.GetString(1); var expires = DateTimeOffset.Parse(reader.GetString(2));
            var maximum = reader.GetInt32(3); var count = reader.GetInt32(4); var approved = reader.GetInt32(5) == 0; await reader.CloseAsync();
            if (expires <= now || count >= maximum) { await transaction.RollbackAsync(cancellationToken); return null; }
            var device = new EnrollmentResult(Guid.NewGuid().ToString("N"), request.DeviceToken, group, now);
            await using var updateInvitation = connection.CreateCommand(); updateInvitation.Transaction = (SqliteTransaction)transaction;
            updateInvitation.CommandText = "UPDATE invitations SET registration_count=registration_count+1 WHERE id=$id AND revoked=0 AND registration_count < max_registrations AND expires_at > $now";
            updateInvitation.Parameters.AddWithValue("$id", invitationId); updateInvitation.Parameters.AddWithValue("$now", now.ToString("O"));
            if (await updateInvitation.ExecuteNonQueryAsync(cancellationToken) != 1) { await transaction.RollbackAsync(cancellationToken); return null; }
            await using var insertDevice = connection.CreateCommand(); insertDevice.Transaction = (SqliteTransaction)transaction;
            insertDevice.CommandText = "INSERT INTO devices(id,token_hash,name,device_group,client_version,registered_at,last_seen_at,approved) VALUES($id,$token,$name,$group,$version,$now,$now,$approved)";
            insertDevice.Parameters.AddWithValue("$id", device.DeviceId); insertDevice.Parameters.AddWithValue("$token", deviceTokenHash);
            insertDevice.Parameters.AddWithValue("$name", request.DeviceName); insertDevice.Parameters.AddWithValue("$group", group);
            insertDevice.Parameters.AddWithValue("$version", request.ClientVersion); insertDevice.Parameters.AddWithValue("$now", now.ToString("O"));
            insertDevice.Parameters.AddWithValue("$approved", approved);
            await insertDevice.ExecuteNonQueryAsync(cancellationToken); await transaction.CommitAsync(cancellationToken); return device;
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<Device?> AuthenticateDeviceAsync(string tokenHash, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id,name,device_group,client_version,registered_at,last_seen_at,revoked,last_error,approved FROM devices WHERE token_hash=$hash AND revoked=0 AND approved=1";
        command.Parameters.AddWithValue("$hash", tokenHash);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return ReadDevice(reader);
    }

    public async Task<IReadOnlyList<Device>> ListDevicesAsync(CancellationToken cancellationToken = default)
    {
        var items = new List<Device>(); await using var connection = await OpenAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id,name,device_group,client_version,registered_at,last_seen_at,revoked,last_error,approved FROM devices ORDER BY name COLLATE NOCASE";
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

    public async Task<bool> SetDeviceApprovalAsync(string id, bool approved, string actorUsername, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await using var command = connection.CreateCommand(); command.Transaction = (SqliteTransaction)transaction;
            command.CommandText = approved
                ? "UPDATE devices SET approved=1 WHERE id=$id AND revoked=0 AND approved=0"
                : "UPDATE devices SET revoked=1,token_hash=$invalidated WHERE id=$id AND revoked=0 AND approved=0";
            command.Parameters.AddWithValue("$id", id);
            if (!approved) command.Parameters.AddWithValue("$invalidated", Guid.NewGuid().ToString("N"));
            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1) { await transaction.RollbackAsync(cancellationToken); return false; }
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, actorUsername, approved ? "device.approved" : "device.rejected", id, cancellationToken);
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

    public async Task<EventBatchResult> IngestEventsAsync(string deviceId, IReadOnlyList<SecurityEventInput> events,
        DateTimeOffset receivedAt, CancellationToken cancellationToken = default)
    {
        if (events.Count is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(events), "Batch musi zawierać 1–100 zdarzeń.");
        foreach (var item in events)
        {
            var validation = SecurityEventRules.Validate(item, receivedAt);
            if (validation is not null) throw new ArgumentException(validation, nameof(events));
        }
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await using (var retention = connection.CreateCommand())
            {
                retention.Transaction = (SqliteTransaction)transaction;
                retention.CommandText = "DELETE FROM security_events WHERE occurred_at < $cutoff";
                retention.Parameters.AddWithValue("$cutoff", receivedAt.AddDays(-_eventRetentionDays).ToUniversalTime().ToString("O"));
                await retention.ExecuteNonQueryAsync(cancellationToken);
            }
            var accepted = 0;
            foreach (var item in events)
            {
                await using var command = connection.CreateCommand(); command.Transaction = (SqliteTransaction)transaction;
                command.CommandText = """
                    INSERT INTO security_events(event_id,device_id,occurred_at,received_at,category,risk_level,rule_code)
                    SELECT $event,$device,$occurred,$received,$category,$risk,$rule
                    WHERE EXISTS(SELECT 1 FROM devices WHERE id=$device AND revoked=0)
                    ON CONFLICT(device_id,event_id) DO NOTHING
                    """;
                command.Parameters.AddWithValue("$event", Guid.Parse(item.EventId).ToString("D"));
                command.Parameters.AddWithValue("$device", deviceId); command.Parameters.AddWithValue("$occurred", item.OccurredAt.ToUniversalTime().ToString("O"));
                command.Parameters.AddWithValue("$received", receivedAt.ToUniversalTime().ToString("O")); command.Parameters.AddWithValue("$category", item.Category);
                command.Parameters.AddWithValue("$risk", item.RiskLevel); command.Parameters.AddWithValue("$rule", item.RuleCode);
                accepted += await command.ExecuteNonQueryAsync(cancellationToken);
            }
            await transaction.CommitAsync(cancellationToken);
            return new(accepted, events.Count - accepted);
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<IReadOnlyList<SecurityEvent>> ListEventsAsync(int limit, string? deviceId = null, CancellationToken cancellationToken = default)
    {
        limit = Math.Clamp(limit, 1, 500);
        var events = new List<SecurityEvent>(); await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT event_id,device_id,occurred_at,received_at,category,risk_level,rule_code,status
            FROM security_events WHERE ($device IS NULL OR device_id=$device) ORDER BY occurred_at DESC LIMIT $limit
            """;
        command.Parameters.AddWithValue("$device", (object?)deviceId ?? DBNull.Value); command.Parameters.AddWithValue("$limit", limit);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            events.Add(new(reader.GetString(0), reader.GetString(1), DateTimeOffset.Parse(reader.GetString(2)), DateTimeOffset.Parse(reader.GetString(3)),
                reader.GetString(4), reader.GetInt32(5), reader.GetString(6), reader.GetString(7)));
        return events;
    }

    public async Task<bool> SetEventStatusAsync(string eventId, string deviceId, string status, string actorUsername,
        DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        if (status is not ("open" or "resolved" or "false_positive")) throw new ArgumentException("Nieprawidłowy status zdarzenia.", nameof(status));
        await using var connection = await OpenAsync(cancellationToken); await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            await using var update = connection.CreateCommand(); update.Transaction = (SqliteTransaction)transaction;
            update.CommandText = "UPDATE security_events SET status=$status WHERE event_id=$event AND device_id=$device AND status<>$status";
            update.Parameters.AddWithValue("$status", status); update.Parameters.AddWithValue("$event", eventId);
            update.Parameters.AddWithValue("$device", deviceId);
            if (await update.ExecuteNonQueryAsync(cancellationToken) != 1) { await transaction.RollbackAsync(cancellationToken); return false; }
            await AddAuditAsync(connection, (SqliteTransaction)transaction, now, actorUsername, "event.status_changed", eventId, cancellationToken);
            await transaction.CommitAsync(cancellationToken); return true;
        }
        catch { await transaction.RollbackAsync(cancellationToken); throw; }
    }

    public async Task<int> PurgeExpiredEventsAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM security_events WHERE occurred_at < $cutoff";
        command.Parameters.AddWithValue("$cutoff", now.AddDays(-_eventRetentionDays).ToUniversalTime().ToString("O"));
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static Device ReadDevice(SqliteDataReader reader) => new(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
        DateTimeOffset.Parse(reader.GetString(4)), reader.IsDBNull(5) ? null : DateTimeOffset.Parse(reader.GetString(5)), reader.GetInt32(6) != 0,
        reader.IsDBNull(7) ? null : reader.GetString(7), reader.GetInt32(8) != 0);
}
