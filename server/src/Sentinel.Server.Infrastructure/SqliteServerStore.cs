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
        if (version > 1) throw new InvalidDataException("Baza serwera została utworzona przez nowszą wersję.");
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
            PRAGMA user_version=1;
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

    public async Task<Invitation> CreateInvitationAsync(InvitationRequest request, string codeHash, CancellationToken cancellationToken = default)
    {
        var result = new Invitation(Guid.NewGuid().ToString("N"), request.Group, request.ExpiresAt.ToUniversalTime(), request.MaximumRegistrations, 0, false);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO invitations(id,code_hash,device_group,expires_at,max_registrations) VALUES($id,$hash,$group,$expires,$max)";
        command.Parameters.AddWithValue("$id", result.Id); command.Parameters.AddWithValue("$hash", codeHash);
        command.Parameters.AddWithValue("$group", result.Group); command.Parameters.AddWithValue("$expires", result.ExpiresAt.ToString("O"));
        command.Parameters.AddWithValue("$max", result.MaximumRegistrations);
        await command.ExecuteNonQueryAsync(cancellationToken);
        return result;
    }

    public async Task<bool> RevokeInvitationAsync(string id, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand(); command.CommandText = "UPDATE invitations SET revoked=1 WHERE id=$id AND revoked=0";
        command.Parameters.AddWithValue("$id", id); return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
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

    public async Task<bool> RevokeDeviceAsync(string id, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE devices SET revoked=1,token_hash=$invalidated WHERE id=$id AND revoked=0";
        command.Parameters.AddWithValue("$id", id); command.Parameters.AddWithValue("$invalidated", Guid.NewGuid().ToString("N"));
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
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
