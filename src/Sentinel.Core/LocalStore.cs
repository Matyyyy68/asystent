using Microsoft.Data.Sqlite;
using System.Globalization;
using System.Text.Json;
using Sentinel.Core.Configuration;
using Sentinel.Core.Enterprise;
namespace Sentinel.Core;
public sealed class LocalStore : IEventRepository, ISettingsRepository
{
    private readonly string connectionString;
    public string DatabasePath { get; }
    public LocalStore(string directory)
    {
        var full = Path.GetFullPath(directory);
        if (full.StartsWith(@"\\", StringComparison.Ordinal)) throw new IOException("Wymagany jest lokalny katalog danych.");
        Directory.CreateDirectory(full);
        DatabasePath = Path.Combine(full, "sentinel.db");
        connectionString = new SqliteConnectionStringBuilder { DataSource = DatabasePath, Pooling = false }.ToString();
    }
    private async Task<SqliteConnection> Open(CancellationToken ct)
    {
        var c = new SqliteConnection(connectionString);
        try { await c.OpenAsync(ct); return c; } catch { await c.DisposeAsync(); throw; }
    }
    private static async Task Execute(SqliteConnection c, string sql, CancellationToken ct, params (string, object)[] values)
    {
        using var cmd = c.CreateCommand(); cmd.CommandText = sql;
        foreach (var (key, value) in values) cmd.Parameters.AddWithValue(key, value);
        await cmd.ExecuteNonQueryAsync(ct);
    }
    public Task InitializeAsync(CancellationToken ct = default) => InitializeAsync(null, ct);
    public async Task InitializeAsync(InstalledProductProfile? initialProfile, CancellationToken ct = default)
    {
        initialProfile?.Validate();
        await using var c = await Open(ct);
        using var version = c.CreateCommand(); version.CommandText = "PRAGMA user_version";
        var v = Convert.ToInt32(await version.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
        if (v > 6) throw new InvalidDataException("Nowsza wersja bazy wymaga nowszej aplikacji.");
        await Execute(c, """
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1), json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, risk INTEGER NOT NULL,
              category TEXT NOT NULL, application TEXT NOT NULL, explanation TEXT NOT NULL, recommendation TEXT NOT NULL, status INTEGER NOT NULL);
            CREATE VIRTUAL TABLE IF NOT EXISTS knowledge USING fts5(source UNINDEXED, content);
            CREATE TABLE IF NOT EXISTS installation_profile(id INTEGER PRIMARY KEY CHECK(id=1), json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS enterprise_event_queue(event_id TEXT PRIMARY KEY, occurred_at TEXT NOT NULL,
              category TEXT NOT NULL, risk_level INTEGER NOT NULL, rule_code TEXT NOT NULL, sent INTEGER NOT NULL DEFAULT 0);
            INSERT OR IGNORE INTO installation_profile(id,json) VALUES(1,$profile);
            COMMIT;
            """, ct, ("$profile", JsonSerializer.Serialize(initialProfile ?? new InstalledProductProfile())));
        if (v < 4)
        {
            await Execute(c, """
                BEGIN IMMEDIATE;
                ALTER TABLE events ADD COLUMN event_id TEXT;
                ALTER TABLE events ADD COLUMN source TEXT;
                ALTER TABLE events ADD COLUMN rule_version TEXT;
                ALTER TABLE events ADD COLUMN confidence INTEGER CHECK(confidence IS NULL OR confidence BETWEEN 0 AND 100);
                CREATE UNIQUE INDEX IF NOT EXISTS ux_events_event_id ON events(event_id) WHERE event_id IS NOT NULL;
                PRAGMA user_version=4;
                COMMIT;
                """, ct);
        }
        if (v < 5)
        {
            await Execute(c, "BEGIN IMMEDIATE; ALTER TABLE events ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1 CHECK(schema_version=1); PRAGMA user_version=5; COMMIT;", ct);
        }
        if (v < 6)
        {
            await Execute(c, "BEGIN IMMEDIATE; ALTER TABLE events ADD COLUMN process_id INTEGER CHECK(process_id IS NULL OR process_id >= 0); ALTER TABLE events ADD COLUMN process_name TEXT CHECK(process_name IS NULL OR length(process_name) <= 260); PRAGMA user_version=6; COMMIT;", ct);
        }
        // Prove the database can be closed and reopened before declaring readiness.
        await c.CloseAsync(); await c.OpenAsync(ct);
    }
    public async Task<InstalledProductProfile> GetInstallationProfileAsync(CancellationToken ct = default)
    {
        await using var c = await Open(ct); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT json FROM installation_profile WHERE id=1";
        var json = await cmd.ExecuteScalarAsync(ct) as string ?? throw new InvalidDataException("Brak profilu instalacji.");
        var profile = JsonSerializer.Deserialize<InstalledProductProfile>(json) ?? throw new InvalidDataException("Nieprawidłowy profil instalacji.");
        try { return profile.Validate(); } catch (ArgumentException ex) { throw new InvalidDataException("Nieprawidłowy profil instalacji.", ex); }
    }
    public async Task UpdateEnterpriseServerAsync(string serverAddress, CancellationToken ct = default)
    {
        var server = new InstalledProductProfile(ProductVariant.EnterpriseClient, serverAddress).Validate();
        await using var c = await Open(ct); using var transaction = c.BeginTransaction();
        using var read = c.CreateCommand(); read.Transaction = transaction; read.CommandText = "SELECT json FROM installation_profile WHERE id=1";
        var currentJson = await read.ExecuteScalarAsync(ct) as string ?? throw new InvalidDataException("Brak profilu instalacji.");
        var current = JsonSerializer.Deserialize<InstalledProductProfile>(currentJson) ?? throw new InvalidDataException("Nieprawidłowy profil instalacji.");
        if (current.Variant != ProductVariant.EnterpriseClient) throw new InvalidOperationException("Adres Enterprise jest dostępny tylko dla wariantu Enterprise Client.");
        using var write = c.CreateCommand(); write.Transaction = transaction; write.CommandText = "UPDATE installation_profile SET json=$json WHERE id=1";
        write.Parameters.AddWithValue("$json", JsonSerializer.Serialize(current with { EnterpriseServerUri = server.EnterpriseServerUri }));
        await write.ExecuteNonQueryAsync(ct); await transaction.CommitAsync(ct);
    }
    public async Task SetEnterpriseProfileAsync(string serverAddress, bool shareSecurityMetadata, CancellationToken ct = default)
    {
        var server = new InstalledProductProfile(ProductVariant.EnterpriseClient, serverAddress, ShareSecurityMetadata: shareSecurityMetadata).Validate();
        await using var c = await Open(ct); using var transaction = c.BeginTransaction();
        using var write = c.CreateCommand(); write.Transaction = transaction; write.CommandText = "UPDATE installation_profile SET json=$json WHERE id=1";
        write.Parameters.AddWithValue("$json", JsonSerializer.Serialize(server));
        if (await write.ExecuteNonQueryAsync(ct) != 1) throw new InvalidDataException("Brak profilu instalacji.");
        await transaction.CommitAsync(ct);
    }
    public async Task<AppSettings> LoadSettingsAsync(CancellationToken cancellationToken = default)
    {
        await using var c = await Open(cancellationToken); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT json FROM settings WHERE id=1";
        var json = await cmd.ExecuteScalarAsync(cancellationToken) as string;
        var result = json is null ? new AppSettings() : JsonSerializer.Deserialize<AppSettings>(json) ?? throw new InvalidDataException("Nieprawidłowe ustawienia.");
        Validate(result); return result;
    }
    private static void Validate(AppSettings s)
    {
        if (s.RetentionDays is < 1 or > 365) throw new ArgumentOutOfRangeException(nameof(s), "Retencja: 1–365 dni.");
        if (s.MinimumIntervalSeconds is < 3 or > 300) throw new ArgumentOutOfRangeException(nameof(s), "Odstęp: 3–300 sekund.");
        if (s.DnsPollIntervalSeconds is < 10 or > 300) throw new ArgumentOutOfRangeException(nameof(s), "Odstęp DNS: 10–300 sekund.");
        if (s.ExcludedApplications is null || s.ExcludedWindowTitles is null || s.ExcludedApplications.Length > 2000 || s.ExcludedWindowTitles.Length > 2000)
            throw new ArgumentException("Nieprawidłowa lista wykluczeń.");
        if (s.Theme is not ("System" or "Light" or "Dark")) throw new ArgumentException("Nieprawidłowy motyw.");
        if (s.LocalAIEndpoint is null || s.LocalAIEndpoint.Length > 2000) throw new ArgumentException("Nieprawidłowy adres lokalnego modelu.");
        if (s.UseLocalAI) _ = Sentinel.Core.Analysis.OllamaLocalProvider.ValidateEndpoint(s.LocalAIEndpoint);
        if (s.LocalAIModel is null || s.LocalAIModel.Length > 160 || s.LocalAIModel.Any(char.IsControl)) throw new ArgumentException("Nieprawidłowa nazwa lokalnego modelu.");
        if (s.UseLocalAI && string.IsNullOrWhiteSpace(s.LocalAIModel)) throw new ArgumentException("Wybierz zainstalowany model przed włączeniem lokalnej analizy AI.");
        if (s.LocalAITimeoutSeconds is < 3 or > 120) throw new ArgumentOutOfRangeException(nameof(s), "Limit czasu modelu: 3–120 sekund.");
    }
    public async Task SaveSettingsAsync(AppSettings settings, CancellationToken cancellationToken = default)
    {
        Validate(settings); await using var c = await Open(cancellationToken);
        await Execute(c, "INSERT INTO settings VALUES(1,$j) ON CONFLICT(id) DO UPDATE SET json=$j", cancellationToken, ("$j", JsonSerializer.Serialize(settings)));
    }
    public Task<long> AddAsync(SecurityEvent item, CancellationToken cancellationToken = default) => AddCoreAsync(item, enqueueEnterprise: true, cancellationToken);
    /// <summary>Persists a local-only event without adding it to the Enterprise metadata queue.</summary>
    public Task<long> AddLocalOnlyAsync(SecurityEvent item, CancellationToken cancellationToken = default) => AddCoreAsync(item, enqueueEnterprise: false, cancellationToken);
    private async Task<long> AddCoreAsync(SecurityEvent item, bool enqueueEnterprise, CancellationToken cancellationToken)
    {
        if (!Enum.IsDefined(item.Risk) || !Enum.IsDefined(item.Status)) throw new ArgumentException("Nieprawidłowe zdarzenie.");
        foreach (var text in new[] {item.Category,item.Application,item.Explanation,item.Recommendation})
            if (string.IsNullOrWhiteSpace(text) || text.Length > 2000) throw new ArgumentException("Nieprawidłowe metadane zdarzenia.");
        var eventId = item.EventId ?? Guid.NewGuid();
        var source = string.IsNullOrWhiteSpace(item.Source) ? item.Application : item.Source;
        if (eventId == Guid.Empty || source.Length > 100 || item.RuleVersion?.Length > 80 || item.Confidence is < 0 or > 100 || item.SchemaVersion != 1 ||
            item.ProcessId < 0 || item.ProcessName?.Length > 260 || item.ProcessName?.Any(char.IsControl) == true)
            throw new ArgumentException("Nieprawidłowe pochodzenie zdarzenia.");
        await using var c = await Open(cancellationToken);
        await Execute(c, "INSERT INTO events(timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name) VALUES($t,$r,$c,$a,$e,$n,$s,$eventId,$source,$ruleVersion,$confidence,$schemaVersion,$processId,$processName)", cancellationToken,
            ("$t", item.Timestamp.ToUniversalTime().ToString("O")), ("$r", (int)item.Risk), ("$c", item.Category), ("$a", item.Application),
            ("$e", item.Explanation), ("$n", item.Recommendation), ("$s", (int)item.Status), ("$eventId", eventId.ToString("D")),
            ("$source", source), ("$ruleVersion", (object?)item.RuleVersion ?? DBNull.Value), ("$confidence", (object?)item.Confidence ?? DBNull.Value), ("$schemaVersion", item.SchemaVersion),
            ("$processId", (object?)item.ProcessId ?? DBNull.Value), ("$processName", (object?)item.ProcessName ?? DBNull.Value));
        using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT last_insert_rowid()"; var id = (long)(await cmd.ExecuteScalarAsync(cancellationToken))!;
        string? profileJson = null;
        if (enqueueEnterprise)
        {
            using var profileRead = c.CreateCommand(); profileRead.CommandText = "SELECT json FROM installation_profile WHERE id=1";
            profileJson = await profileRead.ExecuteScalarAsync(cancellationToken) as string;
        }
        var profile = profileJson is null ? null : JsonSerializer.Deserialize<InstalledProductProfile>(profileJson)?.Validate();
        if (enqueueEnterprise && profile is { Variant: ProductVariant.EnterpriseClient, ShareSecurityMetadata: true } && item.Risk >= RiskLevel.Moderate && Enum.IsDefined(item.Risk))
        {
            var category = item.Category.ToLowerInvariant() switch
            {
                var value when value.Contains("url", StringComparison.Ordinal) => "url",
                var value when value.Contains("document", StringComparison.Ordinal) => "document",
                var value when value.Contains("attachment", StringComparison.Ordinal) => "attachment",
                var value when value.Contains("sender", StringComparison.Ordinal) => "sender",
                var value when value.Contains("login", StringComparison.Ordinal) => "login",
                _ => "message"
            };
            var ruleCode = "local." + category;
            await EnqueueEnterpriseEventAsync(new PendingEnterpriseEvent(eventId, item.Timestamp, category, (int)item.Risk, ruleCode), cancellationToken);
        }
        return id;
    }
    public async Task<IReadOnlyList<PendingEnterpriseEvent>> ReadPendingEnterpriseEventsAsync(int limit = 100, CancellationToken ct = default)
    {
        if (limit is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(limit));
        await using var c = await Open(ct); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT event_id,occurred_at,category,risk_level,rule_code FROM enterprise_event_queue WHERE sent=0 ORDER BY occurred_at LIMIT $limit";
        cmd.Parameters.AddWithValue("$limit", limit); using var reader = await cmd.ExecuteReaderAsync(ct); var rows = new List<PendingEnterpriseEvent>();
        while (await reader.ReadAsync(ct)) rows.Add(new(Guid.Parse(reader.GetString(0)), DateTimeOffset.Parse(reader.GetString(1), CultureInfo.InvariantCulture), reader.GetString(2), reader.GetInt32(3), reader.GetString(4)));
        return rows;
    }
    public async Task MarkEnterpriseEventsSentAsync(IEnumerable<Guid> eventIds, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(eventIds); var ids = eventIds.Take(101).ToArray(); if (ids.Length > 100) throw new ArgumentOutOfRangeException(nameof(eventIds));
        await using var c = await Open(ct); using var transaction = c.BeginTransaction();
        foreach (var id in ids)
        {
            using var command = c.CreateCommand(); command.Transaction = transaction; command.CommandText = "UPDATE enterprise_event_queue SET sent=1 WHERE event_id=$id";
            command.Parameters.AddWithValue("$id", id.ToString("D")); await command.ExecuteNonQueryAsync(ct);
        }
        await transaction.CommitAsync(ct);
    }
    public async Task<bool> EnqueueEnterpriseEventAsync(PendingEnterpriseEvent item, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (item.EventId == Guid.Empty || item.Category is not ("url" or "message" or "document" or "attachment" or "sender" or "login") ||
            item.RiskLevel is < 2 or > 4 || item.RuleCode.Length is < 1 or > 80 ||
            item.RuleCode.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '_' or '-')) ||
            item.OccurredAt > DateTimeOffset.UtcNow.AddMinutes(5) || item.OccurredAt < DateTimeOffset.UtcNow.AddDays(-30))
            throw new ArgumentException("Nieprawidłowe metadane zdarzenia Enterprise.", nameof(item));
        await using var c = await Open(ct); using var transaction = c.BeginTransaction();
        using var profileRead = c.CreateCommand(); profileRead.Transaction = transaction;
        profileRead.CommandText = "SELECT json FROM installation_profile WHERE id=1";
        var raw = await profileRead.ExecuteScalarAsync(ct) as string ?? throw new InvalidDataException("Brak profilu instalacji.");
        var profile = JsonSerializer.Deserialize<InstalledProductProfile>(raw)?.Validate() ?? throw new InvalidDataException("Nieprawidłowy profil instalacji.");
        if (profile.Variant != ProductVariant.EnterpriseClient || !profile.ShareSecurityMetadata)
            throw new InvalidOperationException("Synchronizacja metadanych nie została jawnie włączona.");
        using (var existing = c.CreateCommand())
        {
            existing.Transaction = transaction; existing.CommandText = "SELECT 1 FROM enterprise_event_queue WHERE event_id=$id";
            existing.Parameters.AddWithValue("$id", item.EventId.ToString("D"));
            if (await existing.ExecuteScalarAsync(ct) is not null) { await transaction.CommitAsync(ct); return true; }
        }
        using (var prune = c.CreateCommand())
        {
            prune.Transaction = transaction;
            prune.CommandText = "DELETE FROM enterprise_event_queue WHERE event_id IN (SELECT event_id FROM enterprise_event_queue WHERE sent=1 ORDER BY occurred_at LIMIT 1000)";
            await prune.ExecuteNonQueryAsync(ct);
        }
        using (var count = c.CreateCommand())
        {
            count.Transaction = transaction; count.CommandText = "SELECT COUNT(*) FROM enterprise_event_queue";
            if (Convert.ToInt32(await count.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture) >= 10000)
            { await transaction.CommitAsync(ct); return false; }
        }
        using var command = c.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "INSERT OR IGNORE INTO enterprise_event_queue(event_id,occurred_at,category,risk_level,rule_code) VALUES($id,$time,$category,$risk,$rule)";
        command.Parameters.AddWithValue("$id", item.EventId.ToString("D")); command.Parameters.AddWithValue("$time", item.OccurredAt.ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue("$category", item.Category); command.Parameters.AddWithValue("$risk", item.RiskLevel); command.Parameters.AddWithValue("$rule", item.RuleCode);
        var inserted = await command.ExecuteNonQueryAsync(ct) == 1; await transaction.CommitAsync(ct); return inserted;
    }
    public async Task<int> CountPendingEnterpriseEventsAsync(CancellationToken ct = default)
    {
        await using var c = await Open(ct); using var command = c.CreateCommand(); command.CommandText = "SELECT COUNT(*) FROM enterprise_event_queue WHERE sent=0";
        return Convert.ToInt32(await command.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
    }
    public async Task ClearEnterpriseEventQueueAsync(CancellationToken ct = default)
    {
        await using var c = await Open(ct); await Execute(c, "DELETE FROM enterprise_event_queue", ct);
    }
    public async Task<IReadOnlyList<SecurityEvent>> ReadAsync(CancellationToken cancellationToken = default)
    {
        await using var c = await Open(cancellationToken); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name FROM events ORDER BY id DESC LIMIT 500";
        using var r = await cmd.ExecuteReaderAsync(cancellationToken); var rows = new List<SecurityEvent>();
        while (await r.ReadAsync(cancellationToken)) rows.Add(new(r.GetInt64(0), DateTimeOffset.Parse(r.GetString(1), CultureInfo.InvariantCulture),
            (RiskLevel)r.GetInt32(2), r.GetString(3), r.GetString(4), r.GetString(5), r.GetString(6), (EventStatus)r.GetInt32(7),
            r.IsDBNull(8) ? null : Guid.Parse(r.GetString(8)), r.IsDBNull(9) ? null : r.GetString(9),
            r.IsDBNull(10) ? null : r.GetString(10), r.IsDBNull(11) ? null : r.GetInt32(11), r.GetInt32(12),
            r.IsDBNull(13) ? null : r.GetInt32(13), r.IsDBNull(14) ? null : r.GetString(14)));
        return rows;
    }
    public async Task<int> CountEventsAsync(CancellationToken cancellationToken = default)
    {
        await using var c = await Open(cancellationToken); using var command = c.CreateCommand(); command.CommandText = "SELECT COUNT(*) FROM events";
        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
    }
    public async Task SetStatusAsync(long id, EventStatus status, CancellationToken cancellationToken = default)
    {
        if (!Enum.IsDefined(status)) throw new ArgumentException("Nieprawidłowy status.");
        await using var c = await Open(cancellationToken);
        await Execute(c, "UPDATE events SET status=$s WHERE id=$id", cancellationToken, ("$s", (int)status), ("$id", id));
    }
    public async Task DeleteHistoryAsync(CancellationToken cancellationToken = default)
    { await using var c = await Open(cancellationToken); await Execute(c, "DELETE FROM events; DELETE FROM enterprise_event_queue; VACUUM;", cancellationToken); }
    public async Task ApplyRetentionAsync(int days, CancellationToken ct = default)
    {
        Validate(new AppSettings(days)); await using var c = await Open(ct);
        var cutoff = DateTimeOffset.UtcNow.AddDays(-days).ToString("O");
        await Execute(c, "DELETE FROM events WHERE timestamp < $cutoff; DELETE FROM enterprise_event_queue WHERE occurred_at < $cutoff", ct, ("$cutoff", cutoff));
    }
    public async Task ExportAsync(string path, CancellationToken ct = default)
    {
        // Export all retained rows, independent of the UI's 500-row limit.
        await using var c = await Open(ct); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name FROM events ORDER BY id";
        using var r = await cmd.ExecuteReaderAsync(ct); var rows = new List<SecurityEvent>();
        while (await r.ReadAsync(ct)) rows.Add(new(r.GetInt64(0),DateTimeOffset.Parse(r.GetString(1),CultureInfo.InvariantCulture),(RiskLevel)r.GetInt32(2),r.GetString(3),r.GetString(4),r.GetString(5),r.GetString(6),(EventStatus)r.GetInt32(7),
            r.IsDBNull(8) ? null : Guid.Parse(r.GetString(8)), r.IsDBNull(9) ? null : r.GetString(9),
            r.IsDBNull(10) ? null : r.GetString(10), r.IsDBNull(11) ? null : r.GetInt32(11), r.GetInt32(12),
            r.IsDBNull(13) ? null : r.GetInt32(13), r.IsDBNull(14) ? null : r.GetString(14)));
        await using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await JsonSerializer.SerializeAsync(file, rows, cancellationToken: ct);
    }
    public async Task BackupAsync(string destination, CancellationToken ct = default)
    {
        if (File.Exists(destination)) throw new IOException("Plik kopii już istnieje.");
        await using var source = await Open(ct);
        await using var target = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = destination, Pooling = false }.ToString());
        await target.OpenAsync(ct); source.BackupDatabase(target);
    }

    /// <summary>Restores the local event/settings queue from a verified v6 backup, preserving the installed product identity.</summary>
    public async Task<int> RestoreAsync(string backupPath, CancellationToken ct = default)
    {
        var sourcePath = Path.GetFullPath(backupPath);
        if (!File.Exists(sourcePath)) throw new FileNotFoundException("Nie znaleziono kopii bazy.", sourcePath);
        if (string.Equals(sourcePath, DatabasePath, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Nie można przywrócić bazy z jej aktywnego pliku.");

        await using (var source = new SqliteConnection(new SqliteConnectionStringBuilder
        { DataSource = sourcePath, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString()))
        {
            await source.OpenAsync(ct);
            using var integrity = source.CreateCommand(); integrity.CommandText = "PRAGMA integrity_check";
            if (!string.Equals(await integrity.ExecuteScalarAsync(ct) as string, "ok", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Kopia bazy nie przeszła kontroli integralności.");
            using var version = source.CreateCommand(); version.CommandText = "PRAGMA user_version";
            if (Convert.ToInt32(await version.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture) != 6)
                throw new InvalidDataException("Kopia pochodzi z nieobsługiwanej wersji bazy.");
            using var required = source.CreateCommand();
            required.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('events','settings','enterprise_event_queue','installation_profile')";
            if (Convert.ToInt32(await required.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture) != 4)
                throw new InvalidDataException("Kopia nie zawiera wymaganych tabel Sentinel AI.");
            using var savedSettings = source.CreateCommand(); savedSettings.CommandText = "SELECT json FROM settings WHERE id=1";
            if (await savedSettings.ExecuteScalarAsync(ct) is string json)
            {
                var settings = JsonSerializer.Deserialize<AppSettings>(json) ?? throw new InvalidDataException("Kopia zawiera nieprawidłowe ustawienia.");
                Validate(settings);
            }
        }

        await using var destination = await Open(ct);
        using (var attach = destination.CreateCommand())
        {
            attach.CommandText = "ATTACH DATABASE $source AS restore_source";
            attach.Parameters.AddWithValue("$source", sourcePath);
            await attach.ExecuteNonQueryAsync(ct);
        }
        try
        {
            using var transaction = destination.BeginTransaction();
            using var command = destination.CreateCommand(); command.Transaction = transaction;
            command.CommandText = """
                SELECT COUNT(*) FROM restore_source.events;
                """;
            var count = Convert.ToInt32(await command.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
            command.CommandText = """
                DELETE FROM events;
                INSERT INTO events(id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name)
                    SELECT id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name FROM restore_source.events;
                DELETE FROM settings;
                INSERT INTO settings(id,json) SELECT id,json FROM restore_source.settings;
                DELETE FROM enterprise_event_queue;
                INSERT INTO enterprise_event_queue(event_id,occurred_at,category,risk_level,rule_code,sent)
                    SELECT event_id,occurred_at,category,risk_level,rule_code,sent FROM restore_source.enterprise_event_queue;
                """;
            await command.ExecuteNonQueryAsync(ct);
            await transaction.CommitAsync(ct);
            return count;
        }
        finally
        {
            using var detach = destination.CreateCommand(); detach.CommandText = "DETACH DATABASE restore_source";
            await detach.ExecuteNonQueryAsync(ct);
        }
    }
}
