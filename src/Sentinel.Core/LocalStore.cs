Warning: truncated output (original token count: 42960)
Total output lines: 1916

using Microsoft.Data.Sqlite;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sentinel.Contracts;
using Sentinel.Core.Analysis;
using Sentinel.Core.Configuration;
using Sentinel.Core.Enterprise;
namespace Sentinel.Core;
public sealed record ProcessChangeQueueItem(long QueueId, Guid EventId, DateTimeOffset ObservedAt, string Action,
    int ProcessId, string ProcessName, Guid? CorrelationId);
public sealed record DownloadedFileQuarantineCandidate(Guid EventId, string Sha256);
public sealed record ProcessChangeQueueSnapshot(int Count, IReadOnlyList<ProcessChangeQueueItem> Items);

public sealed class LocalStore : IEventRepository, ISettingsRepository
{
    public const long DefaultMaximumDatabaseBytes = 512L * 1024 * 1024;
    private static readonly DomainNames CorrelationDomainNames = new();
    private readonly string connectionString;
    private readonly long maximumDatabaseBytes;
    public string DatabasePath { get; }
    /// <summary>Returns a stable, privacy-preserving hash for an exact DNS host.</summary>
    public static string? CreateHostSignalHash(string? host)
    {
        if (string.IsNullOrWhiteSpace(host) || IPAddress.TryParse(host.Trim('[', ']'), out _)) return null;
        try
        {
            var ascii = DomainNames.Ascii(host);
            if (ascii.Length is 0 or > 253 || ascii.Split('.').Any(label => label.Length is 0 or > 63)) return null;
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(ascii)));
        }
        catch (ArgumentException) { return null; }
    }
    /// <summary>Returns a local-only key for matching the same URL rule signals across manual and browser analysis.</summary>
    public static string? CreateUrlEvidenceSignalHash(string? host, IEnumerable<string>? evidenceCodes)
    {
        var urlEvidence = evidenceCodes?.Where(code => code.StartsWith("url.", StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray() ?? [];
        if (urlEvidence.Length == 0 || urlEvidence.Any(code => code.Length > 64 || code.Any(char.IsControl))) return null;
        var hostHash = CreateHostSignalHash(host);
        if (hostHash is null) return null;
        var material = "url-evidence-v1\n" + hostHash + "\n" + string.Join('\n', urlEvidence);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
    }
    public Task<DatabaseStorageMetrics> GetStorageMetricsAsync(CancellationToken cancellationToken = default) =>
        DatabaseStorageMetricsReader.ReadAsync(DatabasePath, "SELECT COUNT(*) FROM events", cancellationToken);
    public LocalStore(string directory, long maximumDatabaseBytes = DefaultMaximumDatabaseBytes)
    {
        if (maximumDatabaseBytes < 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(maximumDatabaseBytes), "Limit historii musi wynosić co najmniej 1 MiB.");
        this.maximumDatabaseBytes = maximumDatabaseBytes;
        var full = Path.GetFullPath(directory);
        if (full.StartsWith(@"\\", StringComparison.Ordinal)) throw new IOException("Wymagany jest lokalny katalog danych.");
        Directory.CreateDirectory(full);
        DatabasePath = Path.Combine(full, "sentinel.db");
        connectionString = new SqliteConnectionStringBuilder { DataSource = DatabasePath, Pooling = false }.ToString();
    }
    private async Task<SqliteConnection> Open(CancellationToken ct)
    {
        var c = new SqliteConnection(connectionString);
        try
        {
            await c.OpenAsync(ct);
            using (var foreignKeys = c.CreateCommand()) { foreignKeys.CommandText = "PRAGMA foreign_keys=ON"; await foreignKeys.ExecuteNonQueryAsync(ct); }
            using var pageSize = c.CreateCommand(); pageSize.CommandText = "PRAGMA page_size";
            var pageBytes = Convert.ToInt64(await pageSize.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
            var maximumPages = Math.Max(1, maximumDatabaseBytes / pageBytes);
            using var limit = c.CreateCommand(); limit.CommandText = $"PRAGMA max_page_count={maximumPages.ToString(CultureInfo.InvariantCulture)}";
            await limit.ExecuteScalarAsync(ct);
            return c;
        }
        catch { await c.DisposeAsync(); throw; }
    }
    private static async Task Execute(SqliteConnection c, string sql, CancellationToken ct, params (string, object)[] values)
    {
        using var cmd = c.CreateCommand(); cmd.CommandText = sql;
        foreach (var (key, value) in values) cmd.Parameters.AddWithValue(key, value);
        await cmd.ExecuteNonQueryAsync(ct);
    }
    private static async Task EnsureColumnAsync(SqliteConnection connection, string table, string column, string definition, CancellationToken ct)
    {
        if (!await HasColumnAsync(connection, table, column, ct))
            await Execute(connection, $"ALTER TABLE {table} ADD COLUMN {column} {definition}", ct);
    }
    private static async Task<bool> HasColumnAsync(SqliteConnection connection, string table, string column, CancellationToken ct)
    {
        using (var inspect = connection.CreateCommand())
        {
            inspect.CommandText = $"PRAGMA table_info({table})";
            await using var reader = await inspect.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
                if (string.Equals(reader.GetString(1), column, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }
    public Task InitializeAsync(CancellationToken ct = default) => InitializeAsync(null, ct);
    public async Task InitializeAsync(InstalledProductProfile? initialProfile, CancellationToken ct = default)
    {
        initialProfile?.Validate();
        await using var c = await Open(ct);
        using var version = c.CreateCommand(); version.CommandText = "PRAGMA user_version";
        var v = Convert.ToInt32(await version.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
        if (v > 40) throw new InvalidDataException("Nowsza wersja bazy wymaga nowszej aplikacji.");
        await Execute(c, """
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1), json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, risk INTEGER NOT NULL,
              category TEXT NOT NULL, application TEXT NOT NULL, explanation TEXT NOT NULL, recommendation TEXT NOT NULL, status INTEGER NOT NULL);
            CREATE VIRTUAL TABLE IF NOT EXISTS knowledge USING fts5(source UNINDEXED, content);
            CREATE TABLE IF NOT EXISTS installation_profile(id INTEGER PRIMARY KEY CHECK(id=1), json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS enterprise_event_queue(event_id TEXT PRIMARY KEY, occurred_at TEXT NOT NULL,
              category TEXT NOT NULL, risk_level INTEGER NOT NULL, rule_code TEXT NOT NULL, sent INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS enterprise_event_deferred(event_id TEXT PRIMARY KEY, occurred_at TEXT NOT NULL,
              category TEXT NOT NULL, risk_level INTEGER NOT NULL, rule_code TEXT NOT NULL, source TEXT NOT NULL,
              rule_version TEXT NULL, schema_version INTEGER NOT NULL DEFAULT 1 CHECK(schema_version=1));
            CREATE TABLE IF NOT EXISTS network_endpoint_snapshot(endpoint_key TEXT PRIMARY KEY CHECK(length(endpoint_key) BETWEEN 1 AND 2048));
            CREATE TABLE IF NOT EXISTS network_monitor_metadata(id INTEGER PRIMARY KEY CHECK(id=1), initialized INTEGER NOT NULL CHECK(initialized IN (0,1)));
            INSERT OR IGNORE INTO network_monitor_metadata(id,initialized) VALUES(1,0);
            CREATE TABLE IF NOT EXISTS process_snapshot(process_id INTEGER PRIMARY KEY CHECK(process_id BETWEEN 0 AND 2147483647), process_name TEXT NOT NULL CHECK(length(process_name) BETWEEN 1 AND 260));
            CREATE TABLE IF NOT EXISTS process_monitor_metadata(id INTEGER PRIMARY KEY CHECK(id=1), initialized INTEGER NOT NULL CHECK(initialized IN (0,1)));
            INSERT OR IGNORE INTO process_monitor_metadata(id,initialized) VALUES(1,0);
            CREATE TABLE IF NOT EXISTS downloaded_file_snapshot(path TEXT PRIMARY KEY COLLATE NOCASE, length INTEGER NOT NULL CHECK(length>=0), last_write_ticks INTEGER NOT NULL CHECK(last_write_ticks>=0));
            CREATE TABLE IF NOT EXISTS downloaded_file_monitor_metadata(id INTEGER PRIMARY KEY CHECK(id=1), initialized INTEGER NOT NULL CHECK(initialized IN (0,1)), hash_feed_imported_at TEXT NULL, hash_feed_recheck_at TEXT NULL, hash_feed_state_initialized INTEGER NOT NULL DEFAULT 0 CHECK(hash_feed_state_initialized IN (0,1)));
            INSERT OR IGNORE INTO downloaded_file_monitor_metadata(id,initialized) VALUES(1,0);
            CREATE TABLE IF NOT EXISTS domain_correlation(domain_key TEXT PRIMARY KEY CHECK(length(domain_key)=64), correlation_id TEXT NOT NULL CHECK(length(correlation_id)=36), last_seen_ticks INTEGER NOT NULL CHECK(last_seen_ticks>=0));
            CREATE INDEX IF NOT EXISTS ix_domain_correlation_last_seen ON domain_correlation(last_seen_ticks);
            CREATE TABLE IF NOT EXISTS dns_operational_monitor_metadata(id INTEGER PRIMARY KEY CHECK(id=1), last_record_id INTEGER NULL CHECK(last_record_id IS NULL OR last_record_id>=0));
            INSERT OR IGNORE INTO dns_operational_monitor_metadata(id,last_record_id) VALUES(1,NULL);
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
        if (v < 7)
            await Execute(c, "BEGIN IMMEDIATE; PRAGMA user_version=7; COMMIT;", ct);
        if (v < 8)
            await Execute(c, "BEGIN IMMEDIATE; PRAGMA user_version=8; COMMIT;", ct);
        if (v < 9)
            await Execute(c, "BEGIN IMMEDIATE; PRAGMA user_version=9; COMMIT;", ct);
        if (v < 10)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await EnsureColumnAsync(c, "enterprise_event_queue", "source", "TEXT NOT NULL DEFAULT 'unknown'", ct);
                await EnsureColumnAsync(c, "enterprise_event_queue", "rule_version", "TEXT NULL", ct);
                await EnsureColumnAsync(c, "enterprise_event_queue", "schema_version", "INTEGER NOT NULL DEFAULT 1 CHECK(schema_version=1)", ct);
                await Execute(c, "PRAGMA user_version=10; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 11)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await EnsureColumnAsync(c, "events", "correlation_id", "TEXT NULL CHECK(correlation_id IS NULL OR length(correlation_id)=36)", ct);
                await Execute(c, "PRAGMA user_version=11; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 12)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await EnsureColumnAsync(c, "events", "evidence_codes", "TEXT NOT NULL DEFAULT '[]' CHECK(length(evidence_codes)<=4096)", ct);
                await Execute(c, "PRAGMA user_version=12; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 13)
        {
            await Execute(c, "BEGIN IMMEDIATE; CREATE TABLE IF NOT EXISTS domain_correlation(domain_key TEXT PRIMARY KEY CHECK(length(domain_key)=64), correlation_id TEXT NOT NULL CHECK(length(correlation_id)=36), last_seen_ticks INTEGER NOT NULL CHECK(last_seen_ticks>=0)); CREATE INDEX IF NOT EXISTS ix_domain_correlation_last_seen ON domain_correlation(last_seen_ticks); PRAGMA user_version=13; COMMIT;", ct);
        }
        if (v < 14)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await EnsureColumnAsync(c, "process_monitor_metadata", "truncated", "INTEGER NOT NULL DEFAULT 0 CHECK(truncated IN (0,1))", ct);
                await Execute(c, "PRAGMA user_version=14; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 15)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await EnsureColumnAsync(c, "network_monitor_metadata", "tcp_truncated", "INTEGER NOT NULL DEFAULT 0 CHECK(tcp_truncated IN (0,1))", ct);
                await EnsureColumnAsync(c, "network_monitor_metadata", "udp_truncated", "INTEGER NOT NULL DEFAULT 0 CHECK(udp_truncated IN (0,1))", ct);
                await Execute(c, "PRAGMA user_version=15; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 16)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                // Legacy test/repair fixtures may retain the v16 trigger after rolling back columns.
                await Execute(c, "DROP TRIGGER IF EXISTS trg_events_add_observation", ct);
                await EnsureColumnAsync(c, "events", "signal_hash", "TEXT NULL CHECK(signal_hash IS NULL OR length(signal_hash)=64)", ct);
                await EnsureColumnAsync(c, "events", "event_id", "TEXT NULL", ct);
                await EnsureColumnAsync(c, "events", "source", "TEXT NULL", ct);
                await EnsureColumnAsync(c, "events", "evidence_codes", "TEXT NOT NULL DEFAULT '[]' CHECK(length(evidence_codes)<=4096)", ct);
                await Execute(c, """
                    CREATE TABLE IF NOT EXISTS event_observations(
                      event_id TEXT PRIMARY KEY CHECK(length(event_id)=36),
                      event_row_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
                      observed_at TEXT NOT NULL,
                      source TEXT NOT NULL CHECK(length(source) BETWEEN 1 AND 100),
                      evidence_codes TEXT NOT NULL CHECK(length(evidence_codes)<=4096));
                    CREATE INDEX IF NOT EXISTS ix_event_observations_row ON event_observations(event_row_id);
                    INSERT OR IGNORE INTO event_observations(event_id,event_row_id,observed_at,source,evidence_codes)
                      SELECT event_id,id,timestamp,COALESCE(NULLIF(source,''),'unknown'),COALESCE(evidence_codes,'[]')
                      FROM events WHERE event_id IS NOT NULL;
                    CREATE TRIGGER IF NOT EXISTS trg_events_add_observation AFTER INSERT ON events
                    WHEN NEW.event_id IS NOT NULL
                    BEGIN
                      INSERT OR IGNORE INTO event_observations(event_id,event_row_id,observed_at,source,evidence_codes)
                      VALUES(NEW.event_id,NEW.id,NEW.timestamp,COALESCE(NULLIF(NEW.source,''),'unknown'),'[]');
                    END;
                    PRAGMA user_version=16;
                    COMMIT;
                    """, ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 17)
            await Execute(c, "BEGIN IMMEDIATE; CREATE TABLE IF NOT EXISTS enterprise_event_deferred(event_id TEXT PRIMARY KEY, occurred_at TEXT NOT NULL, category TEXT NOT NULL, risk_level INTEGER NOT NULL, rule_code TEXT NOT NULL, source TEXT NOT NULL, rule_version TEXT NULL, schema_version INTEGER NOT NULL DEFAULT 1 CHECK(schema_version=1)); PRAGMA user_version=17; COMMIT;", ct);
        if (v < 18)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await EnsureColumnAsync(c, "events", "process_image_path", "TEXT NULL CHECK(process_image_path IS NULL OR length(process_image_path)<=4096)", ct);
                await EnsureColumnAsync(c, "events", "process_image_sha256", "TEXT NULL CHECK(process_image_sha256 IS NULL OR length(process_image_sha256)=64)", ct);
                await EnsureColumnAsync(c, "events", "process_image_signature_status", "TEXT NULL CHECK(process_image_signature_status IS NULL OR process_image_signature_status IN ('Pending','Valid','NotSigned','HashMismatch','NotTrusted','Unknown','Unavailable','TooLarge','QueueFull'))", ct);
                await EnsureColumnAsync(c, "events", "process_image_local_hash_match", "INTEGER NULL CHECK(process_image_local_hash_match IS NULL OR process_image_local_hash_match IN (0,1))", ct);
                await Execute(c, "PRAGMA user_version=18; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 19)
        {
            await Execute(c, "BEGIN IMMEDIATE; CREATE TABLE IF NOT EXISTS windows_persistence_snapshot(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 100), source TEXT NOT NULL CHECK(source IN ('registry.run','registry.runonce','startup.folder')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); CREATE TABLE IF NOT EXISTS windows_persistence_monitor_metadata(id INTEGER PRIMARY KEY CHECK(id=1), initialized INTEGER NOT NULL CHECK(initialized IN (0,1))); INSERT OR IGNORE INTO windows_persistence_monitor_metadata(id,initialized) VALUES(1,0); PRAGMA user_version=19; COMMIT;", ct);
        }
        if (v < 20)
        {
            await Execute(c, "BEGIN IMMEDIATE; CREATE TABLE windows_persistence_snapshot_v20(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 100), source TEXT NOT NULL CHECK(source IN ('registry.user.run','registry.user.runonce','registry.machine64.run','registry.machine64.runonce','registry.machine32.run','registry.machine32.runonce','startup.user','startup.common')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); INSERT INTO windows_persistence_snapshot_v20(entry_key,source,fingerprint,writable_location) SELECT entry_key,CASE source WHEN 'registry.run' THEN 'registry.user.run' WHEN 'registry.runonce' THEN 'registry.user.runonce' WHEN 'startup.folder' THEN 'startup.user' END,fingerprint,writable_location FROM windows_persistence_snapshot; DROP TABLE windows_persistence_snapshot; ALTER TABLE windows_persistence_snapshot_v20 RENAME TO windows_persistence_snapshot; PRAGMA user_version=20; COMMIT;", ct);
        }
        if (v < 21)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await Execute(c, "CREATE TABLE windows_persistence_snapshot_v21(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 100), source TEXT NOT NULL CHECK(source IN ('registry.user.run','registry.user.runonce','registry.machine64.run','registry.machine64.runonce','registry.machine32.run','registry.machine32.runonce','startup.user','startup.common','scheduled.task')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); INSERT INTO windows_persistence_snapshot_v21(entry_key,source,fingerprint,writable_location) SELECT entry_key,source,fingerprint,writable_location FROM windows_persistence_snapshot; DROP TABLE windows_persistence_snapshot; ALTER TABLE windows_persistence_snapshot_v21 RENAME TO windows_persistence_snapshot;", ct);
                await EnsureColumnAsync(c, "windows_persistence_monitor_metadata", "scheduled_tasks_initialized", "INTEGER NOT NULL DEFAULT 0 CHECK(scheduled_tasks_initialized IN (0,1))", ct);
                await Execute(c, "PRAGMA user_version=21; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 22)
            await Execute(c, "BEGIN IMMEDIATE; PRAGMA user_version=22; COMMIT;", ct);
        if (v < 23)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await EnsureColumnAsync(c, "events", "processed_at", "TEXT NULL", ct);
                await EnsureColumnAsync(c, "event_observations", "processed_at", "TEXT NULL", ct);
                await Execute(c, "DROP TRIGGER IF EXISTS trg_events_add_observation; CREATE TRIGGER trg_events_add_observation AFTER INSERT ON events WHEN NEW.event_id IS NOT NULL BEGIN INSERT OR IGNORE INTO event_observations(event_id,event_row_id,observed_at,source,evidence_codes,processed_at) VALUES(NEW.event_id,NEW.id,NEW.timestamp,COALESCE(NULLIF(NEW.source,''),'unknown'),NEW.evidence_codes,NEW.processed_at); END; PRAGMA user_version=23; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 24)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await EnsureColumnAsync(c, "events", "analysis_limitations", "TEXT NULL CHECK(analysis_limitations IS NULL OR length(analysis_limitations)<=8192)", ct);
                await EnsureColumnAsync(c, "event_observations", "analysis_limitations", "TEXT NULL CHECK(analysis_limitations IS NULL OR length(analysis_limitations)<=8192)", ct);
                await Execute(c, "DROP TRIGGER IF EXISTS trg_events_add_observation; CREATE TRIGGER trg_events_add_observation AFTER INSERT ON events WHEN NEW.event_id IS NOT NULL BEGIN INSERT OR IGNORE INTO event_observations(event_id,event_row_id,observed_at,source,evidence_codes,processed_at,analysis_limitations) VALUES(NEW.event_id,NEW.id,NEW.timestamp,COALESCE(NULLIF(NEW.source,''),'unknown'),NEW.evidence_codes,NEW.processed_at,NEW.analysis_limitations); END; PRAGMA user_version=24; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 25)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await Execute(c, "CREATE TABLE windows_persistence_snapshot_v25(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 100), source TEXT NOT NULL CHECK(source IN ('registry.user.run','registry.user.runonce','registry.machine64.run','registry.machine64.runonce','registry.machine32.run','registry.machine32.runonce','startup.user','startup.common','scheduled.task','registry.service','registry.driver')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); INSERT INTO windows_persistence_snapshot_v25(…30960 tokens truncated… }
            using (var observations = connection.CreateCommand())
            {
                observations.Transaction = transaction;
                observations.CommandText = "UPDATE event_observations SET evidence_codes=$evidence WHERE event_id=$eventId";
                observations.Parameters.AddWithValue("$evidence", JsonSerializer.Serialize(downloadEvidence));
                observations.Parameters.AddWithValue("$eventId", candidate.EventId.ToString("D"));
                await observations.ExecuteNonQueryAsync(cancellationToken);
            }
            processCorrelationId = correlationId;
            break; // Attach to the nearest compatible download event only; don't merge separate same-hash incidents.
        }
    }
    public async Task<IReadOnlyList<(Guid EventId, string Path)>> ReadPendingProcessImageInspectionsAsync(CancellationToken cancellationToken = default)
    {
        await using var c = await Open(cancellationToken); using var command = c.CreateCommand();
        command.CommandText = "SELECT event_id,process_image_path FROM events WHERE source IN ('process-snapshot','process-wmi') AND process_image_signature_status='Pending' AND event_id IS NOT NULL AND process_image_path IS NOT NULL ORDER BY id LIMIT 33";
        var pending = new List<(Guid EventId, string Path)>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            if (Guid.TryParse(reader.GetString(0), out var eventId)) pending.Add((eventId, reader.GetString(1)));
        return pending;
    }
    public async Task SetStatusAsync(long id, EventStatus status, CancellationToken cancellationToken = default)
    {
        if (!Enum.IsDefined(status)) throw new ArgumentException("Nieprawidłowy status.");
        await using var c = await Open(cancellationToken);
        await Execute(c, "UPDATE events SET status=$s WHERE id=$id", cancellationToken, ("$s", (int)status), ("$id", id));
    }
    public async Task SetStatusByEventIdAsync(Guid eventId, EventStatus status, CancellationToken cancellationToken = default)
    {
        if (eventId == Guid.Empty || !Enum.IsDefined(status)) throw new ArgumentException("Nieprawidłowy identyfikator lub status zdarzenia.");
        await using var connection = await Open(cancellationToken);
        await Execute(connection, "UPDATE events SET status=$s WHERE event_id=$eventId", cancellationToken,
            ("$s", (int)status), ("$eventId", eventId.ToString("D")));
    }
    public async Task DeleteHistoryAsync(CancellationToken cancellationToken = default)
    { await using var c = await Open(cancellationToken); await Execute(c, "DELETE FROM events; DELETE FROM enterprise_event_queue; DELETE FROM enterprise_event_deferred; DELETE FROM domain_correlation; VACUUM;", cancellationToken); }
    public async Task ApplyRetentionAsync(int days, CancellationToken ct = default)
    {
        Validate(new AppSettings(days)); await using var c = await Open(ct);
        var cutoff = DateTimeOffset.UtcNow.AddDays(-days).ToString("O");
        var correlationCutoff = Math.Max(0, DateTimeOffset.UtcNow.ToUniversalTime().Ticks - TimeSpan.FromMinutes(15).Ticks);
        await Execute(c, "DELETE FROM events WHERE timestamp < $cutoff; DELETE FROM enterprise_event_queue WHERE occurred_at < $cutoff; DELETE FROM enterprise_event_deferred WHERE occurred_at < $cutoff; DELETE FROM domain_correlation WHERE last_seen_ticks<$correlationCutoff", ct, ("$cutoff", cutoff), ("$correlationCutoff", correlationCutoff));
    }
    public async Task ExportAsync(string path, CancellationToken ct = default)
    {
        var rows = await ReadAllEventsForExportAsync(ct);
        await using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await JsonSerializer.SerializeAsync(file, rows, cancellationToken: ct);
    }
    public async Task ExportCsvAsync(string path, CancellationToken ct = default)
    {
        var rows = await ReadAllEventsForExportAsync(ct);
        await using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await using var writer = new StreamWriter(file, new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        await writer.WriteLineAsync("id,timestamp_utc,processed_at_utc,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,analysis_limitations,observations,origin");
        foreach (var row in rows)
        {
            ct.ThrowIfCancellationRequested();
            var values = new string?[] { row.Id.ToString(CultureInfo.InvariantCulture), row.Timestamp.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture), row.ProcessedAt?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture), row.Risk.ToString(), row.Category, row.Application, row.Explanation, row.Recommendation, row.Status.ToString(), row.EventId?.ToString("D"), row.Source, row.RuleVersion, row.Confidence?.ToString(CultureInfo.InvariantCulture), row.SchemaVersion.ToString(CultureInfo.InvariantCulture), row.ProcessId?.ToString(CultureInfo.InvariantCulture), row.ProcessName, row.CorrelationId?.ToString("D"), string.Join('|', row.EvidenceCodes ?? []), SerializeAnalysisLimitations(row.AnalysisLimitations), JsonSerializer.Serialize(row.Observations ?? []), "user-engine" };
            await writer.WriteLineAsync(string.Join(',', values.Select(CsvField)));
        }
    }
    private async Task<List<SecurityEvent>> ReadAllEventsForExportAsync(CancellationToken ct)
    {
        // Export all retained rows, independent of the UI's 500-row limit.
        await using var c = await Open(ct); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,signal_hash,processed_at,analysis_limitations FROM events ORDER BY id";
        using var r = await cmd.ExecuteReaderAsync(ct); var rows = new List<SecurityEvent>();
        while (await r.ReadAsync(ct)) rows.Add(new(r.GetInt64(0),DateTimeOffset.Parse(r.GetString(1),CultureInfo.InvariantCulture),(RiskLevel)r.GetInt32(2),r.GetString(3),r.GetString(4),r.GetString(5),r.GetString(6),(EventStatus)r.GetInt32(7),
            r.IsDBNull(8) ? null : Guid.Parse(r.GetString(8)), r.IsDBNull(9) ? null : r.GetString(9),
            r.IsDBNull(10) ? null : r.GetString(10), r.IsDBNull(11) ? null : r.GetInt32(11), r.GetInt32(12),
            r.IsDBNull(13) ? null : r.GetInt32(13), r.IsDBNull(14) ? null : r.GetString(14), r.IsDBNull(15) ? null : Guid.Parse(r.GetString(15)), ParseEvidenceCodes(r.IsDBNull(16) ? null : r.GetString(16)), r.IsDBNull(17) ? null : r.GetString(17), ProcessedAt: r.IsDBNull(18) ? null : DateTimeOffset.Parse(r.GetString(18), CultureInfo.InvariantCulture), AnalysisLimitations: r.IsDBNull(19) ? null : ParseAnalysisLimitations(r.GetString(19))));
        await r.DisposeAsync();
        return await AttachObservationsAsync(c, rows, ct);
    }
    private static async Task<List<SecurityEvent>> AttachObservationsAsync(SqliteConnection connection, List<SecurityEvent> rows, CancellationToken ct)
    {
        var byId = new Dictionary<long, List<EventObservation>>();
        // SQLite limits bound parameters, so read observations in small batches.
        foreach (var batch in rows.Select(row => row.Id).Chunk(400))
        {
            using var command = connection.CreateCommand();
            var parameters = batch.Select((id, index) => { var name = "$id" + index; command.Parameters.AddWithValue(name, id); return name; });
            command.CommandText = $"SELECT event_row_id,event_id,observed_at,source,evidence_codes,processed_at,analysis_limitations FROM event_observations WHERE event_row_id IN ({string.Join(',', parameters)}) ORDER BY observed_at,event_id";
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var rowId = reader.GetInt64(0);
                if (!byId.TryGetValue(rowId, out var observations)) byId[rowId] = observations = [];
                observations.Add(new(Guid.Parse(reader.GetString(1)), DateTimeOffset.Parse(reader.GetString(2), CultureInfo.InvariantCulture),
                    reader.GetString(3), ParseEvidenceCodes(reader.GetString(4)), reader.IsDBNull(5) ? null : DateTimeOffset.Parse(reader.GetString(5), CultureInfo.InvariantCulture), reader.IsDBNull(6) ? null : ParseAnalysisLimitations(reader.GetString(6))));
            }
        }
        return rows.Select(row => row with { Observations = byId.GetValueOrDefault(row.Id) ?? [] }).ToList();
    }
    private static string CsvField(string? value)
    {
        value ??= "";
        // Prevent spreadsheet formula execution, including values prefixed with whitespace or control characters.
        var firstMeaningful = value.FirstOrDefault(character => !char.IsWhiteSpace(character));
        if (firstMeaningful is '=' or '+' or '-' or '@') value = "'" + value;
        return '"' + value.Replace("\"", "\"\"", StringComparison.Ordinal) + '"';
    }
    public async Task BackupAsync(string destination, CancellationToken ct = default)
    {
        if (File.Exists(destination)) throw new IOException("Plik kopii już istnieje.");
        await using var source = await Open(ct);
        await using var target = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = destination, Pooling = false }.ToString());
        await target.OpenAsync(ct); source.BackupDatabase(target);
    }

    /// <summary>Restores local events and settings from a verified v6-v39 backup, preserving installed identity and active monitor baselines.</summary>
    public async Task<int> RestoreAsync(string backupPath, CancellationToken ct = default)
    {
        var sourcePath = Path.GetFullPath(backupPath);
        if (!File.Exists(sourcePath)) throw new FileNotFoundException("Nie znaleziono kopii bazy.", sourcePath);
        if (string.Equals(sourcePath, DatabasePath, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Nie można przywrócić bazy z jej aktywnego pliku.");

        var backupVersion = 0;
        await using (var source = new SqliteConnection(new SqliteConnectionStringBuilder
        { DataSource = sourcePath, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString()))
        {
            await source.OpenAsync(ct);
            using var integrity = source.CreateCommand(); integrity.CommandText = "PRAGMA integrity_check";
            if (!string.Equals(await integrity.ExecuteScalarAsync(ct) as string, "ok", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Kopia bazy nie przeszła kontroli integralności.");
            using var version = source.CreateCommand(); version.CommandText = "PRAGMA user_version";
            backupVersion = Convert.ToInt32(await version.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
            if (backupVersion is < 6 or > 40)
                throw new InvalidDataException("Kopia pochodzi z nieobsługiwanej wersji bazy.");
            using var required = source.CreateCommand();
            required.CommandText = backupVersion == 8
                ? "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('events','settings','enterprise_event_queue','installation_profile','network_endpoint_snapshot','network_monitor_metadata','process_snapshot','process_monitor_metadata')"
                : backupVersion == 7
                    ? "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('events','settings','enterprise_event_queue','installation_profile','network_endpoint_snapshot','network_monitor_metadata')"
                    : "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('events','settings','enterprise_event_queue','installation_profile')";
            if (backupVersion is 9 or 10 or 11 or 12 or 13 or 14 or 15 or 16)
            {
                required.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('events','settings','enterprise_event_queue','installation_profile','network_endpoint_snapshot','network_monitor_metadata','process_snapshot','process_monitor_metadata','downloaded_file_snapshot','downloaded_file_monitor_metadata')";
            }
            if (backupVersion is 13 or 14 or 15 or 16)
                required.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('events','settings','enterprise_event_queue','installation_profile','network_endpoint_snapshot','network_monitor_metadata','process_snapshot','process_monitor_metadata','downloaded_file_snapshot','downloaded_file_monitor_metadata','domain_correlation')";
            if (backupVersion is 16 or 17 or 18)
                required.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('events','settings','enterprise_event_queue','installation_profile','network_endpoint_snapshot','network_monitor_metadata','process_snapshot','process_monitor_metadata','downloaded_file_snapshot','downloaded_file_monitor_metadata','domain_correlation','event_observations'" + (backupVersion >= 17 ? ",'enterprise_event_deferred'" : "") + ")";
            if (backupVersion is 19 or 20 or 21)
                required.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('events','settings','enterprise_event_queue','installation_profile','network_endpoint_snapshot','network_monitor_metadata','process_snapshot','process_monitor_metadata','downloaded_file_snapshot','downloaded_file_monitor_metadata','domain_correlation','event_observations','enterprise_event_deferred','windows_persistence_snapshot','windows_persistence_monitor_metadata')";
            if (backupVersion >= 22)
                required.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('events','settings','enterprise_event_queue','installation_profile','network_endpoint_snapshot','network_monitor_metadata','process_snapshot','process_monitor_metadata','downloaded_file_snapshot','downloaded_file_monitor_metadata','domain_correlation','event_observations','enterprise_event_deferred','windows_persistence_snapshot','windows_persistence_monitor_metadata','dns_operational_monitor_metadata')";
            if (backupVersion >= 35)
                required.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('events','settings','enterprise_event_queue','installation_profile','network_endpoint_snapshot','network_monitor_metadata','process_snapshot','process_monitor_metadata','downloaded_file_snapshot','downloaded_file_monitor_metadata','domain_correlation','event_observations','enterprise_event_deferred','windows_persistence_snapshot','windows_persistence_monitor_metadata','dns_operational_monitor_metadata','process_change_backlog')";
            var expectedTables = backupVersion >= 35 ? 17 : backupVersion >= 22 ? 16 : backupVersion is 19 or 20 or 21 ? 15 : backupVersion >= 17 ? 13 : backupVersion == 16 ? 12 : backupVersion is 13 or 14 or 15 ? 11 : backupVersion is 9 or 10 or 11 or 12 ? 10 : backupVersion == 8 ? 8 : backupVersion == 7 ? 6 : 4;
            if (Convert.ToInt32(await required.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture) != expectedTables)
                throw new InvalidDataException("Kopia nie zawiera wymaganych tabel Sentinel AI.");
            if (backupVersion >= 36 && !await HasColumnAsync(source, "process_monitor_metadata", "dropped_changes", ct))
                throw new InvalidDataException("Kopia nie zawiera licznika pominiętych zmian procesu.");
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
            var deferredRestore = backupVersion >= 17
                ? "INSERT INTO enterprise_event_deferred(event_id,occurred_at,category,risk_level,rule_code,source,rule_version,schema_version) SELECT event_id,occurred_at,category,risk_level,rule_code,source,rule_version,schema_version FROM restore_source.enterprise_event_deferred;"
                : "";
            command.CommandText = """
                SELECT COUNT(*) FROM restore_source.events;
                """;
            var count = Convert.ToInt32(await command.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
            var queueRestore = backupVersion >= 10
                ? "INSERT INTO enterprise_event_queue(event_id,occurred_at,category,risk_level,rule_code,sent,source,rule_version,schema_version) SELECT event_id,occurred_at,category,risk_level,rule_code,sent,source,rule_version,schema_version FROM restore_source.enterprise_event_queue;"
                : "INSERT INTO enterprise_event_queue(event_id,occurred_at,category,risk_level,rule_code,sent) SELECT event_id,occurred_at,category,risk_level,rule_code,sent FROM restore_source.enterprise_event_queue;";
            var eventRestore = backupVersion >= 24
                ? "INSERT INTO events(id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,signal_hash,process_image_path,process_image_sha256,process_image_signature_status,process_image_local_hash_match,processed_at,analysis_limitations) SELECT id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,signal_hash,process_image_path,process_image_sha256,process_image_signature_status,process_image_local_hash_match,processed_at,analysis_limitations FROM restore_source.events;"
                : backupVersion >= 23
                ? "INSERT INTO events(id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,signal_hash,process_image_path,process_image_sha256,process_image_signature_status,process_image_local_hash_match,processed_at) SELECT id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,signal_hash,process_image_path,process_image_sha256,process_image_signature_status,process_image_local_hash_match,processed_at FROM restore_source.events;"
                : backupVersion >= 18
                ? "INSERT INTO events(id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,signal_hash,process_image_path,process_image_sha256,process_image_signature_status,process_image_local_hash_match) SELECT id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,signal_hash,process_image_path,process_image_sha256,process_image_signature_status,process_image_local_hash_match FROM restore_source.events;"
                : backupVersion >= 16
                ? "INSERT INTO events(id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,signal_hash) SELECT id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,signal_hash FROM restore_source.events;"
                : backupVersion >= 12
                ? "INSERT INTO events(id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes) SELECT id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes FROM restore_source.events;"
                : backupVersion >= 11
                    ? "INSERT INTO events(id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes) SELECT id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,'[]' FROM restore_source.events;"
                    : "INSERT INTO events(id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes) SELECT id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,NULL,'[]' FROM restore_source.events;";
            command.CommandText = """
                DELETE FROM events;
                """ + eventRestore + (backupVersion >= 24
                    ? "INSERT OR REPLACE INTO event_observations(event_id,event_row_id,observed_at,source,evidence_codes,processed_at,analysis_limitations) SELECT event_id,event_row_id,observed_at,source,evidence_codes,processed_at,analysis_limitations FROM restore_source.event_observations;"
                    : backupVersion >= 23
                    ? "INSERT OR REPLACE INTO event_observations(event_id,event_row_id,observed_at,source,evidence_codes,processed_at) SELECT event_id,event_row_id,observed_at,source,evidence_codes,processed_at FROM restore_source.event_observations;"
                    : backupVersion >= 16
                    ? "INSERT OR REPLACE INTO event_observations(event_id,event_row_id,observed_at,source,evidence_codes) SELECT event_id,event_row_id,observed_at,source,evidence_codes FROM restore_source.event_observations;"
                    : "") + """
                DELETE FROM settings;
                INSERT INTO settings(id,json) SELECT id,json FROM restore_source.settings;
                DELETE FROM enterprise_event_queue;
                DELETE FROM enterprise_event_deferred;
                """ + queueRestore + deferredRestore + "DELETE FROM domain_correlation;";
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

