Warning: truncated output (original token count: 40881)
Total output lines: 1817

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
        if (v > 38) throw new InvalidDataException("Nowsza wersja bazy wymaga nowszej aplikacji.");
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
            CREATE TABLE IF NOT EXISTS downloaded_file_monitor_metadata(id INTEGER PRIMARY KEY CHECK(id=1), initialized INTEGER NOT NULL CHECK(initialized IN (0,1)));
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
                await Execute(c, "CREATE TABLE windows_persistence_snapshot_v25(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 100), source TEXT NOT NULL CHECK(source IN ('registry.user.run','registry.user.runonce','registry.machine64.run','registry.machine64.runonce','registry.machine32.run','registry.machine32.runonce','startup.user','startup.common','scheduled.task','registry.service','registry.driver')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); INSERT INTO windows_persistence_snapshot_v25(entry_key,source,fingerprint,writable_location) SELECT entry_key,source,fingerprint,writable_location FROM windows_persistence_snapshot; DROP TABLE windows_persistence_snapshot; ALTER TABLE windows_persistence_snapshot_v25 RENAME TO windows_persistence_snapshot; PRAGMA user_version=25; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 26)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await EnsureColumnAsync(c, "windows_persistence_monitor_metadata", "services_initialized", "INTEGER NOT NULL DEFAULT 0 CHECK(services_initialized IN (0,1))", ct);
                await Execute(c, "PRAGMA user_version=26; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 27)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await Execute(c, "CREATE TABLE windows_persistence_snapshot_v27(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 100), source TEXT NOT NULL CHECK(source IN ('registry.user.run','registry.user.runonce','registry.machine64.run','registry.machine64.runonce','registry.machine32.run','registry.machine32.runonce','registry.user.policy.run','registry.machine64.policy.run','registry.machine32.policy.run','startup.user','startup.common','scheduled.task','registry.service','registry.driver')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); INSERT INTO windows_persistence_snapshot_v27(entry_key,source,fingerprint,writable_location) SELECT entry_key,source,fingerprint,writable_location FROM windows_persistence_snapshot; DROP TABLE windows_persistence_snapshot; ALTER TABLE windows_persistence_snapshot_v27 RENAME TO windows_persistence_snapshot; PRAGMA user_version=27; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 28)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await Execute(c, "CREATE TABLE windows_persistence_snapshot_v28(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 100), source TEXT NOT NULL CHECK(source IN ('registry.user.run','registry.user.runonce','registry.machine64.run','registry.machine64.runonce','registry.machine32.run','registry.machine32.runonce','registry.user.policy.run','registry.machine64.policy.run','registry.machine32.policy.run','registry.user.winlogon','registry.machine64.winlogon','registry.machine32.winlogon','startup.user','startup.common','scheduled.task','registry.service','registry.driver')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); INSERT INTO windows_persistence_snapshot_v28(entry_key,source,fingerprint,writable_location) SELECT entry_key,source,fingerprint,writable_location FROM windows_persistence_snapshot; DROP TABLE windows_persistence_snapshot; ALTER TABLE windows_persistence_snapshot_v28 RENAME TO windows_persistence_snapshot; PRAGMA user_version=28; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 29)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await Execute(c, "CREATE TABLE windows_persistence_snapshot_v29(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 100), source TEXT NOT NULL CHECK(source IN ('registry.user.run','registry.user.runonce','registry.machine64.run','registry.machine64.runonce','registry.machine32.run','registry.machine32.runonce','registry.user.policy.run','registry.machine64.policy.run','registry.machine32.policy.run','registry.user.winlogon','registry.machine64.winlogon','registry.machine32.winlogon','registry.machine64.appinit','registry.machine32.appinit','startup.user','startup.common','scheduled.task','registry.service','registry.driver')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); INSERT INTO windows_persistence_snapshot_v29(entry_key,source,fingerprint,writable_location) SELECT entry_key,source,fingerprint,writable_location FROM windows_persistence_snapshot; DROP TABLE windows_persistence_snapshot; ALTER TABLE windows_persistence_snapshot_v29 RENAME TO windows_persistence_snapshot; PRAGMA user_version=29; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 30)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await Execute(c, "CREATE TABLE windows_persistence_snapshot_v30(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 100), source TEXT NOT NULL CHECK(source IN ('registry.user.run','registry.user.runonce','registry.machine64.run','registry.machine64.runonce','registry.machine32.run','registry.machine32.runonce','registry.user.policy.run','registry.machine64.policy.run','registry.machine32.policy.run','registry.user.winlogon','registry.machine64.winlogon','registry.machine32.winlogon','registry.machine64.appinit','registry.machine32.appinit','registry.machine64.ifeo','registry.machine32.ifeo','startup.user','startup.common','scheduled.task','registry.service','registry.driver')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); INSERT INTO windows_persistence_snapshot_v30(entry_key,source,fingerprint,writable_location) SELECT entry_key,source,fingerprint,writable_location FROM windows_persistence_snapshot; DROP TABLE windows_persistence_snapshot; ALTER TABLE windows_persistence_snapshot_v30 RENAME TO windows_persistence_snapshot; PRAGMA user_version=30; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 31)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await Execute(c, "CREATE TABLE windows_persistence_snapshot_v31(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 100), source TEXT NOT NULL CHECK(source IN ('registry.user.run','registry.user.runonce','registry.machine64.run','registry.machine64.runonce','registry.machine32.run','registry.machine32.runonce','registry.user.policy.run','registry.machine64.policy.run','registry.machine32.policy.run','registry.user.winlogon','registry.machine64.winlogon','registry.machine32.winlogon','registry.machine64.appinit','registry.machine32.appinit','registry.machine64.ifeo','registry.machine32.ifeo','registry.machine64.shell.delay','registry.machine32.shell.delay','startup.user','startup.common','scheduled.task','registry.service','registry.driver')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); INSERT INTO windows_persistence_snapshot_v31(entry_key,source,fingerprint,writable_location) SELECT entry_key,source,fingerprint,writable_location FROM windows_persistence_snapshot; DROP TABLE windows_persistence_snapshot; ALTER TABLE windows_persistence_snapshot_v31 RENAME TO windows_persistence_snapshot; PRAGMA user_version=31; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 32)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await Execute(c, "CREATE TABLE windows_persistence_snapshot_v32(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 100), source TEXT NOT NULL CHECK(source IN ('registry.user.run','registry.user.runonce','registry.machine64.run','registry.machine64.runonce','registry.machine32.run','registry.machine32.runonce','registry.user.runonceex','registry.machine64.runonceex','registry.machine32.runonceex','registry.user.policy.run','registry.machine64.policy.run','registry.machine32.policy.run','registry.user.winlogon','registry.machine64.winlogon','registry.machine32.winlogon','registry.machine64.appinit','registry.machine32.appinit','registry.machine64.ifeo','registry.machine32.ifeo','registry.machine64.shell.delay','registry.machine32.shell.delay','startup.user','startup.common','scheduled.task','registry.service','registry.driver')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); INSERT INTO windows_persistence_snapshot_v32(entry_key,source,fingerprint,writable_location) SELECT entry_key,source,fingerprint,writable_location FROM windows_persistence_snapshot; DROP TABLE windows_persistence_snapshot; ALTER TABLE windows_persistence_snapshot_v32 RENAME TO windows_persistence_snapshot; PRAGMA user_version=32; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 33)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await Execute(c, "CREATE TABLE windows_persistence_snapshot_v33(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 100), source TEXT NOT NULL CHECK(source IN ('registry.user.run','registry.user.runonce','registry.machine64.run','registry.machine64.runonce','registry.machine32.run','registry.machine32.runonce','registry.user.runonceex','registry.machine64.runonceex','registry.machine32.runonceex','registry.user.policy.run','registry.machine64.policy.run','registry.machine32.policy.run','registry.user.winlogon','registry.machine64.winlogon','registry.machine32.winlogon','registry.machine64.appinit','registry.machine32.appinit','registry.machine64.ifeo','registry.machine32.ifeo','registry.machine64.shell.delay','registry.machine32.shell.delay','registry.machine64.silent.exit','registry.machine32.silent.exit','startup.user','startup.common','scheduled.task','registry.service','registry.driver')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); INSERT INTO windows_persistence_snapshot_v33(entry_key,source,fingerprint,writable_location) SELECT entry_key,source,fingerprint,writable_location FROM windows_persistence_snapshot; DROP TABLE windows_persistence_snapshot; ALTER TABLE windows_persistence_snapshot_v33 RENAME TO windows_persistence_snapshot; PRAGMA user_version=33; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 34)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await Execute(c, "CREATE TABLE windows_persistence_snapshot_v34(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 100), source TEXT NOT NULL CHECK(source IN ('registry.user.run','registry.user.runonce','registry.machine64.run','registry.machine64.runonce','registry.machine32.run','registry.machine32.runonce','registry.user.runonceex','registry.machine64.runonceex','registry.machine32.runonceex','registry.user.policy.run','registry.machine64.policy.run','registry.machine32.policy.run','registry.user.winlogon','registry.machine64.winlogon','registry.machine32.winlogon','registry.machine64.appinit','registry.machine32.appinit','registry.machine64.ifeo','registry.machine32.ifeo','registry.machine64.shell.delay','registry.machine32.shell.delay','registry.machine64.silent.exit','registry.machine32.silent.exit','registry.user.startup.approved.run','registry.user.startup.approved.run32','registry.user.startup.approved.startupfolder','registry.machine64.startup.approved.run','registry.machine64.startup.approved.run32','registry.machine64.startup.approved.startupfolder','registry.machine32.startup.approved.run','registry.machine32.startup.approved.run32','registry.machine32.startup.approved.startupfolder','startup.user','startup.common','scheduled.task','registry.service','registry.driver')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); INSERT INTO windows_persistence_snapshot_v34(entry_key,source,fingerprint,writable_location) SELECT entry_key,source,fingerprint,writable_location FROM windows_persistence_snapshot; DROP TABLE windows_persistence_snapshot; ALTER TABLE windows_persistence_snapshot_v34 RENAME TO windows_persistence_snapshot; PRAGMA user_version=34; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 35)
        {
            await Execute(c, "BEGIN IMMEDIATE; CREATE TABLE IF NOT EXISTS process_change_backlog(queue_id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE CHECK(length(event_id)=36), observed_at TEXT NOT NULL, action TEXT NOT NULL CHECK(action IN ('Proces zaobserwowany','Proces zniknął z migawki')), process_id INTEGER NOT NULL CHECK(process_id BETWEEN 0 AND 2147483647), process_name TEXT NOT NULL CHECK(length(process_name) BETWEEN 1 AND 260), correlation_id TEXT NULL CHECK(correlation_id IS NULL OR length(correlation_id)=36)); PRAGMA user_version=35; COMMIT;", ct);
        }
        if (v < 36)
        {
            if (await HasColumnAsync(c, "process_monitor_metadata", "dropped_changes", ct))
                await Execute(c, "PRAGMA user_version=36", ct);
            else
                await Execute(c, "BEGIN IMMEDIATE; ALTER TABLE process_monitor_metadata ADD COLUMN dropped_changes INTEGER NOT NULL DEFAULT 0 CHECK(dropped_changes>=0); PRAGMA user_version=36; COMMIT;", ct);
        }
        if (v < 37)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await EnsureColumnAsync(c, "windows_persistence_monitor_metadata", "ifeo_machine64_initialized", "INTEGER NOT NULL DEFAULT 0 CHECK(ifeo_machine64_initialized IN (0,1))", ct);
                await EnsureColumnAsync(c, "windows_persistence_monitor_metadata", "ifeo_machine32_initialized", "INTEGER NOT NULL DEFAULT 0 CHECK(ifeo_machine32_initialized IN (0,1))", ct);
                if (v >= 30)
                    await Execute(c, "UPDATE windows_persistence_monitor_metadata SET ifeo_machine64_initialized=initialized,ifeo_machine32_initialized=initialized WHERE id=1", ct);
                await Execute(c, "PRAGMA user_version=37; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        if (v < 38)
        {
            await Execute(c, "BEGIN IMMEDIATE;", ct);
            try
            {
                await Execute(c, "CREATE TABLE windows_persistence_snapshot_v38(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 160), source TEXT NOT NULL CHECK(source IN ('registry.user.run','registry.user.runonce','registry.machine64.run','registry.machine64.runonce','registry.machine32.run','registry.machine32.runonce','registry.user.runonceex','registry.machine64.runonceex','registry.machine32.runonceex','registry.user.policy.run','registry.machine64.policy.run','registry.machine32.policy.run','registry.user.winlogon','registry.machine64.winlogon','registry.machine32.winlogon','registry.machine64.appinit','registry.machine32.appinit','registry.machine64.ifeo','registry.machine32.ifeo','registry.machine64.shell.delay','registry.machine32.shell.delay','registry.machine64.silent.exit','registry.machine32.silent.exit','registry.user.startup.approved.run','registry.user.startup.approved.run32','registry.user.startup.approved.startupfolder','registry.machine64.startup.approved.run','registry.machine64.startup.approved.run32','registry.machine64.startup.approved.startupfolder','registry.machine32.startup.approved.run','registry.machine32.startup.approved.run32','registry.machine32.startup.approved.startupfolder','startup.user','startup.common','scheduled.task','registry.service','registry.driver')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); INSERT INTO windows_persistence_snapshot_v38(entry_key,source,fingerprint,writable_location) SELECT entry_key,source,fingerprint,writable_location FROM windows_persistence_snapshot; DROP TABLE windows_persistence_snapshot; ALTER TABLE windows_persistence_snapshot_v38 RENAME TO windows_persistence_snapshot; PRAGMA user_version=38; COMMIT;", ct);
            }
            catch { await Execute(c, "ROLLBACK;", ct); throw; }
        }
        await Execute(c, "CREATE INDEX IF NOT EXISTS ix_event_observations_source_time ON event_observations(source,observed_at,event_row_id)", ct);
        // Keep restart-time correlation lookup bounded on large retained event histories.
        if (await HasColumnAsync(c, "events", "process_id", ct) && await HasColumnAsync(c, "events", "process_name", ct) &&
            await HasColumnAsync(c, "events", "source", ct) && await HasColumnAsync(c, "events", "correlation_id", ct))
            await Execute(c, "CREATE INDEX IF NOT EXISTS ix_process_start_recent_correlation ON events(timestamp DESC,process_id,process_name,correlation_id) WHERE source='process-snapshot' AND category='Proces zaobserwowany' AND correlation_id IS NOT NULL", ct);
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
        if (!shareSecurityMetadata)
        {
            using var clear = c.CreateCommand(); clear.Transaction = transaction;
            clear.CommandText = "DELETE FROM enterprise_event_queue; DELETE FROM enterprise_event_deferred";
            await clear.ExecuteNonQueryAsync(ct);
        }
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

    public async Task<long?> GetDnsOperationalRecordCursorAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await Open(cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT last_record_id FROM dns_operational_monitor_metadata WHERE id=1";
        var value = await command.ExecuteScalarAsync(cancellationToken);
        return value is null or DBNull ? null : Convert.ToInt64(value, CultureInfo.InvariantCulture);
    }

    public async Task SetDnsOperationalRecordCursorAsync(long recordId, CancellationToken cancellationToken = default)
    {
        if (recordId < 0) throw new ArgumentOutOfRangeException(nameof(recordId));
        await using var connection = await Open(cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO dns_operational_monitor_metadata(id,last_record_id) VALUES(1,$recordId) ON CONFLICT(id) DO UPDATE SET last_record_id=excluded.last_record_id";
        command.Parameters.AddWithValue("$recordId", recordId);
        await command.ExecuteNonQueryAsync(cancellationToken);
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
        if (s.LocalAIEmbeddingModel is null || s.LocalAIEmbeddingModel.Length > 160 || s.LocalAIEmbeddingModel.Any(char.IsControl)) throw new ArgumentException("Nieprawidłowa nazwa lokalnego modelu embeddingów.");
        if (s.LocalAITimeoutSeconds is < 3 or > 120) throw new ArgumentOutOfRangeException(nameof(s), "Limit czasu modelu: 3–120 sekund.");
    }
    public async Task SaveSettingsAsync(AppSettings settings, CancellationToken cancellationToken = default)
    {
        Validate(settings); await using var c = await Open(cancellationToken);
        await Execute(c, "INSERT INTO settings VALUES(1,$j) ON CONFLICT(id) DO UPDATE SET json=$j", cancellationToken, ("$j", JsonSerializer.Serialize(settings)));
    }
    public async Task<long> AddAsync(SecurityEvent item, CancellationToken cancellationToken = default) =>
        (await AddCoreAsync(item, enqueueEnterprise: true, cancellationToken)).EventRowId;
    /// <summary>Persists a local-only event without adding it to the Enterprise metadata queue.</summary>
    public async Task<long> AddLocalOnlyAsync(SecurityEvent item, CancellationToken cancellationToken = default) =>
        (await AddCoreAsync(item, enqueueEnterprise: false, cancellationToken)).EventRowId;
    /// <summary>Persists a local-only event unless its source already reported the same signal in the requested interval.</summary>
    public async Task<bool> AddLocalOnlyDeduplicatedAsync(SecurityEvent item, TimeSpan sourceSignalWindow,
        CancellationToken cancellationToken = default)
    {
        if (item.SignalHash is null || item.SignalHash.Length != 64 || item.SignalHash.Any(character => !Uri.IsHexDigit(character)))
            throw new ArgumentException("Trwała deduplikacja wymaga 64-znakowego skrótu sygnału.", nameof(item));
        if (sourceSignalWindow < TimeSpan.FromSeconds(1) || sourceSignalWindow > TimeSpan.FromHours(1))
            throw new ArgumentOutOfRangeException(nameof(sourceSignalWindow), "Okno deduplikacji musi mieścić się w zakresie 1 s–1 h.");
        var result = await AddCoreAsync(item, enqueueEnterprise: false, cancellationToken, sameSourceSignalWindow: sourceSignalWindow);
        return !result.WasDeduplicated;
    }
    /// <summary>Atomically persists a detection and its explicitly categorized Enterprise outbox entry when sharing is enabled.</summary>
    /// <returns>True when Enterprise sharing is enabled but the bounded outbox is full; the local detection remains saved.</returns>
    public async Task<bool> AddWithEnterpriseMetadataAsync(SecurityEvent item, string category, string ruleCode,
        CancellationToken cancellationToken = default)
    {
        if (category is not ("url" or "message" or "document" or "attachment" or "sender" or "login") ||
            string.IsNullOrEmpty(ruleCode) || ruleCode.Length > 80 ||
            ruleCode.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('.' or '_' or '-')))
            throw new ArgumentException("Nieprawidłowe metadane zdarzenia Enterprise.", nameof(category));
        var result = await AddCoreAsync(item, enqueueEnterprise: true, cancellationToken, category, ruleCode);
        return result.EnterpriseQueueFull;
    }

    /// <summary>Persists a detection unless the same source reported the same signal within the requested interval.</summary>
    public async Task<(bool Duplicate, bool EnterpriseQueueFull)> AddWithEnterpriseMetadataDeduplicatedAsync(
        SecurityEvent item, string category, string ruleCode, TimeSpan sourceSignalWindow,
        CancellationToken cancellationToken = default)
    {
        if (item.SignalHash is null) throw new ArgumentException("Trwała deduplikacja wymaga skrótu sygnału.", nameof(item));
        if (sourceSignalWindow < TimeSpan.FromSeconds(1) || sourceSignalWindow > TimeSpan.FromHours(1))
            throw new ArgumentOutOfRangeException(nameof(sourceSignalWindow), "Okno deduplikacji musi mieścić się w zakresie 1 s–1 h.");
        if (category is not ("url" or "message" or "document" or "attachment" or "sender" or "login") ||
            string.IsNullOrEmpty(ruleCode) || ruleCode.Length > 80 ||
            ruleCode.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('.' or '_' or '-')))
            throw new ArgumentException("Nieprawidłowe metadane zdarzenia Enterprise.", nameof(category));
        var result = await AddCoreAsync(item, enqueueEnterprise: true, cancellationToken, category, ruleCode, sourceSignalWindow);
        return (result.WasDeduplicated, result.EnterpriseQueueFull);
    }

    /// <summary>Returns a short-lived local correlation id for the registrable domain, storing only its SHA-256 key.</summary>
    public async Task<Guid> GetDomainCorrelationIdAsync(string host, DateTimeOffset observedAt,
        TimeSpan? correlationWindow = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        if (host.Length > 253 || host.Any(char.IsControl)) throw new ArgumentException("Nieprawidłowa nazwa domeny.", nameof(host));
        var window = correlationWindow ?? TimeSpan.FromSeconds(60);
        if (window < TimeSpan.FromSeconds(1) || window > TimeSpan.FromMinutes(15))
            throw new ArgumentOutOfRangeException(nameof(correlationWindow), "Okno korelacji musi mieścić się w zakresie 1 s–15 min.");
        string asciiHost;
        try { asciiHost = DomainNames.Ascii(host); }
        catch (ArgumentException ex) { throw new ArgumentException("Nieprawidłowa nazwa domeny.", nameof(host), ex); }
        if (asciiHost.Length is 0 or > 253 || IPAddress.TryParse(asciiHost.Trim('[', ']'), out _) ||
            Uri.CheckHostName(asciiHost) != UriHostNameType.Dns || asciiHost.Split('.').Any(label => label.Length is 0 or > 63))
            throw new ArgumentException("Korelacja wymaga poprawnej nazwy DNS, a nie adresu IP.", nameof(host));
        var registrableDomain = CorrelationDomainNames.RegistrableDomain(asciiHost) ?? asciiHost;
        var domainKey = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(registrableDomain)));
        var observedTicks = observedAt.ToUniversalTime().Ticks;
        var windowTicks = window.Ticks;
        var pruneBefore = Math.Max(0, observedTicks - Math.Min(long.MaxValue, windowTicks * 2));

        await using var connection = await Open(ct);
        using var transaction = connection.BeginTransaction();
        Guid correlationId = Guid.NewGuid();
        var lastSeenTicksToStore = observedTicks;
        var persistCorrelation = true;
        using (var find = connection.CreateCommand())
        {
            find.Transaction = transaction;
            find.CommandText = "SELECT correlation_id,last_seen_ticks FROM domain_correlation WHERE domain_key=$key";
            find.Parameters.AddWithValue("$key", domainKey);
            using var reader = await find.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                var previousId = reader.GetString(0);
                var previousTicks = reader.GetInt64(1);
                if (Guid.TryParse(previousId, out var parsed))
                {
                    if (observedTicks >= previousTicks && observedTicks - previousTicks <= windowTicks)
                        correlationId = parsed;
                    else if (observedTicks < previousTicks && previousTicks - observedTicks <= windowTicks)
                    {
                        // A late-arriving event may join the recent group, but it
                        // must never move that group's sliding timestamp backward.
                        correlationId = parsed;
                        lastSeenTicksToStore = previousTicks;
                    }
                    else if (observedTicks < previousTicks)
                    {
                        // Keep the current group intact when an old event arrives
                        // outside its window; this event receives an isolated ID.
                        persistCorrelation = false;
                    }
                }
            }
        }
        if (persistCorrelation)
        {
            using var upsert = connection.CreateCommand();
            upsert.Transaction = transaction;
            upsert.CommandText = "INSERT INTO domain_correlation(domain_key,correlation_id,last_seen_ticks) VALUES($key,$id,$seen) ON CONFLICT(domain_key) DO UPDATE SET correlation_id=excluded.correlation_id,last_seen_ticks=excluded.last_seen_ticks";
            upsert.Parameters.AddWithValue("$key", domainKey);
            upsert.Parameters.AddWithValue("$id", correlationId.ToString("D"));
            upsert.Parameters.AddWithValue("$seen", lastSeenTicksToStore);
            await upsert.ExecuteNonQueryAsync(ct);
        }
        using (var prune = connection.CreateCommand())
        {
            prune.Transaction = transaction;
            prune.CommandText = "DELETE FROM domain_correlation WHERE last_seen_ticks<$cutoff AND domain_key<>$key; DELETE FROM domain_correlation WHERE domain_key IN (SELECT domain_key FROM domain_correlation ORDER BY last_seen_ticks DESC LIMIT -1 OFFSET 2048)";
            prune.Parameters.AddWithValue("$cutoff", pruneBefore);
            prune.Parameters.AddWithValue("$key", domainKey);
            await prune.ExecuteNonQueryAsync(ct);
        }
        await transaction.CommitAsync(ct);
        return correlationId;
    }
    public async Task<int> AddLocalOnlyBatchAsync(IReadOnlyCollection<SecurityEvent> items, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(items);
        if (items.Count > 100) throw new ArgumentOutOfRangeException(nameof(items), "Limit batcha lokalnego zapisu to 100 zdarzeń.");
        if (items.Count == 0) return 0;
        var validated = items.Select(item => { item = item with { ProcessedAt = item.ProcessedAt ?? DateTimeOffset.UtcNow }; return (Item: item, Metadata: ValidateEvent(item)); }).ToArray();
        await using var c = await Open(cancellationToken);
        using var transaction = c.BeginTransaction();
        foreach (var (item, (eventId, source)) in validated)
        {
            using var command = c.CreateCommand(); command.Transaction = transaction;
            command.CommandText = "INSERT INTO events(timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,signal_hash,process_image_path,process_image_sha256,process_image_signature_status,process_image_local_hash_match,processed_at,analysis_limitations) VALUES($t,$r,$c,$a,$e,$n,$s,$eventId,$source,$ruleVersion,$confidence,$schemaVersion,$processId,$processName,$correlationId,$evidenceCodes,$signalHash,$processImagePath,$processImageSha256,$processImageSignatureStatus,$processImageLocalHashMatch,$processedAt,$analysisLimitations)";
            AddEventParameters(command, item, eventId, source);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        return validated.Length;
    }
    public async Task<NetworkMonitorSnapshot> ReadNetworkMonitorSnapshotAsync(CancellationToken ct = default)
    {
        await using var c = await Open(ct);
        using var metadata = c.CreateCommand(); metadata.CommandText = "SELECT initialized,tcp_truncated,udp_truncated FROM network_monitor_metadata WHERE id=1";
        await using var metadataReader = await metadata.ExecuteReaderAsync(ct);
        if (!await metadataReader.ReadAsync(ct)) throw new InvalidDataException("Brak metadanych migawki sieci.");
        var initialized = metadataReader.GetInt32(0) == 1;
        var tcpTruncated = metadataReader.GetInt32(1) == 1;
        var udpTruncated = metadataReader.GetInt32(2) == 1;
        await metadataReader.DisposeAsync();
        using var query = c.CreateCommand(); query.CommandText = "SELECT endpoint_key FROM network_endpoint_snapshot ORDER BY endpoint_key LIMIT 20000";
 …10881 tokens truncated…terpriseEventCoreAsync(c, transaction, new PendingEnterpriseEvent(eventId, item.Timestamp, category,
                    (int)item.Risk, ruleCode, EnterpriseEventV1Rules.NormalizeSource(source),
                    EnterpriseEventV1Rules.NormalizeRuleVersion(item.RuleVersion), item.SchemaVersion), cancellationToken);
            }
        }
        await transaction.CommitAsync(cancellationToken);
        return (id, enterpriseQueueFull, wasDeduplicated);
    }
    private static bool HasCertEvidence(IEnumerable<string>? evidence) => evidence?.Any(code =>
        string.Equals(code, "reputation.cert", StringComparison.Ordinal) ||
        code.StartsWith("reputation.cert.", StringComparison.Ordinal)) == true;
    private static bool HasFileReputationEvidence(IEnumerable<string>? evidence) => evidence?.Any(code =>
        string.Equals(code, "file.sha256.matches-local-list", StringComparison.Ordinal)) == true;
    private static bool HasUrlSignalEvidence(IEnumerable<string>? evidence) => evidence?.Any(code =>
        code.StartsWith("url.", StringComparison.Ordinal) || string.Equals(code, "reputation.url-feed", StringComparison.Ordinal)) == true;
    private static async Task<long?> FindRecentSameSourceSignalAsync(SqliteConnection c, SqliteTransaction transaction,
        SecurityEvent item, string source, TimeSpan window, CancellationToken ct)
    {
        var from = item.Timestamp.ToUniversalTime().Subtract(window).ToString("O");
        var to = item.Timestamp.ToUniversalTime().Add(window).ToString("O");
        using var command = c.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "SELECT e.id FROM event_observations o JOIN events e ON e.id=o.event_row_id WHERE o.source=$source AND e.signal_hash=$hash AND e.risk=$risk AND o.observed_at BETWEEN $from AND $to ORDER BY o.observed_at DESC LIMIT 1";
        command.Parameters.AddWithValue("$source", source);
        command.Parameters.AddWithValue("$hash", item.SignalHash!.ToUpperInvariant());
        command.Parameters.AddWithValue("$risk", (int)item.Risk);
        command.Parameters.AddWithValue("$from", from); command.Parameters.AddWithValue("$to", to);
        var existing = await command.ExecuteScalarAsync(ct);
        return existing is null ? null : Convert.ToInt64(existing, CultureInfo.InvariantCulture);
    }
    private static async Task<long?> FindCrossSourceDuplicateAsync(SqliteConnection c, SqliteTransaction transaction,
        SecurityEvent item, string source, CancellationToken ct)
    {
        var isCertSignal = HasCertEvidence(item.EvidenceCodes);
        var isFileSignal = HasFileReputationEvidence(item.EvidenceCodes);
        var isUrlSignal = !isCertSignal && HasUrlSignalEvidence(item.EvidenceCodes) && (source is "manual-analysis" or "browser-extension");
        if (item.SignalHash is null || (!isCertSignal && !isFileSignal && !isUrlSignal) || (isCertSignal && item.Risk < RiskLevel.Moderate)) return null;
        var from = item.Timestamp.ToUniversalTime().AddSeconds(-60).ToString("O");
        var to = item.Timestamp.ToUniversalTime().AddSeconds(60).ToString("O");
        using var candidates = c.CreateCommand(); candidates.Transaction = transaction;
        candidates.CommandText = "SELECT id FROM events WHERE signal_hash=$hash AND risk=$risk AND timestamp BETWEEN $from AND $to ORDER BY ABS(julianday(timestamp)-julianday($timestamp)) LIMIT 20";
        candidates.Parameters.AddWithValue("$hash", item.SignalHash);
        candidates.Parameters.AddWithValue("$risk", (int)item.Risk);
        candidates.Parameters.AddWithValue("$from", from); candidates.Parameters.AddWithValue("$to", to);
        candidates.Parameters.AddWithValue("$timestamp", item.Timestamp.ToUniversalTime().ToString("O"));
        var ids = new List<long>();
        await using (var reader = await candidates.ExecuteReaderAsync(ct)) while (await reader.ReadAsync(ct)) ids.Add(reader.GetInt64(0));
        foreach (var id in ids)
        {
            using var observations = c.CreateCommand(); observations.Transaction = transaction;
            observations.CommandText = "SELECT source,evidence_codes FROM event_observations WHERE event_row_id=$id";
            observations.Parameters.AddWithValue("$id", id);
            await using var reader = await observations.ExecuteReaderAsync(ct);
            var hasSignalFromOtherSource = false;
            var hasSignalFromSameSource = false;
            while (await reader.ReadAsync(ct))
            {
                var codes = ParseEvidenceCodes(reader.GetString(1));
                var observationSource = reader.GetString(0);
                var matchingSignal = isCertSignal ? HasCertEvidence(codes)
                    : isFileSignal ? HasFileReputationEvidence(codes)
                    : HasUrlSignalEvidence(codes) && (observationSource is "manual-analysis" or "browser-extension");
                if (!matchingSignal) continue;
                if (string.Equals(observationSource, source, StringComparison.Ordinal)) hasSignalFromSameSource = true;
                else hasSignalFromOtherSource = true;
            }
            if (!hasSignalFromSameSource && hasSignalFromOtherSource) return id;
        }
        return null;
    }
    private static string MapEnterpriseCategory(SecurityEvent item, string source)
    {
        // Map stable category identifiers and known event sources. Do not infer a
        // transport category by searching localized, user-visible text.
        var category = item.Category.Trim();
        if (Enum.GetNames<Sentinel.Core.Analysis.ThreatCategory>()
            .Any(name => string.Equals(name, category, StringComparison.OrdinalIgnoreCase)))
        {
            return category.ToLowerInvariant() switch
            {
                "suspiciousnavigation" => "url",
                "credentialphishing" => "login",
                "unsafeexecution" => "attachment",
                _ => "message"
            };
        }
        if (string.Equals(category, "url", StringComparison.OrdinalIgnoreCase)) return "url";
        if (string.Equals(category, "document", StringComparison.OrdinalIgnoreCase)) return "document";
        if (string.Equals(category, "attachment", StringComparison.OrdinalIgnoreCase)) return "attachment";
        if (string.Equals(category, "sender", StringComparison.OrdinalIgnoreCase)) return "sender";
        if (string.Equals(category, "login", StringComparison.OrdinalIgnoreCase)) return "login";
        return source switch
        {
            "browser-extension" or "dns-cache" => "url",
            "downloads-local-hash" => "attachment",
            _ => "message"
        };
    }
    private static (Guid EventId, string Source) ValidateEvent(SecurityEvent item)
    {
        if (!Enum.IsDefined(item.Risk) || !Enum.IsDefined(item.Status)) throw new ArgumentException("Nieprawidłowe zdarzenie.");
        foreach (var text in new[] { item.Category, item.Application, item.Explanation, item.Recommendation })
            if (string.IsNullOrWhiteSpace(text) || text.Length > 2000) throw new ArgumentException("Nieprawidłowe metadane zdarzenia.");
        var eventId = item.EventId ?? Guid.NewGuid();
        var source = string.IsNullOrWhiteSpace(item.Source) ? item.Application : item.Source;
        if (eventId == Guid.Empty || source.Length > 100 || item.RuleVersion?.Length > 80 || item.Confidence is < 0 or > 100 || item.SchemaVersion != 1 ||
            item.ProcessId < 0 || item.ProcessName?.Length > 260 || item.ProcessName?.Any(char.IsControl) == true || item.CorrelationId == Guid.Empty ||
            item.EvidenceCodes?.Count > 32 || item.EvidenceCodes?.Any(code => string.IsNullOrWhiteSpace(code) || code.Length > 64 ||
                code.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('.' or '_' or '-'))) == true ||
            item.EvidenceCodes is not null && item.EvidenceCodes.Distinct(StringComparer.Ordinal).Count() != item.EvidenceCodes.Count)
            throw new ArgumentException("Nieprawidłowe pochodzenie zdarzenia.");
        if (item.SignalHash is { } hash && (hash.Length != 64 || hash.Any(character => !Uri.IsHexDigit(character))))
            throw new ArgumentException("Nieprawidłowy skrót sygnału.");
        if (item.AnalysisLimitations?.Count > 16 || item.AnalysisLimitations?.Any(code => string.IsNullOrWhiteSpace(code) || code.Length > 64 ||
                code.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('.' or '_' or '-'))) == true ||
            item.AnalysisLimitations is not null && item.AnalysisLimitations.Distinct(StringComparer.Ordinal).Count() != item.AnalysisLimitations.Count)
            throw new ArgumentException("Nieprawidłowe ograniczenia analizy.");
        if (item.ProcessImagePath is { } imagePath && (imagePath.Length is 0 or > 4096 || !Path.IsPathFullyQualified(imagePath) || imagePath.StartsWith(@"\\", StringComparison.Ordinal) || imagePath.Any(char.IsControl)))
            throw new ArgumentException("Nieprawidłowa ścieżka obrazu procesu.");
        if (item.ProcessImageSha256 is { } imageHash && (imageHash.Length != 64 || imageHash.Any(character => !Uri.IsHexDigit(character))))
            throw new ArgumentException("Nieprawidłowy skrót obrazu procesu.");
        if (item.ProcessImageSignatureStatus is { } signatureStatus && signatureStatus is not ("Pending" or "Valid" or "NotSigned" or "HashMismatch" or "NotTrusted" or "Unknown" or "Unavailable" or "TooLarge" or "QueueFull"))
            throw new ArgumentException("Nieprawidłowy status podpisu obrazu procesu.");
        if (item.ProcessImagePath is null && (item.ProcessImageSha256 is not null || item.ProcessImageSignatureStatus is not null || item.ProcessImageLocalHashMatch is not null))
            throw new ArgumentException("Metadane obrazu procesu wymagają ścieżki lokalnej.");
        return (eventId, source);
    }
    private static string? SerializeAnalysisLimitations(IReadOnlyList<string>? limitations) => limitations is null ? null : JsonSerializer.Serialize(limitations);
    private static IReadOnlyList<string> ParseAnalysisLimitations(string json)
    {
        try
        {
            var limitations = JsonSerializer.Deserialize<string[]>(json) ?? throw new InvalidDataException("Nieprawidłowe ograniczenia analizy.");
            if (limitations.Length > 16 || limitations.Any(code => string.IsNullOrWhiteSpace(code) || code.Length > 64 ||
                    code.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('.' or '_' or '-'))) ||
                limitations.Distinct(StringComparer.Ordinal).Count() != limitations.Length) throw new InvalidDataException("Nieprawidłowe ograniczenia analizy.");
            return limitations;
        }
        catch (JsonException exception) { throw new InvalidDataException("Nieprawidłowe ograniczenia analizy.", exception); }
    }
    private static IReadOnlyList<string> ParseEvidenceCodes(string? json)
    {
        if (json is null) return [];
        try
        {
            var codes = JsonSerializer.Deserialize<string[]>(json) ?? throw new InvalidDataException("Nieprawidłowe kody dowodowe zdarzenia.");
            if (codes.Length > 32 || codes.Any(code => string.IsNullOrWhiteSpace(code) || code.Length > 64 ||
                code.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('.' or '_' or '-'))) ||
                codes.Distinct(StringComparer.Ordinal).Count() != codes.Length)
                throw new InvalidDataException("Nieprawidłowe kody dowodowe zdarzenia.");
            return codes;
        }
        catch (JsonException exception) { throw new InvalidDataException("Nieprawidłowe kody dowodowe zdarzenia.", exception); }
    }
    private static void AddEventParameters(SqliteCommand command, SecurityEvent item, Guid eventId, string source)
    {
        command.Parameters.AddWithValue("$t", item.Timestamp.ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue("$processedAt", (item.ProcessedAt ?? DateTimeOffset.UtcNow).ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue("$r", (int)item.Risk); command.Parameters.AddWithValue("$c", item.Category);
        command.Parameters.AddWithValue("$a", item.Application); command.Parameters.AddWithValue("$e", item.Explanation);
        command.Parameters.AddWithValue("$n", item.Recommendation); command.Parameters.AddWithValue("$s", (int)item.Status);
        command.Parameters.AddWithValue("$eventId", eventId.ToString("D")); command.Parameters.AddWithValue("$source", source);
        command.Parameters.AddWithValue("$ruleVersion", (object?)item.RuleVersion ?? DBNull.Value);
        command.Parameters.AddWithValue("$confidence", (object?)item.Confidence ?? DBNull.Value);
        command.Parameters.AddWithValue("$schemaVersion", item.SchemaVersion);
        command.Parameters.AddWithValue("$processId", (object?)item.ProcessId ?? DBNull.Value);
        command.Parameters.AddWithValue("$processName", (object?)item.ProcessName ?? DBNull.Value);
        command.Parameters.AddWithValue("$correlationId", (object?)item.CorrelationId?.ToString("D") ?? DBNull.Value);
        command.Parameters.AddWithValue("$evidenceCodes", JsonSerializer.Serialize(item.EvidenceCodes ?? Array.Empty<string>()));
        command.Parameters.AddWithValue("$analysisLimitations", (object?)SerializeAnalysisLimitations(item.AnalysisLimitations) ?? DBNull.Value);
        command.Parameters.AddWithValue("$signalHash", (object?)item.SignalHash?.ToUpperInvariant() ?? DBNull.Value);
        command.Parameters.AddWithValue("$processImagePath", (object?)item.ProcessImagePath ?? DBNull.Value);
        command.Parameters.AddWithValue("$processImageSha256", (object?)item.ProcessImageSha256?.ToUpperInvariant() ?? DBNull.Value);
        command.Parameters.AddWithValue("$processImageSignatureStatus", (object?)item.ProcessImageSignatureStatus ?? DBNull.Value);
        command.Parameters.AddWithValue("$processImageLocalHashMatch", (object?)(item.ProcessImageLocalHashMatch is { } match ? (match ? 1 : 0) : null) ?? DBNull.Value);
    }
    public async Task<IReadOnlyList<PendingEnterpriseEvent>> ReadPendingEnterpriseEventsAsync(int limit = 100, CancellationToken ct = default)
    {
        if (limit is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(limit));
        await PromoteDeferredEnterpriseEventsAsync(ct);
        await using var c = await Open(ct); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT event_id,occurred_at,category,risk_level,rule_code,source,rule_version,schema_version FROM enterprise_event_queue WHERE sent=0 ORDER BY occurred_at LIMIT $limit";
        cmd.Parameters.AddWithValue("$limit", limit); using var reader = await cmd.ExecuteReaderAsync(ct); var rows = new List<PendingEnterpriseEvent>();
        while (await reader.ReadAsync(ct)) rows.Add(new(Guid.Parse(reader.GetString(0)), DateTimeOffset.Parse(reader.GetString(1), CultureInfo.InvariantCulture), reader.GetString(2), reader.GetInt32(3), reader.GetString(4),
            reader.GetString(5), reader.IsDBNull(6) ? null : reader.GetString(6), reader.GetInt32(7)));
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
        ValidatePendingEnterpriseEvent(item);
        await using var c = await Open(ct); using var transaction = c.BeginTransaction();
        using var profileRead = c.CreateCommand(); profileRead.Transaction = transaction;
        profileRead.CommandText = "SELECT json FROM installation_profile WHERE id=1";
        var raw = await profileRead.ExecuteScalarAsync(ct) as string ?? throw new InvalidDataException("Brak profilu instalacji.");
        var profile = JsonSerializer.Deserialize<InstalledProductProfile>(raw)?.Validate() ?? throw new InvalidDataException("Nieprawidłowy profil instalacji.");
        if (profile.Variant != ProductVariant.EnterpriseClient || !profile.ShareSecurityMetadata)
            throw new InvalidOperationException("Synchronizacja metadanych nie została jawnie włączona.");
        var inserted = await EnqueueEnterpriseEventCoreAsync(c, transaction, item, ct);
        await transaction.CommitAsync(ct);
        return inserted;
    }
    private static void ValidatePendingEnterpriseEvent(PendingEnterpriseEvent item)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (item.EventId == Guid.Empty || item.Category is not ("url" or "message" or "document" or "attachment" or "sender" or "login") ||
            item.RiskLevel is < 2 or > 4 || string.IsNullOrEmpty(item.RuleCode) || item.RuleCode.Length > 80 ||
            item.RuleCode.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '_' or '-')) ||
            item.SchemaVersion != 1 || item.OccurredAt > DateTimeOffset.UtcNow.AddMinutes(5) || item.OccurredAt < DateTimeOffset.UtcNow.AddDays(-30))
            throw new ArgumentException("Nieprawidłowe metadane zdarzenia Enterprise.", nameof(item));
    }
    private static async Task<bool> EnqueueEnterpriseEventCoreAsync(SqliteConnection c, SqliteTransaction transaction,
        PendingEnterpriseEvent item, CancellationToken ct)
    {
        ValidatePendingEnterpriseEvent(item);
        using (var existing = c.CreateCommand())
        {
            existing.Transaction = transaction; existing.CommandText = "SELECT 1 FROM enterprise_event_queue WHERE event_id=$id";
            existing.Parameters.AddWithValue("$id", item.EventId.ToString("D"));
            existing.CommandText = "SELECT 1 FROM enterprise_event_queue WHERE event_id=$id UNION ALL SELECT 1 FROM enterprise_event_deferred WHERE event_id=$id LIMIT 1";
            if (await existing.ExecuteScalarAsync(ct) is not null) return true;
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
            {
                using var deferred = c.CreateCommand(); deferred.Transaction = transaction;
                deferred.CommandText = "INSERT OR IGNORE INTO enterprise_event_deferred(event_id,occurred_at,category,risk_level,rule_code,source,rule_version,schema_version) VALUES($id,$time,$category,$risk,$rule,$source,$ruleVersion,$schemaVersion)";
                BindEnterpriseEvent(deferred, item);
                await deferred.ExecuteNonQueryAsync(ct);
                return false;
            }
        }
        using var command = c.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "INSERT OR IGNORE INTO enterprise_event_queue(event_id,occurred_at,category,risk_level,rule_code,source,rule_version,schema_version) VALUES($id,$time,$category,$risk,$rule,$source,$ruleVersion,$schemaVersion)";
        BindEnterpriseEvent(command, item);
        return await command.ExecuteNonQueryAsync(ct) == 1;
    }
    private static void BindEnterpriseEvent(SqliteCommand command, PendingEnterpriseEvent item)
    {
        command.Parameters.AddWithValue("$id", item.EventId.ToString("D")); command.Parameters.AddWithValue("$time", item.OccurredAt.ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue("$category", item.Category); command.Parameters.AddWithValue("$risk", item.RiskLevel); command.Parameters.AddWithValue("$rule", item.RuleCode);
        command.Parameters.AddWithValue("$source", EnterpriseEventV1Rules.NormalizeSource(item.Source));
        command.Parameters.AddWithValue("$ruleVersion", (object?)EnterpriseEventV1Rules.NormalizeRuleVersion(item.RuleVersion) ?? DBNull.Value);
        command.Parameters.AddWithValue("$schemaVersion", item.SchemaVersion);
    }
    private async Task PromoteDeferredEnterpriseEventsAsync(CancellationToken ct)
    {
        await using var c = await Open(ct); using var transaction = c.BeginTransaction();
        using var prune = c.CreateCommand(); prune.Transaction = transaction;
        prune.CommandText = "DELETE FROM enterprise_event_queue WHERE event_id IN (SELECT event_id FROM enterprise_event_queue WHERE sent=1 ORDER BY occurred_at LIMIT 1000)";
        await prune.ExecuteNonQueryAsync(ct);
        using var count = c.CreateCommand(); count.Transaction = transaction; count.CommandText = "SELECT MAX(0,10000-COUNT(*)) FROM enterprise_event_queue";
        var available = Convert.ToInt32(await count.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
        if (available > 0)
        {
            using var promote = c.CreateCommand(); promote.Transaction = transaction;
            promote.CommandText = "INSERT OR IGNORE INTO enterprise_event_queue(event_id,occurred_at,category,risk_level,rule_code,source,rule_version,schema_version) SELECT event_id,occurred_at,category,risk_level,rule_code,source,rule_version,schema_version FROM enterprise_event_deferred ORDER BY occurred_at LIMIT $available";
            promote.Parameters.AddWithValue("$available", available); await promote.ExecuteNonQueryAsync(ct);
            using var removePromoted = c.CreateCommand(); removePromoted.Transaction = transaction;
            removePromoted.CommandText = "DELETE FROM enterprise_event_deferred WHERE event_id IN (SELECT event_id FROM enterprise_event_queue)";
            await removePromoted.ExecuteNonQueryAsync(ct);
        }
        await transaction.CommitAsync(ct);
    }
    public async Task<int> CountPendingEnterpriseEventsAsync(CancellationToken ct = default)
    {
        await using var c = await Open(ct); using var command = c.CreateCommand(); command.CommandText = "SELECT (SELECT COUNT(*) FROM enterprise_event_queue WHERE sent=0)+(SELECT COUNT(*) FROM enterprise_event_deferred)";
        return Convert.ToInt32(await command.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
    }
    public async Task ClearEnterpriseEventQueueAsync(CancellationToken ct = default)
    {
        await using var c = await Open(ct); await Execute(c, "DELETE FROM enterprise_event_queue; DELETE FROM enterprise_event_deferred", ct);
    }
    public async Task<IReadOnlyList<SecurityEvent>> ReadAsync(CancellationToken cancellationToken = default)
    {
        await using var c = await Open(cancellationToken); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,signal_hash,process_image_path,process_image_sha256,process_image_signature_status,process_image_local_hash_match,processed_at,analysis_limitations FROM events ORDER BY id DESC LIMIT 500";
        using var r = await cmd.ExecuteReaderAsync(cancellationToken); var rows = new List<SecurityEvent>();
        while (await r.ReadAsync(cancellationToken)) rows.Add(new(r.GetInt64(0), DateTimeOffset.Parse(r.GetString(1), CultureInfo.InvariantCulture),
            (RiskLevel)r.GetInt32(2), r.GetString(3), r.GetString(4), r.GetString(5), r.GetString(6), (EventStatus)r.GetInt32(7),
            r.IsDBNull(8) ? null : Guid.Parse(r.GetString(8)), r.IsDBNull(9) ? null : r.GetString(9),
            r.IsDBNull(10) ? null : r.GetString(10), r.IsDBNull(11) ? null : r.GetInt32(11), r.GetInt32(12),
            r.IsDBNull(13) ? null : r.GetInt32(13), r.IsDBNull(14) ? null : r.GetString(14), r.IsDBNull(15) ? null : Guid.Parse(r.GetString(15)), ParseEvidenceCodes(r.IsDBNull(16) ? null : r.GetString(16)), r.IsDBNull(17) ? null : r.GetString(17),
            ProcessImagePath: r.IsDBNull(18) ? null : r.GetString(18), ProcessImageSha256: r.IsDBNull(19) ? null : r.GetString(19),
            ProcessImageSignatureStatus: r.IsDBNull(20) ? null : r.GetString(20), ProcessImageLocalHashMatch: r.IsDBNull(21) ? null : r.GetInt32(21) != 0, ProcessedAt: r.IsDBNull(22) ? null : DateTimeOffset.Parse(r.GetString(22), CultureInfo.InvariantCulture), AnalysisLimitations: r.IsDBNull(23) ? null : ParseAnalysisLimitations(r.GetString(23))));
        await r.DisposeAsync();
        return await AttachObservationsAsync(c, rows, cancellationToken);
    }
    public async Task<int> CountEventsAsync(CancellationToken cancellationToken = default)
    {
        await using var c = await Open(cancellationToken); using var command = c.CreateCommand(); command.CommandText = "SELECT COUNT(*) FROM events";
        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
    }
    public async Task<DownloadedFileQuarantineCandidate> ReadDownloadedFileQuarantineCandidateAsync(long eventRowId, CancellationToken cancellationToken = default)
    {
        if (eventRowId <= 0) throw new ArgumentOutOfRangeException(nameof(eventRowId));
        await using var connection = await Open(cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT event_id,source,evidence_codes,signal_hash,EXISTS(SELECT 1 FROM event_observations WHERE event_row_id=events.id AND source='downloads-local-hash') FROM events WHERE id=$id";
        command.Parameters.AddWithValue("$id", eventRowId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken) || reader.IsDBNull(0) || !Guid.TryParse(reader.GetString(0), out var eventId) ||
            eventId == Guid.Empty || reader.IsDBNull(1) ||
            (!string.Equals(reader.GetString(1), "downloads-local-hash", StringComparison.Ordinal) && reader.GetInt64(4) != 1))
            throw new InvalidOperationException("Tylko zdarzenie z dopasowaniem lokalnej reputacji nowego pliku może zostać przeniesione do kwarantanny.");
        var evidence = ParseEvidenceCodes(reader.IsDBNull(2) ? null : reader.GetString(2));
        var hash = reader.IsDBNull(3) ? null : reader.GetString(3);
        if (!evidence.Contains("file.sha256.matches-local-list", StringComparer.Ordinal) ||
            hash is null || hash.Length != 64 || hash.Any(character => !Uri.IsHexDigit(character)))
            throw new InvalidOperationException("Zdarzenie nie zawiera prawidłowego potwierdzenia lokalnego hasha pliku.");
        return new(eventId, hash.ToUpperInvariant());
    }
    public async Task UpdateProcessImageInspectionAsync(Guid eventId, string? sha256, string signatureStatus, bool? localHashMatch, CancellationToken cancellationToken = default)
    {
        if (eventId == Guid.Empty || signatureStatus is not ("Valid" or "NotSigned" or "HashMismatch" or "NotTrusted" or "Unknown" or "Unavailable" or "TooLarge" or "QueueFull"))
            throw new ArgumentException("Nieprawidłowy wynik inspekcji pliku procesu.");
        if (sha256 is not null && (sha256.Length != 64 || sha256.Any(character => !Uri.IsHexDigit(character))))
            throw new ArgumentException("Nieprawidłowy SHA-256 pliku procesu.");
        await using var c = await Open(cancellationToken); using var transaction = c.BeginTransaction();
        using var read = c.CreateCommand(); read.Transaction = transaction;
        read.CommandText = "SELECT id,evidence_codes,correlation_id,timestamp FROM events WHERE event_id=$eventId AND process_image_path IS NOT NULL AND source='process-snapshot'";
        read.Parameters.AddWithValue("$eventId", eventId.ToString("D"));
        long rowId; IReadOnlyList<string> evidence; Guid? processCorrelationId; DateTimeOffset processTimestamp;
        await using (var reader = await read.ExecuteReaderAsync(cancellationToken))
        {
            if (!await reader.ReadAsync(cancellationToken)) { await transaction.RollbackAsync(cancellationToken); return; }
            rowId = reader.GetInt64(0); evidence = ParseEvidenceCodes(reader.GetString(1));
            processCorrelationId = reader.IsDBNull(2) ? null : Guid.Parse(reader.GetString(2));
            processTimestamp = DateTimeOffset.Parse(reader.GetString(3), CultureInfo.InvariantCulture);
        }
        var codes = evidence.ToList();
        void AddCode(string code) { if (codes.Count < 32 && !codes.Contains(code, StringComparer.Ordinal)) codes.Add(code); }
        if (sha256 is not null) AddCode("process.image.sha256.available");
        if (signatureStatus is "Valid" or "NotSigned" or "HashMismatch" or "NotTrusted") AddCode("process.image.authenticode." + signatureStatus.ToLowerInvariant());
        if (localHashMatch == true) AddCode("process.image.local-hash-match");
        using var update = c.CreateCommand(); update.Transaction = transaction;
        update.CommandText = "UPDATE events SET process_image_sha256=$sha256,process_image_signature_status=$signatureStatus,process_image_local_hash_match=$localHashMatch,evidence_codes=$evidence WHERE id=$id";
        update.Parameters.AddWithValue("$sha256", (object?)sha256?.ToUpperInvariant() ?? DBNull.Value);
        update.Parameters.AddWithValue("$signatureStatus", signatureStatus);
        update.Parameters.AddWithValue("$localHashMatch", (object?)(localHashMatch is { } match ? (match ? 1 : 0) : null) ?? DBNull.Value);
        update.Parameters.AddWithValue("$evidence", JsonSerializer.Serialize(codes)); update.Parameters.AddWithValue("$id", rowId);
        await update.ExecuteNonQueryAsync(cancellationToken);
        using var updateObservation = c.CreateCommand(); updateObservation.Transaction = transaction;
        updateObservation.CommandText = "UPDATE event_observations SET evidence_codes=$evidence WHERE event_id=$eventId";
        updateObservation.Parameters.AddWithValue("$evidence", JsonSerializer.Serialize(codes)); updateObservation.Parameters.AddWithValue("$eventId", eventId.ToString("D"));
        await updateObservation.ExecuteNonQueryAsync(cancellationToken);

        if (sha256 is not null)
            await CorrelateProcessWithDownloadedHashAsync(c, transaction, rowId, eventId, sha256.ToUpperInvariant(),
                processTimestamp, processCorrelationId, codes, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    private static async Task CorrelateProcessWithDownloadedHashAsync(SqliteConnection connection, SqliteTransaction transaction,
        long processRowId, Guid processEventId, string sha256, DateTimeOffset processTimestamp, Guid? processCorrelationId,
        List<string> processEvidence, CancellationToken cancellationToken)
    {
        var from = processTimestamp.ToUniversalTime().AddMinutes(-10).ToString("O", CultureInfo.InvariantCulture);
        var to = processTimestamp.ToUniversalTime().AddMinutes(10).ToString("O", CultureInfo.InvariantCulture);
        using var find = connection.CreateCommand(); find.Transaction = transaction;
        find.CommandText = "SELECT id,event_id,evidence_codes,correlation_id FROM events WHERE source='downloads-local-hash' AND signal_hash=$hash AND timestamp BETWEEN $from AND $to ORDER BY ABS(julianday(timestamp)-julianday($timestamp)) LIMIT 20";
        find.Parameters.AddWithValue("$hash", sha256); find.Parameters.AddWithValue("$from", from); find.Parameters.AddWithValue("$to", to);
        find.Parameters.AddWithValue("$timestamp", processTimestamp.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        var candidates = new List<(long RowId, Guid EventId, IReadOnlyList<string> Evidence, Guid? CorrelationId)>();
        await using (var reader = await find.ExecuteReaderAsync(cancellationToken))
            while (await reader.ReadAsync(cancellationToken))
                if (Guid.TryParse(reader.GetString(1), out var downloadEventId))
                    candidates.Add((reader.GetInt64(0), downloadEventId, ParseEvidenceCodes(reader.GetString(2)),
                        reader.IsDBNull(3) ? null : Guid.Parse(reader.GetString(3))));

        foreach (var candidate in candidates)
        {
            if (processCorrelationId is { } existingProcessId && candidate.CorrelationId is { } existingDownloadId && existingProcessId != existingDownloadId)
                continue;
            var correlationId = processCorrelationId ?? candidate.CorrelationId ?? Guid.NewGuid();
            const string evidenceCode = "correlation.download-process.same-sha256";
            if (!processEvidence.Contains(evidenceCode, StringComparer.Ordinal)) processEvidence.Add(evidenceCode);
            var downloadEvidence = candidate.Evidence.ToList();
            if (!downloadEvidence.Contains(evidenceCode, StringComparer.Ordinal)) downloadEvidence.Add(evidenceCode);

            using (var updateProcess = connection.CreateCommand())
            {
                updateProcess.Transaction = transaction;
                updateProcess.CommandText = "UPDATE events SET correlation_id=$correlationId,evidence_codes=$evidence WHERE id=$id";
                updateProcess.Parameters.AddWithValue("$correlationId", correlationId.ToString("D"));
                updateProcess.Parameters.AddWithValue("$evidence", JsonSerializer.Serialize(processEvidence));
                updateProcess.Parameters.AddWithValue("$id", processRowId);
                await updateProcess.ExecuteNonQueryAsync(cancellationToken);
            }
            using (var updateDownload = connection.CreateCommand())
            {
                updateDownload.Transaction = transaction;
                updateDownload.CommandText = "UPDATE events SET correlation_id=$correlationId,evidence_codes=$evidence WHERE id=$id";
                updateDownload.Parameters.AddWithValue("$correlationId", correlationId.ToString("D"));
                updateDownload.Parameters.AddWithValue("$evidence", JsonSerializer.Serialize(downloadEvidence));
                updateDownload.Parameters.AddWithValue("$id", candidate.RowId);
                await updateDownload.ExecuteNonQueryAsync(cancellationToken);
            }
            using (var observations = connection.CreateCommand())
            {
                observations.Transaction = transaction;
                observations.CommandText = "UPDATE event_observations SET evidence_codes=$evidence WHERE event_id=$eventId";
                observations.Parameters.AddWithValue("$evidence", JsonSerializer.Serialize(processEvidence));
                observations.Parameters.AddWithValue("$eventId", processEventId.ToString("D"));
                await observations.ExecuteNonQueryAsync(cancellationToken);
            }
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
        command.CommandText = "SELECT event_id,process_image_path FROM events WHERE source='process-snapshot' AND process_image_signature_status='Pending' AND event_id IS NOT NULL AND process_image_path IS NOT NULL ORDER BY id LIMIT 33";
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

    /// <summary>Restores local events and settings from a verified v6-v38 backup, preserving installed identity and active monitor baselines.</summary>
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
            if (backupVersion is < 6 or > 38)
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

