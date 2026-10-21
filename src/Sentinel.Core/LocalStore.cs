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
        var found = false;
        using (var inspect = connection.CreateCommand())
        {
            inspect.CommandText = $"PRAGMA table_info({table})";
            await using var reader = await inspect.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
                if (string.Equals(reader.GetString(1), column, StringComparison.OrdinalIgnoreCase)) { found = true; break; }
        }
        if (!found) await Execute(connection, $"ALTER TABLE {table} ADD COLUMN {column} {definition}", ct);
    }
    public Task InitializeAsync(CancellationToken ct = default) => InitializeAsync(null, ct);
    public async Task InitializeAsync(InstalledProductProfile? initialProfile, CancellationToken ct = default)
    {
        initialProfile?.Validate();
        await using var c = await Open(ct);
        using var version = c.CreateCommand(); version.CommandText = "PRAGMA user_version";
        var v = Convert.ToInt32(await version.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
        if (v > 18) throw new InvalidDataException("Nowsza wersja bazy wymaga nowszej aplikacji.");
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
    public async Task<long> AddAsync(SecurityEvent item, CancellationToken cancellationToken = default) =>
        (await AddCoreAsync(item, enqueueEnterprise: true, cancellationToken)).EventRowId;
    /// <summary>Persists a local-only event without adding it to the Enterprise metadata queue.</summary>
    public async Task<long> AddLocalOnlyAsync(SecurityEvent item, CancellationToken cancellationToken = default) =>
        (await AddCoreAsync(item, enqueueEnterprise: false, cancellationToken)).EventRowId;
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
        var validated = items.Select(item => (Item: item, Metadata: ValidateEvent(item))).ToArray();
        await using var c = await Open(cancellationToken);
        using var transaction = c.BeginTransaction();
        foreach (var (item, (eventId, source)) in validated)
        {
            using var command = c.CreateCommand(); command.Transaction = transaction;
            command.CommandText = "INSERT INTO events(timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,signal_hash,process_image_path,process_image_sha256,process_image_signature_status,process_image_local_hash_match) VALUES($t,$r,$c,$a,$e,$n,$s,$eventId,$source,$ruleVersion,$confidence,$schemaVersion,$processId,$processName,$correlationId,$evidenceCodes,$signalHash,$processImagePath,$processImageSha256,$processImageSignatureStatus,$processImageLocalHashMatch)";
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
        using var reader = await query.ExecuteReaderAsync(ct); var keys = new HashSet<string>(StringComparer.Ordinal);
        while (await reader.ReadAsync(ct)) keys.Add(reader.GetString(0));
        return new(initialized, keys, tcpTruncated, udpTruncated);
    }
    public async Task ResetNetworkMonitorSnapshotAsync(CancellationToken ct = default)
    {
        await using var c = await Open(ct); using var transaction = c.BeginTransaction();
        using var command = c.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "DELETE FROM network_endpoint_snapshot; UPDATE network_monitor_metadata SET initialized=0,tcp_truncated=0,udp_truncated=0 WHERE id=1";
        await command.ExecuteNonQueryAsync(ct); await transaction.CommitAsync(ct);
    }
    public async Task<ProcessMonitorSnapshot> ReadProcessMonitorSnapshotAsync(CancellationToken ct = default)
    {
        await using var c = await Open(ct);
        using var metadata = c.CreateCommand(); metadata.CommandText = "SELECT initialized,truncated FROM process_monitor_metadata WHERE id=1";
        await using var metadataReader = await metadata.ExecuteReaderAsync(ct);
        if (!await metadataReader.ReadAsync(ct)) throw new InvalidDataException("Brak metadanych migawki procesów.");
        var initialized = metadataReader.GetInt32(0) == 1;
        var truncated = metadataReader.GetInt32(1) == 1;
        await metadataReader.DisposeAsync();
        using var query = c.CreateCommand(); query.CommandText = "SELECT process_id,process_name FROM process_snapshot ORDER BY process_id LIMIT 10000";
        using var reader = await query.ExecuteReaderAsync(ct); var processes = new Dictionary<int, string>();
        while (await reader.ReadAsync(ct)) processes.Add(reader.GetInt32(0), reader.GetString(1));
        return new(initialized, processes, truncated);
    }
    /// <summary>Atomically records process events and advances the persisted process baseline.</summary>
    public async Task CommitProcessMonitorChangesAsync(IReadOnlyCollection<SecurityEvent> events,
        IReadOnlyCollection<KeyValuePair<int, string>> upserts, IReadOnlyCollection<int> removedProcessIds,
        CancellationToken ct = default, bool truncated = false)
    {
        ArgumentNullException.ThrowIfNull(events); ArgumentNullException.ThrowIfNull(upserts); ArgumentNullException.ThrowIfNull(removedProcessIds);
        if (events.Count > 100 || upserts.Count > 10_000 || removedProcessIds.Count > 10_000)
            throw new ArgumentOutOfRangeException(nameof(events), "Przekroczono limit zmian migawki procesów.");
        foreach (var (processId, processName) in upserts)
            if (processId < 0 || string.IsNullOrWhiteSpace(processName) || processName.Length > 260 || processName.Any(char.IsControl))
                throw new ArgumentException("Nieprawidłowy wpis migawki procesu.", nameof(upserts));
        if (removedProcessIds.Any(processId => processId < 0))
            throw new ArgumentException("Nieprawidłowy PID w migawce procesów.", nameof(removedProcessIds));
        var validated = events.Select(item => (Item: item, Metadata: ValidateEvent(item))).ToArray();
        await using var c = await Open(ct); using var transaction = c.BeginTransaction();
        foreach (var (item, (eventId, source)) in validated)
        {
            using var insert = c.CreateCommand(); insert.Transaction = transaction;
            insert.CommandText = "INSERT INTO events(timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,signal_hash,process_image_path,process_image_sha256,process_image_signature_status,process_image_local_hash_match) VALUES($t,$r,$c,$a,$e,$n,$s,$eventId,$source,$ruleVersion,$confidence,$schemaVersion,$processId,$processName,$correlationId,$evidenceCodes,$signalHash,$processImagePath,$processImageSha256,$processImageSignatureStatus,$processImageLocalHashMatch)";
            AddEventParameters(insert, item, eventId, source); await insert.ExecuteNonQueryAsync(ct);
        }
        foreach (var processId in removedProcessIds)
        {
            using var remove = c.CreateCommand(); remove.Transaction = transaction;
            remove.CommandText = "DELETE FROM process_snapshot WHERE process_id=$processId";
            remove.Parameters.AddWithValue("$processId", processId); await remove.ExecuteNonQueryAsync(ct);
        }
        foreach (var (processId, processName) in upserts)
        {
            using var upsert = c.CreateCommand(); upsert.Transaction = transaction;
            upsert.CommandText = "INSERT INTO process_snapshot(process_id,process_name) VALUES($processId,$processName) ON CONFLICT(process_id) DO UPDATE SET process_name=excluded.process_name";
            upsert.Parameters.AddWithValue("$processId", processId); upsert.Parameters.AddWithValue("$processName", processName); await upsert.ExecuteNonQueryAsync(ct);
        }
        using (var initialized = c.CreateCommand())
        {
            initialized.Transaction = transaction; initialized.CommandText = "UPDATE process_monitor_metadata SET initialized=1,truncated=$truncated WHERE id=1";
            initialized.Parameters.AddWithValue("$truncated", truncated ? 1 : 0);
            await initialized.ExecuteNonQueryAsync(ct);
        }
        await transaction.CommitAsync(ct);
    }
    public async Task<DownloadMonitorSnapshot> ReadDownloadedFileMonitorSnapshotAsync(CancellationToken ct = default)
    {
        await using var c = await Open(ct);
        using var metadata = c.CreateCommand(); metadata.CommandText = "SELECT initialized FROM downloaded_file_monitor_metadata WHERE id=1";
        var initialized = Convert.ToInt32(await metadata.ExecuteScalarAsync(ct) ?? 0, CultureInfo.InvariantCulture) == 1;
        using var query = c.CreateCommand(); query.CommandText = "SELECT path,length,last_write_ticks FROM downloaded_file_snapshot ORDER BY path LIMIT 100000";
        using var reader = await query.ExecuteReaderAsync(ct); var files = new Dictionary<string, DownloadFileFingerprint>(StringComparer.OrdinalIgnoreCase);
        while (await reader.ReadAsync(ct))
        {
            var path = reader.GetString(0); var length = reader.GetInt64(1); var ticks = reader.GetInt64(2);
            if (path.Length is 0 or > 32767 || length < 0 || ticks < 0) throw new InvalidDataException("Nieprawidłowy baseline monitoringu Downloads.");
            files[path] = new(path, length, ticks);
        }
        return new(initialized, files);
    }
    public async Task InitializeDownloadedFileMonitorSnapshotAsync(IReadOnlyCollection<DownloadFileFingerprint> files,
        int maximumFiles = 100_000, CancellationToken ct = default)
    {
        ValidateDownloadedFiles(files, maximumFiles);
        await using var c = await Open(ct); using var transaction = c.BeginTransaction();
        using (var clear = c.CreateCommand()) { clear.Transaction = transaction; clear.CommandText = "DELETE FROM downloaded_file_snapshot"; await clear.ExecuteNonQueryAsync(ct); }
        foreach (var file in files)
            await UpsertDownloadedFileAsync(c, transaction, file, ct);
        using (var initialized = c.CreateCommand())
        {
            initialized.Transaction = transaction; initialized.CommandText = "UPDATE downloaded_file_monitor_metadata SET initialized=1 WHERE id=1";
            await initialized.ExecuteNonQueryAsync(ct);
        }
        await transaction.CommitAsync(ct);
    }
    public async Task PruneDownloadedFileMonitorSnapshotAsync(IReadOnlyCollection<string> currentPaths, int maximumFiles = 100_000, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(currentPaths);
        if (currentPaths.Count > maximumFiles || currentPaths.Any(path => string.IsNullOrWhiteSpace(path) || path.Length > 32767 || !Path.IsPathFullyQualified(path)))
            throw new ArgumentOutOfRangeException(nameof(currentPaths), "Nieprawidłowa lub zbyt duża migawka Downloads.");
        await using var c = await Open(ct); using var transaction = c.BeginTransaction();
        using (var create = c.CreateCommand()) { create.Transaction = transaction; create.CommandText = "CREATE TEMP TABLE current_download_paths(path TEXT PRIMARY KEY COLLATE NOCASE)"; await create.ExecuteNonQueryAsync(ct); }
        foreach (var path in currentPaths)
        {
            using var insert = c.CreateCommand(); insert.Transaction = transaction; insert.CommandText = "INSERT OR IGNORE INTO current_download_paths(path) VALUES($path)";
            insert.Parameters.AddWithValue("$path", Path.GetFullPath(path)); await insert.ExecuteNonQueryAsync(ct);
        }
        using (var prune = c.CreateCommand())
        {
            prune.Transaction = transaction; prune.CommandText = "DELETE FROM downloaded_file_snapshot WHERE NOT EXISTS (SELECT 1 FROM current_download_paths current WHERE current.path=downloaded_file_snapshot.path)";
            await prune.ExecuteNonQueryAsync(ct);
        }
        await transaction.CommitAsync(ct);
    }
    public async Task CommitDownloadedFileMonitorResultAsync(DownloadFileFingerprint file, SecurityEvent? detectedEvent = null, CancellationToken ct = default)
    {
        ValidateDownloadedFile(file);
        var metadata = detectedEvent is null ? default : ValidateEvent(detectedEvent);
        await using var c = await Open(ct); using var transaction = c.BeginTransaction();
        if (detectedEvent is not null)
        {
            using var insert = c.CreateCommand(); insert.Transaction = transaction;
            insert.CommandText = "INSERT INTO events(timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,signal_hash,process_image_path,process_image_sha256,process_image_signature_status,process_image_local_hash_match) VALUES($t,$r,$c,$a,$e,$n,$s,$eventId,$source,$ruleVersion,$confidence,$schemaVersion,$processId,$processName,$correlationId,$evidenceCodes,$signalHash,$processImagePath,$processImageSha256,$processImageSignatureStatus,$processImageLocalHashMatch)";
            AddEventParameters(insert, detectedEvent, metadata.EventId, metadata.Source); await insert.ExecuteNonQueryAsync(ct);
        }
        await UpsertDownloadedFileAsync(c, transaction, file, ct);
        await transaction.CommitAsync(ct);
    }
    public async Task RemoveDownloadedFileMonitorPathAsync(string path, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 32767 || !Path.IsPathFullyQualified(path)) return;
        await using var c = await Open(ct);
        await Execute(c, "DELETE FROM downloaded_file_snapshot WHERE path=$path", ct, ("$path", Path.GetFullPath(path)));
    }
    public async Task ResetDownloadedFileMonitorSnapshotAsync(CancellationToken ct = default)
    {
        await using var c = await Open(ct); using var transaction = c.BeginTransaction();
        using var command = c.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "DELETE FROM downloaded_file_snapshot; UPDATE downloaded_file_monitor_metadata SET initialized=0 WHERE id=1";
        await command.ExecuteNonQueryAsync(ct); await transaction.CommitAsync(ct);
    }
    private static void ValidateDownloadedFiles(IReadOnlyCollection<DownloadFileFingerprint> files, int maximumFiles)
    {
        ArgumentNullException.ThrowIfNull(files);
        if (maximumFiles < 1 || files.Count > maximumFiles) throw new ArgumentOutOfRangeException(nameof(files), "Przekroczono limit baseline'u Downloads.");
        foreach (var file in files) ValidateDownloadedFile(file);
        if (files.Select(file => file.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != files.Count)
            throw new ArgumentException("Migawka Downloads zawiera powtórzone ścieżki.", nameof(files));
    }
    private static void ValidateDownloadedFile(DownloadFileFingerprint file)
    {
        if (string.IsNullOrWhiteSpace(file.Path) || file.Path.Length > 32767 || !Path.IsPathFullyQualified(file.Path) || file.Length < 0 || file.LastWriteTicks < 0)
            throw new ArgumentException("Nieprawidłowy wpis baseline'u Downloads.", nameof(file));
    }
    private static async Task UpsertDownloadedFileAsync(SqliteConnection c, SqliteTransaction transaction, DownloadFileFingerprint file, CancellationToken ct)
    {
        using var command = c.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "INSERT INTO downloaded_file_snapshot(path,length,last_write_ticks) VALUES($path,$length,$ticks) ON CONFLICT(path) DO UPDATE SET length=excluded.length,last_write_ticks=excluded.last_write_ticks";
        command.Parameters.AddWithValue("$path", Path.GetFullPath(file.Path)); command.Parameters.AddWithValue("$length", file.Length); command.Parameters.AddWithValue("$ticks", file.LastWriteTicks);
        await command.ExecuteNonQueryAsync(ct);
    }
    /// <summary>Atomically records monitor events and advances the persisted endpoint baseline.</summary>
    public async Task CommitNetworkMonitorChangesAsync(IReadOnlyCollection<SecurityEvent> events,
        IReadOnlyCollection<string> addedEndpointKeys, IReadOnlyCollection<string> removedEndpointKeys,
        CancellationToken ct = default, bool tcpTruncated = false, bool udpTruncated = false)
    {
        ArgumentNullException.ThrowIfNull(events); ArgumentNullException.ThrowIfNull(addedEndpointKeys); ArgumentNullException.ThrowIfNull(removedEndpointKeys);
        if (events.Count > 100 || addedEndpointKeys.Count > 20_000 || removedEndpointKeys.Count > 20_000)
            throw new ArgumentOutOfRangeException(nameof(events), "Przekroczono limit zmian migawki monitoringu sieci.");
        static void ValidateKeys(IEnumerable<string> keys)
        {
            foreach (var key in keys)
                if (string.IsNullOrEmpty(key) || key.Length > 2048 || key.Any(char.IsControl))
                    throw new ArgumentException("Nieprawidłowy klucz endpointu sieciowego.", nameof(keys));
        }
        ValidateKeys(addedEndpointKeys); ValidateKeys(removedEndpointKeys);
        var validated = events.Select(item => (Item: item, Metadata: ValidateEvent(item))).ToArray();
        await using var c = await Open(ct); using var transaction = c.BeginTransaction();
        foreach (var (item, (eventId, source)) in validated)
        {
            using var insert = c.CreateCommand(); insert.Transaction = transaction;
            insert.CommandText = "INSERT INTO events(timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,signal_hash,process_image_path,process_image_sha256,process_image_signature_status,process_image_local_hash_match) VALUES($t,$r,$c,$a,$e,$n,$s,$eventId,$source,$ruleVersion,$confidence,$schemaVersion,$processId,$processName,$correlationId,$evidenceCodes,$signalHash,$processImagePath,$processImageSha256,$processImageSignatureStatus,$processImageLocalHashMatch)";
            AddEventParameters(insert, item, eventId, source); await insert.ExecuteNonQueryAsync(ct);
        }
        foreach (var key in removedEndpointKeys)
        {
            using var remove = c.CreateCommand(); remove.Transaction = transaction;
            remove.CommandText = "DELETE FROM network_endpoint_snapshot WHERE endpoint_key=$key";
            remove.Parameters.AddWithValue("$key", key); await remove.ExecuteNonQueryAsync(ct);
        }
        foreach (var key in addedEndpointKeys)
        {
            using var add = c.CreateCommand(); add.Transaction = transaction;
            add.CommandText = "INSERT OR IGNORE INTO network_endpoint_snapshot(endpoint_key) VALUES($key)";
            add.Parameters.AddWithValue("$key", key); await add.ExecuteNonQueryAsync(ct);
        }
        using (var initialized = c.CreateCommand())
        {
            initialized.Transaction = transaction; initialized.CommandText = "UPDATE network_monitor_metadata SET initialized=1,tcp_truncated=$tcpTruncated,udp_truncated=$udpTruncated WHERE id=1";
            initialized.Parameters.AddWithValue("$tcpTruncated", tcpTruncated ? 1 : 0);
            initialized.Parameters.AddWithValue("$udpTruncated", udpTruncated ? 1 : 0);
            await initialized.ExecuteNonQueryAsync(ct);
        }
        await transaction.CommitAsync(ct);
    }
    private async Task<(long EventRowId, bool EnterpriseQueueFull)> AddCoreAsync(SecurityEvent item, bool enqueueEnterprise,
        CancellationToken cancellationToken, string? enterpriseCategoryOverride = null, string? enterpriseRuleCodeOverride = null)
    {
        var (eventId, source) = ValidateEvent(item);
        await using var c = await Open(cancellationToken);
        using var transaction = c.BeginTransaction();
        long id;
        var enterpriseQueueFull = false;
        // A retried event id may already be either a canonical event or a merged observation.
        using (var prior = c.CreateCommand())
        {
            prior.Transaction = transaction;
            prior.CommandText = "SELECT event_row_id FROM event_observations WHERE event_id=$eventId";
            prior.Parameters.AddWithValue("$eventId", eventId.ToString("D"));
            var priorId = await prior.ExecuteScalarAsync(cancellationToken);
            if (priorId is not null) id = Convert.ToInt64(priorId, CultureInfo.InvariantCulture);
            else
            {
                var duplicateId = await FindCrossSourceDuplicateAsync(c, transaction, item, source, cancellationToken);
                if (duplicateId is not null)
                {
                    using var observation = c.CreateCommand(); observation.Transaction = transaction;
                    observation.CommandText = "INSERT INTO event_observations(event_id,event_row_id,observed_at,source,evidence_codes) VALUES($eventId,$rowId,$timestamp,$source,$evidence)";
                    observation.Parameters.AddWithValue("$eventId", eventId.ToString("D"));
                    observation.Parameters.AddWithValue("$rowId", duplicateId.Value);
                    observation.Parameters.AddWithValue("$timestamp", item.Timestamp.ToUniversalTime().ToString("O"));
                    observation.Parameters.AddWithValue("$source", source);
                    observation.Parameters.AddWithValue("$evidence", JsonSerializer.Serialize(item.EvidenceCodes ?? Array.Empty<string>()));
                    await observation.ExecuteNonQueryAsync(cancellationToken);
                    id = duplicateId.Value;
                }
                else
                {
                    using var insert = c.CreateCommand(); insert.Transaction = transaction;
                    insert.CommandText = "INSERT INTO events(timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,signal_hash,process_image_path,process_image_sha256,process_image_signature_status,process_image_local_hash_match) VALUES($t,$r,$c,$a,$e,$n,$s,$eventId,$source,$ruleVersion,$confidence,$schemaVersion,$processId,$processName,$correlationId,$evidenceCodes,$signalHash,$processImagePath,$processImageSha256,$processImageSignatureStatus,$processImageLocalHashMatch) ON CONFLICT(event_id) WHERE event_id IS NOT NULL DO NOTHING";
                    AddEventParameters(insert, item, eventId, source);
                    await insert.ExecuteNonQueryAsync(cancellationToken);
                    using var get = c.CreateCommand(); get.Transaction = transaction;
                    get.CommandText = "SELECT id FROM events WHERE event_id=$eventId";
                    get.Parameters.AddWithValue("$eventId", eventId.ToString("D"));
                    var storedId = await get.ExecuteScalarAsync(cancellationToken);
                    if (storedId is null) throw new InvalidDataException("Nie udało się odczytać zapisanego zdarzenia.");
                    id = Convert.ToInt64(storedId, CultureInfo.InvariantCulture);
                    using var updateObservation = c.CreateCommand(); updateObservation.Transaction = transaction;
                    updateObservation.CommandText = "UPDATE event_observations SET evidence_codes=$evidence WHERE event_id=$eventId";
                    updateObservation.Parameters.AddWithValue("$evidence", JsonSerializer.Serialize(item.EvidenceCodes ?? Array.Empty<string>()));
                    updateObservation.Parameters.AddWithValue("$eventId", eventId.ToString("D"));
                    await updateObservation.ExecuteNonQueryAsync(cancellationToken);
                }
            }
        }
        if (enqueueEnterprise && item.Risk >= RiskLevel.Moderate && Enum.IsDefined(item.Risk))
        {
            using var profileRead = c.CreateCommand(); profileRead.Transaction = transaction;
            profileRead.CommandText = "SELECT json FROM installation_profile WHERE id=1";
            var profileJson = await profileRead.ExecuteScalarAsync(cancellationToken) as string;
            var profile = profileJson is null ? null : JsonSerializer.Deserialize<InstalledProductProfile>(profileJson)?.Validate();
            if (profile is { Variant: ProductVariant.EnterpriseClient, ShareSecurityMetadata: true } &&
                item.Timestamp <= DateTimeOffset.UtcNow.AddMinutes(5) && item.Timestamp >= DateTimeOffset.UtcNow.AddDays(-30))
            {
                var category = enterpriseCategoryOverride ?? MapEnterpriseCategory(item, source);
                var ruleCode = enterpriseRuleCodeOverride ?? "local." + category;
                enterpriseQueueFull = !await EnqueueEnterpriseEventCoreAsync(c, transaction, new PendingEnterpriseEvent(eventId, item.Timestamp, category,
                    (int)item.Risk, ruleCode, EnterpriseEventV1Rules.NormalizeSource(source),
                    EnterpriseEventV1Rules.NormalizeRuleVersion(item.RuleVersion), item.SchemaVersion), cancellationToken);
            }
        }
        await transaction.CommitAsync(cancellationToken);
        return (id, enterpriseQueueFull);
    }
    private static bool HasCertEvidence(IEnumerable<string>? evidence) => evidence?.Any(code =>
        string.Equals(code, "reputation.cert", StringComparison.Ordinal) ||
        code.StartsWith("reputation.cert.", StringComparison.Ordinal)) == true;
    private static bool HasFileReputationEvidence(IEnumerable<string>? evidence) => evidence?.Any(code =>
        string.Equals(code, "file.sha256.matches-local-list", StringComparison.Ordinal)) == true;
    private static bool HasUrlRuleEvidence(IEnumerable<string>? evidence) => evidence?.Any(code =>
        code.StartsWith("url.", StringComparison.Ordinal)) == true;
    private static async Task<long?> FindCrossSourceDuplicateAsync(SqliteConnection c, SqliteTransaction transaction,
        SecurityEvent item, string source, CancellationToken ct)
    {
        var isCertSignal = HasCertEvidence(item.EvidenceCodes);
        var isFileSignal = HasFileReputationEvidence(item.EvidenceCodes);
        var isUrlSignal = !isCertSignal && HasUrlRuleEvidence(item.EvidenceCodes) && (source is "manual-analysis" or "browser-extension");
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
                    : HasUrlRuleEvidence(codes) && (observationSource is "manual-analysis" or "browser-extension");
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
        cmd.CommandText = "SELECT id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,signal_hash,process_image_path,process_image_sha256,process_image_signature_status,process_image_local_hash_match FROM events ORDER BY id DESC LIMIT 500";
        using var r = await cmd.ExecuteReaderAsync(cancellationToken); var rows = new List<SecurityEvent>();
        while (await r.ReadAsync(cancellationToken)) rows.Add(new(r.GetInt64(0), DateTimeOffset.Parse(r.GetString(1), CultureInfo.InvariantCulture),
            (RiskLevel)r.GetInt32(2), r.GetString(3), r.GetString(4), r.GetString(5), r.GetString(6), (EventStatus)r.GetInt32(7),
            r.IsDBNull(8) ? null : Guid.Parse(r.GetString(8)), r.IsDBNull(9) ? null : r.GetString(9),
            r.IsDBNull(10) ? null : r.GetString(10), r.IsDBNull(11) ? null : r.GetInt32(11), r.GetInt32(12),
            r.IsDBNull(13) ? null : r.GetInt32(13), r.IsDBNull(14) ? null : r.GetString(14), r.IsDBNull(15) ? null : Guid.Parse(r.GetString(15)), ParseEvidenceCodes(r.IsDBNull(16) ? null : r.GetString(16)), r.IsDBNull(17) ? null : r.GetString(17),
            ProcessImagePath: r.IsDBNull(18) ? null : r.GetString(18), ProcessImageSha256: r.IsDBNull(19) ? null : r.GetString(19),
            ProcessImageSignatureStatus: r.IsDBNull(20) ? null : r.GetString(20), ProcessImageLocalHashMatch: r.IsDBNull(21) ? null : r.GetInt32(21) != 0));
        await r.DisposeAsync();
        return await AttachObservationsAsync(c, rows, cancellationToken);
    }
    public async Task<int> CountEventsAsync(CancellationToken cancellationToken = default)
    {
        await using var c = await Open(cancellationToken); using var command = c.CreateCommand(); command.CommandText = "SELECT COUNT(*) FROM events";
        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
    }
    public async Task UpdateProcessImageInspectionAsync(Guid eventId, string? sha256, string signatureStatus, bool? localHashMatch, CancellationToken cancellationToken = default)
    {
        if (eventId == Guid.Empty || signatureStatus is not ("Valid" or "NotSigned" or "HashMismatch" or "NotTrusted" or "Unknown" or "Unavailable" or "TooLarge" or "QueueFull"))
            throw new ArgumentException("Nieprawidłowy wynik inspekcji pliku procesu.");
        if (sha256 is not null && (sha256.Length != 64 || sha256.Any(character => !Uri.IsHexDigit(character))))
            throw new ArgumentException("Nieprawidłowy SHA-256 pliku procesu.");
        await using var c = await Open(cancellationToken); using var transaction = c.BeginTransaction();
        using var read = c.CreateCommand(); read.Transaction = transaction;
        read.CommandText = "SELECT id,evidence_codes FROM events WHERE event_id=$eventId AND process_image_path IS NOT NULL AND source='process-snapshot'";
        read.Parameters.AddWithValue("$eventId", eventId.ToString("D"));
        long rowId; IReadOnlyList<string> evidence;
        await using (var reader = await read.ExecuteReaderAsync(cancellationToken))
        {
            if (!await reader.ReadAsync(cancellationToken)) { await transaction.RollbackAsync(cancellationToken); return; }
            rowId = reader.GetInt64(0); evidence = ParseEvidenceCodes(reader.GetString(1));
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
        await transaction.CommitAsync(cancellationToken);
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
        await writer.WriteLineAsync("id,timestamp_utc,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,observations");
        foreach (var row in rows)
        {
            ct.ThrowIfCancellationRequested();
            var values = new string?[] { row.Id.ToString(CultureInfo.InvariantCulture), row.Timestamp.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture), row.Risk.ToString(), row.Category, row.Application, row.Explanation, row.Recommendation, row.Status.ToString(), row.EventId?.ToString("D"), row.Source, row.RuleVersion, row.Confidence?.ToString(CultureInfo.InvariantCulture), row.SchemaVersion.ToString(CultureInfo.InvariantCulture), row.ProcessId?.ToString(CultureInfo.InvariantCulture), row.ProcessName, row.CorrelationId?.ToString("D"), string.Join('|', row.EvidenceCodes ?? []), JsonSerializer.Serialize(row.Observations ?? []) };
            await writer.WriteLineAsync(string.Join(',', values.Select(CsvField)));
        }
    }
    private async Task<List<SecurityEvent>> ReadAllEventsForExportAsync(CancellationToken ct)
    {
        // Export all retained rows, independent of the UI's 500-row limit.
        await using var c = await Open(ct); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT id,timestamp,risk,category,application,explanation,recommendation,status,event_id,source,rule_version,confidence,schema_version,process_id,process_name,correlation_id,evidence_codes,signal_hash FROM events ORDER BY id";
        using var r = await cmd.ExecuteReaderAsync(ct); var rows = new List<SecurityEvent>();
        while (await r.ReadAsync(ct)) rows.Add(new(r.GetInt64(0),DateTimeOffset.Parse(r.GetString(1),CultureInfo.InvariantCulture),(RiskLevel)r.GetInt32(2),r.GetString(3),r.GetString(4),r.GetString(5),r.GetString(6),(EventStatus)r.GetInt32(7),
            r.IsDBNull(8) ? null : Guid.Parse(r.GetString(8)), r.IsDBNull(9) ? null : r.GetString(9),
            r.IsDBNull(10) ? null : r.GetString(10), r.IsDBNull(11) ? null : r.GetInt32(11), r.GetInt32(12),
            r.IsDBNull(13) ? null : r.GetInt32(13), r.IsDBNull(14) ? null : r.GetString(14), r.IsDBNull(15) ? null : Guid.Parse(r.GetString(15)), ParseEvidenceCodes(r.IsDBNull(16) ? null : r.GetString(16)), r.IsDBNull(17) ? null : r.GetString(17)));
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
            command.CommandText = $"SELECT event_row_id,event_id,observed_at,source,evidence_codes FROM event_observations WHERE event_row_id IN ({string.Join(',', parameters)}) ORDER BY observed_at,event_id";
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var rowId = reader.GetInt64(0);
                if (!byId.TryGetValue(rowId, out var observations)) byId[rowId] = observations = [];
                observations.Add(new(Guid.Parse(reader.GetString(1)), DateTimeOffset.Parse(reader.GetString(2), CultureInfo.InvariantCulture),
                    reader.GetString(3), ParseEvidenceCodes(reader.GetString(4))));
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

    /// <summary>Restores the local event/settings queue from a verified v6-v17 backup, preserving installed identity and active monitor baselines.</summary>
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
            if (backupVersion is not (6 or 7 or 8 or 9 or 10 or 11 or 12 or 13 or 14 or 15 or 16 or 17 or 18))
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
            var expectedTables = backupVersion >= 17 ? 13 : backupVersion == 16 ? 12 : backupVersion is 13 or 14 or 15 ? 11 : backupVersion is 9 or 10 or 11 or 12 ? 10 : backupVersion == 8 ? 8 : backupVersion == 7 ? 6 : 4;
            if (Convert.ToInt32(await required.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture) != expectedTables)
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
            var eventRestore = backupVersion >= 18
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
                """ + eventRestore + (backupVersion >= 16
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
