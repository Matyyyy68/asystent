using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Sentinel.Core.Analysis;

public sealed record ReputationStatus(int Count, DateTimeOffset? FetchedAt, string? Version, bool Expired);
public sealed record DomainFeedRefreshCheckpoint(DateTimeOffset? LastAttemptAt, string? LastErrorCode);

/// <summary>CERT domain and subdomain reputation. Never infer IP reputation from a domain.</summary>
public sealed class DomainReputation
{
    public const string FeedUrl = "https://hole.cert.pl/domains/v2/domains.txt";
    private readonly string connectionString;
    private readonly SemaphoreSlim updateGate = new(1, 1);
    private readonly DomainNames domains = new();
    public DomainReputation(string directory)
    {
        Directory.CreateDirectory(directory);
        connectionString = new SqliteConnectionStringBuilder { DataSource = Path.Combine(directory, "reputation.db"), Pooling = false }.ToString();
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS domains(value TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS previous_domains(value TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS metadata(id INTEGER PRIMARY KEY CHECK(id IN (1,2)), fetched TEXT NOT NULL, version TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS auto_refresh_checkpoint(id INTEGER PRIMARY KEY CHECK(id=1), attempted TEXT NOT NULL, error_code TEXT);
            PRAGMA user_version=1;
            """;
        cmd.ExecuteNonQuery();
    }
    private SqliteConnection Open() { var c = new SqliteConnection(connectionString); c.Open(); return c; }
    public DomainFeedRefreshCheckpoint AutoRefreshCheckpoint()
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT attempted,error_code FROM auto_refresh_checkpoint WHERE id=1";
        using var reader = cmd.ExecuteReader();
        return reader.Read()
            ? new(DateTimeOffset.Parse(reader.GetString(0), CultureInfo.InvariantCulture), reader.IsDBNull(1) ? null : reader.GetString(1))
            : new(null, null);
    }
    public void SaveAutoRefreshCheckpoint(DateTimeOffset attemptedAt, string? errorCode)
    {
        if (errorCode is { Length: > 64 } || errorCode is not null && errorCode.Any(character => !char.IsAsciiLetterOrDigit(character)))
            throw new ArgumentException("Invalid automatic-refresh error code.", nameof(errorCode));
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT OR REPLACE INTO auto_refresh_checkpoint(id,attempted,error_code) VALUES(1,$attempted,$error)";
        cmd.Parameters.AddWithValue("$attempted", attemptedAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        cmd.Parameters.AddWithValue("$error", (object?)errorCode ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }
    public static string Normalize(string domain)
    {
        var value = new IdnMapping().GetAscii(domain.Trim().TrimEnd('.')).ToLowerInvariant();
        if (value.Length > 253 || !value.Contains('.') || Uri.CheckHostName(value) != UriHostNameType.Dns
            || IPAddress.TryParse(value, out _) || value.Split('.').Any(s => s.Length is 0 or > 63))
            throw new InvalidDataException("Nieprawidłowa domena w feedzie.");
        return value;
    }
    public ReputationStatus Status(DateTimeOffset now)
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT (SELECT COUNT(*) FROM domains), fetched, version FROM metadata WHERE id=1";
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return new(0, null, null, true);
        var count = r.GetInt32(0);
        var fetched = DateTimeOffset.Parse(r.GetString(1), CultureInfo.InvariantCulture);
        return new(count, fetched, r.GetString(2), count == 0 || now < fetched || now - fetched > TimeSpan.FromHours(48));
    }
    public bool Contains(string domain, DateTimeOffset now)
    {
        if (Status(now).Expired) return false;
        string normalized;
        try { normalized = Normalize(domain); } catch (ArgumentException) { return false; } catch (InvalidDataException) { return false; }
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM domains WHERE value=$value";
        var parameter = cmd.Parameters.Add("$value", SqliteType.Text);
        return HasListedDomainAncestor(normalized, cmd, parameter);
    }
    public IReadOnlyList<string> FindMatches(IEnumerable<string> candidates, DateTimeOffset now)
    {
        if (Status(now).Expired) return [];
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM domains WHERE value=$value";
        var parameter = cmd.Parameters.Add("$value", SqliteType.Text);
        var matches = new List<string>();
        foreach (var candidate in candidates.Take(2000).Where(s => !string.IsNullOrWhiteSpace(s)))
        {
            string normalized;
            try { normalized = Normalize(candidate); }
            catch (ArgumentException) { continue; }
            catch (InvalidDataException) { continue; }
            if (HasListedDomainAncestor(normalized, cmd, parameter)) matches.Add(normalized);
        }
        return matches.Distinct().ToArray();
    }
    private bool HasListedDomainAncestor(string host, SqliteCommand command, SqliteParameter parameter)
    {
        var labels = host.Split('.');
        for (var start = 0; start < labels.Length - 1; start++)
        {
            var candidate = string.Join('.', labels, start, labels.Length - start);
            // Never let a feed entry that is itself a public suffix match all its tenants.
            if (domains.RegistrableDomain(candidate) is null) continue;
            parameter.Value = candidate;
            if (command.ExecuteScalar() is not null) return true;
        }
        return false;
    }
    public void Import(string content, DateTimeOffset fetched)
    {
        if (content.Length > 20 * 1024 * 1024) throw new InvalidDataException("Feed przekracza limit 20 MiB.");
        var domains = content.Split('\n').Select(s => s.Trim()).Where(s => s.Length > 0).Select(Normalize).Distinct().ToArray();
        if (domains.Length is 0 or > 500000) throw new InvalidDataException("Nieprawidłowa liczba rekordów.");
        var version = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content)));
        using var c = Open(); using var tx = c.BeginTransaction();
        using var prepare = c.CreateCommand(); prepare.Transaction = tx;
        prepare.CommandText = "DELETE FROM previous_domains; INSERT INTO previous_domains SELECT value FROM domains; DELETE FROM metadata WHERE id=2; INSERT INTO metadata SELECT 2,fetched,version FROM metadata WHERE id=1; DELETE FROM domains;";
        prepare.ExecuteNonQuery();
        using var insert = c.CreateCommand(); insert.Transaction = tx; insert.CommandText = "INSERT INTO domains(value) VALUES($value)";
        var parameter = insert.Parameters.Add("$value", SqliteType.Text);
        foreach (var value in domains) { parameter.Value = value; insert.ExecuteNonQuery(); }
        using var meta = c.CreateCommand(); meta.Transaction = tx;
        meta.CommandText = "INSERT OR REPLACE INTO metadata VALUES(1,$fetched,$version)";
        meta.Parameters.AddWithValue("$fetched", fetched.ToString("O")); meta.Parameters.AddWithValue("$version", version);
        meta.ExecuteNonQuery(); tx.Commit();
    }
    public void Rollback()
    {
        using var c = Open(); using var tx = c.BeginTransaction(); using var cmd = c.CreateCommand(); cmd.Transaction = tx;
        cmd.CommandText = "SELECT COUNT(*) FROM metadata WHERE id=2";
        if (Convert.ToInt32(cmd.ExecuteScalar(), CultureInfo.InvariantCulture) == 0) throw new InvalidDataException("Brak poprzedniej wersji.");
        cmd.CommandText = "DELETE FROM domains; INSERT INTO domains SELECT value FROM previous_domains; DELETE FROM metadata WHERE id=1; INSERT INTO metadata SELECT 1,fetched,version FROM metadata WHERE id=2; DELETE FROM metadata WHERE id=2; DELETE FROM previous_domains;";
        cmd.ExecuteNonQuery(); tx.Commit();
    }
    public async Task UpdateAsync(CancellationToken ct = default)
    {
        await updateGate.WaitAsync(ct);
        try
        {
            var now = DateTimeOffset.UtcNow;
            if (Status(now).FetchedAt is { } last && now - last < TimeSpan.FromMinutes(5))
                throw new InvalidDataException("Poczekaj 5 minut między aktualizacjami.");
            using var handler = new HttpClientHandler { AllowAutoRedirect = false };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30), MaxResponseContentBufferSize = 20 * 1024 * 1024 };
            // This fixed source receives no browsing data. Redirects and arbitrary URLs are forbidden.
            using var response = await http.GetAsync(FeedUrl, ct);
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync(ct);
            Import(content, now);
        }
        finally { updateGate.Release(); }
    }
}
