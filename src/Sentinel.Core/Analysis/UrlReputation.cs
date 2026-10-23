using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Sentinel.Core.Analysis;

public sealed record UrlReputationStatus(int UrlCount, DateTimeOffset? ImportedAt, string? Version, bool Expired,
    bool PreviousAvailable = false);
public sealed record UrlReputationCheck(bool FeedImported, bool Match, string? SignalHash);

/// <summary>Exact matching for a locally supplied URL list. Only URL hashes are persisted.</summary>
public sealed class UrlReputation
{
    public const int MaximumFeedBytes = 20 * 1024 * 1024;
    public const int MaximumUrls = 250_000;
    private readonly string connectionString;

    public UrlReputation(string directory)
    {
        Directory.CreateDirectory(directory);
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(directory, "url-reputation.db"), Pooling = false
        }.ToString();
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS urls(value TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS previous_urls(value TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS metadata(id INTEGER PRIMARY KEY CHECK(id IN (1,2)), imported TEXT NOT NULL, version TEXT NOT NULL);
            PRAGMA user_version=1;
            """;
        command.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        return connection;
    }

    public static string Normalize(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 4096 ||
            !Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("http" or "https") || string.IsNullOrEmpty(uri.Host))
            throw new InvalidDataException("Nieprawidłowy adres HTTP/HTTPS w lokalnej liście URL.");

        var normalized = new UriBuilder(uri) { Fragment = "" }.Uri;
        return normalized.AbsoluteUri;
    }

    public static string CreateSignalHash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Normalize(value))));

    public UrlReputationStatus Status(DateTimeOffset now)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT (SELECT COUNT(*) FROM urls), imported, version, (SELECT COUNT(*) FROM metadata WHERE id=2) > 0 FROM metadata WHERE id=1";
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return new(0, null, null, true);
        var count = reader.GetInt32(0);
        var imported = DateTimeOffset.Parse(reader.GetString(1), CultureInfo.InvariantCulture);
        return new(count, imported, reader.GetString(2), count == 0 || now < imported || now - imported > TimeSpan.FromHours(48),
            reader.GetBoolean(3));
    }

    public UrlReputationCheck Check(string value, DateTimeOffset now)
    {
        var status = Status(now);
        if (status.Expired) return new(false, false, null);
        string hash;
        try { hash = CreateSignalHash(value); }
        catch (InvalidDataException) { return new(true, false, null); }
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1 FROM urls WHERE value=$value";
        command.Parameters.AddWithValue("$value", hash);
        return new(true, command.ExecuteScalar() is not null, hash);
    }

    public void Import(string content, DateTimeOffset importedAt)
    {
        if (Encoding.UTF8.GetByteCount(content) > MaximumFeedBytes)
            throw new InvalidDataException("Lista URL przekracza limit 20 MiB.");
        var hashes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var line in content.Split('\n'))
        {
            var value = line.Trim();
            if (value.Length == 0 || value.StartsWith('#')) continue;
            hashes.Add(CreateSignalHash(value));
            if (hashes.Count > MaximumUrls) throw new InvalidDataException("Lista URL przekracza limit 250 000 wpisów.");
        }
        if (hashes.Count == 0) throw new InvalidDataException("Lista URL nie zawiera poprawnych adresów.");
        var version = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content)));

        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using (var prepare = connection.CreateCommand())
        {
            prepare.Transaction = transaction;
            prepare.CommandText = "DELETE FROM previous_urls; INSERT INTO previous_urls SELECT value FROM urls; DELETE FROM metadata WHERE id=2; INSERT INTO metadata SELECT 2,imported,version FROM metadata WHERE id=1; DELETE FROM urls;";
            prepare.ExecuteNonQuery();
        }
        using (var insert = connection.CreateCommand())
        {
            insert.Transaction = transaction;
            insert.CommandText = "INSERT INTO urls(value) VALUES($value)";
            var parameter = insert.Parameters.Add("$value", SqliteType.Text);
            foreach (var hash in hashes)
            {
                parameter.Value = hash;
                insert.ExecuteNonQuery();
            }
        }
        using (var metadata = connection.CreateCommand())
        {
            metadata.Transaction = transaction;
            metadata.CommandText = "INSERT OR REPLACE INTO metadata VALUES(1,$imported,$version)";
            metadata.Parameters.AddWithValue("$imported", importedAt.ToUniversalTime().ToString("O"));
            metadata.Parameters.AddWithValue("$version", version);
            metadata.ExecuteNonQuery();
        }
        transaction.Commit();
    }

    public async Task<UrlReputationStatus> ImportFileAsync(string path, DateTimeOffset importedAt,
        CancellationToken cancellationToken = default)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length > MaximumFeedBytes) throw new InvalidDataException("Lista URL przekracza limit 20 MiB.");
        using var reader = new StreamReader(stream, new UTF8Encoding(false, true));
        var content = await reader.ReadToEndAsync(cancellationToken);
        Import(content, importedAt);
        return Status(importedAt);
    }

    public void Rollback()
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT COUNT(*) FROM metadata WHERE id=2";
        if (Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture) == 0)
            throw new InvalidDataException("Brak poprzedniej wersji lokalnej listy URL.");
        command.CommandText = "DELETE FROM urls; INSERT INTO urls SELECT value FROM previous_urls; DELETE FROM metadata WHERE id=1; INSERT INTO metadata SELECT 1,imported,version FROM metadata WHERE id=2; DELETE FROM metadata WHERE id=2; DELETE FROM previous_urls;";
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    public UrlReputationStatus Clear()
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "DELETE FROM urls; DELETE FROM previous_urls; DELETE FROM metadata;";
        command.ExecuteNonQuery();
        transaction.Commit();
        return Status(DateTimeOffset.UtcNow);
    }
}
