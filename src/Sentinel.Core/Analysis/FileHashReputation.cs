using Microsoft.Data.Sqlite;
using System.Globalization;
using System.Text;

namespace Sentinel.Core.Analysis;

public sealed record FileHashReputationStatus(int HashCount, DateTimeOffset? ImportedAt);
public sealed record FileHashReputationCheck(bool FeedImported, bool Match);

/// <summary>Exact SHA-256 lookups against a user-imported local list. No verdict is inferred from absence.</summary>
public sealed class FileHashReputation
{
    public const int MaximumFeedBytes = 20 * 1024 * 1024;
    public const int MaximumHashes = 250_000;
    private readonly string connectionString;

    public FileHashReputation(string directory)
    {
        Directory.CreateDirectory(directory);
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(directory, "file-reputation.db"),
            Pooling = false
        }.ToString();
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "CREATE TABLE IF NOT EXISTS hashes(sha256 TEXT PRIMARY KEY CHECK(length(sha256)=64)); CREATE TABLE IF NOT EXISTS metadata(id INTEGER PRIMARY KEY CHECK(id=1), imported_at TEXT NOT NULL);";
        command.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        return connection;
    }

    public FileHashReputationStatus Status()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT (SELECT COUNT(*) FROM hashes), (SELECT imported_at FROM metadata WHERE id=1)";
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return new(0, null);
        var count = reader.GetInt32(0);
        DateTimeOffset? importedAt = reader.IsDBNull(1) ? null : DateTimeOffset.Parse(reader.GetString(1), CultureInfo.InvariantCulture);
        return new(count, importedAt);
    }

    public FileHashReputationCheck Check(string sha256)
    {
        var normalized = Normalize(sha256);
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT EXISTS(SELECT 1 FROM hashes WHERE sha256=$hash)";
        command.Parameters.AddWithValue("$hash", normalized);
        var imported = Status().HashCount > 0;
        var match = Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture) != 0;
        return new(imported, match);
    }

    public async Task<FileHashReputationStatus> ImportFileAsync(string path, CancellationToken cancellationToken = default)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > MaximumFeedBytes) throw new InvalidDataException("Lista hashy przekracza limit 20 MiB.");
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
        var content = new StringBuilder();
        var buffer = new char[8192];
        int read;
        while ((read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken)) > 0)
        {
            if (content.Length + read > MaximumFeedBytes) throw new InvalidDataException("Lista hashy przekracza limit 20 MiB.");
            content.Append(buffer, 0, read);
        }
        Import(content.ToString(), DateTimeOffset.UtcNow);
        return Status();
    }

    public void Import(string content, DateTimeOffset importedAt)
    {
        if (content.Length > MaximumFeedBytes) throw new InvalidDataException("Lista hashy przekracza limit 20 MiB.");
        var values = content.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line => !line.StartsWith('#'))
            .Select(Normalize)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (values.Length is 0 or > MaximumHashes) throw new InvalidDataException($"Lista musi zawierać od 1 do {MaximumHashes} unikalnych hashy SHA-256.");

        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using var delete = connection.CreateCommand();
        delete.Transaction = transaction;
        delete.CommandText = "DELETE FROM hashes";
        delete.ExecuteNonQuery();

        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = "INSERT INTO hashes(sha256) VALUES($hash)";
        var parameter = insert.Parameters.Add("$hash", SqliteType.Text);
        foreach (var value in values)
        {
            parameter.Value = value;
            insert.ExecuteNonQuery();
        }

        using var metadata = connection.CreateCommand();
        metadata.Transaction = transaction;
        metadata.CommandText = "INSERT OR REPLACE INTO metadata(id,imported_at) VALUES(1,$time)";
        metadata.Parameters.AddWithValue("$time", importedAt.ToString("O", CultureInfo.InvariantCulture));
        metadata.ExecuteNonQuery();
        transaction.Commit();
    }

    private static string Normalize(string value)
    {
        var hash = value.Trim();
        if (hash.Length != 64 || hash.Any(character => !Uri.IsHexDigit(character)))
            throw new InvalidDataException("Każdy wpis listy musi być pojedynczym 64-znakowym hashem SHA-256 w zapisie szesnastkowym.");
        return hash.ToUpperInvariant();
    }
}
