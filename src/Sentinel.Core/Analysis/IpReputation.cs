using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Sentinel.Core.Analysis;

public sealed record IpReputationStatus(int NetworkCount, DateTimeOffset? ImportedAt);

/// <summary>Offline matches against an explicitly imported local IP/CIDR list. A miss is not a safety verdict.</summary>
public sealed class IpReputation
{
    public const int MaximumFeedBytes = 20 * 1024 * 1024;
    public const int MaximumNetworks = 250_000;
    private readonly string connectionString;
    private volatile HashSet<string> networks = new(StringComparer.Ordinal);

    public IpReputation(string directory)
    {
        Directory.CreateDirectory(directory);
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(directory, "ip-reputation.db"), Pooling = false
        }.ToString();
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "CREATE TABLE IF NOT EXISTS networks(value TEXT PRIMARY KEY); CREATE TABLE IF NOT EXISTS metadata(id INTEGER PRIMARY KEY CHECK(id=1), imported_at TEXT NOT NULL);";
        command.ExecuteNonQuery();
        networks = LoadNetworks();
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        return connection;
    }

    public IpReputationStatus Status()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT (SELECT COUNT(*) FROM networks), (SELECT imported_at FROM metadata WHERE id=1)";
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return new(0, null);
        return new(reader.GetInt32(0), reader.IsDBNull(1) ? null : DateTimeOffset.Parse(reader.GetString(1), CultureInfo.InvariantCulture));
    }

    public bool Contains(string address)
    {
        if (!TryNormalizeAddress(address, out var ip)) return false;
        var bytes = ip.GetAddressBytes();
        var maxPrefix = bytes.Length * 8;
        var current = networks;
        for (var prefix = maxPrefix; prefix >= 0; prefix--)
            if (current.Contains(Key(bytes, prefix))) return true;
        return false;
    }

    public IpReputationStatus Clear()
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "DELETE FROM networks; DELETE FROM metadata WHERE id=1;";
        command.ExecuteNonQuery();
        transaction.Commit();
        networks = new HashSet<string>(StringComparer.Ordinal);
        return new(0, null);
    }

    public async Task<IpReputationStatus> ImportFileAsync(string path, CancellationToken cancellationToken = default)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > MaximumFeedBytes) throw new InvalidDataException("Lista IP przekracza limit 20 MiB.");
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
        var content = new StringBuilder();
        var buffer = new char[8192];
        int read;
        while ((read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken)) > 0)
        {
            if (content.Length + read > MaximumFeedBytes) throw new InvalidDataException("Lista IP przekracza limit 20 MiB.");
            content.Append(buffer, 0, read);
        }
        Import(content.ToString(), DateTimeOffset.UtcNow);
        return Status();
    }

    public void Import(string content, DateTimeOffset importedAt)
    {
        if (content.Length > MaximumFeedBytes) throw new InvalidDataException("Lista IP przekracza limit 20 MiB.");
        var entries = content.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => line.Split('#', 2)[0].Trim())
            .Where(line => line.Length > 0)
            .Select(ParseNetwork)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (entries.Length is 0 or > MaximumNetworks)
            throw new InvalidDataException($"Lista musi zawierać od 1 do {MaximumNetworks} unikalnych adresów IP lub sieci CIDR.");

        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using var delete = connection.CreateCommand();
        delete.Transaction = transaction;
        delete.CommandText = "DELETE FROM networks";
        delete.ExecuteNonQuery();
        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = "INSERT INTO networks(value) VALUES($value)";
        var parameter = insert.Parameters.Add("$value", SqliteType.Text);
        foreach (var entry in entries)
        {
            parameter.Value = entry;
            insert.ExecuteNonQuery();
        }
        using var metadata = connection.CreateCommand();
        metadata.Transaction = transaction;
        metadata.CommandText = "INSERT OR REPLACE INTO metadata(id,imported_at) VALUES(1,$time)";
        metadata.Parameters.AddWithValue("$time", importedAt.ToString("O", CultureInfo.InvariantCulture));
        metadata.ExecuteNonQuery();
        transaction.Commit();
        networks = entries.ToHashSet(StringComparer.Ordinal);
    }

    private HashSet<string> LoadNetworks()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT value FROM networks";
        using var reader = command.ExecuteReader();
        var result = new HashSet<string>(StringComparer.Ordinal);
        while (reader.Read()) result.Add(reader.GetString(0));
        return result;
    }

    private static string ParseNetwork(string value)
    {
        var parts = value.Split('/', 2, StringSplitOptions.TrimEntries);
        if (!TryNormalizeAddress(parts[0], out var address)) throw new InvalidDataException("Nieprawidłowy adres IP w liście.");
        var prefix = parts.Length == 1 ? address.GetAddressBytes().Length * 8 :
            int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) ? parsed : -1;
        var bytes = address.GetAddressBytes();
        if (prefix < 0 || prefix > bytes.Length * 8) throw new InvalidDataException("Nieprawidłowa długość prefiksu CIDR.");
        return Key(bytes, prefix);
    }

    private static bool TryNormalizeAddress(string value, out IPAddress address)
    {
        if (IPAddress.TryParse(value.Trim().Trim('[', ']'), out var parsed))
        {
            address = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : new IPAddress(parsed.GetAddressBytes());
            return true;
        }
        address = IPAddress.None;
        return false;
    }

    private static string Key(byte[] source, int prefix)
    {
        var bytes = source.ToArray();
        var fullBytes = prefix / 8;
        var remainingBits = prefix % 8;
        if (remainingBits > 0 && fullBytes < bytes.Length)
        {
            bytes[fullBytes] &= (byte)(0xff << (8 - remainingBits));
            fullBytes++;
        }
        Array.Clear(bytes, fullBytes, bytes.Length - fullBytes);
        return (bytes.Length == 4 ? "4" : "6") + ":" + prefix.ToString(CultureInfo.InvariantCulture) + ":" + Convert.ToHexString(bytes);
    }
}
