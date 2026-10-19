using Microsoft.Data.Sqlite;

namespace Sentinel.Core;

public sealed record DatabaseStorageMetrics(
    long DatabaseBytes,
    long WriteAheadLogBytes,
    long SharedMemoryBytes,
    long TotalBytes,
    long PageCount,
    long FreePages,
    long RecordCount);

internal static class DatabaseStorageMetricsReader
{
    public static async Task<DatabaseStorageMetrics> ReadAsync(
        string databasePath,
        string recordCountQuery,
        CancellationToken cancellationToken = default)
    {
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path.GetFullPath(databasePath),
            Pooling = false
        }.ToString();
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        var pageCount = await ReadInt64Async(connection, "PRAGMA page_count", cancellationToken);
        var pageSize = await ReadInt64Async(connection, "PRAGMA page_size", cancellationToken);
        var freePages = await ReadInt64Async(connection, "PRAGMA freelist_count", cancellationToken);
        var recordCount = await ReadInt64Async(connection, recordCountQuery, cancellationToken);

        var databaseBytes = GetFileLength(databasePath);
        var walBytes = GetFileLength(databasePath + "-wal");
        var sharedMemoryBytes = GetFileLength(databasePath + "-shm");
        return new DatabaseStorageMetrics(databaseBytes, walBytes, sharedMemoryBytes,
            checked(databaseBytes + walBytes + sharedMemoryBytes), checked(pageCount * pageSize), freePages, recordCount);
    }

    private static async Task<long> ReadInt64Async(SqliteConnection connection, string sql, CancellationToken cancellationToken)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static long GetFileLength(string path) => File.Exists(path) ? new FileInfo(path).Length : 0;
}
