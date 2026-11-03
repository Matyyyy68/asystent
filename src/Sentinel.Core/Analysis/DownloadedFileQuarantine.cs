using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Sentinel.Core.Analysis;

public sealed record QuarantineResult(Guid EventId, string FileName, string State);

/// <summary>Reversible, user-confirmed quarantine for a file selected from the Downloads tree.</summary>
public sealed class DownloadedFileQuarantine
{
    private const long MaximumFileBytes = 256L * 1024 * 1024;
    private readonly string downloadsRoot;
    private readonly string quarantineRoot;
    private readonly string databasePath;
    private readonly string connectionString;
    private readonly SemaphoreSlim gate = new(1, 1);

    public DownloadedFileQuarantine(string dataDirectory, string downloadsDirectory)
    {
        var dataRoot = Path.GetFullPath(dataDirectory);
        downloadsRoot = Path.GetFullPath(downloadsDirectory);
        quarantineRoot = Path.Combine(dataRoot, "Quarantine");
        databasePath = Path.Combine(dataRoot, "quarantine.db");
        connectionString = new SqliteConnectionStringBuilder { DataSource = databasePath, Pooling = false }.ToString();
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(databasePath)!);
        EnsureNotReparsePoint(Path.GetDirectoryName(databasePath)!);
        if (File.Exists(databasePath)) EnsureNotReparsePoint(databasePath);
        await using var connection = await OpenAsync(cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS quarantine_records(
              event_guid TEXT PRIMARY KEY CHECK(length(event_guid)=36),
              sha256 TEXT NOT NULL CHECK(length(sha256)=64),
              original_path TEXT NOT NULL CHECK(length(original_path) BETWEEN 1 AND 32768),
              quarantine_path TEXT NOT NULL CHECK(length(quarantine_path) BETWEEN 1 AND 32768),
              file_name TEXT NOT NULL CHECK(length(file_name) BETWEEN 1 AND 260),
              created_at TEXT NOT NULL,
              state TEXT NOT NULL CHECK(state IN ('Pending','Quarantined','Restored','NeedsAttention')));
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
        await ReconcilePendingAsync(connection, cancellationToken);
    }

    public async Task<QuarantineResult> QuarantineAsync(Guid eventId, string selectedPath, string expectedSha256,
        CancellationToken cancellationToken = default)
    {
        if (eventId == Guid.Empty) throw new ArgumentOutOfRangeException(nameof(eventId));
        var expectedHash = NormalizeHash(expectedSha256);
        var sourcePath = ValidateDownloadsFile(selectedPath);
        await gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await ReconcilePendingAsync(connection, cancellationToken);
            using (var existing = connection.CreateCommand())
            {
                existing.CommandText = "SELECT state FROM quarantine_records WHERE event_guid=$id";
                existing.Parameters.AddWithValue("$id", eventId.ToString("D"));
                if (await existing.ExecuteScalarAsync(cancellationToken) is string state && state is "Quarantined" or "Pending" or "NeedsAttention")
                    throw new InvalidOperationException("Dla tego zdarzenia istnieje już operacja kwarantanny.");
            }

            var before = new FileInfo(sourcePath);
            if (!before.Exists || before.Length > MaximumFileBytes)
                throw new InvalidOperationException("Wybrany plik nie istnieje albo przekracza limit 256 MiB.");
            var actualHash = await HashStableFileAsync(sourcePath, cancellationToken);
            if (!actualHash.Equals(expectedHash, StringComparison.Ordinal))
                throw new InvalidOperationException("Hash wybranego pliku nie pasuje do wykrycia Sentinel AI.");

            if (IsUnder(quarantineRoot, downloadsRoot) || IsUnder(downloadsRoot, quarantineRoot))
                throw new InvalidOperationException("Folder danych i Downloads nie mogą zawierać się wzajemnie przy użyciu kwarantanny.");
            Directory.CreateDirectory(quarantineRoot);
            EnsureNotReparsePoint(quarantineRoot);
            var destinationPath = Path.Combine(quarantineRoot, $"{eventId:N}-{Guid.NewGuid():N}.quarantined");
            if (!string.Equals(Path.GetPathRoot(sourcePath), Path.GetPathRoot(destinationPath), StringComparison.OrdinalIgnoreCase))
                throw new IOException("Downloads i lokalny folder Sentinel są na różnych woluminach; przeniesienie bezpieczne atomowo nie jest możliwe.");

            using (var begin = connection.CreateCommand())
            {
                begin.CommandText = "INSERT INTO quarantine_records(event_guid,sha256,original_path,quarantine_path,file_name,created_at,state) VALUES($id,$hash,$original,$quarantined,$name,$created,'Pending')";
                begin.Parameters.AddWithValue("$id", eventId.ToString("D"));
                begin.Parameters.AddWithValue("$hash", expectedHash);
                begin.Parameters.AddWithValue("$original", sourcePath);
                begin.Parameters.AddWithValue("$quarantined", destinationPath);
                begin.Parameters.AddWithValue("$name", Path.GetFileName(sourcePath));
                begin.Parameters.AddWithValue("$created", DateTimeOffset.UtcNow.ToString("O"));
                await begin.ExecuteNonQueryAsync(cancellationToken);
            }

            var moved = false;
            try
            {
                File.Move(sourcePath, destinationPath);
                moved = true;
                EnsureNotReparsePoint(destinationPath);
                var movedHash = await HashStableFileAsync(destinationPath, cancellationToken);
                if (!movedHash.Equals(expectedHash, StringComparison.Ordinal))
                    throw new IOException("Plik zmienił się podczas przenoszenia; operacja została cofnięta.");
                using var finish = connection.CreateCommand();
                finish.CommandText = "UPDATE quarantine_records SET state='Quarantined' WHERE event_guid=$id AND state='Pending'";
                finish.Parameters.AddWithValue("$id", eventId.ToString("D"));
                if (await finish.ExecuteNonQueryAsync(cancellationToken) != 1)
                    throw new IOException("Nie można potwierdzić zapisu kwarantanny.");
                return new(eventId, Path.GetFileName(sourcePath), "Quarantined");
            }
            catch
            {
                var rolledBack = !moved;
                if (moved && !File.Exists(sourcePath))
                {
                    try { File.Move(destinationPath, sourcePath); rolledBack = true; }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
                if (rolledBack)
                {
                    using var remove = connection.CreateCommand();
                    remove.CommandText = "DELETE FROM quarantine_records WHERE event_guid=$id AND state='Pending'";
                    remove.Parameters.AddWithValue("$id", eventId.ToString("D"));
                    await remove.ExecuteNonQueryAsync(CancellationToken.None);
                }
                else
                {
                    using var attention = connection.CreateCommand();
                    attention.CommandText = "UPDATE quarantine_records SET state='NeedsAttention' WHERE event_guid=$id";
                    attention.Parameters.AddWithValue("$id", eventId.ToString("D"));
                    await attention.ExecuteNonQueryAsync(CancellationToken.None);
                }
                throw;
            }
        }
        finally { gate.Release(); }
    }

    public async Task<QuarantineResult> RestoreAsync(Guid eventId, CancellationToken cancellationToken = default)
    {
        if (eventId == Guid.Empty) throw new ArgumentOutOfRangeException(nameof(eventId));
        await gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await ReconcilePendingAsync(connection, cancellationToken);
            string hash, originalPath, quarantinedPath, fileName;
            using (var read = connection.CreateCommand())
            {
                read.CommandText = "SELECT sha256,original_path,quarantine_path,file_name FROM quarantine_records WHERE event_guid=$id AND state='Quarantined'";
                read.Parameters.AddWithValue("$id", eventId.ToString("D"));
                await using var reader = await read.ExecuteReaderAsync(cancellationToken);
                if (!await reader.ReadAsync(cancellationToken)) throw new InvalidOperationException("Nie znaleziono pliku w kwarantannie.");
                hash = reader.GetString(0); originalPath = reader.GetString(1); quarantinedPath = reader.GetString(2); fileName = reader.GetString(3);
            }
            EnsureQuarantineFile(quarantinedPath);
            var validatedOriginal = ValidateDownloadsDestination(originalPath);
            if (File.Exists(validatedOriginal)) throw new IOException("Plik o pierwotnej nazwie już istnieje. Sentinel nie nadpisze go.");
            var actualHash = await HashStableFileAsync(quarantinedPath, cancellationToken);
            if (!actualHash.Equals(hash, StringComparison.Ordinal)) throw new InvalidDataException("Plik w kwarantannie nie zgadza się z zapisanym SHA-256.");

            File.Move(quarantinedPath, validatedOriginal);
            try
            {
                if (!(await HashStableFileAsync(validatedOriginal, cancellationToken)).Equals(hash, StringComparison.Ordinal))
                    throw new IOException("Przywrócony plik nie przeszedł kontroli SHA-256.");
                using var finish = connection.CreateCommand();
                finish.CommandText = "UPDATE quarantine_records SET state='Restored' WHERE event_guid=$id AND state='Quarantined'";
                finish.Parameters.AddWithValue("$id", eventId.ToString("D"));
                if (await finish.ExecuteNonQueryAsync(cancellationToken) != 1) throw new IOException("Nie można zapisać przywrócenia pliku.");
                return new(eventId, fileName, "Restored");
            }
            catch
            {
                if (File.Exists(validatedOriginal) && !File.Exists(quarantinedPath))
                {
                    try { File.Move(validatedOriginal, quarantinedPath); }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
                throw;
            }
        }
        finally { gate.Release(); }
    }

    public async Task<HashSet<Guid>> ReadQuarantinedEventIdsAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT event_guid FROM quarantine_records WHERE state='Quarantined'";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var ids = new HashSet<Guid>();
        while (await reader.ReadAsync(cancellationToken))
            if (Guid.TryParseExact(reader.GetString(0), "D", out var eventId)) ids.Add(eventId);
        return ids;
    }

    public async Task<IReadOnlyList<QuarantineResult>> ReadOutstandingAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT event_guid,file_name,state FROM quarantine_records WHERE state IN ('Quarantined','Pending','NeedsAttention') ORDER BY created_at DESC LIMIT 100";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var rows = new List<QuarantineResult>();
        while (await reader.ReadAsync(cancellationToken))
            if (Guid.TryParseExact(reader.GetString(0), "D", out var eventId))
                rows.Add(new(eventId, reader.GetString(1), reader.GetString(2)));
        return rows;
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        if (File.Exists(databasePath)) EnsureNotReparsePoint(databasePath);
        var connection = new SqliteConnection(connectionString);
        try { await connection.OpenAsync(cancellationToken); return connection; }
        catch { await connection.DisposeAsync(); throw; }
    }

    private async Task ReconcilePendingAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        var pending = new List<(Guid Id, string Hash, string Original, string Quarantine)>();
        using (var read = connection.CreateCommand())
        {
            read.CommandText = "SELECT event_guid,sha256,original_path,quarantine_path FROM quarantine_records WHERE state='Pending' LIMIT 100";
            await using var reader = await read.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                if (Guid.TryParseExact(reader.GetString(0), "D", out var eventId)) pending.Add((eventId, reader.GetString(1), reader.GetString(2), reader.GetString(3)));
        }
        foreach (var item in pending)
        {
            try
            {
                ValidateDownloadsDestination(item.Original);
                EnsureNoReparsePath(quarantineRoot, item.Quarantine, allowMissingLeaf: true);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException)
            {
                using var invalid = connection.CreateCommand();
                invalid.CommandText = "UPDATE quarantine_records SET state='NeedsAttention' WHERE event_guid=$id";
                invalid.Parameters.AddWithValue("$id", item.Id.ToString("D"));
                await invalid.ExecuteNonQueryAsync(cancellationToken);
                continue;
            }
            var quarantineMatches = await FileMatchesHashAsync(item.Quarantine, item.Hash, cancellationToken);
            var originalMatches = await FileMatchesHashAsync(item.Original, item.Hash, cancellationToken);
            using var update = connection.CreateCommand();
            update.CommandText = quarantineMatches && !File.Exists(item.Original)
                ? "UPDATE quarantine_records SET state='Quarantined' WHERE event_guid=$id"
                : originalMatches && !File.Exists(item.Quarantine)
                    ? "DELETE FROM quarantine_records WHERE event_guid=$id"
                    : "UPDATE quarantine_records SET state='NeedsAttention' WHERE event_guid=$id";
            update.Parameters.AddWithValue("$id", item.Id.ToString("D"));
            await update.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private string ValidateDownloadsFile(string selectedPath)
    {
        var fullPath = Path.GetFullPath(selectedPath);
        if (!IsUnder(fullPath, downloadsRoot) || !File.Exists(fullPath))
            throw new InvalidOperationException("Wybierz istniejący plik z folderu Downloads.");
        EnsureNoReparsePath(downloadsRoot, fullPath);
        EnsureNotReparsePoint(fullPath);
        return fullPath;
    }

    private string ValidateDownloadsDestination(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (!IsUnder(fullPath, downloadsRoot)) throw new InvalidDataException("Zapisana ścieżka wykracza poza folder Downloads.");
        EnsureNoReparsePath(downloadsRoot, fullPath, allowMissingLeaf: true);
        return fullPath;
    }

    private void EnsureQuarantineFile(string path)
    {
        if (!IsUnder(path, quarantineRoot)) throw new InvalidDataException("Zapisana ścieżka wykracza poza kwarantannę.");
        EnsureNoReparsePath(quarantineRoot, path);
        EnsureNotReparsePoint(path);
        if (!File.Exists(path)) throw new FileNotFoundException("Nie znaleziono pliku w kwarantannie.");
    }

    private static void EnsureNoReparsePath(string root, string fullPath, bool allowMissingLeaf = false)
    {
        EnsureNotReparsePoint(root);
        var relative = Path.GetRelativePath(root, fullPath);
        var parts = relative.Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries);
        var current = root;
        for (var index = 0; index < parts.Length; index++)
        {
            current = Path.Combine(current, parts[index]);
            if (allowMissingLeaf && index == parts.Length - 1 && !File.Exists(current) && !Directory.Exists(current)) return;
            EnsureNotReparsePoint(current);
        }
    }

    private static void EnsureNotReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Operacja kwarantanny nie obsługuje dowiązań ani junctionów.");
    }

    private static bool IsUnder(string path, string root)
    {
        var relative = Path.GetRelativePath(root, path);
        return relative is not ("." or "..") && !Path.IsPathRooted(relative) &&
            !relative.StartsWith(".." + Path.DirectorySeparatorChar, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) &&
            !relative.StartsWith(".." + Path.AltDirectorySeparatorChar, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
    }

    private static string NormalizeHash(string hash)
    {
        if (hash.Length != 64 || hash.Any(character => !Uri.IsHexDigit(character))) throw new ArgumentException("Wymagany jest poprawny SHA-256.", nameof(hash));
        return hash.ToUpperInvariant();
    }

    private static async Task<string> HashStableFileAsync(string path, CancellationToken cancellationToken)
    {
        var before = new FileInfo(path);
        if (!before.Exists || before.Length > MaximumFileBytes) throw new InvalidOperationException("Plik jest niedostępny albo przekracza limit 256 MiB.");
        var length = before.Length; var modified = before.LastWriteTimeUtc;
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length != length) throw new IOException("Plik zmienił się podczas sprawdzania.");
        var hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken));
        var after = new FileInfo(path);
        if (!after.Exists || after.Length != length || after.LastWriteTimeUtc != modified)
            throw new IOException("Plik zmienił się podczas sprawdzania.");
        return hash;
    }

    private static async Task<bool> FileMatchesHashAsync(string path, string hash, CancellationToken cancellationToken)
    {
        try { return File.Exists(path) && (await HashStableFileAsync(path, cancellationToken)).Equals(hash, StringComparison.Ordinal); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException) { return false; }
    }
}
