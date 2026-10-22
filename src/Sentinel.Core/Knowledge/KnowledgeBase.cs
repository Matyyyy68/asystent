using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Data.Sqlite;
using Sentinel.Core;
using UglyToad.PdfPig;
using UglyToad.PdfPig.DocumentLayoutAnalysis.TextExtractor;

namespace Sentinel.Core.Knowledge;

public sealed record KnowledgeDocument(string Id, string Name, DateTimeOffset ImportedAt, int ChunkCount);
public sealed record KnowledgeHit(string DocumentId, string SourceName, int ChunkNumber, string Excerpt, double Rank);

public interface IKnowledgeBaseProvider
{
    Task<IReadOnlyList<KnowledgeDocument>> ListAsync(CancellationToken cancellationToken = default);
    Task<KnowledgeDocument> ImportAsync(string filePath, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<KnowledgeHit>> SearchAsync(string query, int limit = 5, CancellationToken cancellationToken = default);
    Task<bool> DeleteAsync(string documentId, CancellationToken cancellationToken = default);
    Task BackupAsync(string destination, CancellationToken cancellationToken = default);
    Task<int> RestoreAsync(string backupPath, CancellationToken cancellationToken = default);
}

/// <summary>
/// Private, per-user FTS5 knowledge index. It deliberately makes no semantic/vector-search claim.
/// Supported inputs are plain text, Markdown, DOCX and text-based PDF; unsupported formats are rejected.
/// </summary>
public sealed class LocalKnowledgeBase : IKnowledgeBaseProvider
{
    public const int MaximumFileBytes = 10 * 1024 * 1024;
    public const int MaximumExtractedCharacters = 2_000_000;
    public const int MaximumPdfPages = 500;
    public const int MaximumDocuments = 100;
    public const long MaximumIndexedCharacters = 20_000_000;
    private const int ChunkCharacters = 1200;
    private const int ChunkOverlap = 180;
    private readonly string connectionString;

    public string DatabasePath { get; }
    public Task<DatabaseStorageMetrics> GetStorageMetricsAsync(CancellationToken cancellationToken = default) =>
        DatabaseStorageMetricsReader.ReadAsync(DatabasePath, "SELECT COUNT(*) FROM documents", cancellationToken);

    public LocalKnowledgeBase(string dataDirectory)
    {
        var full = Path.GetFullPath(dataDirectory);
        if (full.StartsWith(@"\\", StringComparison.Ordinal)) throw new IOException("Baza wiedzy wymaga lokalnego katalogu danych.");
        Directory.CreateDirectory(full);
        DatabasePath = Path.Combine(full, "knowledge.db");
        connectionString = new SqliteConnectionStringBuilder { DataSource = DatabasePath, Pooling = false }.ToString();
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        using var versionCommand = connection.CreateCommand();
        versionCommand.CommandText = "PRAGMA user_version";
        var version = Convert.ToInt32(await versionCommand.ExecuteScalarAsync(cancellationToken), System.Globalization.CultureInfo.InvariantCulture);
        if (version > 1) throw new InvalidDataException("Baza wiedzy pochodzi z nowszej wersji aplikacji.");
        using var command = connection.CreateCommand();
        command.CommandText = """
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS documents(
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              sha256 TEXT NOT NULL UNIQUE,
              imported_at TEXT NOT NULL,
              chunk_count INTEGER NOT NULL CHECK(chunk_count >= 0));
            CREATE VIRTUAL TABLE IF NOT EXISTS chunks USING fts5(source UNINDEXED, content, tokenize='unicode61 remove_diacritics 2');
            PRAGMA user_version=1;
            COMMIT;
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
        await connection.CloseAsync();
        await connection.OpenAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<KnowledgeDocument>> ListAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id,name,imported_at,chunk_count FROM documents ORDER BY imported_at DESC,name COLLATE NOCASE";
        using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var items = new List<KnowledgeDocument>();
        while (await reader.ReadAsync(cancellationToken))
            items.Add(new(reader.GetString(0), reader.GetString(1), DateTimeOffset.Parse(reader.GetString(2), System.Globalization.CultureInfo.InvariantCulture), reader.GetInt32(3)));
        return items;
    }

    public async Task<KnowledgeDocument> ImportAsync(string filePath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        var info = new FileInfo(filePath);
        if (!info.Exists) throw new FileNotFoundException("Nie znaleziono wskazanego dokumentu.", filePath);
        if (info.Length is <= 0 or > MaximumFileBytes) throw new InvalidDataException("Dokument musi mieć od 1 bajta do 10 MB.");
        var extension = info.Extension.ToLowerInvariant();
        if (extension is not (".txt" or ".md" or ".docx" or ".pdf"))
            throw new NotSupportedException("Obsługiwane formaty to TXT, Markdown, DOCX i PDF.");

        var bytes = await ReadBoundedAsync(filePath, cancellationToken);
        var extracted = extension switch
        {
            ".docx" => ExtractDocx(bytes),
            ".pdf" => ExtractPdf(bytes, cancellationToken),
            _ => DecodeText(bytes)
        };
        extracted = extracted.Replace("\0", "", StringComparison.Ordinal).Trim();
        if (extracted.Length == 0) throw new InvalidDataException("Dokument nie zawiera tekstu do zaindeksowania.");
        if (extracted.Length > MaximumExtractedCharacters) throw new InvalidDataException("Tekst po ekstrakcji przekracza limit 2 MB znaków.");

        var digest = Convert.ToHexString(SHA256.HashData(bytes));
        var documentId = Guid.NewGuid().ToString("N");
        var sourceName = Path.GetFileName(info.Name);
        if (sourceName.Length > 180) sourceName = sourceName[^180..];
        var chunks = SplitIntoChunks(extracted);
        var importedAt = DateTimeOffset.UtcNow;

        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        using (var check = connection.CreateCommand())
        {
            check.Transaction = (SqliteTransaction)transaction;
            check.CommandText = "SELECT id,name,imported_at,chunk_count FROM documents WHERE sha256=$hash";
            check.Parameters.AddWithValue("$hash", digest);
            using var reader = await check.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                var existing = new KnowledgeDocument(reader.GetString(0), reader.GetString(1), DateTimeOffset.Parse(reader.GetString(2), System.Globalization.CultureInfo.InvariantCulture), reader.GetInt32(3));
                await reader.CloseAsync();
                await transaction.CommitAsync(cancellationToken);
                return existing;
            }
        }
        using (var capacity = connection.CreateCommand())
        {
            capacity.Transaction = (SqliteTransaction)transaction;
            capacity.CommandText = "SELECT (SELECT COUNT(*) FROM documents), (SELECT COALESCE(SUM(length(content)),0) FROM chunks)";
            using var reader = await capacity.ExecuteReaderAsync(cancellationToken);
            await reader.ReadAsync(cancellationToken);
            var documentCount = reader.GetInt32(0);
            var indexedCharacters = reader.GetInt64(1);
            await reader.CloseAsync();
            if (documentCount >= MaximumDocuments)
                throw new InvalidOperationException($"Baza wiedzy osiągnęła limit {MaximumDocuments} dokumentów. Usuń dokumenty, których już nie potrzebujesz.");
            if (indexedCharacters + chunks.Sum(chunk => (long)chunk.Length) > MaximumIndexedCharacters)
                throw new InvalidOperationException($"Baza wiedzy osiągnęła limit {MaximumIndexedCharacters:N0} indeksowanych znaków. Usuń dokumenty albo zaimportuj krótszy materiał.");
        }
        using (var document = connection.CreateCommand())
        {
            document.Transaction = (SqliteTransaction)transaction;
            document.CommandText = "INSERT INTO documents(id,name,sha256,imported_at,chunk_count) VALUES($id,$name,$hash,$time,$count)";
            document.Parameters.AddWithValue("$id", documentId);
            document.Parameters.AddWithValue("$name", sourceName);
            document.Parameters.AddWithValue("$hash", digest);
            document.Parameters.AddWithValue("$time", importedAt.ToString("O"));
            document.Parameters.AddWithValue("$count", chunks.Count);
            await document.ExecuteNonQueryAsync(cancellationToken);
        }
        for (var index = 0; index < chunks.Count; index++)
        {
            using var insert = connection.CreateCommand();
            insert.Transaction = (SqliteTransaction)transaction;
            insert.CommandText = "INSERT INTO chunks(source,content) VALUES($source,$content)";
            insert.Parameters.AddWithValue("$source", $"{documentId}#{index}");
            insert.Parameters.AddWithValue("$content", chunks[index]);
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        return new(documentId, sourceName, importedAt, chunks.Count);
    }

    public async Task<IReadOnlyList<KnowledgeHit>> SearchAsync(string query, int limit = 5, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (query.Length > 4000) throw new ArgumentException("Zapytanie jest za długie.", nameof(query));
        if (limit is < 1 or > 20) throw new ArgumentOutOfRangeException(nameof(limit), "Limit wyników musi wynosić 1–20.");
        var terms = query.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(term => new string(term.Where(char.IsLetterOrDigit).ToArray()))
            .Where(term => term.Length >= 2).Distinct(StringComparer.OrdinalIgnoreCase).Take(16).ToArray();
        if (terms.Length == 0) return [];
        var match = string.Join(" OR ", terms.Select(term =>
        {
            var quoted = $"\"{term.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
            // A bounded prefix alternative helps with common Polish inflection while preserving
            // the exact token for ranking. Short tokens stay exact to avoid broad matches.
            return term.Length >= 8 ? $"({quoted} OR \"{term[..^3]}\"*)" : quoted;
        }));

        await using var connection = await OpenAsync(cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT d.id,d.name,CAST(substr(c.source,instr(c.source,'#')+1) AS INTEGER),snippet(chunks,1,'[',']',' … ',18),bm25(chunks)
            FROM chunks c JOIN documents d ON d.id=substr(c.source,1,instr(c.source,'#')-1)
            WHERE chunks MATCH $match ORDER BY bm25(chunks) LIMIT $limit
            """;
        command.Parameters.AddWithValue("$match", match);
        command.Parameters.AddWithValue("$limit", limit);
        using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var results = new List<KnowledgeHit>();
        while (await reader.ReadAsync(cancellationToken))
            results.Add(new(reader.GetString(0), reader.GetString(1), reader.GetInt32(2), reader.GetString(3), reader.GetDouble(4)));
        return results;
    }

    public async Task<bool> DeleteAsync(string documentId, CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParseExact(documentId, "N", out _)) return false;
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        using var removeChunks = connection.CreateCommand();
        removeChunks.Transaction = (SqliteTransaction)transaction;
        removeChunks.CommandText = "DELETE FROM chunks WHERE source GLOB $prefix";
        removeChunks.Parameters.AddWithValue("$prefix", documentId + "#*");
        await removeChunks.ExecuteNonQueryAsync(cancellationToken);
        using var removeDocument = connection.CreateCommand();
        removeDocument.Transaction = (SqliteTransaction)transaction;
        removeDocument.CommandText = "DELETE FROM documents WHERE id=$id";
        removeDocument.Parameters.AddWithValue("$id", documentId);
        var deleted = await removeDocument.ExecuteNonQueryAsync(cancellationToken) == 1;
        await transaction.CommitAsync(cancellationToken);
        return deleted;
    }

    public async Task BackupAsync(string destination, CancellationToken cancellationToken = default)
    {
        if (File.Exists(destination)) throw new IOException("Plik kopii już istnieje.");
        var parent = Path.GetDirectoryName(Path.GetFullPath(destination))!;
        Directory.CreateDirectory(parent);
        await using var source = await OpenAsync(cancellationToken);
        await using var target = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = destination, Pooling = false }.ToString());
        await target.OpenAsync(cancellationToken);
        source.BackupDatabase(target);
    }

    public async Task<int> RestoreAsync(string backupPath, CancellationToken cancellationToken = default)
    {
        var sourcePath = Path.GetFullPath(backupPath);
        if (!File.Exists(sourcePath)) throw new FileNotFoundException("Nie znaleziono kopii bazy wiedzy.", sourcePath);
        if (string.Equals(sourcePath, DatabasePath, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Nie można przywrócić bazy wiedzy z jej aktywnego pliku.");
        var documentCount = 0;
        await using (var source = new SqliteConnection(new SqliteConnectionStringBuilder
        { DataSource = sourcePath, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString()))
        {
            await source.OpenAsync(cancellationToken);
            using var integrity = source.CreateCommand(); integrity.CommandText = "PRAGMA integrity_check";
            if (!string.Equals(await integrity.ExecuteScalarAsync(cancellationToken) as string, "ok", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Kopia bazy wiedzy nie przeszła kontroli integralności.");
            using var version = source.CreateCommand(); version.CommandText = "PRAGMA user_version";
            if (Convert.ToInt32(await version.ExecuteScalarAsync(cancellationToken), System.Globalization.CultureInfo.InvariantCulture) != 1)
                throw new InvalidDataException("Kopia bazy wiedzy pochodzi z nieobsługiwanej wersji.");
            using var tables = source.CreateCommand();
            tables.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('documents','chunks')";
            if (Convert.ToInt32(await tables.ExecuteScalarAsync(cancellationToken), System.Globalization.CultureInfo.InvariantCulture) != 2)
                throw new InvalidDataException("Kopia nie zawiera wymaganych tabel bazy wiedzy.");
            using var documents = source.CreateCommand(); documents.CommandText = "SELECT id,name,sha256,imported_at,chunk_count,(SELECT COUNT(*) FROM chunks c WHERE c.source GLOB documents.id||'#*') FROM documents";
            using var reader = await documents.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var id = reader.GetString(0); var name = reader.GetString(1); var hash = reader.GetString(2);
                if (!Guid.TryParseExact(id, "N", out _) || name.Length is < 1 or > 180 || hash.Length != 64 ||
                    !DateTimeOffset.TryParse(reader.GetString(3), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out _) ||
                    reader.GetInt32(4) < 0 || reader.GetInt32(4) != reader.GetInt32(5))
                    throw new InvalidDataException("Kopia zawiera nieprawidłowe metadane dokumentu lub liczbę fragmentów.");
                try { _ = Convert.FromHexString(hash); } catch (FormatException ex) { throw new InvalidDataException("Kopia zawiera nieprawidłowy hash dokumentu.", ex); }
                documentCount++;
            }
        }

        await using var destination = await OpenAsync(cancellationToken);
        using (var attach = destination.CreateCommand())
        {
            attach.CommandText = "ATTACH DATABASE $source AS restore_source";
            attach.Parameters.AddWithValue("$source", sourcePath);
            await attach.ExecuteNonQueryAsync(cancellationToken);
        }
        try
        {
            await using var transaction = await destination.BeginTransactionAsync(cancellationToken);
            using var command = destination.CreateCommand(); command.Transaction = (SqliteTransaction)transaction;
            command.CommandText = "DELETE FROM chunks; DELETE FROM documents; INSERT INTO documents(id,name,sha256,imported_at,chunk_count) SELECT id,name,sha256,imported_at,chunk_count FROM restore_source.documents; INSERT INTO chunks(source,content) SELECT source,content FROM restore_source.chunks;";
            await command.ExecuteNonQueryAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return documentCount;
        }
        finally
        {
            using var detach = destination.CreateCommand(); detach.CommandText = "DETACH DATABASE restore_source";
            await detach.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(connectionString);
        try { await connection.OpenAsync(cancellationToken); return connection; }
        catch { await connection.DisposeAsync(); throw; }
    }

    private static async Task<byte[]> ReadBoundedAsync(string path, CancellationToken cancellationToken)
    {
        await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (input.Length is <= 0 or > MaximumFileBytes) throw new InvalidDataException("Dokument musi mieć od 1 bajta do 10 MB.");
        using var output = new MemoryStream((int)input.Length);
        var buffer = new byte[81920];
        while (true)
        {
            var count = await input.ReadAsync(buffer, cancellationToken);
            if (count == 0) break;
            if (output.Length + count > MaximumFileBytes) throw new InvalidDataException("Dokument przekroczył limit 10 MB podczas odczytu.");
            await output.WriteAsync(buffer.AsMemory(0, count), cancellationToken);
        }
        return output.ToArray();
    }

    private static string DecodeText(byte[] bytes)
    {
        try { return new UTF8Encoding(false, true).GetString(bytes); }
        catch (DecoderFallbackException exception) { throw new InvalidDataException("Dokument musi być zapisany w UTF-8.", exception); }
    }

    private static string ExtractPdf(byte[] bytes, CancellationToken cancellationToken)
    {
        using var input = new MemoryStream(bytes, writable: false);
        using var document = PdfDocument.Open(input);
        if (document.NumberOfPages > MaximumPdfPages)
            throw new InvalidDataException($"PDF przekracza limit {MaximumPdfPages} stron.");

        var text = new StringBuilder(Math.Min(MaximumExtractedCharacters, bytes.Length * 2));
        for (var pageNumber = 1; pageNumber <= document.NumberOfPages; pageNumber++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var pageText = ContentOrderTextExtractor.GetText(document.GetPage(pageNumber));
            if (text.Length + pageText.Length + Environment.NewLine.Length > MaximumExtractedCharacters)
                throw new InvalidDataException("Tekst po ekstrakcji przekracza limit 2 MB znaków.");
            if (pageText.Length > 0) text.AppendLine(pageText);
        }
        return text.ToString();
    }

    private static string ExtractDocx(byte[] bytes)
    {
        using var stream = new MemoryStream(bytes, writable: false);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);
        var entry = archive.GetEntry("word/document.xml") ?? throw new InvalidDataException("Plik DOCX nie zawiera głównego dokumentu Word.");
        if (entry.Length > 8 * 1024 * 1024) throw new InvalidDataException("Główny dokument DOCX jest zbyt duży po rozpakowaniu.");
        using var xmlStream = entry.Open();
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaximumExtractedCharacters * 4L };
        using var reader = XmlReader.Create(xmlStream, settings);
        var document = XDocument.Load(reader, LoadOptions.None);
        XNamespace word = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
        var paragraphs = document.Descendants(word + "p").Select(p => string.Concat(p.Descendants().Where(e => e.Name == word + "t").Select(e => e.Value)));
        return string.Join(Environment.NewLine, paragraphs);
    }

    private static List<string> SplitIntoChunks(string text)
    {
        var chunks = new List<string>();
        var start = 0;
        while (start < text.Length)
        {
            var end = Math.Min(start + ChunkCharacters, text.Length);
            if (end < text.Length)
            {
                var boundary = text.LastIndexOfAny(['.', '!', '?', '\n', ' '], end - 1, end - start);
                if (boundary > start + ChunkCharacters / 2) end = boundary + 1;
            }
            var chunk = text[start..end].Trim();
            if (chunk.Length > 0) chunks.Add(chunk);
            if (end >= text.Length) break;
            start = Math.Max(start + 1, end - ChunkOverlap);
        }
        return chunks;
    }
}
