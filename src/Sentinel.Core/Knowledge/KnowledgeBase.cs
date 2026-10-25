using System.Collections.Concurrent;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Microsoft.Data.Sqlite;
using Sentinel.Core;
using Sentinel.Core.Analysis;
using Sentinel.Core.Context;
using UglyToad.PdfPig;
using UglyToad.PdfPig.DocumentLayoutAnalysis.TextExtractor;

namespace Sentinel.Core.Knowledge;

public sealed record KnowledgeDocument(string Id, string Name, DateTimeOffset ImportedAt, int ChunkCount);
public sealed record KnowledgeHit(string DocumentId, string SourceName, int ChunkNumber, string Excerpt, double Rank);

public interface IKnowledgeBaseProvider
{
    Task<IReadOnlyList<KnowledgeDocument>> ListAsync(CancellationToken cancellationToken = default);
    Task<KnowledgeDocument> ImportAsync(string filePath, CancellationToken cancellationToken = default);
    Task<KnowledgeDocument> ImportAsync(string filePath, string sourceName, CancellationToken cancellationToken = default) => ImportAsync(filePath, cancellationToken);
    Task<IReadOnlyList<KnowledgeHit>> SearchAsync(string query, int limit = 5, CancellationToken cancellationToken = default);
    Task<bool> DeleteAsync(string documentId, CancellationToken cancellationToken = default);
    Task BackupAsync(string destination, CancellationToken cancellationToken = default);
    Task<int> RestoreAsync(string backupPath, CancellationToken cancellationToken = default);
}

public interface ISemanticKnowledgeBaseProvider
{
    Task<IReadOnlyList<KnowledgeHit>> SearchSemanticAsync(string query, string endpoint, string model,
        ITextEmbeddingProvider embeddings, int limit = 5, CancellationToken cancellationToken = default);
}

/// <summary>
/// Private, per-user FTS5 knowledge index with an optional, locally generated semantic vector index.
/// Supported inputs are plain text, Markdown, DOCX and text-based PDF; unsupported formats are rejected.
/// </summary>
public sealed class LocalKnowledgeBase : IKnowledgeBaseProvider, ISemanticKnowledgeBaseProvider
{
    public const int MaximumFileBytes = 10 * 1024 * 1024;
    public const int MaximumExtractedCharacters = 2_000_000;
    public const int MaximumPdfPages = 500;
    public const int MaximumDocuments = 100;
    public const long MaximumIndexedCharacters = 20_000_000;
    public const long MaximumSemanticIndexBytes = 256L * 1024 * 1024;
    private const int ChunkCharacters = 1200;
    private const int ChunkOverlap = 180;
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> SemanticSearchGates = new(
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
    private readonly string connectionString;
    private readonly SemaphoreSlim semanticSearchGate;

    public string DatabasePath { get; }
    public Task<DatabaseStorageMetrics> GetStorageMetricsAsync(CancellationToken cancellationToken = default) =>
        DatabaseStorageMetricsReader.ReadAsync(DatabasePath, "SELECT COUNT(*) FROM documents", cancellationToken);

    public LocalKnowledgeBase(string dataDirectory)
    {
        var full = Path.GetFullPath(dataDirectory);
        if (full.StartsWith(@"\\", StringComparison.Ordinal)) throw new IOException("Baza wiedzy wymaga lokalnego katalogu danych.");
        Directory.CreateDirectory(full);
        DatabasePath = Path.Combine(full, "knowledge.db");
        semanticSearchGate = SemanticSearchGates.GetOrAdd(DatabasePath, _ => new SemaphoreSlim(1, 1));
        connectionString = new SqliteConnectionStringBuilder { DataSource = DatabasePath, Pooling = false }.ToString();
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var operationLock = await AcquireDatabaseOperationAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        using var versionCommand = connection.CreateCommand();
        versionCommand.CommandText = "PRAGMA user_version";
        var version = Convert.ToInt32(await versionCommand.ExecuteScalarAsync(cancellationToken), System.Globalization.CultureInfo.InvariantCulture);
        if (version > 2) throw new InvalidDataException("Baza wiedzy pochodzi z nowszej wersji aplikacji.");
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
            CREATE TABLE IF NOT EXISTS semantic_index_state(id INTEGER PRIMARY KEY CHECK(id=1), endpoint TEXT NOT NULL, model TEXT NOT NULL, dimensions INTEGER NOT NULL CHECK(dimensions BETWEEN 1 AND 4096));
            CREATE TABLE IF NOT EXISTS semantic_embeddings(source TEXT PRIMARY KEY, vector BLOB NOT NULL);
            PRAGMA user_version=2;
            COMMIT;
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
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

    public Task<KnowledgeDocument> ImportAsync(string filePath, CancellationToken cancellationToken = default) => ImportCoreAsync(filePath, null, cancellationToken);

    public Task<KnowledgeDocument> ImportAsync(string filePath, string sourceName, CancellationToken cancellationToken = default) => ImportCoreAsync(filePath, sourceName, cancellationToken);

    private async Task<KnowledgeDocument> ImportCoreAsync(string filePath, string? sourceName, CancellationToken cancellationToken)
    {
        await using var operationLock = await AcquireDatabaseOperationAsync(cancellationToken);
        return await ImportCoreUnlockedAsync(filePath, sourceName, cancellationToken);
    }

    private async Task<KnowledgeDocument> ImportCoreUnlockedAsync(string filePath, string? sourceName, CancellationToken cancellationToken)
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
            ".docx" => ExtractDocx(bytes, cancellationToken),
            ".pdf" => ExtractPdf(bytes, cancellationToken),
            _ => DecodeText(bytes)
        };
        extracted = extracted.Replace("\0", "", StringComparison.Ordinal).Trim();
        if (extracted.Length == 0) throw new InvalidDataException("Dokument nie zawiera tekstu do zaindeksowania.");
        if (extracted.Length > MaximumExtractedCharacters) throw new InvalidDataException("Tekst po ekstrakcji przekracza limit 2 MB znaków.");

        var digest = Convert.ToHexString(SHA256.HashData(bytes));
        var documentId = Guid.NewGuid().ToString("N");
        sourceName ??= Path.GetFileName(info.Name);
        if (string.IsNullOrWhiteSpace(sourceName) || sourceName.Length > 180 || sourceName != Path.GetFileName(sourceName)
            || sourceName.Any(char.IsControl) || sourceName.Contains('/') || sourceName.Contains('\\'))
            throw new InvalidDataException("Nazwa dokumentu jest nieprawidłowa.");
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

    /// <summary>Searches every indexed chunk by cosine similarity, building and caching local embeddings as needed.</summary>
    public async Task<IReadOnlyList<KnowledgeHit>> SearchSemanticAsync(string query, string endpoint, string model,
        ITextEmbeddingProvider embeddings, int limit = 5, CancellationToken cancellationToken = default)
    {
        await using var operationLock = await AcquireDatabaseOperationAsync(cancellationToken);
        return await SearchSemanticCoreAsync(query, endpoint, model, embeddings, limit, cancellationToken);
    }

    private async Task<IReadOnlyList<KnowledgeHit>> SearchSemanticCoreAsync(string query, string endpoint, string model,
        ITextEmbeddingProvider embeddings, int limit = 5, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(embeddings);
        if (string.IsNullOrWhiteSpace(query)) return [];
        if (query.Length > 4000) throw new ArgumentException("Zapytanie jest za długie.", nameof(query));
        if (limit is < 1 or > 20) throw new ArgumentOutOfRangeException(nameof(limit));
        if (string.IsNullOrWhiteSpace(model) || model.Length > 160 || model.Any(char.IsControl))
            throw new ArgumentException("Wybierz nazwę lokalnego modelu embeddingów.", nameof(model));
        _ = OllamaLocalProvider.ValidateEndpoint(endpoint);

        var chunks = new List<(string Source, string Content)>();
        await using (var connection = await OpenAsync(cancellationToken))
        {
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT source,content FROM chunks ORDER BY source";
            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) chunks.Add((reader.GetString(0), reader.GetString(1)));
        }
        if (chunks.Count == 0) return [];

        var dimensions = await PrepareSemanticIndexAsync(endpoint, model, cancellationToken);
        var missing = await ReadMissingSemanticChunksAsync(chunks, cancellationToken);
        for (var offset = 0; offset < missing.Count; offset += 20)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var batch = missing.Skip(offset).Take(20).ToArray();
            var texts = batch.Select(item => ToEmbeddingText(item.Content)).ToArray();
            var vectors = await embeddings.EmbedAsync(endpoint, model, texts, cancellationToken);
            if (vectors.Count != batch.Length) throw new InvalidDataException("Model embeddingów zwrócił nieprawidłową liczbę wektorów.");
            dimensions ??= vectors[0].Length;
            if (vectors.Any(vector => vector.Length != dimensions || vector.Length is < 1 or > 4096 || vector.Any(value => !float.IsFinite(value))))
                throw new InvalidDataException("Model embeddingów zwrócił niezgodne lub nieprawidłowe wektory.");
            if ((long)chunks.Count * dimensions.Value * sizeof(float) > MaximumSemanticIndexBytes)
                throw new InvalidOperationException("Pełny indeks semantyczny przekroczyłby limit 256 MB dla wybranego modelu.");
            await StoreSemanticBatchAsync(endpoint, model, dimensions.Value, batch, vectors, cancellationToken);
        }

        var queryVectors = await embeddings.EmbedAsync(endpoint, model, [ToEmbeddingText(query)], cancellationToken);
        var queryVector = queryVectors.Count == 1 ? queryVectors[0] : throw new InvalidDataException("Model embeddingów nie zwrócił wektora zapytania.");
        if (dimensions is null || queryVector.Length != dimensions || queryVector.Any(value => !float.IsFinite(value)))
            throw new InvalidDataException("Wymiary wektora zapytania nie pasują do lokalnego indeksu.");

        var scores = await ReadSemanticScoresAsync(queryVector, cancellationToken);
        var contentBySource = chunks.ToDictionary(item => item.Source, item => item.Content, StringComparer.Ordinal);
        await using var resultConnection = await OpenAsync(cancellationToken);
        var results = new List<KnowledgeHit>();
        foreach (var score in scores.OrderByDescending(item => item.Score).ThenBy(item => item.Source, StringComparer.Ordinal).Take(limit))
        {
            if (!contentBySource.TryGetValue(score.Source, out var content)) continue;
            using var command = resultConnection.CreateCommand();
            command.CommandText = "SELECT id,name FROM documents WHERE id=$id";
            command.Parameters.AddWithValue("$id", score.Source[..score.Source.IndexOf('#')]);
            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
                results.Add(new(reader.GetString(0), reader.GetString(1), int.Parse(score.Source[(score.Source.IndexOf('#') + 1)..], System.Globalization.CultureInfo.InvariantCulture),
                    content.Length <= 1200 ? content : content[..1200], -score.Score));
        }
        return results;
    }

    private async Task<int?> PrepareSemanticIndexAsync(string endpoint, string model, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        using var read = connection.CreateCommand();
        read.Transaction = (SqliteTransaction)transaction;
        read.CommandText = "SELECT endpoint,model,dimensions FROM semantic_index_state WHERE id=1";
        using var reader = await read.ExecuteReaderAsync(cancellationToken);
        var hasState = await reader.ReadAsync(cancellationToken);
        var existingEndpoint = hasState ? reader.GetString(0) : null;
        var existingModel = hasState ? reader.GetString(1) : null;
        int? dimensions = hasState ? reader.GetInt32(2) : null;
        await reader.CloseAsync();
        if (!string.Equals(existingEndpoint, endpoint, StringComparison.OrdinalIgnoreCase) || !string.Equals(existingModel, model, StringComparison.Ordinal))
        {
            using var reset = connection.CreateCommand(); reset.Transaction = (SqliteTransaction)transaction;
            reset.CommandText = "DELETE FROM semantic_embeddings; DELETE FROM semantic_index_state;";
            await reset.ExecuteNonQueryAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return null;
        }
        await transaction.CommitAsync(cancellationToken);
        return dimensions;
    }

    private async Task<List<(string Source, string Content)>> ReadMissingSemanticChunksAsync(
        IReadOnlyList<(string Source, string Content)> chunks, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        using var command = connection.CreateCommand(); command.CommandText = "SELECT source FROM semantic_embeddings";
        using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var indexed = new HashSet<string>(StringComparer.Ordinal);
        while (await reader.ReadAsync(cancellationToken)) indexed.Add(reader.GetString(0));
        return chunks.Where(chunk => !indexed.Contains(chunk.Source)).ToList();
    }

    private async Task StoreSemanticBatchAsync(string endpoint, string model, int dimensions, IReadOnlyList<(string Source, string Content)> chunks,
        IReadOnlyList<float[]> vectors, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        using (var state = connection.CreateCommand())
        {
            state.Transaction = (SqliteTransaction)transaction;
            state.CommandText = "INSERT INTO semantic_index_state(id,endpoint,model,dimensions) VALUES(1,$endpoint,$model,$dimensions) ON CONFLICT(id) DO UPDATE SET endpoint=excluded.endpoint,model=excluded.model,dimensions=excluded.dimensions";
            state.Parameters.AddWithValue("$endpoint", endpoint); state.Parameters.AddWithValue("$model", model); state.Parameters.AddWithValue("$dimensions", dimensions);
            await state.ExecuteNonQueryAsync(cancellationToken);
        }
        for (var index = 0; index < chunks.Count; index++)
        {
            using var insert = connection.CreateCommand(); insert.Transaction = (SqliteTransaction)transaction;
            insert.CommandText = "INSERT INTO semantic_embeddings(source,vector) VALUES($source,$vector) ON CONFLICT(source) DO UPDATE SET vector=excluded.vector";
            insert.Parameters.AddWithValue("$source", chunks[index].Source);
            insert.Parameters.Add("$vector", SqliteType.Blob).Value = SerializeVector(vectors[index]);
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
    }

    private async Task<List<(string Source, double Score)>> ReadSemanticScoresAsync(float[] queryVector, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        using var command = connection.CreateCommand(); command.CommandText = "SELECT source,vector FROM semantic_embeddings ORDER BY source";
        using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var results = new List<(string Source, double Score)>();
        while (await reader.ReadAsync(cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var vector = DeserializeVector((byte[])reader[1]);
            if (vector.Length != queryVector.Length) throw new InvalidDataException("Wymiary zapisanych embeddingów są niezgodne.");
            double dot = 0, leftSquared = 0, rightSquared = 0;
            for (var index = 0; index < vector.Length; index++)
            { dot += queryVector[index] * vector[index]; leftSquared += queryVector[index] * queryVector[index]; rightSquared += vector[index] * vector[index]; }
            var score = leftSquared <= 0 || rightSquared <= 0 ? 0 : dot / Math.Sqrt(leftSquared * rightSquared);
            results.Add((reader.GetString(0), score));
        }
        return results;
    }

    private static byte[] SerializeVector(float[] vector)
    {
        using var stream = new MemoryStream(vector.Length * sizeof(float));
        using var writer = new BinaryWriter(stream);
        foreach (var value in vector) writer.Write(value);
        return stream.ToArray();
    }

    private static float[] DeserializeVector(byte[] bytes)
    {
        if (bytes.Length is < sizeof(float) or > 4096 * sizeof(float) || bytes.Length % sizeof(float) != 0)
            throw new InvalidDataException("Zapisany embedding ma nieprawidłowy rozmiar.");
        var vector = new float[bytes.Length / sizeof(float)];
        using var stream = new MemoryStream(bytes, writable: false); using var reader = new BinaryReader(stream);
        for (var index = 0; index < vector.Length; index++)
        {
            vector[index] = reader.ReadSingle();
            if (!float.IsFinite(vector[index])) throw new InvalidDataException("Zapisany embedding zawiera nieprawidłową wartość.");
        }
        return vector;
    }

    private static string ToEmbeddingText(string text)
    {
        var redacted = PrivacyFilter.Redact(text);
        var normalized = new string(redacted.Select(character => char.IsControl(character) ? ' ' : character).ToArray());
        return normalized.Length <= 4000 ? normalized : normalized[..4000];
    }

    public async Task<bool> DeleteAsync(string documentId, CancellationToken cancellationToken = default)
    {
        await using var operationLock = await AcquireDatabaseOperationAsync(cancellationToken);
        return await DeleteCoreAsync(documentId, cancellationToken);
    }

    private async Task<bool> DeleteCoreAsync(string documentId, CancellationToken cancellationToken)
    {
        if (!Guid.TryParseExact(documentId, "N", out _)) return false;
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        using var removeChunks = connection.CreateCommand();
        removeChunks.Transaction = (SqliteTransaction)transaction;
        removeChunks.CommandText = "DELETE FROM chunks WHERE source GLOB $prefix";
        removeChunks.Parameters.AddWithValue("$prefix", documentId + "#*");
        await removeChunks.ExecuteNonQueryAsync(cancellationToken);
        using (var removeEmbeddings = connection.CreateCommand())
        {
            removeEmbeddings.Transaction = (SqliteTransaction)transaction;
            removeEmbeddings.CommandText = "DELETE FROM semantic_embeddings WHERE source GLOB $prefix";
            removeEmbeddings.Parameters.AddWithValue("$prefix", documentId + "#*");
            await removeEmbeddings.ExecuteNonQueryAsync(cancellationToken);
        }
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
        await using var operationLock = await AcquireDatabaseOperationAsync(cancellationToken);
        return await RestoreCoreAsync(backupPath, cancellationToken);
    }

    private async Task<int> RestoreCoreAsync(string backupPath, CancellationToken cancellationToken)
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
            var backupVersion = Convert.ToInt32(await version.ExecuteScalarAsync(cancellationToken), System.Globalization.CultureInfo.InvariantCulture);
            if (backupVersion is not (1 or 2))
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
            command.CommandText = "DELETE FROM semantic_embeddings; DELETE FROM semantic_index_state; DELETE FROM chunks; DELETE FROM documents; INSERT INTO documents(id,name,sha256,imported_at,chunk_count) SELECT id,name,sha256,imported_at,chunk_count FROM restore_source.documents; INSERT INTO chunks(source,content) SELECT source,content FROM restore_source.chunks;";
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

    private async Task<DatabaseOperationLock> AcquireDatabaseOperationAsync(CancellationToken cancellationToken)
    {
        await semanticSearchGate.WaitAsync(cancellationToken);
        try
        {
            if (!OperatingSystem.IsWindows()) return new(semanticSearchGate, null);

            var lockPath = DatabasePath + ".operation.lock";
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var file = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None,
                        bufferSize: 1, FileOptions.Asynchronous);
                    return new(semanticSearchGate, file);
                }
                catch (IOException exception) when (IsFileSharingViolation(exception))
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken);
                }
            }
        }
        catch
        {
            semanticSearchGate.Release();
            throw;
        }
    }

    private static bool IsFileSharingViolation(IOException exception) =>
        OperatingSystem.IsWindows() && (exception.HResult & 0xFFFF) is 32 or 33;

    private sealed class DatabaseOperationLock(SemaphoreSlim gate, FileStream? file) : IAsyncDisposable
    {
        private SemaphoreSlim? gate = gate;
        private FileStream? file = file;

        public async ValueTask DisposeAsync()
        {
            var heldFile = Interlocked.Exchange(ref file, null);
            try
            {
                if (heldFile is not null) await heldFile.DisposeAsync();
            }
            finally { Interlocked.Exchange(ref gate, null)?.Release(); }
        }
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

    private static string ExtractDocx(byte[] bytes, CancellationToken cancellationToken)
    {
        using var stream = new MemoryStream(bytes, writable: false);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);
        var entry = archive.GetEntry("word/document.xml") ?? throw new InvalidDataException("Plik DOCX nie zawiera głównego dokumentu Word.");
        if (entry.Length > 8 * 1024 * 1024) throw new InvalidDataException("Główny dokument DOCX jest zbyt duży po rozpakowaniu.");
        using var xmlStream = entry.Open();
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaximumExtractedCharacters * 4L };
        using var reader = XmlReader.Create(xmlStream, settings);
        const string wordNamespace = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
        var output = new StringBuilder(Math.Min(MaximumExtractedCharacters, bytes.Length));
        var textBuffer = new char[4096];
        var paragraphDepth = 0;
        var sawParagraph = false;
        var inText = false;
        while (reader.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (reader.NodeType == XmlNodeType.Element)
            {
                if (reader.NamespaceURI == wordNamespace && reader.LocalName == "p")
                {
                    if (paragraphDepth == 0)
                    {
                        if (sawParagraph) AppendBounded(output, Environment.NewLine);
                        sawParagraph = true;
                    }
                    paragraphDepth++;
                    if (reader.IsEmptyElement) paragraphDepth--;
                }
                else if (paragraphDepth > 0 && reader.NamespaceURI == wordNamespace && reader.LocalName == "t")
                {
                    inText = !reader.IsEmptyElement;
                }
            }
            else if (reader.NodeType == XmlNodeType.EndElement)
            {
                if (reader.NamespaceURI == wordNamespace && reader.LocalName == "t") inText = false;
                if (reader.NamespaceURI == wordNamespace && reader.LocalName == "p") paragraphDepth--;
            }
            else if (inText && reader.NodeType is XmlNodeType.Text or XmlNodeType.CDATA or XmlNodeType.SignificantWhitespace or XmlNodeType.Whitespace)
            {
                int read;
                while ((read = reader.ReadValueChunk(textBuffer, 0, textBuffer.Length)) > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (output.Length + read > MaximumExtractedCharacters)
                        throw new InvalidDataException("Tekst po ekstrakcji przekracza limit 2 MB znaków.");
                    output.Append(textBuffer, 0, read);
                }
            }
        }
        cancellationToken.ThrowIfCancellationRequested();
        return output.ToString();
    }

    private static void AppendBounded(StringBuilder output, string value)
    {
        if (output.Length + value.Length > MaximumExtractedCharacters)
            throw new InvalidDataException("Tekst po ekstrakcji przekracza limit 2 MB znaków.");
        output.Append(value);
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
