using System.IO.Compression;
using System.Text;
using Sentinel.Core.Knowledge;
using Xunit;

namespace Sentinel.Tests;

public sealed class KnowledgeBaseTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "sentinel-knowledge-" + Guid.NewGuid().ToString("N"));

    private async Task<LocalKnowledgeBase> CreateAsync()
    {
        var store = new LocalKnowledgeBase(directory);
        await store.InitializeAsync();
        return store;
    }

    [Fact]
    public async Task ImportsIndexesSearchesAndDeletesTextDocuments()
    {
        var store = await CreateAsync();
        var path = Path.Combine(directory, "procedura.md");
        await File.WriteAllTextAsync(path, "Zweryfikuj przelew telefonicznie. Podejrzane wiadomości mogą wyłudzać dane logowania.");

        var document = await store.ImportAsync(path);
        Assert.Equal("procedura.md", document.Name);
        Assert.True(document.ChunkCount > 0);
        Assert.Equal(document, Assert.Single(await store.ListAsync()));
        var results = await store.SearchAsync("wyłudzać logowania");
        Assert.NotEmpty(results);
        Assert.Equal(document.Id, results[0].DocumentId);
        Assert.Contains("[", results[0].Excerpt);
        Assert.True(await store.DeleteAsync(document.Id));
        Assert.Empty(await store.SearchAsync("wyłudzać"));
        Assert.Empty(await store.ListAsync());
    }

    [Fact]
    public async Task StorageMetricsReportKnowledgeDocumentsAndIndexSize()
    {
        var store = await CreateAsync();
        var path = Path.Combine(directory, "knowledge.txt");
        await File.WriteAllTextAsync(path, "Local knowledge storage measurement.");
        await store.ImportAsync(path);

        var metrics = await store.GetStorageMetricsAsync();

        Assert.Equal(1, metrics.RecordCount);
        Assert.True(metrics.DatabaseBytes > 0);
        Assert.True(metrics.TotalBytes >= metrics.DatabaseBytes);
        Assert.True(metrics.PageCount > 0);
        Assert.InRange(metrics.FreePages, 0, metrics.PageCount);
    }

    [Fact]
    public async Task ExtractsDocxTextWithoutUnpackingFilesToDisk()
    {
        var store = await CreateAsync();
        var path = Path.Combine(directory, "guide.docx");
        await using (var file = new FileStream(path, FileMode.CreateNew))
        using (var archive = new ZipArchive(file, ZipArchiveMode.Create))
        {
            var entry = archive.CreateEntry("word/document.xml");
            await using var stream = entry.Open();
            await stream.WriteAsync(Encoding.UTF8.GetBytes("<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>Verify payment by phone</w:t></w:r></w:p></w:body></w:document>"));
        }

        await store.ImportAsync(path);
        Assert.NotEmpty(await store.SearchAsync("payment phone"));
        Assert.Single(Directory.GetFiles(directory, "*.docx"));
    }

    [Fact]
    public async Task RejectsUnsupportedFormatOversizedInputAndFtsSyntaxInjection()
    {
        var store = await CreateAsync();
        var pdf = Path.Combine(directory, "document.pdf");
        await File.WriteAllTextAsync(pdf, "%PDF synthetic");
        await Assert.ThrowsAsync<NotSupportedException>(() => store.ImportAsync(pdf));

        var large = Path.Combine(directory, "large.txt");
        await using (var stream = new FileStream(large, FileMode.CreateNew)) { stream.SetLength(LocalKnowledgeBase.MaximumFileBytes + 1L); }
        await Assert.ThrowsAsync<InvalidDataException>(() => store.ImportAsync(large));
        Assert.Empty(await store.SearchAsync("NOT NEAR ( * )"));
    }

    [Fact]
    public async Task DeduplicatesSameContentAndKeepsKnowledgeSeparateFromEventDatabase()
    {
        var store = await CreateAsync();
        var first = Path.Combine(directory, "one.txt");
        var second = Path.Combine(directory, "two.txt");
        await File.WriteAllTextAsync(first, "Local knowledge synthetic content");
        await File.WriteAllTextAsync(second, "Local knowledge synthetic content");
        var a = await store.ImportAsync(first);
        var b = await store.ImportAsync(second);
        Assert.Equal(a.Id, b.Id);
        Assert.Single(await store.ListAsync());
        Assert.EndsWith("knowledge.db", store.DatabasePath);
        Assert.False(File.Exists(Path.Combine(directory, "sentinel.db")));
    }

    [Fact]
    public async Task EnforcesDocumentCountLimitWithoutChangingExistingIndex()
    {
        var store = await CreateAsync();
        for (var index = 0; index < LocalKnowledgeBase.MaximumDocuments; index++)
        {
            var path = Path.Combine(directory, $"document-{index}.txt");
            await File.WriteAllTextAsync(path, $"Unique knowledge fixture {index}.");
            await store.ImportAsync(path);
        }

        var overflow = Path.Combine(directory, "overflow.txt");
        await File.WriteAllTextAsync(overflow, "One more unique document.");
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => store.ImportAsync(overflow));

        Assert.Contains(LocalKnowledgeBase.MaximumDocuments.ToString(), error.Message);
        Assert.Equal(LocalKnowledgeBase.MaximumDocuments, (await store.ListAsync()).Count);
    }

    [Fact]
    public async Task EnforcesIndexedCharacterLimitWithoutChangingExistingIndex()
    {
        var store = await CreateAsync();
        await using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={store.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync();
            using var seed = connection.CreateCommand();
            seed.CommandText = "INSERT INTO documents(id,name,sha256,imported_at,chunk_count) VALUES('seed','existing.txt','seed-hash',$now,1); INSERT INTO chunks(source,content) VALUES('seed#0',$content)";
            seed.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            seed.Parameters.AddWithValue("$content", new string(' ', checked((int)LocalKnowledgeBase.MaximumIndexedCharacters)));
            await seed.ExecuteNonQueryAsync();
        }

        var incoming = Path.Combine(directory, "incoming.txt");
        await File.WriteAllTextAsync(incoming, "New unique content.");
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => store.ImportAsync(incoming));

        Assert.Contains("znaków", error.Message);
        Assert.Equal("existing.txt", Assert.Single(await store.ListAsync()).Name);
    }

    [Fact]
    public async Task BackupCanBeReopenedWithDocumentsAndSearchIndexIntact()
    {
        var store = await CreateAsync();
        var documentPath = Path.Combine(directory, "backup-guide.txt");
        await File.WriteAllTextAsync(documentPath, "Backup knowledge fixture stays searchable.");
        await store.ImportAsync(documentPath);
        var backupDirectory = Path.Combine(directory, "backup"); Directory.CreateDirectory(backupDirectory);
        await store.BackupAsync(Path.Combine(backupDirectory, "knowledge.db"));
        var restored = new LocalKnowledgeBase(backupDirectory); await restored.InitializeAsync();
        Assert.Equal("backup-guide.txt", Assert.Single(await restored.ListAsync()).Name);
        Assert.NotEmpty(await restored.SearchAsync("searchable"));
    }

    [Fact]
    public async Task RestoreReplacesKnowledgeIndexAndRejectsCorruptBackupWithoutDataLoss()
    {
        var sourceDirectory = Path.Combine(directory, "source"); Directory.CreateDirectory(sourceDirectory);
        var source = new LocalKnowledgeBase(sourceDirectory); await source.InitializeAsync();
        var sourceDocument = Path.Combine(directory, "source.txt"); await File.WriteAllTextAsync(sourceDocument, "Restored knowledge remains searchable.");
        await source.ImportAsync(sourceDocument);
        var backupPath = Path.Combine(directory, "knowledge-backup.db"); await source.BackupAsync(backupPath);

        var targetDirectory = Path.Combine(directory, "target"); Directory.CreateDirectory(targetDirectory);
        var target = new LocalKnowledgeBase(targetDirectory); await target.InitializeAsync();
        var targetDocument = Path.Combine(directory, "target.txt"); await File.WriteAllTextAsync(targetDocument, "Discarded index content should disappear.");
        await target.ImportAsync(targetDocument);
        Assert.Equal(1, await target.RestoreAsync(backupPath));
        Assert.Equal("source.txt", Assert.Single(await target.ListAsync()).Name);
        Assert.NotEmpty(await target.SearchAsync("searchable"));
        Assert.Empty(await target.SearchAsync("discarded"));

        var corrupt = Path.Combine(directory, "corrupt-knowledge.db"); await File.WriteAllTextAsync(corrupt, "not a SQLite database");
        await Assert.ThrowsAsync<Microsoft.Data.Sqlite.SqliteException>(() => target.RestoreAsync(corrupt));
        Assert.Equal("source.txt", Assert.Single(await target.ListAsync()).Name);
        Assert.NotEmpty(await target.SearchAsync("searchable"));
    }

    public void Dispose() { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
}
