using System.IO.Compression;
using System.Diagnostics;
using System.Text;
using Microsoft.Data.Sqlite;
using Sentinel.Core.Analysis;
using Sentinel.Core.Knowledge;
using UglyToad.PdfPig.Content;
using UglyToad.PdfPig.Core;
using UglyToad.PdfPig.Fonts.Standard14Fonts;
using UglyToad.PdfPig.Writer;
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
    public async Task ControlledRetrievalQueriesRankRelevantKnowledgeSourcesInTopThree()
    {
        var store = await CreateAsync();
        var documents = new Dictionary<string, string>
        {
            ["credential-phishing.md"] = "Phishing email credential theft. Check the sender domain and report malicious links. Never enter an account password from a message link.",
            ["dns-cache.md"] = "DNS cache records domain lookups. Inspect cached DNS entries when troubleshooting name resolution.",
            ["invoice-fraud.md"] = "Invoice fraud can redirect a bank transfer. Verify vendor bank details using a trusted phone number.",
            ["browser-privacy.md"] = "Browser privacy settings control history, cookies, and cross-site tracking.",
            ["security-overview.md"] = "Security guidance: protect accounts, update software, verify senders, review invoices, and inspect network settings.",
            ["password-recovery.md"] = "Account recovery lets a user reset a forgotten password through the official service."
        };
        foreach (var (name, content) in documents)
        {
            var path = Path.Combine(directory, name);
            await File.WriteAllTextAsync(path, content);
            await store.ImportAsync(path);
        }

        (string Query, string RelevantSource)[] cases =
        [
            ("phishing email sender", "credential-phishing.md"),
            ("dns cache lookup", "dns-cache.md"),
            ("invoice fraud transfer", "invoice-fraud.md"),
            ("browser history privacy", "browser-privacy.md")
        ];
        var reciprocalRanks = new List<double>();
        var hitsAtThree = 0;
        foreach (var (query, relevantSource) in cases)
        {
            var results = await store.SearchAsync(query, limit: 5);
            var rank = results.ToList().FindIndex(hit => hit.SourceName == relevantSource) + 1;
            if (rank is > 0 and <= 3) hitsAtThree++;
            reciprocalRanks.Add(rank > 0 ? 1d / rank : 0d);
        }

        var recallAtThree = (double)hitsAtThree / cases.Length;
        var meanReciprocalRank = reciprocalRanks.Average();
        Assert.Equal(1d, recallAtThree);
        Assert.Equal(1d, meanReciprocalRank);
    }

    [Fact]
    public async Task SearchExpandsLongPolishTermsByBoundedPrefix()
    {
        var store = await CreateAsync();
        var path = Path.Combine(directory, "logowanie.md");
        await File.WriteAllTextAsync(path, "Nigdy nie logować się do banku przez link z wiadomości.");
        var document = await store.ImportAsync(path);

        var results = await store.SearchAsync("logowania");

        Assert.Equal(document.Id, Assert.Single(results).DocumentId);
    }

    [Fact]
    public async Task SemanticSearchFindsLexicallyUnmatchedChunkAcrossTheWholeIndexAndCachesVectors()
    {
        var store = await CreateAsync();
        var relevantPath = Path.Combine(directory, "compensation.md");
        var unrelatedPath = Path.Combine(directory, "dns.md");
        await File.WriteAllTextAsync(relevantPath, "Annual salary changes require approval by human resources. password: kb-secret-value");
        await File.WriteAllTextAsync(unrelatedPath, "DNS records resolve domain names to network addresses.");
        var relevant = await store.ImportAsync(relevantPath);
        await store.ImportAsync(unrelatedPath);
        var embeddings = new SyntheticEmbeddingProvider();

        Assert.Empty(await store.SearchAsync("compensation policy"));
        var semantic = await store.SearchSemanticAsync("compensation policy", "http://127.0.0.1:11434", "synthetic-embed", embeddings);

        Assert.NotEmpty(semantic);
        Assert.Equal(relevant.Id, semantic[0].DocumentId);
        Assert.Contains("salary", semantic[0].Excerpt, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(3, embeddings.InputCount); // Two indexed chunks and the query vector.

        var reopened = new LocalKnowledgeBase(directory);
        await reopened.InitializeAsync();
        var cached = await reopened.SearchSemanticAsync("compensation policy", "http://127.0.0.1:11434", "synthetic-embed", embeddings);
        Assert.NotEmpty(cached);
        Assert.Equal(relevant.Id, cached[0].DocumentId);
        Assert.Equal(4, embeddings.InputCount); // Reopening reuses both persisted vectors; only the query is embedded.

        var backupPath = Path.Combine(directory, "semantic-backup.db");
        await reopened.BackupAsync(backupPath);

        Assert.True(await reopened.DeleteAsync(relevant.Id));
        Assert.DoesNotContain(relevant.Id, (await reopened.SearchSemanticAsync("compensation policy", "http://127.0.0.1:11434", "synthetic-embed", embeddings)).Select(hit => hit.DocumentId));
        Assert.Equal(5, embeddings.InputCount); // Deleted document vector was removed; only the query was embedded.

        Assert.Equal(2, await reopened.RestoreAsync(backupPath));
        var restored = await reopened.SearchSemanticAsync("compensation policy", "http://127.0.0.1:11434", "synthetic-embed", embeddings);
        Assert.Equal(relevant.Id, restored[0].DocumentId);
        Assert.Equal(8, embeddings.InputCount); // Restore clears derived vectors and rebuilds from restored source chunks.
        Assert.Contains(embeddings.Inputs, input => input.Contains("[dane poufne]", StringComparison.Ordinal));
        Assert.DoesNotContain(embeddings.Inputs, input => input.Contains("kb-secret-value", StringComparison.Ordinal));

        var changedModel = await reopened.SearchSemanticAsync("compensation policy", "http://127.0.0.1:11434", "synthetic-embed-v2", embeddings);
        Assert.Equal(relevant.Id, changedModel[0].DocumentId);
        Assert.Equal(11, embeddings.InputCount); // A model change invalidates and rebuilds all cached document vectors.

        var changedEndpoint = await reopened.SearchSemanticAsync("compensation policy", "http://localhost:11434", "synthetic-embed-v2", embeddings);
        Assert.Equal(relevant.Id, changedEndpoint[0].DocumentId);
        Assert.Equal(14, embeddings.InputCount); // Endpoint changes invalidate the cache too.
    }

    [Fact]
    public async Task ConcurrentSemanticSearchesAcrossInstancesSerializeCacheRebuildsAcrossModels()
    {
        var store = await CreateAsync();
        var secondStore = new LocalKnowledgeBase(directory);
        await secondStore.InitializeAsync();
        var path = Path.Combine(directory, "policy.md");
        await File.WriteAllTextAsync(path, "Annual salary changes require approval by human resources.");
        await store.ImportAsync(path);

        var embeddings = new ConcurrentEmbeddingProvider();
        var first = store.SearchSemanticAsync("salary policy", "http://127.0.0.1:11434", "model-a", embeddings);
        await embeddings.FirstCallEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        var secondStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var second = Task.Run(async () =>
        {
            secondStarted.SetResult();
            return await secondStore.SearchSemanticAsync("salary policy", "http://localhost:11434", "model-b", embeddings);
        });
        await secondStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Task.Delay(TimeSpan.FromMilliseconds(100));
        var concurrencyBeforeRelease = embeddings.MaximumConcurrentCalls;

        embeddings.ReleaseFirstCall.TrySetResult();
        await Task.WhenAll(first, second);

        Assert.Equal(1, concurrencyBeforeRelease);
        Assert.Equal(1, embeddings.MaximumConcurrentCalls);
        Assert.Single(await store.SearchSemanticAsync("salary policy", "http://localhost:11434", "model-b", embeddings));
    }

    [Fact]
    public async Task ImportWaitsForExclusiveDatabaseOperationLockFile()
    {
        if (!OperatingSystem.IsWindows()) return;
        var store = await CreateAsync();
        var lockPath = store.DatabasePath + ".operation.lock";
        var helperPath = Path.Combine(directory, "hold-operation-lock.ps1");
        await File.WriteAllTextAsync(helperPath, """
            param([string]$LockPath)
            $lock = [System.IO.File]::Open($LockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            try {
                [Console]::Out.WriteLine('READY')
                [Console]::Out.Flush()
                [Console]::In.ReadLine() | Out-Null
            } finally { $lock.Dispose() }
            """);
        var powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
        Assert.True(File.Exists(powershell), "Windows PowerShell is required for the cross-process lock test.");
        var start = new ProcessStartInfo(powershell)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        start.ArgumentList.Add("-NoLogo");
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-ExecutionPolicy");
        start.ArgumentList.Add("Bypass");
        start.ArgumentList.Add("-File");
        start.ArgumentList.Add(helperPath);
        start.ArgumentList.Add(lockPath);
        using var lockProcess = Process.Start(start) ?? throw new IOException("Could not start the cross-process lock helper.");
        var stderrTask = lockProcess.StandardError.ReadToEndAsync();
        try
        {
            Assert.Equal("READY", await lockProcess.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5)));
            var sourcePath = Path.Combine(directory, "locked-import.md");
            await File.WriteAllTextAsync(sourcePath, "This import must wait for the database operation lock.");

            var import = store.ImportAsync(sourcePath);
            await Task.Delay(TimeSpan.FromMilliseconds(150));
            var waitedForOtherProcess = !import.IsCompleted;
            await lockProcess.StandardInput.WriteLineAsync("release");
            await lockProcess.StandardInput.FlushAsync();
            await lockProcess.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            var result = await import.WaitAsync(TimeSpan.FromSeconds(5));
            var lockProcessError = await stderrTask;
            Assert.True(lockProcess.ExitCode == 0, lockProcessError);
            Assert.True(waitedForOtherProcess, "Import should wait while a separate process holds the exclusive lock file.");
            Assert.Equal("locked-import.md", result.Name);
        }
        finally
        {
            if (!lockProcess.HasExited)
            {
                try { await lockProcess.StandardInput.WriteLineAsync("release"); } catch (IOException) { }
                try { lockProcess.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                try { await lockProcess.WaitForExitAsync(); } catch (InvalidOperationException) { }
            }
        }
    }

    [Fact]
    public async Task DeleteWaitsForSemanticIndexingAndRemovesItsVectors()
    {
        var store = await CreateAsync();
        var secondStore = new LocalKnowledgeBase(directory);
        await secondStore.InitializeAsync();
        var path = Path.Combine(directory, "policy.md");
        await File.WriteAllTextAsync(path, "Annual salary changes require approval by human resources.");
        var document = await store.ImportAsync(path);
        var embeddings = new ConcurrentEmbeddingProvider();

        var search = store.SearchSemanticAsync("salary policy", "http://127.0.0.1:11434", "model-a", embeddings);
        await embeddings.FirstCallEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var deletion = secondStore.DeleteAsync(document.Id);
        await Task.Delay(TimeSpan.FromMilliseconds(100));
        var deletionWaited = !deletion.IsCompleted;

        embeddings.ReleaseFirstCall.TrySetResult();
        await search;
        Assert.True(await deletion);

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        { DataSource = store.DatabasePath, Pooling = false }.ToString());
        await connection.OpenAsync();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM semantic_embeddings";

        Assert.True(deletionWaited);
        Assert.Equal(0L, (long)(await command.ExecuteScalarAsync())!);
        Assert.Empty(await store.SearchSemanticAsync("salary policy", "http://127.0.0.1:11434", "model-a", embeddings));
    }

    private sealed class ConcurrentEmbeddingProvider : ITextEmbeddingProvider
    {
        private int activeCalls;
        private int maximumConcurrentCalls;
        private int firstCall = 1;

        public TaskCompletionSource FirstCallEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseFirstCall { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int MaximumConcurrentCalls => Volatile.Read(ref maximumConcurrentCalls);

        public async Task<IReadOnlyList<float[]>> EmbedAsync(string endpoint, string model, IReadOnlyList<string> inputs,
            CancellationToken cancellationToken = default)
        {
            var active = Interlocked.Increment(ref activeCalls);
            UpdateMaximum(active);
            try
            {
                if (Interlocked.Exchange(ref firstCall, 0) == 1)
                {
                    FirstCallEntered.TrySetResult();
                    await ReleaseFirstCall.Task.WaitAsync(cancellationToken);
                }

                IReadOnlyList<float[]> vectors = inputs.Select(_ => model == "model-a" ? new[] { 1f, 0f } : new[] { 0f, 1f }).ToArray();
                return vectors;
            }
            finally { Interlocked.Decrement(ref activeCalls); }
        }

        private void UpdateMaximum(int value)
        {
            var current = Volatile.Read(ref maximumConcurrentCalls);
            while (value > current)
            {
                var observed = Interlocked.CompareExchange(ref maximumConcurrentCalls, value, current);
                if (observed == current) return;
                current = observed;
            }
        }
    }

    private sealed class SyntheticEmbeddingProvider : ITextEmbeddingProvider
    {
        public int InputCount { get; private set; }
        public List<string> Inputs { get; } = [];

        public Task<IReadOnlyList<float[]>> EmbedAsync(string endpoint, string model, IReadOnlyList<string> inputs,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            InputCount += inputs.Count;
            Inputs.AddRange(inputs);
            IReadOnlyList<float[]> vectors = inputs.Select(text =>
                text.Contains("compensation", StringComparison.OrdinalIgnoreCase) || text.Contains("salary", StringComparison.OrdinalIgnoreCase)
                    ? new[] { 1f, 0f }
                    : new[] { 0f, 1f }).ToArray();
            return Task.FromResult(vectors);
        }
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
    public async Task ExistingVersionOneKnowledgeDatabaseMigratesAndKeepsFtsContent()
    {
        Directory.CreateDirectory(directory);
        var databasePath = Path.Combine(directory, "knowledge.db");
        var documentId = Guid.NewGuid().ToString("N");
        var importedAt = DateTimeOffset.UtcNow.ToString("O");
        await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = databasePath, Pooling = false }.ToString()))
        {
            await connection.OpenAsync();
            using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE documents(id TEXT PRIMARY KEY,name TEXT NOT NULL,sha256 TEXT NOT NULL UNIQUE,imported_at TEXT NOT NULL,chunk_count INTEGER NOT NULL CHECK(chunk_count>=0));
                CREATE VIRTUAL TABLE chunks USING fts5(source UNINDEXED,content,tokenize='unicode61 remove_diacritics 2');
                INSERT INTO documents(id,name,sha256,imported_at,chunk_count) VALUES($id,'legacy.txt',lower(hex(randomblob(32))),$time,1);
                INSERT INTO chunks(source,content) VALUES($source,'Legacy knowledge remains searchable.');
                PRAGMA user_version=1;
                """;
            command.Parameters.AddWithValue("$id", documentId);
            command.Parameters.AddWithValue("$time", importedAt);
            command.Parameters.AddWithValue("$source", documentId + "#0");
            await command.ExecuteNonQueryAsync();
        }

        var store = new LocalKnowledgeBase(directory);
        await store.InitializeAsync();

        Assert.Equal("legacy.txt", Assert.Single(await store.SearchAsync("Legacy searchable")).SourceName);
        await using var verify = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = databasePath, Pooling = false }.ToString());
        await verify.OpenAsync();
        using var version = verify.CreateCommand(); version.CommandText = "PRAGMA user_version";
        Assert.Equal(2L, (long)(await version.ExecuteScalarAsync())!);
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
    public async Task StreamsDocxTextAndRejectsExtractionBeyondLimitWithoutChangingIndex()
    {
        var store = await CreateAsync();
        var path = Path.Combine(directory, "oversized-text.docx");
        var text = new string('x', LocalKnowledgeBase.MaximumExtractedCharacters + 1);
        var xml = "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>" + text + "</w:t></w:r></w:p></w:body></w:document>";
        await using (var file = new FileStream(path, FileMode.CreateNew))
        using (var archive = new ZipArchive(file, ZipArchiveMode.Create))
        {
            var entry = archive.CreateEntry("word/document.xml");
            await using var stream = entry.Open();
            await stream.WriteAsync(Encoding.UTF8.GetBytes(xml));
        }

        var error = await Assert.ThrowsAsync<InvalidDataException>(() => store.ImportAsync(path));

        Assert.Contains("2 MB", error.Message);
        Assert.Empty(await store.ListAsync());
    }

    [Fact]
    public async Task RejectsDocxExternalEntities()
    {
        var store = await CreateAsync();
        var secretPath = Path.Combine(directory, "local-secret.txt");
        await File.WriteAllTextAsync(secretPath, "Synthetic secret that must not be read");
        var uri = new Uri(secretPath).AbsoluteUri;
        var path = Path.Combine(directory, "external-entity.docx");
        var xml = "<!DOCTYPE w:document [<!ENTITY xxe SYSTEM \"" + uri + "\">]><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body></w:document>";
        await using (var file = new FileStream(path, FileMode.CreateNew))
        using (var archive = new ZipArchive(file, ZipArchiveMode.Create))
        {
            var entry = archive.CreateEntry("word/document.xml");
            await using var stream = entry.Open();
            await stream.WriteAsync(Encoding.UTF8.GetBytes(xml));
        }

        await Assert.ThrowsAsync<System.Xml.XmlException>(() => store.ImportAsync(path));
        Assert.Empty(await store.ListAsync());
    }

    [Fact]
    public async Task ExtractsSearchablePdfTextLocally()
    {
        var store = await CreateAsync();
        var path = Path.Combine(directory, "payment-guide.pdf");
        var builder = new PdfDocumentBuilder();
        var page = builder.AddPage(PageSize.A4);
        var font = builder.AddStandard14Font(Standard14Font.Helvetica);
        page.AddText("Verify payment by phone before sending funds", 12, new PdfPoint(25, 700), font);
        await File.WriteAllBytesAsync(path, builder.Build());

        var document = await store.ImportAsync(path);
        var hits = await store.SearchAsync("payment phone");

        Assert.Equal("payment-guide.pdf", document.Name);
        Assert.Contains(hits, hit => hit.DocumentId == document.Id && hit.SourceName == "payment-guide.pdf");
    }

    [Fact]
    public async Task RejectsPdfOverPageLimitWithoutChangingIndex()
    {
        var store = await CreateAsync();
        var path = Path.Combine(directory, "too-many-pages.pdf");
        var builder = new PdfDocumentBuilder();
        for (var index = 0; index <= LocalKnowledgeBase.MaximumPdfPages; index++) builder.AddPage(PageSize.A4);
        await File.WriteAllBytesAsync(path, builder.Build());

        var error = await Assert.ThrowsAsync<InvalidDataException>(() => store.ImportAsync(path));

        Assert.Contains(LocalKnowledgeBase.MaximumPdfPages.ToString(), error.Message);
        Assert.Empty(await store.ListAsync());
    }

    [Fact]
    public async Task RejectsUnsupportedFormatOversizedInputAndFtsSyntaxInjection()
    {
        var store = await CreateAsync();
        var unsupported = Path.Combine(directory, "document.bin");
        await File.WriteAllTextAsync(unsupported, "unsupported content");
        await Assert.ThrowsAsync<NotSupportedException>(() => store.ImportAsync(unsupported));

        var malformedPdf = Path.Combine(directory, "malformed.pdf");
        await File.WriteAllTextAsync(malformedPdf, "%PDF synthetic");
        await Assert.ThrowsAnyAsync<Exception>(() => store.ImportAsync(malformedPdf));
        Assert.Empty(await store.ListAsync());

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
