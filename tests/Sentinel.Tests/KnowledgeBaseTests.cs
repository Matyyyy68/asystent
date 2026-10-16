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

    public void Dispose() { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
}
