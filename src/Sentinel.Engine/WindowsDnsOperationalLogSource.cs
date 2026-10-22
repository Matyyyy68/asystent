using System.Diagnostics;
using System.Globalization;
using System.Xml;
using System.Xml.Linq;
using Sentinel.Core.Analysis;

namespace Sentinel.Engine;

/// <summary>Read-only access to the optional Windows DNS Client Operational channel.</summary>
public sealed class WindowsDnsOperationalLogSource
{
    public const string ChannelName = "Microsoft-Windows-DNS-Client/Operational";
    public const int MaximumBatchSize = 256;
    private const int MaximumOutputCharacters = 2 * 1024 * 1024;
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(5);

    public async Task<bool> IsEnabledAsync(CancellationToken cancellationToken = default)
    {
        var result = await RunAsync(["gl", ChannelName, "/f:xml", "/uni:true"], cancellationToken);
        if (result.ExitCode != 0) throw new IOException("Nie można odczytać stanu kanału DNS Operational.");
        using var text = new StringReader(result.Output);
        using var reader = XmlReader.Create(text, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null,
            MaxCharactersInDocument = 64 * 1024 });
        var root = XDocument.Load(reader).Root;
        return bool.TryParse(root?.Attribute("enabled")?.Value, out var enabled) && enabled;
    }

    public async Task<long?> ReadLatestRecordIdAsync(CancellationToken cancellationToken = default)
    {
        var xml = await QueryAsync("*[System[(EventID=3008)]]", newestFirst: true, count: 1, cancellationToken);
        return WindowsDnsOperationalEventParser.Parse(xml, maximumEvents: 1).FirstOrDefault()?.RecordId;
    }

    public async Task<IReadOnlyList<WindowsDnsOperationalEvent>> ReadAfterAsync(long recordId,
        CancellationToken cancellationToken = default)
    {
        if (recordId < 0) throw new ArgumentOutOfRangeException(nameof(recordId));
        var xpath = $"*[System[(EventID=3008) and (EventRecordID > {recordId.ToString(CultureInfo.InvariantCulture)})]]";
        var xml = await QueryAsync(xpath, newestFirst: false, count: MaximumBatchSize, cancellationToken);
        return WindowsDnsOperationalEventParser.Parse(xml, recordId, MaximumBatchSize);
    }

    private static async Task<string> QueryAsync(string xpath, bool newestFirst, int count, CancellationToken cancellationToken)
    {
        var result = await RunAsync(["qe", ChannelName, $"/q:{xpath}", "/f:xml", "/e:Events", "/uni:true",
            newestFirst ? "/rd:true" : "/rd:false", $"/c:{count.ToString(CultureInfo.InvariantCulture)}"], cancellationToken);
        if (result.ExitCode != 0) throw new IOException("Nie można odczytać zdarzeń DNS Operational.");
        return result.Output;
    }

    private static async Task<(int ExitCode, string Output)> RunAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Dziennik DNS Operational wymaga Windows.");
        var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "wevtutil.exe");
        using var process = new Process { StartInfo = new ProcessStartInfo
        {
            FileName = executable, UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true,
            RedirectStandardError = true, StandardOutputEncoding = System.Text.Encoding.Unicode,
            StandardErrorEncoding = System.Text.Encoding.Unicode
        } };
        foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        process.Start();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(CommandTimeout);
        var outputTask = ReadBoundedAsync(process.StandardOutput, MaximumOutputCharacters, timeout.Token);
        var errorTask = ReadBoundedAsync(process.StandardError, 16 * 1024, timeout.Token);
        try { await process.WaitForExitAsync(timeout.Token); }
        catch
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw;
        }
        var output = await outputTask;
        _ = await errorTask;
        return (process.ExitCode, output);
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader, int maximumCharacters, CancellationToken cancellationToken)
    {
        var builder = new System.Text.StringBuilder(Math.Min(maximumCharacters, 4096));
        var buffer = new char[4096];
        while (true)
        {
            var count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (count == 0) return builder.ToString();
            if (builder.Length + count > maximumCharacters) throw new InvalidDataException("Odpowiedź dziennika DNS przekracza limit.");
            builder.Append(buffer, 0, count);
        }
    }
}
