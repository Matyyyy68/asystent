using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

public sealed record ScheduledTaskSnapshotCapture(
    bool Available,
    IReadOnlyDictionary<string, PersistenceSnapshotEntry> Entries,
    string Status);

/// <summary>Reads scheduled-task definitions without executing them or persisting their names or commands.</summary>
public static class WindowsScheduledTaskSnapshotReader
{
    private const int MaximumEntries = 256;
    private const int MaximumOutputCharacters = 8 * 1024 * 1024;
    private static readonly Regex XmlDeclaration = new(
        @"(?m)^\s*<\?xml[^?]*\?>\s*", RegexOptions.CultureInvariant);

    public static async Task<ScheduledTaskSnapshotCapture> CaptureAsync(CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            return Unavailable("Scheduled Tasks wymagają Windows.");

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "schtasks.exe"),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            }
        };
        process.StartInfo.ArgumentList.Add("/query");
        process.StartInfo.ArgumentList.Add("/xml");

        try
        {
            if (!process.Start()) return Unavailable("nie udało się uruchomić czytnika zadań");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            var outputTask = ReadBoundedAsync(process.StandardOutput, MaximumOutputCharacters, timeout.Token);
            var errorTask = DrainAsync(process.StandardError, timeout.Token);
            try
            {
                await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                TryKill(process);
                if (cancellationToken.IsCancellationRequested) throw;
                return Unavailable("przekroczono limit czasu odczytu");
            }

            var (output, tooLarge) = await outputTask.ConfigureAwait(false);
            await errorTask.ConfigureAwait(false);
            if (tooLarge) return Unavailable("wynik przekracza limit rozmiaru");
            if (process.ExitCode != 0) return Unavailable($"odmowa lub błąd źródła (kod {process.ExitCode})");

            try
            {
                var entries = ParseXml(output);
                return new(true, entries, $"odczytano {entries.Count} zadań");
            }
            catch (Exception exception) when (exception is XmlException or InvalidDataException or ArgumentException)
            {
                return Unavailable("nieprawidłowy snapshot (" + exception.GetType().Name + ")");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            TryKill(process);
            throw;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            TryKill(process);
            return Unavailable("źródło zadań niedostępne (" + exception.GetType().Name + ")");
        }
    }

    public static IReadOnlyDictionary<string, PersistenceSnapshotEntry> ParseXml(string xml)
    {
        ArgumentNullException.ThrowIfNull(xml);
        if (xml.Length > MaximumOutputCharacters) throw new InvalidDataException("Snapshot zadań przekracza limit rozmiaru.");
        var fragment = XmlDeclaration.Replace(xml, string.Empty);
        var document = new XmlDocument { XmlResolver = null };
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaximumOutputCharacters,
            MaxCharactersFromEntities = 0,
            ConformanceLevel = ConformanceLevel.Document
        };
        using (var reader = XmlReader.Create(new StringReader("<Tasks>" + fragment + "</Tasks>"), settings))
            document.Load(reader);

        var tasks = document.SelectNodes("//*[local-name()='Task']") ?? throw new InvalidDataException("Brak listy zadań.");
        if (tasks.Count > MaximumEntries) throw new InvalidDataException("Liczba zadań przekracza limit snapshotu.");
        var entries = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal);
        foreach (XmlNode task in tasks)
        {
            var uri = task.SelectSingleNode("./*[local-name()='RegistrationInfo']/*[local-name()='URI']")?.InnerText;
            if (string.IsNullOrWhiteSpace(uri)) throw new InvalidDataException("Zadanie nie ma stabilnego identyfikatora.");

            var identity = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("scheduled.task\0" + uri.ToUpperInvariant())));
            var key = "scheduled.task:" + identity;
            var xmlFingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(task.OuterXml)));
            var writableLocation = task.SelectNodes(".//*[local-name()='Command' or local-name()='Arguments']")!
                .Cast<XmlNode>().Any(node => LooksLikeWritableLocation(node.InnerText));
            if (!entries.TryAdd(key, new("scheduled.task", xmlFingerprint, writableLocation)))
                throw new InvalidDataException("Snapshot zawiera powtórzony identyfikator zadania.");
        }
        return entries;
    }

    private static bool LooksLikeWritableLocation(string command)
    {
        var normalized = command.Replace('/', '\\');
        string[] markers = ["%TEMP%", "%TMP%", "%APPDATA%", "%LOCALAPPDATA%", "\\AppData\\Local\\Temp\\",
            "\\AppData\\Roaming\\", "\\Downloads\\", "\\Users\\Public\\"];
        if (markers.Any(marker => normalized.Contains(marker, StringComparison.OrdinalIgnoreCase))) return true;
        foreach (var specialFolder in new[] { Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolder.ApplicationData,
                     Environment.SpecialFolder.InternetCache, Environment.SpecialFolder.UserProfile })
        {
            var folder = Environment.GetFolderPath(specialFolder);
            if (!string.IsNullOrWhiteSpace(folder) && normalized.Contains(folder + Path.DirectorySeparatorChar + "Temp", StringComparison.OrdinalIgnoreCase)) return true;
        }
        var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        return !string.IsNullOrWhiteSpace(downloads) && normalized.Contains(downloads, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<(string Text, bool TooLarge)> ReadBoundedAsync(StreamReader reader, int maximumCharacters, CancellationToken cancellationToken)
    {
        var output = new StringBuilder(Math.Min(maximumCharacters, 64 * 1024));
        var tooLarge = false;
        var total = 0;
        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
        {
            total = checked(total + line.Length + 1);
            if (total > maximumCharacters) { tooLarge = true; continue; }
            output.AppendLine(line);
        }
        return (output.ToString(), tooLarge);
    }

    private static async Task DrainAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is not null) { }
    }

    private static ScheduledTaskSnapshotCapture Unavailable(string status)
        => new(false, new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal), status);

    private static void TryKill(Process process)
    {
        try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        catch { }
    }
}
