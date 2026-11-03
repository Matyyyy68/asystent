using System.Diagnostics;
using System.Globalization;
using System.Text.Json;

namespace Sentinel.Engine;

public sealed record WindowsDefenderStatusSnapshot(bool Available, bool? AntivirusEnabled,
    bool? RealTimeProtectionEnabled, string? SignatureVersion, int? SignatureAgeDays,
    DateTimeOffset? SignatureLastUpdatedUtc, DateTimeOffset ReadAtUtc);

/// <summary>Reads Defender's own reported status without changing protection settings.</summary>
public sealed class WindowsDefenderStatusReader
{
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan UnavailableRetryInterval = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(4);
    private const int MaximumOutputCharacters = 4096;
    private const string Query = """
        $ErrorActionPreference = 'Stop'
        $s = Get-MpComputerStatus -ErrorAction Stop
        $updated = $null
        if ($null -ne $s.AntivirusSignatureLastUpdated) { $updated = $s.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o') }
        $result = [ordered]@{
            antivirusEnabled = [bool]$s.AntivirusEnabled
            realTimeProtectionEnabled = [bool]$s.RealTimeProtectionEnabled
            signatureVersion = [string]$s.AntivirusSignatureVersion
            signatureAgeDays = [int]$s.AntivirusSignatureAge
            signatureLastUpdatedUtc = $updated
        }
        [Console]::Out.Write((ConvertTo-Json -InputObject $result -Compress))
        """;

    private readonly object gate = new();
    private WindowsDefenderStatusSnapshot snapshot = Unavailable(DateTimeOffset.UtcNow);
    private DateTimeOffset lastAttemptUtc = DateTimeOffset.MinValue;
    private bool queryRunning;

    public WindowsDefenderStatusSnapshot Snapshot
    {
        get { lock (gate) return snapshot; }
    }

    public void RefreshIfDue()
    {
        if (!OperatingSystem.IsWindows()) return;
        lock (gate)
        {
            var now = DateTimeOffset.UtcNow;
            var refreshInterval = snapshot.Available ? RefreshInterval : UnavailableRetryInterval;
            if (queryRunning || now - lastAttemptUtc < refreshInterval) return;
            queryRunning = true;
            lastAttemptUtc = now;
        }
        _ = Task.Run(async () =>
        {
            var result = Unavailable(DateTimeOffset.UtcNow);
            try { result = await ReadAsync().ConfigureAwait(false); }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            { /* This optional probe must never stop Engine status or future retries. */ }
            finally
            {
                lock (gate)
                {
                    snapshot = result;
                    queryRunning = false;
                }
            }
        });
    }

    public static WindowsDefenderStatusSnapshot Parse(string output, DateTimeOffset? readAtUtc = null)
    {
        ArgumentNullException.ThrowIfNull(output);
        var now = readAtUtc ?? DateTimeOffset.UtcNow;
        if (output.Length is 0 or > MaximumOutputCharacters) return Unavailable(now);
        try
        {
            using var document = JsonDocument.Parse(output, new JsonDocumentOptions { MaxDepth = 4 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("antivirusEnabled", out var antivirus) || antivirus.ValueKind is not (JsonValueKind.True or JsonValueKind.False) ||
                !root.TryGetProperty("realTimeProtectionEnabled", out var realTime) || realTime.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                return Unavailable(now);

            var version = ReadBoundedVersion(root);
            var age = root.TryGetProperty("signatureAgeDays", out var ageElement) && ageElement.TryGetInt32(out var parsedAge) && parsedAge is >= 0 and < 65535
                ? parsedAge : (int?)null;
            DateTimeOffset? updated = null;
            if (root.TryGetProperty("signatureLastUpdatedUtc", out var updatedElement) && updatedElement.ValueKind == JsonValueKind.String &&
                DateTimeOffset.TryParse(updatedElement.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsedUpdated))
                updated = parsedUpdated.ToUniversalTime();

            return new(true, antivirus.GetBoolean(), realTime.GetBoolean(), version, age, updated, now);
        }
        catch (JsonException) { return Unavailable(now); }
    }

    private static string? ReadBoundedVersion(JsonElement root)
    {
        if (!root.TryGetProperty("signatureVersion", out var value) || value.ValueKind != JsonValueKind.String) return null;
        var version = value.GetString();
        return version is { Length: > 0 and <= 32 } && version.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-')
            ? version : null;
    }

    private static async Task<WindowsDefenderStatusSnapshot> ReadAsync()
    {
        var now = DateTimeOffset.UtcNow;
        try
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (string.IsNullOrWhiteSpace(windows)) return Unavailable(now);
            var executable = Path.Combine(windows, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
            if (!File.Exists(executable)) return Unavailable(now);
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = executable,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    WorkingDirectory = windows
                }
            };
            process.StartInfo.ArgumentList.Add("-NoLogo");
            process.StartInfo.ArgumentList.Add("-NoProfile");
            process.StartInfo.ArgumentList.Add("-NonInteractive");
            process.StartInfo.ArgumentList.Add("-Command");
            process.StartInfo.ArgumentList.Add(Query);
            if (!process.Start()) return Unavailable(now);

            using var timeout = new CancellationTokenSource(QueryTimeout);
            var outputTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var errorTask = process.StandardError.ReadToEndAsync(timeout.Token);
            try { await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false); }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                return Unavailable(now);
            }
            var output = await outputTask.ConfigureAwait(false);
            _ = await errorTask.ConfigureAwait(false);
            if (process.ExitCode != 0 || output.Length > MaximumOutputCharacters) return Unavailable(now);
            return Parse(output, DateTimeOffset.UtcNow);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception or OperationCanceledException)
        { return Unavailable(now); }
    }

    private static WindowsDefenderStatusSnapshot Unavailable(DateTimeOffset now) => new(false, null, null, null, null, null, now);
}
