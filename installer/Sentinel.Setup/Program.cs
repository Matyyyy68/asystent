using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Sentinel.Setup;

internal static class Program
{
    private const string Product = "Sentinel AI";
    internal static readonly string LogPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), Product, "Logs", "installer.log");
    private static readonly string DefaultDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", Product);
    private static string PayloadHash => Assembly.GetExecutingAssembly().GetCustomAttributes<AssemblyMetadataAttribute>()
        .FirstOrDefault(x => x.Key == "SentinelPayloadSha256")?.Value ?? "";
    private const long MinimumFreeSpaceMargin = 32L * 1024 * 1024;

    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Contains("--integration-test", StringComparer.OrdinalIgnoreCase)) return IntegrationTest();
        if (args.Contains("--self-test", StringComparer.OrdinalIgnoreCase)) return SelfTest();
        if (args.Contains("--uninstall", StringComparer.OrdinalIgnoreCase))
        {
            ApplicationConfiguration.Initialize();
            if (MessageBox.Show($"Czy na pewno odinstalować Sentinel AI?\n\nTwoje lokalne dane i historia pozostaną na tym komputerze.", Product, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return 0;
            try { Uninstall(Path.GetDirectoryName(Environment.ProcessPath!)!); return 0; }
            catch (Exception ex) { MessageBox.Show($"Nie udało się odinstalować Sentinel AI.\n\n{ex.Message}", Product, MessageBoxButtons.OK, MessageBoxIcon.Error); return 1; }
        }
        ApplicationConfiguration.Initialize();
        Application.Run(new SetupWizard());
        return 0;
    }

    private static int IntegrationTest()
    {
        Log("INTEGRATION_TEST_REQUESTED");
        if (!OperatingSystem.IsWindows()) return 2;
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Programs", ".SentinelAI-Integration-Test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var uninstallKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI");
            using (uninstallKey)
                if (uninstallKey is not null) throw new InvalidOperationException("Integration test refused: a Sentinel AI installation is already registered.");
            if (Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")?.GetValue("Sentinel AI") is not null)
                throw new InvalidOperationException("Integration test refused: a Sentinel AI autostart value already exists.");
            foreach (var keyPath in new[]
            {
                @"Software\Google\Chrome\NativeMessagingHosts\com.sentinelai.urlcheck",
                @"Software\Microsoft\Edge\NativeMessagingHosts\com.sentinelai.urlcheck"
            })
                using (var key = Registry.CurrentUser.OpenSubKey(keyPath))
                    if (key is not null) throw new InvalidOperationException($"Integration test refused: Native Messaging key already exists ({keyPath}).");
            var startMenuLink = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "Sentinel AI.lnk");
            var desktopLink = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Sentinel AI.lnk");
            if (File.Exists(startMenuLink) || File.Exists(desktopLink))
                throw new InvalidOperationException("Integration test refused: a Sentinel AI shortcut already exists.");
            if (Directory.Exists(root)) throw new IOException("Generated integration-test folder unexpectedly already exists.");

            Log($"INTEGRATION_TEST_START target={root}");
            Install(root, startMenuShortcut: false, desktopShortcut: false, autoStart: false,
                (_, _) => { }, CancellationToken.None);
            VerifyInstallation(root, startMenuShortcut: false, desktopShortcut: false, autoStart: false);
            Uninstall(root);

            if (Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI") is not null)
                throw new InvalidDataException("Uninstall registration remained after integration-test cleanup.");
            if (Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")?.GetValue("Sentinel AI") is not null)
                throw new InvalidDataException("Autostart remained after integration-test cleanup.");
            foreach (var keyPath in new[]
            {
                @"Software\Google\Chrome\NativeMessagingHosts\com.sentinelai.urlcheck",
                @"Software\Microsoft\Edge\NativeMessagingHosts\com.sentinelai.urlcheck"
            })
                using (var key = Registry.CurrentUser.OpenSubKey(keyPath))
                    if (key is not null) throw new InvalidDataException($"Native Messaging registration remained after cleanup ({keyPath}).");
            if (File.Exists(startMenuLink) || File.Exists(desktopLink))
                throw new InvalidDataException("A Sentinel AI shortcut remained after integration-test cleanup.");
            using (var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip")!)
            using (var archive = new ZipArchive(resource, ZipArchiveMode.Read))
                foreach (var entry in archive.Entries.Where(x => !string.IsNullOrEmpty(x.Name)))
                {
                    var installedPath = Path.GetFullPath(Path.Combine(root, entry.FullName.Replace('/', Path.DirectorySeparatorChar)));
                    if (File.Exists(installedPath)) throw new InvalidDataException($"Uninstall left an application file: {entry.FullName}.");
                }

            Log("INTEGRATION_TEST_SUCCESS install=true verification=true uninstall=true registry=true nativeMessaging=true shortcuts=false autostart=false");
            return 0;
        }
        catch (Exception ex)
        {
            Log($"INTEGRATION_TEST_FAILED type={ex.GetType().Name} message={Clean(ex.Message)}");
            try
            {
                var registered = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI")?.GetValue("InstallLocation") as string;
                if (Directory.Exists(root) && string.Equals(Path.GetFullPath(registered ?? string.Empty), root, StringComparison.OrdinalIgnoreCase))
                    Uninstall(root);
            }
            catch (Exception cleanupError) { Log($"INTEGRATION_TEST_CLEANUP_FAILED type={cleanupError.GetType().Name} message={Clean(cleanupError.Message)}"); }
            return 1;
        }
    }

    private static bool VerifyPayload(bool showErrors)
    {
        try
        {
            using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip")
                ?? throw new InvalidDataException("Brak pakietu aplikacji w instalatorze.");
            if (!PayloadHashMatches(stream, PayloadHash))
                throw new InvalidDataException("Pakiet instalacyjny jest uszkodzony (niezgodna suma kontrolna).");
            stream.Position = 0;
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
            if (!archive.Entries.Any(e => e.FullName.Replace('\\', '/').Equals("Sentinel AI.exe", StringComparison.OrdinalIgnoreCase))
                || !archive.Entries.Any(e => e.FullName.Replace('\\', '/').Equals("resources/engine/Sentinel.Engine.exe", StringComparison.OrdinalIgnoreCase)))
                throw new InvalidDataException("Pakiet jest niekompletny.");
            return true;
        }
        catch (Exception ex)
        {
            Log($"PAYLOAD_VERIFY_FAILED type={ex.GetType().Name} message={Clean(ex.Message)} expected={PayloadHash}");
            if (showErrors) MessageBox.Show($"Nie można zweryfikować instalatora. Pobierz go ponownie ze strony Sentinel AI.\n\n{ex.Message}", Product, MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
    }

    private static bool PayloadHashMatches(Stream payload, string expectedHash)
    {
        if (expectedHash.Length != 64) return false;
        var actual = Convert.ToHexString(SHA256.HashData(payload));
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(actual), Encoding.ASCII.GetBytes(expectedHash.ToUpperInvariant()));
    }

    private static long CalculateRequiredFreeSpace(long payloadBytes, long preservedBytes)
    {
        if (payloadBytes < 0 || preservedBytes < 0) throw new ArgumentOutOfRangeException(nameof(payloadBytes));
        var margin = Math.Max(MinimumFreeSpaceMargin, payloadBytes / 20);
        return checked(payloadBytes + preservedBytes + margin);
    }

    private static void EnsureSufficientFreeSpace(long availableBytes, long requiredBytes)
    {
        if (availableBytes < 0 || requiredBytes < 0) throw new ArgumentOutOfRangeException(nameof(availableBytes));
        if (availableBytes < requiredBytes)
            throw new IOException($"Za mało wolnego miejsca na dysku. Wymagane: {requiredBytes / 1_048_576:N0} MB, dostępne: {availableBytes / 1_048_576:N0} MB.");
    }

    internal static bool ShouldPublishProgressUpdate(ref long previousTick, long currentTick, int value)
    {
        const long minimumIntervalMilliseconds = 200;
        var previous = Interlocked.Read(ref previousTick);
        if (value < 100 && previous != long.MinValue && currentTick - previous < minimumIntervalMilliseconds) return false;
        Interlocked.Exchange(ref previousTick, currentTick);
        return true;
    }

    private static int SelfTest()
    {
        ApplicationConfiguration.Initialize();
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var testId = Guid.NewGuid().ToString("N");
        var root = Path.Combine(localAppData, "Programs", ".SentinelAI-Setup-SelfTest-" + testId);
        var data = Path.Combine(localAppData, "SentinelAI-Setup-SelfTest-" + testId);
        try
        {
            long previousProgressTick = long.MinValue;
            var progressUpdates = 0;
            for (var tick = 0; tick < 1_000; tick++)
                if (ShouldPublishProgressUpdate(ref previousProgressTick, tick, 50)) progressUpdates++;
            if (progressUpdates != 5 || !ShouldPublishProgressUpdate(ref previousProgressTick, 1_000, 100))
                throw new InvalidDataException("Ograniczenie aktualizacji postępu UI nie utrzymuje limitu 200 ms albo blokuje końcowy postęp.");

            var samplePayload = Encoding.UTF8.GetBytes("sentinel-installer-integrity-test");
            var sampleHash = Convert.ToHexString(SHA256.HashData(samplePayload));
            using (var validPayload = new MemoryStream(samplePayload))
                if (!PayloadHashMatches(validPayload, sampleHash)) throw new InvalidDataException("Test poprawnego hasha pakietu nie przeszedł.");
            samplePayload[0] ^= 0xFF;
            using (var tamperedPayload = new MemoryStream(samplePayload))
                if (PayloadHashMatches(tamperedPayload, sampleHash)) throw new InvalidDataException("Weryfikator zaakceptował zmieniony pakiet.");

            var noisyAclOutput = string.Join(Environment.NewLine,
                Enumerable.Range(0, 500).Select(index => index % 2 == 0
                    ? "processed file: C:\\private\\staging\\chrome_100_percent.pak"
                    : "Przetworzono plik: C:\\private\\staging\\chrome_100_percent.pak"))
                + Environment.NewLine + "Successfully processed 500 files; Failed processing 0 files";
            var aclSummary = SummarizeProcessOutputForLog(noisyAclOutput, string.Empty);
            if (aclSummary.Length > 400 || aclSummary.Contains("C:\\private", StringComparison.OrdinalIgnoreCase)
                || aclSummary.Contains("processed file:", StringComparison.OrdinalIgnoreCase)
                || !aclSummary.Contains("Successfully processed 500 files", StringComparison.Ordinal))
                throw new InvalidDataException("Podsumowanie logu ACL nie ogranicza listy ścieżek ani nie zachowuje wyniku zbiorczego.");

            var requiredSpace = CalculateRequiredFreeSpace(100L * 1024 * 1024, 10L * 1024 * 1024);
            EnsureSufficientFreeSpace(requiredSpace, requiredSpace);
            var rejectedLowSpace = false;
            try { EnsureSufficientFreeSpace(requiredSpace - 1, requiredSpace); }
            catch (IOException ex) when (ex.Message.StartsWith("Za mało wolnego miejsca", StringComparison.Ordinal)) { rejectedLowSpace = true; }
            if (!rejectedLowSpace) throw new InvalidDataException("Kontrola miejsca na dysku nie odrzuciła niewystarczającej przestrzeni.");
            var expectedRunValue = $"\"{Path.Combine(root, "Sentinel AI.exe")}\" --minimized";
            if (!AutoStartValueMatches(expectedRunValue, Path.Combine(root, "Sentinel AI.exe"), enabled: true)
                || AutoStartValueMatches("\"C:\\wrong\\Sentinel AI.exe\" --minimized", Path.Combine(root, "Sentinel AI.exe"), enabled: true)
                || !AutoStartValueMatches(null, Path.Combine(root, "Sentinel AI.exe"), enabled: false)
                || AutoStartValueMatches(expectedRunValue, Path.Combine(root, "Sentinel AI.exe"), enabled: false))
                throw new InvalidDataException("Weryfikacja wartości autostartu nie odróżnia prawidłowej ścieżki od braku lub błędnej wartości.");

            if (!VerifyPayload(showErrors: false)) throw new InvalidDataException("Nieprawidłowy pakiet instalacyjny.");
            SetupWizard.ValidateVisualStates();
            foreach (var resourceName in new[] { "welcome", "prepare", "configure", "installing", "complete", "error", "cancel" })
            {
                using var illustration = Assembly.GetExecutingAssembly().GetManifestResourceStream($"installer-{resourceName}.png");
                if (illustration is null || illustration.Length == 0)
                    throw new InvalidDataException($"Brakuje osadzonej ilustracji instalatora: {resourceName}.");
            }
            var fallbackDirectory = DefaultDirectory;
            if (!ResolveInstallDirectory(root, fallbackDirectory).Equals(Path.GetFullPath(root), StringComparison.OrdinalIgnoreCase)
                || !ResolveInstallDirectory(Environment.GetFolderPath(Environment.SpecialFolder.System), fallbackDirectory)
                    .Equals(Path.GetFullPath(fallbackDirectory), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Wykrywanie istniejącej lokalizacji instalacji nie działa poprawnie.");
            Install(root, startMenuShortcut: true, desktopShortcut: false, autoStart: false, (_, _) => { }, CancellationToken.None, testMode: true);
            var preservedFile = Path.Combine(root, "self-test-user-file.txt");
            File.WriteAllText(preservedFile, "preserve across update and rollback");
            var engineExecutable = Path.Combine(root, "resources", "engine", "Sentinel.Engine.exe");
            File.WriteAllText(engineExecutable, "outdated-payload-marker");
            Install(root, startMenuShortcut: true, desktopShortcut: false, autoStart: false, (_, _) => { }, CancellationToken.None,
                testMode: true, registeredInstallOverride: root);
            using (var engine = new FileStream(engineExecutable, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                Span<byte> signature = stackalloc byte[2];
                if (engine.Read(signature) != signature.Length || signature[0] != (byte)'M' || signature[1] != (byte)'Z')
                    throw new InvalidDataException("Aktualizacja nie zastąpiła uszkodzonego pliku silnika.");
            }
            if (File.ReadAllText(preservedFile) != "preserve across update and rollback")
                throw new InvalidDataException("Aktualizacja nie zachowała pliku spoza pakietu.");

            Directory.CreateDirectory(data);
            var shortcutTest = Path.Combine(data, "start-menu-test.lnk");
            ApplyShortcutOption(shortcutTest, Path.Combine(root, "Sentinel AI.exe"), root, enabled: true);
            if (!File.Exists(shortcutTest)) throw new InvalidDataException("Wybrana opcja skrótu nie utworzyła skrótu.");
            ApplyShortcutOption(shortcutTest, Path.Combine(root, "Sentinel AI.exe"), root, enabled: false);
            if (File.Exists(shortcutTest)) throw new InvalidDataException("Wyłączona opcja skrótu nie usunęła skrótu Sentinel.");
            var otherExecutable = Path.Combine(data, "other-app.exe");
            File.WriteAllText(otherExecutable, "other app");
            var unrelatedShortcut = Path.Combine(data, "unrelated.lnk");
            CreateShortcut(unrelatedShortcut, otherExecutable);
            ApplyShortcutOption(unrelatedShortcut, Path.Combine(root, "Sentinel AI.exe"), root, enabled: false);
            if (!File.Exists(unrelatedShortcut)) throw new InvalidDataException("Wyłączenie skrótu usunęło skrót nienależący do Sentinel.");

            byte[] engineBeforeSpaceFailure;
            using (var engine = File.OpenRead(engineExecutable)) engineBeforeSpaceFailure = SHA256.HashData(engine);
            var parentDirectory = Path.GetDirectoryName(root)!;
            var stagingBeforeSpaceFailure = Directory.GetDirectories(parentDirectory, ".sentinel-install-*", SearchOption.TopDirectoryOnly).Order(StringComparer.OrdinalIgnoreCase).ToArray();
            var spaceFailureInjected = false;
            try
            {
                Install(root, startMenuShortcut: true, desktopShortcut: false, autoStart: false,
                    (_, percent) => { if (percent > 10) throw new IOException("Simulated disk full during staging."); }, CancellationToken.None,
                    testMode: true, registeredInstallOverride: root);
            }
            catch (IOException ex) when (ex.Message == "Simulated disk full during staging.") { spaceFailureInjected = true; }
            if (!spaceFailureInjected) throw new InvalidDataException("Testowy błąd braku miejsca nie przerwał stagingu.");
            using (var engine = File.OpenRead(engineExecutable))
                if (!CryptographicOperations.FixedTimeEquals(engineBeforeSpaceFailure, SHA256.HashData(engine)))
                    throw new InvalidDataException("Błąd miejsca podczas stagingu zmienił poprzednią instalację.");
            if (File.ReadAllText(preservedFile) != "preserve across update and rollback" ||
                !stagingBeforeSpaceFailure.SequenceEqual(Directory.GetDirectories(parentDirectory, ".sentinel-install-*", SearchOption.TopDirectoryOnly).Order(StringComparer.OrdinalIgnoreCase)))
                throw new InvalidDataException("Błąd miejsca podczas stagingu nie posprzątał plików tymczasowych albo zmienił dane użytkownika.");

            Directory.CreateDirectory(data);
            var app = Path.Combine(root, "Sentinel AI.exe");
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo(app)
                {
                    WorkingDirectory = root,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                }
            };
            process.StartInfo.ArgumentList.Add("--smoke-test");
            process.StartInfo.ArgumentList.Add("--disable-gpu");
            process.StartInfo.ArgumentList.Add("--user-data-dir=" + Path.Combine(data, "electron-profile"));
            process.StartInfo.Environment["SENTINEL_DATA_ROOT"] = data;
            if (!process.Start()) throw new IOException("Nie udało się uruchomić aplikacji testowej.");
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(120_000))
            {
                process.Kill(entireProcessTree: true);
                throw new TimeoutException("Test uruchomienia aplikacji przekroczył 120 sekund.");
            }
            var output = stdout.GetAwaiter().GetResult();
            var error = stderr.GetAwaiter().GetResult();
            if (process.ExitCode != 0 || !output.Contains("PASS: Electron renderer", StringComparison.Ordinal)
                || !File.Exists(Path.Combine(data, "smoke-test.passed")))
                throw new InvalidOperationException($"Smoke test nie powiódł się (kod {process.ExitCode}). {error.Trim()}");
            var databaseDirectory = Path.Combine(data, "data");
            var dataPathPointer = Path.Combine(data, "data-path.txt");
            if (!File.Exists(dataPathPointer) || !Path.GetFullPath(File.ReadAllText(dataPathPointer).Trim())
                    .Equals(Path.GetFullPath(databaseDirectory), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Aplikacja zapisała nieprawidłową ścieżkę lokalnych danych.");
            VerifySmokeDatabase(databaseDirectory, "sentinel.db");
            VerifySmokeDatabase(databaseDirectory, "knowledge.db");

            const string rollbackMarker = "old-installation-rollback-marker";
            File.WriteAllText(engineExecutable, rollbackMarker);
            using (var cancellation = new CancellationTokenSource())
            {
                var cancelled = false;
                try
                {
                    Install(root, startMenuShortcut: true, desktopShortcut: false, autoStart: false,
                        (_, percent) => { if (percent == 90) cancellation.Cancel(); }, cancellation.Token,
                        testMode: true, registeredInstallOverride: root);
                }
                catch (OperationCanceledException) { cancelled = true; }
                if (!cancelled) throw new InvalidOperationException("Instalacja nie przerwała transakcji po anulowaniu.");
            }
            if (File.ReadAllText(engineExecutable) != rollbackMarker
                || File.ReadAllText(preservedFile) != "preserve across update and rollback")
                throw new InvalidDataException("Rollback nie odtworzył poprzedniego katalogu instalacji.");

            Uninstall(root, testMode: true);
            if (File.Exists(app) || File.Exists(engineExecutable) || !File.Exists(preservedFile) ||
                File.ReadAllText(preservedFile) != "preserve across update and rollback" || !Directory.Exists(root))
                throw new InvalidDataException("Deinstalacja nie usunęła plików aplikacji albo zmieniła plik spoza pakietu.");
            using (var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip")!)
            using (var archive = new ZipArchive(resource, ZipArchiveMode.Read))
                foreach (var entry in archive.Entries.Where(x => !string.IsNullOrEmpty(x.Name)))
                {
                    var installedPath = Path.GetFullPath(Path.Combine(root, entry.FullName.Replace('/', Path.DirectorySeparatorChar)));
                    if (File.Exists(installedPath)) throw new InvalidDataException($"Deinstalacja pozostawiła plik aplikacji: {entry.FullName}.");
                }
            VerifySmokeDatabase(databaseDirectory, "sentinel.db");
            VerifySmokeDatabase(databaseDirectory, "knowledge.db");

            Log("SELF_TEST_SUCCESS progressThrottle=true payload=true tamperRejected=true diskSpacePreflight=true stagingFailurePreservedInstall=true chromiumAcl=true update=true rollback=true appSmoke=true uninstall=true userDataPreserved=true");
            return 0;
        }
        catch (Exception ex)
        {
            Log($"SELF_TEST_FAILED type={ex.GetType().Name} message={Clean(ex.Message)}");
            return 1;
        }
        finally { TryDelete(root); TryDelete(data); }
    }

    private static void VerifySmokeDatabase(string dataDirectory, string fileName)
    {
        var database = Path.Combine(dataDirectory, fileName);
        using var stream = new FileStream(database, FileMode.Open, FileAccess.Read, FileShare.Read);
        Span<byte> header = stackalloc byte[16];
        if (stream.Read(header) != header.Length || !header[..15].SequenceEqual("SQLite format 3"u8) || header[15] != 0)
            throw new InvalidDataException($"Aplikacja nie utworzyła poprawnej bazy SQLite {fileName} w izolowanym katalogu danych.");
    }

    private static void ApplyChromiumPermissions(string directory)
    {
        var icacls = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "icacls.exe");
        var start = new ProcessStartInfo(icacls) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        start.ArgumentList.Add(directory);
        start.ArgumentList.Add("/grant");
        start.ArgumentList.Add("*S-1-15-2-1:(OI)(CI)(RX)");
        start.ArgumentList.Add("/T");
        start.ArgumentList.Add("/C");
        using var process = Process.Start(start) ?? throw new IOException("Nie udało się uruchomić icacls.exe.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(30_000)) { process.Kill(entireProcessTree: true); throw new TimeoutException("Konfiguracja uprawnień Chromium trwała zbyt długo."); }
        var stdout = stdoutTask.GetAwaiter().GetResult();
        var stderr = stderrTask.GetAwaiter().GetResult();
        var outputSummary = SummarizeProcessOutputForLog(stdout, stderr);
        Log($"CHROMIUM_ACL exit={process.ExitCode} outputChars={stdout.Length} errorChars={stderr.Length} summary={outputSummary}");
        if (process.ExitCode != 0) throw new IOException($"Windows nie ustawił uprawnień wymaganych przez Chromium (kod {process.ExitCode}). {outputSummary}");
    }

    private static string SummarizeProcessOutputForLog(string stdout, string stderr)
    {
        var summaryLines = (stdout + Environment.NewLine + stderr)
            .Split(["\r\n", "\n", "\r"], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line => !Regex.IsMatch(line, @"(?i)(?:[a-z]:\\|\\\\)"))
            .ToArray();
        var summary = Clean(string.Join(" ", summaryLines));
        if (summary.Length == 0) return "no diagnostic summary";
        return summary.Length <= 400 ? summary : summary[..400];
    }

    internal static void Log(string message)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
            File.AppendAllText(LogPath, $"{DateTimeOffset.Now:O} {message}{Environment.NewLine}", Encoding.UTF8);
        }
        catch { }
    }

    internal static string Clean(string value) => value.Replace('\r', ' ').Replace('\n', ' ').Trim();

    internal static string GetPreferredInstallDirectory()
    {
        var registered = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI")
            ?.GetValue("InstallLocation") as string;
        return ResolveInstallDirectory(registered, DefaultDirectory);
    }

    internal static string ValidateInstallSelection(string target, string? registeredOverride = null)
    {
        target = Path.GetFullPath(target);
        var local = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        if (!target.StartsWith(local + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Wybierz folder w swoim profilu użytkownika. Instalacja nie wymaga uprawnień administratora.");
        var registeredInstall = registeredOverride ?? Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI")?.GetValue("InstallLocation") as string;
        if (!string.IsNullOrWhiteSpace(registeredInstall) && !Path.GetFullPath(registeredInstall).Equals(target, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Sentinel AI jest już zainstalowany w folderze {registeredInstall}. Użyj tej lokalizacji, aby go zaktualizować lub naprawić.");
        if (Directory.Exists(target) && Directory.EnumerateFileSystemEntries(target).Any() &&
            !Path.GetFullPath(registeredInstall ?? string.Empty).Equals(target, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Wybrany folder zawiera pliki, które nie należą do Sentinel AI. Wybierz pusty folder albo lokalizację istniejącej instalacji.");
        return target;
    }

    internal static string GetInstallSpaceSummary(string selectedTarget)
    {
        var target = ValidateInstallSelection(selectedTarget);
        var parent = Path.GetDirectoryName(target) ?? throw new InvalidOperationException("Nieprawidłowy folder instalacji.");
        using var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip")
            ?? throw new InvalidDataException("Brak pakietu aplikacji w instalatorze.");
        using var archive = new ZipArchive(resource, ZipArchiveMode.Read);
        var entries = archive.Entries.Where(entry => !string.IsNullOrEmpty(entry.Name)).ToArray();
        var payloadBytes = entries.Sum(entry => entry.Length);
        var payloadPaths = entries.Select(entry => entry.FullName.Replace('\\', '/')).ToHashSet(StringComparer.OrdinalIgnoreCase);
        long preservedBytes = 0;
        if (Directory.Exists(target))
            foreach (var existing in Directory.EnumerateFiles(target, "*", SearchOption.AllDirectories))
            {
                var relative = Path.GetRelativePath(target, existing).Replace('\\', '/');
                if (relative.Equals("Uninstall Sentinel AI.exe", StringComparison.OrdinalIgnoreCase) || payloadPaths.Contains(relative)) continue;
                preservedBytes = checked(preservedBytes + new FileInfo(existing).Length);
            }
        var requiredBytes = CalculateRequiredFreeSpace(payloadBytes, preservedBytes);
        var volumeRoot = Path.GetPathRoot(parent) ?? throw new IOException("Nie można określić dysku instalacji.");
        var availableBytes = new DriveInfo(volumeRoot).AvailableFreeSpace;
            EnsureSufficientFreeSpace(availableBytes, requiredBytes);
        return $"Pliki aplikacji: {payloadBytes / 1_048_576:N0} MB\r\nWymagane miejsce z zapasem: {requiredBytes / 1_048_576:N0} MB\r\nDostępne miejsce: {availableBytes / 1_048_576:N0} MB";
    }

    internal static void VerifyInstallation(string target, bool startMenuShortcut, bool desktopShortcut, bool autoStart)
    {
        target = Path.GetFullPath(target);
        foreach (var relative in new[] { "Sentinel AI.exe", "Uninstall Sentinel AI.exe", "resources/engine/Sentinel.Engine.exe", "resources/engine/Sentinel.UrlHost.exe", "resources/engine/com.sentinelai.urlcheck.json" })
            if (!File.Exists(Path.Combine(target, relative.Replace('/', Path.DirectorySeparatorChar))))
                throw new InvalidDataException($"Weryfikacja nie znalazła wymaganego pliku: {relative}.");

        var registered = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI")?.GetValue("InstallLocation") as string;
        if (!string.Equals(registered, target, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Weryfikacja wpisu aplikacji w profilu Windows nie powiodła się.");

        var executable = Path.Combine(target, "Sentinel AI.exe");
        var runValue = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")?.GetValue("Sentinel AI") as string;
        if (!AutoStartValueMatches(runValue, executable, autoStart))
            throw new InvalidDataException("Weryfikacja ustawienia autostartu nie powiodła się.");

        var startMenuLink = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "Sentinel AI.lnk");
        var desktopLink = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Sentinel AI.lnk");
        if (ShortcutPointsToInstall(startMenuLink, target) != startMenuShortcut || ShortcutPointsToInstall(desktopLink, target) != desktopShortcut)
            throw new InvalidDataException("Weryfikacja skrótów nie zgadza się z wybranymi opcjami instalacji.");

        foreach (var keyPath in new[] { @"Software\Google\Chrome\NativeMessagingHosts\com.sentinelai.urlcheck", @"Software\Microsoft\Edge\NativeMessagingHosts\com.sentinelai.urlcheck" })
        {
            var manifest = Registry.CurrentUser.OpenSubKey(keyPath)?.GetValue(null) as string;
            if (!string.Equals(manifest, Path.Combine(target, "resources", "engine", "com.sentinelai.urlcheck.json"), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Weryfikacja rejestracji hosta przeglądarki nie powiodła się.");
        }

        var manifestPath = Path.Combine(target, "resources", "engine", "com.sentinelai.urlcheck.json");
        using var nativeManifest = JsonDocument.Parse(File.ReadAllText(manifestPath));
        var manifestRoot = nativeManifest.RootElement;
        if (manifestRoot.GetProperty("name").GetString() != "com.sentinelai.urlcheck"
            || !string.Equals(manifestRoot.GetProperty("path").GetString(), Path.Combine(target, "resources", "engine", "Sentinel.UrlHost.exe"), StringComparison.OrdinalIgnoreCase)
            || manifestRoot.GetProperty("type").GetString() != "stdio"
            || !manifestRoot.GetProperty("allowed_origins").EnumerateArray().Any(origin => origin.GetString() == "chrome-extension://nakmencmekkefmcddpihiiohjgabfemg/"))
            throw new InvalidDataException("Weryfikacja manifestu Native Messaging nie powiodła się.");
    }

    private static bool AutoStartValueMatches(string? value, string executable, bool enabled)
    {
        var expected = $"\"{Path.GetFullPath(executable)}\" --minimized";
        return enabled
            ? string.Equals(value, expected, StringComparison.OrdinalIgnoreCase)
            : string.IsNullOrEmpty(value);
    }

    private static bool ShortcutPointsToInstall(string shortcutPath, string installPath)
    {
        if (!File.Exists(shortcutPath)) return false;
        object? shell = null;
        object? shortcut = null;
        try
        {
            var shellType = Type.GetTypeFromProgID("WScript.Shell") ?? throw new InvalidOperationException("Windows nie udostępnia odczytu skrótów.");
            shell = Activator.CreateInstance(shellType)!;
            shortcut = ((dynamic)shell).CreateShortcut(shortcutPath);
            var target = (string)((dynamic)shortcut).TargetPath;
            return Path.GetFullPath(Path.GetDirectoryName(target) ?? string.Empty).Equals(installPath, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (shortcut is not null) System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shortcut);
            if (shell is not null) System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell);
        }
    }

    internal static string ResolveInstallDirectory(string? registered, string fallback)
    {
        var local = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        var defaultDirectory = Path.GetFullPath(fallback);
        if (!string.IsNullOrWhiteSpace(registered))
        {
            try
            {
                var candidate = Path.GetFullPath(registered);
                if (candidate.StartsWith(local + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return candidate;
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { }
        }
        return defaultDirectory;
    }

    internal static void Install(string target, bool startMenuShortcut, bool desktopShortcut, bool autoStart, Action<string, int> progress,
        CancellationToken cancellationToken, bool testMode = false, string? registeredInstallOverride = null)
    {
        if (!VerifyPayload(showErrors: true)) throw new InvalidDataException("Weryfikacja instalatora nie powiodła się.");
        target = ValidateInstallSelection(target, testMode ? registeredInstallOverride : null);

        var parent = Path.GetDirectoryName(target) ?? throw new InvalidOperationException("Nieprawidłowy folder instalacji.");
        using (var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip")!)
        using (var archive = new ZipArchive(resource, ZipArchiveMode.Read))
        {
            var files = archive.Entries.Where(x => !string.IsNullOrEmpty(x.Name)).ToArray();
            var payloadPaths = files.Select(x => x.FullName.Replace('\\', '/')).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var payloadBytes = files.Sum(x => x.Length);
            long preservedBytes = 0;
            if (Directory.Exists(target))
                foreach (var existingFile in Directory.EnumerateFiles(target, "*", SearchOption.AllDirectories))
                {
                    var relative = Path.GetRelativePath(target, existingFile).Replace('\\', '/');
                    if (relative.Equals("Uninstall Sentinel AI.exe", StringComparison.OrdinalIgnoreCase) || payloadPaths.Contains(relative)) continue;
                    preservedBytes = checked(preservedBytes + new FileInfo(existingFile).Length);
                }

            var requiredBytes = CalculateRequiredFreeSpace(payloadBytes, preservedBytes);
            var volumeRoot = Path.GetPathRoot(parent) ?? throw new IOException("Nie można określić dysku instalacji.");
            var availableBytes = new DriveInfo(volumeRoot).AvailableFreeSpace;
            EnsureSufficientFreeSpace(availableBytes, requiredBytes);
            Log($"INSTALL_SPACE_CHECK required={requiredBytes} available={availableBytes}");
        }
        Directory.CreateDirectory(parent);
        var staging = Path.Combine(parent, ".sentinel-install-" + Guid.NewGuid().ToString("N"));
        var backup = Path.Combine(parent, ".sentinel-backup-" + Guid.NewGuid().ToString("N"));
        var integrationBackup = Path.Combine(Path.GetTempPath(), "SentinelAI-Integration-" + Guid.NewGuid().ToString("N"));
        var uninstallKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI";
        var runKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        var oldUninstallValues = CaptureRegistry(uninstallKeyPath);
        var oldRunValue = CaptureRegistryValue(runKeyPath, "Sentinel AI");
        var startMenuLink = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "Sentinel AI.lnk");
        var desktopLink = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Sentinel AI.lnk");
        var linkBackups = testMode ? new Dictionary<string, string?>() : CaptureShortcuts([startMenuLink, desktopLink], integrationBackup);
        var oldMoved = false;
        try
        {
            Log($"INSTALL_START target={target} startMenu={startMenuShortcut} autostart={autoStart} desktop={desktopShortcut}");
            Directory.CreateDirectory(staging);
            progress("Przygotowuję pliki programu…", 10);
            using (var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip")!)
            using (var archive = new ZipArchive(resource, ZipArchiveMode.Read))
            {
                var files = archive.Entries.Where(x => !string.IsNullOrEmpty(x.Name)).ToArray();
                var payloadPaths = files.Select(x => x.FullName.Replace('\\', '/')).ToHashSet(StringComparer.OrdinalIgnoreCase);
                var totalBytes = files.Sum(x => x.Length);
                long copied = 0;
                var buffer = new byte[128 * 1024];
                foreach (var entry in archive.Entries)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var destination = Path.GetFullPath(Path.Combine(staging, entry.FullName.Replace('/', Path.DirectorySeparatorChar)));
                    if (!destination.StartsWith(staging + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("Pakiet zawiera nieprawidłową ścieżkę.");
                    if (string.IsNullOrEmpty(entry.Name)) { Directory.CreateDirectory(destination); continue; }
                    Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                    using var input = entry.Open();
                    using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, buffer.Length, FileOptions.SequentialScan);
                    int read;
                    while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        output.Write(buffer, 0, read);
                        copied += read;
                        var percent = totalBytes == 0 ? 75 : 10 + (int)(copied * 65.0 / totalBytes);
                        progress($"Rozpakowuję aplikację z pakietu lokalnego… {copied / 1_048_576:N0} z {totalBytes / 1_048_576:N0} MB", Math.Min(75, percent));
                    }
                    output.Flush();
                    var copiedLength = new FileInfo(destination).Length;
                    if (copiedLength != entry.Length)
                        throw new IOException($"Nie skopiowano kompletnego pliku {entry.FullName} ({copiedLength} z {entry.Length} bajtów).");
                }
                if (Directory.Exists(target))
                {
                    foreach (var existingFile in Directory.EnumerateFiles(target, "*", SearchOption.AllDirectories))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var relative = Path.GetRelativePath(target, existingFile).Replace('\\', '/');
                        if (relative.Equals("Uninstall Sentinel AI.exe", StringComparison.OrdinalIgnoreCase) || payloadPaths.Contains(relative)) continue;
                        var preserved = Path.GetFullPath(Path.Combine(staging, relative.Replace('/', Path.DirectorySeparatorChar)));
                        Directory.CreateDirectory(Path.GetDirectoryName(preserved)!);
                        File.Copy(existingFile, preserved, overwrite: false);
                        Log($"UPDATE_PRESERVED relative={Clean(relative)}");
                    }
                }
            }
            progress("Sprawdzam pliki programu…", 80);
            cancellationToken.ThrowIfCancellationRequested();
            if (!File.Exists(Path.Combine(staging, "Sentinel AI.exe")) || !File.Exists(Path.Combine(staging, "resources", "engine", "Sentinel.Engine.exe")))
                throw new InvalidDataException("Brakuje wymaganych plików aplikacji.");
            File.Copy(Environment.ProcessPath!, Path.Combine(staging, "Uninstall Sentinel AI.exe"), overwrite: true);
            ApplyChromiumPermissions(staging);

            if (Directory.Exists(target)) { Directory.Move(target, backup); oldMoved = true; }
            Directory.Move(staging, target);
            try
            {
                progress("Kończę konfigurację…", 90);
                cancellationToken.ThrowIfCancellationRequested();
                if (!testMode)
                {
                    var executable = Path.Combine(target, "Sentinel AI.exe");
                    SetUninstallRegistration(target);
                    using var run = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
                    if (autoStart) run.SetValue("Sentinel AI", $"\"{executable}\" --minimized"); else run.DeleteValue("Sentinel AI", false);
                    ApplyShortcutOption(startMenuLink, executable, target, startMenuShortcut);
                    ApplyShortcutOption(desktopLink, executable, target, desktopShortcut);
                    RunHostCommand(Path.Combine(target, "resources", "engine", "Sentinel.UrlHost.exe"), "--register", 8000);
                }
                progress("Gotowe.", 100);
                Log($"INSTALL_SUCCESS target={target} testMode={testMode} startMenu={startMenuShortcut} autostart={autoStart} desktop={desktopShortcut}");
            }
            catch (Exception ex)
            {
                Log($"INSTALL_CONFIG_FAILED type={ex.GetType().Name} message={Clean(ex.Message)}");
                if (!testMode) try { RunHostCommand(Path.Combine(target, "resources", "engine", "Sentinel.UrlHost.exe"), "--unregister", 5000); } catch (Exception cleanupError) { Log($"ROLLBACK_HOST_UNREGISTER_FAILED message={Clean(cleanupError.Message)}"); }
                TryDelete(target);
                if (oldMoved && Directory.Exists(backup)) Directory.Move(backup, target);
                if (!testMode)
                {
                    RestoreRegistry(uninstallKeyPath, oldUninstallValues);
                    RestoreRegistryValue(runKeyPath, "Sentinel AI", oldRunValue);
                    RestoreShortcuts(linkBackups);
                }
                if (!testMode && oldMoved && Directory.Exists(target))
                    try { RunHostCommand(Path.Combine(target, "resources", "engine", "Sentinel.UrlHost.exe"), "--register", 8000); } catch (Exception restoreError) { Log($"ROLLBACK_HOST_REGISTER_FAILED message={Clean(restoreError.Message)}"); }
                throw;
            }
            if (oldMoved) TryDelete(backup);
        }
        catch (OperationCanceledException)
        {
            Log("INSTALL_CANCELLED stage=transaction");
            throw;
        }
        catch (Exception ex)
        {
            Log($"INSTALL_FAILED type={ex.GetType().Name} message={Clean(ex.Message)}");
            throw;
        }
        finally { TryDelete(staging); if (Directory.Exists(backup) && Directory.Exists(target)) TryDelete(backup); TryDelete(integrationBackup); }
    }

    private static void RunHostCommand(string executable, string argument, int timeoutMs)
    {
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new IOException($"Nie udało się uruchomić hosta Native Messaging ({argument}).");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(timeoutMs)) { process.Kill(entireProcessTree: true); throw new TimeoutException($"Rejestracja hosta Native Messaging przekroczyła {timeoutMs} ms."); }
        var stdout = stdoutTask.GetAwaiter().GetResult();
        var stderr = stderrTask.GetAwaiter().GetResult();
        Log($"NATIVE_HOST {argument} exit={process.ExitCode} output={Clean((stdout + " " + stderr).Trim())}");
        if (process.ExitCode != 0) throw new IOException($"Host Native Messaging zakończył działanie z kodem {process.ExitCode}. {Clean(stderr.Trim())}");
    }

    private static Dictionary<string, (object Value, RegistryValueKind Kind)> CaptureRegistry(string path)
    {
        var values = new Dictionary<string, (object, RegistryValueKind)>(StringComparer.OrdinalIgnoreCase);
        using var key = Registry.CurrentUser.OpenSubKey(path);
        if (key is null) return values;
        foreach (var name in key.GetValueNames())
        {
            var value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (value is not null) values[name] = (value, key.GetValueKind(name));
        }
        return values;
    }

    private static (object Value, RegistryValueKind Kind)? CaptureRegistryValue(string path, string name)
    {
        using var key = Registry.CurrentUser.OpenSubKey(path);
        var value = key?.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        return value is null || key is null ? null : (value, key.GetValueKind(name));
    }

    private static void RestoreRegistry(string path, IReadOnlyDictionary<string, (object Value, RegistryValueKind Kind)> values)
    {
        if (values.Count == 0) { Registry.CurrentUser.DeleteSubKeyTree(path, throwOnMissingSubKey: false); return; }
        using var key = Registry.CurrentUser.CreateSubKey(path, writable: true);
        if (key is null) throw new IOException($"Nie można przywrócić klucza rejestru {path}.");
        foreach (var name in key.GetValueNames()) if (!values.ContainsKey(name)) key.DeleteValue(name, throwOnMissingValue: false);
        foreach (var item in values) key.SetValue(item.Key, item.Value.Value, item.Value.Kind);
    }

    private static void RestoreRegistryValue(string path, string name, (object Value, RegistryValueKind Kind)? value)
    {
        using var key = Registry.CurrentUser.CreateSubKey(path, writable: true);
        if (key is null) throw new IOException($"Nie można przywrócić klucza rejestru {path}.");
        if (value is null) key.DeleteValue(name, throwOnMissingValue: false);
        else key.SetValue(name, value.Value.Value, value.Value.Kind);
    }

    private static Dictionary<string, string?> CaptureShortcuts(IReadOnlyList<string> paths, string backupDirectory)
    {
        var backups = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in paths)
        {
            if (!File.Exists(path)) { backups[path] = null; continue; }
            Directory.CreateDirectory(backupDirectory);
            var backup = Path.Combine(backupDirectory, backups.Count.ToString("D3") + ".lnk");
            File.Copy(path, backup, overwrite: true);
            backups[path] = backup;
        }
        return backups;
    }

    private static void RestoreShortcuts(IReadOnlyDictionary<string, string?> backups)
    {
        foreach (var item in backups)
        {
            if (item.Value is null) { if (File.Exists(item.Key)) File.Delete(item.Key); }
            else File.Copy(item.Value, item.Key, overwrite: true);
        }
    }

    private static void SetUninstallRegistration(string target)
    {
        using var key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI");
        key.SetValue("DisplayName", Product); key.SetValue("DisplayVersion", typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "0.0.0");
        key.SetValue("Publisher", "Sentinel AI contributors");
        key.SetValue("InstallLocation", target);
        key.SetValue("UninstallString", $"\"{Path.Combine(target, "Uninstall Sentinel AI.exe")}\" --uninstall");
        key.SetValue("NoModify", 1, RegistryValueKind.DWord); key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
    }

    private static void CreateShortcut(string link, string executable)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(link)!);
        var shellType = Type.GetTypeFromProgID("WScript.Shell") ?? throw new InvalidOperationException("Windows nie udostępnia tworzenia skrótów.");
        dynamic shell = Activator.CreateInstance(shellType)!;
        dynamic shortcut = shell.CreateShortcut(link);
        shortcut.TargetPath = executable; shortcut.WorkingDirectory = Path.GetDirectoryName(executable); shortcut.Description = "Sentinel AI"; shortcut.IconLocation = executable + ",0"; shortcut.Save();
        System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shortcut);
        System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell);
    }

    private static void ApplyShortcutOption(string link, string executable, string installPath, bool enabled)
    {
        if (enabled) CreateShortcut(link, executable);
        else DeleteShortcutIfOwned(link, installPath);
    }

    private static void Uninstall(string target, bool testMode = false)
    {
        target = Path.GetFullPath(target);
        if (!target.StartsWith(Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Odmowa usunięcia folderu poza profilem użytkownika.");
        var registered = testMode ? null : Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI")?.GetValue("InstallLocation") as string;
        if (!string.IsNullOrWhiteSpace(registered) && !Path.GetFullPath(registered).Equals(target, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Lokalizacja w rejestrze nie zgadza się z uruchomionym deinstalatorem.");
        Log($"UNINSTALL_START target={target}");
        if (!testMode)
        {
            RunHostCommand(Path.Combine(target, "resources", "engine", "Sentinel.UrlHost.exe"), "--unregister", 5000);
            using (var run = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")) run.DeleteValue("Sentinel AI", false);
            Registry.CurrentUser.DeleteSubKeyTree(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI", false);
            DeleteShortcutIfOwned(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "Sentinel AI.lnk"), target);
            DeleteShortcutIfOwned(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Sentinel AI.lnk"), target);
        }
        using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip")!)
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Read))
        {
            foreach (var entry in archive.Entries.Where(x => !string.IsNullOrEmpty(x.Name)))
            {
                var path = Path.GetFullPath(Path.Combine(target, entry.FullName.Replace('/', Path.DirectorySeparatorChar)));
                if (!path.StartsWith(target + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Pakiet zawiera nieprawidłową ścieżkę podczas odinstalowania.");
                if (File.Exists(path)) File.Delete(path);
            }
        }
        if (Directory.Exists(target))
            foreach (var directory in Directory.GetDirectories(target, "*", SearchOption.AllDirectories).OrderByDescending(x => x.Length))
                try { Directory.Delete(directory, recursive: false); } catch (IOException) { }

        var uninstallPath = Path.Combine(target, "Uninstall Sentinel AI.exe");
        if (testMode)
        {
            if (File.Exists(uninstallPath)) File.Delete(uninstallPath);
            foreach (var directory in Directory.GetDirectories(target, "*", SearchOption.AllDirectories).OrderByDescending(x => x.Length))
                try { Directory.Delete(directory, recursive: false); } catch (IOException) { }
            Log("UNINSTALL_SUCCESS testMode=true appFilesRemoved=true userFilesPreserved=true");
            return;
        }
        var script = "$id=" + Environment.ProcessId + "; try { Wait-Process -Id $id -Timeout 120 -ErrorAction Stop } catch {}; $p=" + PowerShellQuote(uninstallPath) + "; for($i=0;$i -lt 30 -and (Test-Path -LiteralPath $p);$i++){try{Remove-Item -LiteralPath $p -Force -ErrorAction Stop;break}catch{Start-Sleep -Milliseconds 500}}; $d=Split-Path -Parent $p; $r=" + PowerShellQuote(target) + "; while($d.StartsWith($r,[StringComparison]::OrdinalIgnoreCase)){try{if((Get-ChildItem -LiteralPath $d -Force | Measure-Object).Count -ne 0){break}; Remove-Item -LiteralPath $d -Force; $d=Split-Path -Parent $d}catch{break}}";
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var cleanup = new ProcessStartInfo("powershell.exe") { UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden };
        cleanup.ArgumentList.Add("-NoProfile"); cleanup.ArgumentList.Add("-EncodedCommand"); cleanup.ArgumentList.Add(encoded);
        if (Process.Start(cleanup) is null) throw new IOException("Nie udało się uruchomić bezpiecznego czyszczenia deinstalatora.");
        Log("UNINSTALL_SUCCESS appFilesRemoved=true userFilesPreserved=true");
    }

    private static void DeleteShortcutIfOwned(string shortcutPath, string installPath)
    {
        if (!File.Exists(shortcutPath)) return;
        object? shell = null;
        object? shortcut = null;
        try
        {
            var shellType = Type.GetTypeFromProgID("WScript.Shell") ?? throw new InvalidOperationException("Windows nie udostępnia odczytu skrótów.");
            shell = Activator.CreateInstance(shellType)!;
            shortcut = ((dynamic)shell).CreateShortcut(shortcutPath);
            var target = (string)((dynamic)shortcut).TargetPath;
            if (Path.GetFullPath(Path.GetDirectoryName(target) ?? string.Empty).Equals(installPath, StringComparison.OrdinalIgnoreCase)) File.Delete(shortcutPath);
        }
        catch (Exception ex) { throw new IOException($"Nie udało się zweryfikować skrótu {shortcutPath}.", ex); }
        finally
        {
            if (shortcut is not null) System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shortcut);
            if (shell is not null) System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell);
        }
    }

    private static string PowerShellQuote(string value) => "'" + value.Replace("'", "''") + "'";
    private static void TryDelete(string path) { try { if (Directory.Exists(path)) Directory.Delete(path, true); else if (File.Exists(path)) File.Delete(path); } catch { } }
}

internal sealed class SetupWizard : Form
{
    private enum WizardPage { Welcome, Location, Options, Summary, Installing, Verify, Complete, Error }

    private readonly Label heading = new() { AutoSize = true, Font = new Font("Segoe UI Semibold", 22), ForeColor = Color.White, Location = new Point(32, 24) };
    private readonly Label step = new() { AutoSize = true, ForeColor = Color.FromArgb(255, 166, 72), Location = new Point(34, 66) };
    private readonly Label intro = new() { AutoSize = false, ForeColor = Color.FromArgb(216, 224, 235), Location = new Point(34, 99), Size = new Size(420, 64) };
    private readonly Label pathLabel = new() { Text = "Folder instalacji", AutoSize = true, ForeColor = Color.White, Location = new Point(34, 171) };
    private readonly TextBox folder = new() { Text = Program.GetPreferredInstallDirectory(), Location = new Point(34, 197), Size = new Size(430, 32), Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
    private readonly Button browse = new() { Text = "Wybierz…", Size = new Size(104, 32), Location = new Point(475, 197), Anchor = AnchorStyles.Top | AnchorStyles.Right };
    private readonly Label spaceInfo = new() { AutoSize = false, ForeColor = Color.FromArgb(190, 204, 222), Location = new Point(34, 244), Size = new Size(540, 68) };
    private readonly CheckBox startMenu = new() { Text = "Utwórz skrót w menu &Start", Checked = true, AutoSize = true, ForeColor = Color.White, BackColor = Color.Transparent };
    private readonly CheckBox desktop = new() { Text = "Utwórz skrót na &pulpicie", Checked = true, AutoSize = true, ForeColor = Color.White, BackColor = Color.Transparent };
    private readonly CheckBox start = new() { Text = "&Uruchamiaj przy logowaniu do Windows", Checked = true, AutoSize = true, ForeColor = Color.White, BackColor = Color.Transparent };
    private readonly CheckBox launchAfter = new() { Text = "Uruchom Sentinel AI po &instalacji", Checked = true, AutoSize = true, ForeColor = Color.White, BackColor = Color.Transparent };
    private readonly Label summary = new() { AutoSize = false, ForeColor = Color.White, Location = new Point(34, 178), Size = new Size(420, 180) };
    private readonly Label status = new() { AutoSize = false, ForeColor = Color.White, Location = new Point(34, 292), Size = new Size(570, 42) };
    private readonly Label errorDetails = new() { AutoSize = false, ForeColor = Color.FromArgb(255, 185, 185), Location = new Point(34, 166), Size = new Size(420, 175) };
    private readonly ProgressBar progress = new() { Minimum = 0, Maximum = 100, Height = 14, Location = new Point(34, 344), Size = new Size(620, 14), Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right };
    private readonly Button back = new() { Text = "Wstecz", Size = new Size(100, 38), Location = new Point(34, 408), Anchor = AnchorStyles.Bottom | AnchorStyles.Left };
    private readonly Button next = new() { Text = "Rozpocznij", Size = new Size(136, 38), Location = new Point(518, 408), Anchor = AnchorStyles.Bottom | AnchorStyles.Right };
    private readonly Button cancel = new() { Text = "Anuluj", Size = new Size(100, 38), Location = new Point(400, 408), Anchor = AnchorStyles.Bottom | AnchorStyles.Right };
    private readonly Button openLog = new() { Text = "Otwórz log", Size = new Size(110, 38), Location = new Point(270, 408), Anchor = AnchorStyles.Bottom | AnchorStyles.Right };
    private readonly PictureBox illustration = new() { Bounds = new Rectangle(475, 82, 180, 170), SizeMode = PictureBoxSizeMode.Zoom, BackColor = Color.Transparent, Anchor = AnchorStyles.Top | AnchorStyles.Right };
    private CancellationTokenSource? installCancellation;
    private bool installationRunning;
    private WizardPage page = WizardPage.Welcome;
    private string lastError = string.Empty;
    private bool errorCanRetry;

    public SetupWizard()
    {
        Text = "Sentinel AI — Instalator"; ClientSize = new Size(700, 480); MinimumSize = new Size(680, 500); StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi; BackColor = Color.FromArgb(19, 28, 42); Font = new Font("Segoe UI", 10); FormBorderStyle = FormBorderStyle.Sizable; MaximizeBox = false;
        try { Icon = Icon.ExtractAssociatedIcon(Environment.ProcessPath!); } catch { }
        next.BackColor = Color.FromArgb(238, 126, 42); next.ForeColor = Color.White; next.FlatStyle = FlatStyle.Flat; next.FlatAppearance.BorderSize = 0;
        back.BackColor = Color.FromArgb(47, 61, 80); back.ForeColor = Color.White; back.FlatStyle = FlatStyle.Flat;
        cancel.BackColor = Color.FromArgb(47, 61, 80); cancel.ForeColor = Color.White; cancel.FlatStyle = FlatStyle.Flat;
        openLog.BackColor = Color.FromArgb(47, 61, 80); openLog.ForeColor = Color.White; openLog.FlatStyle = FlatStyle.Flat;
        folder.SetBounds(34, 197, 430, 32); browse.Location = new Point(475, 197);
        startMenu.Location = new Point(36, 185); desktop.Location = new Point(36, 223); start.Location = new Point(36, 261);
        launchAfter.Location = new Point(36, 299); summary.Location = new Point(34, 178);
        Controls.AddRange([heading, step, intro, pathLabel, folder, browse, spaceInfo, startMenu, desktop, start, launchAfter, summary, status, errorDetails, progress, illustration, back, next, cancel, openLog]);
        AcceptButton = next;
        CancelButton = cancel;
        browse.Click += (_, _) => { using var dialog = new FolderBrowserDialog { SelectedPath = folder.Text, Description = "Wybierz folder instalacji Sentinel AI" }; if (dialog.ShowDialog(this) == DialogResult.OK) { folder.Text = Path.Combine(dialog.SelectedPath, "Sentinel AI"); RefreshSpaceInfo(); } };
        next.Click += async (_, _) => await MoveNextAsync();
        back.Click += (_, _) => MoveBack();
        openLog.Click += (_, _) => OpenLog();
        cancel.Click += (_, _) =>
        {
            if (installationRunning)
            {
                cancel.DialogResult = DialogResult.None;
                if (installCancellation?.IsCancellationRequested == false)
                {
                    status.Text = "Anulowanie instalacji…";
                    cancel.Enabled = false;
                    installCancellation.Cancel();
                }
                return;
            }
            DialogResult = DialogResult.Cancel;
            Close();
        };
        FormClosing += (_, e) =>
        {
            if (!installationRunning) return;
            e.Cancel = true;
            cancel.PerformClick();
        };
        folder.Validated += (_, _) => RefreshSpaceInfo();
        ShowPage(WizardPage.Welcome);
    }

    protected override bool ShowWithoutActivation => true;

    private async Task MoveNextAsync()
    {
        switch (page)
        {
            case WizardPage.Welcome: ShowPage(WizardPage.Location); break;
            case WizardPage.Location:
                try { spaceInfo.Text = Program.GetInstallSpaceSummary(folder.Text); ShowPage(WizardPage.Options); }
                catch (Exception ex) { spaceInfo.Text = ex.Message; spaceInfo.ForeColor = Color.FromArgb(255, 185, 185); }
                break;
            case WizardPage.Options: ShowPage(WizardPage.Summary); break;
            case WizardPage.Summary: await InstallAsync(); break;
            case WizardPage.Error:
                if (errorCanRetry) await InstallAsync();
                else { DialogResult = DialogResult.OK; Close(); }
                break;
            case WizardPage.Complete:
                if (launchAfter.Checked)
                {
                    try
                    {
                        var process = Process.Start(new ProcessStartInfo(Path.Combine(folder.Text, "Sentinel AI.exe")) { UseShellExecute = true })
                            ?? throw new IOException("Windows nie uruchomił Sentinel AI.");
                        Program.Log($"APP_LAUNCH_STARTED pid={process.Id}");
                    }
                    catch (Exception ex) { lastError = $"Instalacja przebiegła poprawnie, ale aplikacja nie wystartowała: {ex.Message}"; Program.Log($"APP_LAUNCH_FAILED type={ex.GetType().Name} message={Program.Clean(ex.Message)}"); ShowPage(WizardPage.Error, retryable: false); return; }
                }
                DialogResult = DialogResult.OK; Close();
                break;
        }
    }

    private void MoveBack()
    {
        switch (page)
        {
            case WizardPage.Location: ShowPage(WizardPage.Welcome); break;
            case WizardPage.Options: ShowPage(WizardPage.Location); break;
            case WizardPage.Summary: ShowPage(WizardPage.Options); break;
            case WizardPage.Error: ShowPage(WizardPage.Summary); break;
        }
    }

    private async Task InstallAsync()
    {
        installationRunning = true;
        installCancellation = new CancellationTokenSource();
        progress.Value = 0;
        ShowPage(WizardPage.Installing);
        long lastProgressUiUpdate = long.MinValue;
        try
        {
            var selectedPath = Program.ValidateInstallSelection(folder.Text);
            await Task.Run(() => Program.Install(selectedPath, startMenu.Checked, desktop.Checked, start.Checked, (message, value) =>
            {
                if (!Program.ShouldPublishProgressUpdate(ref lastProgressUiUpdate, Environment.TickCount64, value)) return;
                BeginInvoke(() =>
                {
                    status.Text = message;
                    progress.Value = value;
                    if (value >= 80) cancel.Enabled = false;
                    SetIllustration(value >= 90 ? "configure" : value > 10 ? "installing" : "prepare");
                });
            }, installCancellation.Token));
            installationRunning = false;
            ShowPage(WizardPage.Verify);
            status.Text = "Sprawdzam pliki, ustawienia, skróty i rejestrację przeglądarki…";
            await Task.Run(() => Program.VerifyInstallation(selectedPath, startMenu.Checked, desktop.Checked, start.Checked));
            Program.Log($"INSTALL_VERIFIED files=true registration=true shortcuts=true autostart={start.Checked} target={selectedPath}");
            status.Text = "Instalacja została zweryfikowana.";
            progress.Value = 100;
            ShowPage(WizardPage.Complete);
        }
        catch (OperationCanceledException)
        {
            lastError = "Instalacja została anulowana. Poprzedni stan został przywrócony.";
            Program.Log("UI_INSTALL_CANCELLED rollback=true");
            ShowPage(WizardPage.Error, retryable: false);
        }
        catch (Exception ex)
        {
            Program.Log($"UI_INSTALL_ERROR type={ex.GetType().Name} message={Program.Clean(ex.Message)}");
            installationRunning = false;
            lastError = $"Nie udało się zakończyć instalacji.\r\n\r\n{ex.Message}\r\n\r\nLog diagnostyczny: {Program.LogPath}";
            ShowPage(WizardPage.Error, retryable: true);
        }
        finally
        {
            installationRunning = false;
            installCancellation?.Dispose();
            installCancellation = null;
        }
    }

    private void ShowPage(WizardPage target, bool retryable = false)
    {
        page = target;
        if (target == WizardPage.Error) errorCanRetry = retryable;
        var showLocation = target == WizardPage.Location;
        var showOptions = target == WizardPage.Options;
        var showSummary = target == WizardPage.Summary;
        var showProgress = target is WizardPage.Installing or WizardPage.Verify;
        var showError = target == WizardPage.Error;
        pathLabel.Visible = folder.Visible = browse.Visible = spaceInfo.Visible = showLocation;
        startMenu.Visible = desktop.Visible = start.Visible = showOptions;
        summary.Visible = showSummary;
        status.Visible = showProgress || target == WizardPage.Complete;
        progress.Visible = showProgress || target == WizardPage.Complete;
        errorDetails.Visible = showError;
        openLog.Visible = showError;
        launchAfter.Visible = target is WizardPage.Options or WizardPage.Complete;
        illustration.Visible = target is WizardPage.Welcome or WizardPage.Options or WizardPage.Installing or WizardPage.Verify or WizardPage.Complete or WizardPage.Error;
        back.Visible = target is WizardPage.Location or WizardPage.Options or WizardPage.Summary or WizardPage.Error;
        cancel.Visible = target is WizardPage.Location or WizardPage.Options or WizardPage.Summary or WizardPage.Installing or WizardPage.Verify;
        cancel.Enabled = target != WizardPage.Verify && !(target == WizardPage.Installing && progress.Value >= 80);
        next.Visible = target is not (WizardPage.Installing or WizardPage.Verify);
        next.Enabled = !installationRunning;
        next.Text = target switch
        {
            WizardPage.Welcome => "Rozpocznij",
            WizardPage.Location or WizardPage.Options => "Dalej",
            WizardPage.Summary => "Zainstaluj",
            WizardPage.Error when errorCanRetry => "Ponów instalację",
            WizardPage.Error => "Zakończ",
            WizardPage.Complete => "Zakończ",
            _ => "Dalej"
        };
        back.Enabled = !installationRunning;
        ActiveControl = next.Visible && next.Enabled ? next : cancel.Visible && cancel.Enabled ? cancel : null;
        step.Text = target switch
        {
            WizardPage.Welcome => "KROK 1 Z 7  •  POWITANIE",
            WizardPage.Location => "KROK 2 Z 7  •  LOKALIZACJA",
            WizardPage.Options => "KROK 3 Z 7  •  USTAWIENIA",
            WizardPage.Summary => "KROK 4 Z 7  •  PODSUMOWANIE",
            WizardPage.Installing => "KROK 5 Z 7  •  INSTALOWANIE",
            WizardPage.Verify => "KROK 6 Z 7  •  WERYFIKACJA",
            WizardPage.Complete => "KROK 7 Z 7  •  GOTOWE",
            _ => "BŁĄD INSTALACJI"
        };
        heading.Text = target switch
        {
            WizardPage.Welcome => "Sentinel AI",
            WizardPage.Location => "Wybierz lokalizację",
            WizardPage.Options => "Dostosuj instalację",
            WizardPage.Summary => "Sprawdź ustawienia",
            WizardPage.Installing => "Instaluję Sentinel AI",
            WizardPage.Verify => "Weryfikuję instalację",
            WizardPage.Complete => "Instalacja zakończona",
            _ => "Wystąpił problem"
        };
        intro.Text = target switch
        {
            WizardPage.Welcome => "Własna instalacja Sentinel AI. Program zostanie zainstalowany w profilu użytkownika; nie wymaga uprawnień administratora.",
            WizardPage.Location => "Wybierz bezpieczny folder w swoim profilu. Istniejąca instalacja zostanie zaktualizowana w tym samym miejscu.",
            WizardPage.Options => "Wybierz skróty i zachowanie aplikacji. Możesz zmienić te ustawienia później.",
            WizardPage.Summary => "Instalator sprawdzi pakiet, skopiuje pliki, skonfiguruje wybrane opcje i zweryfikuje wynik.",
            WizardPage.Installing => "Rozpakowuję aplikację z pakietu osadzonego w instalatorze; pobieranie nie jest wymagane.",
            WizardPage.Verify => "Sprawdzam pliki programu, ustawienie autostartu, skróty i host przeglądarki.",
            WizardPage.Complete => "Pliki i konfiguracja instalacji zostały sprawdzone.",
            _ => "Instalator nie zgłosi sukcesu, jeśli konfiguracja lub weryfikacja się nie powiedzie."
        };
        status.Text = target switch
        {
            WizardPage.Installing => "Przygotowuję instalację…",
            WizardPage.Verify => "Weryfikuję pliki i konfigurację…",
            WizardPage.Complete => "Sentinel AI został zainstalowany i zweryfikowany.",
            _ => status.Text
        };
        if (showSummary)
        {
            var path = folder.Text.Trim();
            summary.Text = $"Lokalizacja: {path}\r\n\r\nSkrót menu Start: {(startMenu.Checked ? "tak" : "nie")}\r\nSkrót na pulpicie: {(desktop.Checked ? "tak" : "nie")}\r\nAutostart Windows: {(start.Checked ? "tak" : "nie")}\r\nUruchom po instalacji: {(launchAfter.Checked ? "tak" : "nie")}\r\n\r\n{TryGetSpaceSummary(path)}";
        }
        if (showError) errorDetails.Text = lastError;
        SetIllustration(target switch
        {
            WizardPage.Welcome => "welcome",
            WizardPage.Options or WizardPage.Summary => "configure",
            WizardPage.Location => "prepare",
            WizardPage.Installing => progress.Value < 10 ? "prepare" : "installing",
            WizardPage.Verify => "configure",
            WizardPage.Complete => "complete",
            WizardPage.Error when lastError.Contains("anulowana", StringComparison.OrdinalIgnoreCase) => "cancel",
            _ => "error"
        });
        if (showLocation) RefreshSpaceInfo();
    }

    private string TryGetSpaceSummary(string path)
    {
        try { return Program.GetInstallSpaceSummary(path); }
        catch (Exception ex) { return ex.Message; }
    }

    private void RefreshSpaceInfo()
    {
        try
        {
            spaceInfo.ForeColor = Color.FromArgb(190, 204, 222);
            spaceInfo.Text = Program.GetInstallSpaceSummary(folder.Text);
        }
        catch (Exception ex)
        {
            spaceInfo.ForeColor = Color.FromArgb(255, 185, 185);
            spaceInfo.Text = ex.Message;
        }
    }

    private void OpenLog()
    {
        try
        {
            if (!File.Exists(Program.LogPath)) Program.Log("Installer log opened by user after an error.");
            Process.Start(new ProcessStartInfo(Program.LogPath) { UseShellExecute = true });
        }
        catch (Exception ex) { MessageBox.Show(this, $"Nie można otworzyć logu: {ex.Message}", "Sentinel AI", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }

    private void SetIllustration(string name)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"installer-{name}.png");
        if (stream is null) return;
        using var source = Image.FromStream(stream);
        illustration.Image?.Dispose();
        illustration.Image = new Bitmap(source);
    }

    internal static void ValidateVisualStates()
    {
        using var wizard = new SetupWizard();
        wizard.ShowInTaskbar = false;
        wizard.StartPosition = FormStartPosition.Manual;
        wizard.Location = new Point(-32_000, -32_000);
        wizard.Opacity = 0;
        wizard.Show();
        Application.DoEvents();
        if (!ReferenceEquals(wizard.AcceptButton, wizard.next) || !ReferenceEquals(wizard.CancelButton, wizard.cancel))
            throw new InvalidDataException("Kreator nie udostępnia klawiaturowych przycisków Dalej i Anuluj.");
        wizard.lastError = "Kontrolowany błąd testowy instalatora.";
        foreach (var page in Enum.GetValues<WizardPage>())
        {
            wizard.ShowPage(page, retryable: page == WizardPage.Error);
            if (string.IsNullOrWhiteSpace(wizard.heading.Text) || string.IsNullOrWhiteSpace(wizard.step.Text))
                throw new InvalidDataException($"Ekran instalatora {page} nie ma nagłówka lub wskaźnika kroku.");
            var expectedActiveControl = wizard.next.Visible && wizard.next.Enabled ? wizard.next
                : wizard.cancel.Visible && wizard.cancel.Enabled ? wizard.cancel
                : null;
            if (!ReferenceEquals(wizard.ActiveControl, expectedActiveControl))
                throw new InvalidDataException($"Ekran instalatora {page} nie ustawia fokusu na bezpiecznym przycisku klawiatury.");
            if (wizard.illustration.Visible && wizard.illustration.Image is null)
                throw new InvalidDataException($"Ekran instalatora {page} nie załadował swojej ilustracji.");
        }
        wizard.ShowPage(WizardPage.Location);
        if (!wizard.folder.Visible || !wizard.browse.Visible || !wizard.spaceInfo.Visible)
            throw new InvalidDataException("Ekran lokalizacji nie pokazuje ścieżki i informacji o miejscu.");
        wizard.ShowPage(WizardPage.Options);
        if (!wizard.startMenu.Visible || !wizard.desktop.Visible || !wizard.start.Visible || !wizard.launchAfter.Visible || !wizard.startMenu.Checked || !wizard.desktop.Checked || !wizard.start.Checked || !wizard.launchAfter.Checked
            || !wizard.startMenu.Text.Contains('&') || !wizard.desktop.Text.Contains('&') || !wizard.start.Text.Contains('&') || !wizard.launchAfter.Text.Contains('&'))
            throw new InvalidDataException("Ekran ustawień nie pokazuje domyślnych opcji instalacji.");
        var accessKeys = new[] { wizard.startMenu.Text, wizard.desktop.Text, wizard.start.Text, wizard.launchAfter.Text }
            .Select(text => text.IndexOf('&') is var ampersand && ampersand >= 0 && ampersand + 1 < text.Length
                ? char.ToUpperInvariant(text[ampersand + 1])
                : '\0')
            .ToArray();
        if (accessKeys.Any(key => key == '\0') || accessKeys.Distinct().Count() != accessKeys.Length)
            throw new InvalidDataException("Opcje instalatora nie mają unikalnych skrótów klawiaturowych.");
        wizard.ShowPage(WizardPage.Summary);
        if (!wizard.summary.Visible || !wizard.summary.Text.Contains("Autostart Windows", StringComparison.Ordinal) || !wizard.summary.Text.Contains("Uruchom po instalacji", StringComparison.Ordinal))
            throw new InvalidDataException("Ekran podsumowania nie zawiera wybranych ustawień.");
        wizard.ShowPage(WizardPage.Installing);
        if (!wizard.progress.Visible || !wizard.status.Visible || !wizard.cancel.Visible)
            throw new InvalidDataException("Ekran instalacji nie pokazuje postępu lub bezpiecznego anulowania.");
        wizard.ShowPage(WizardPage.Verify);
        if (!wizard.progress.Visible || wizard.cancel.Enabled)
            throw new InvalidDataException("Ekran weryfikacji pozwala anulować zatwierdzanie instalacji.");
        wizard.ShowPage(WizardPage.Complete);
        if (!wizard.launchAfter.Visible || !wizard.progress.Visible)
            throw new InvalidDataException("Ekran zakończenia nie pokazuje uruchomienia aplikacji.");
        wizard.ShowPage(WizardPage.Error, retryable: true);
        if (!wizard.errorDetails.Visible || !wizard.openLog.Visible || wizard.next.Text != "Ponów instalację")
            throw new InvalidDataException("Ekran błędu nie udostępnia komunikatu, logu i ponowienia.");
    }
}
