using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
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

    [STAThread]
    private static int Main(string[] args)
    {
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

    private static bool VerifyPayload(bool showErrors)
    {
        try
        {
            using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip")
                ?? throw new InvalidDataException("Brak pakietu aplikacji w instalatorze.");
            var actual = Convert.ToHexString(SHA256.HashData(stream));
            if (PayloadHash.Length != 64 || !CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(actual), Encoding.ASCII.GetBytes(PayloadHash.ToUpperInvariant())))
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

    private static int SelfTest()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var testId = Guid.NewGuid().ToString("N");
        var root = Path.Combine(localAppData, "Programs", ".SentinelAI-Setup-SelfTest-" + testId);
        var data = Path.Combine(localAppData, "SentinelAI-Setup-SelfTest-" + testId);
        try
        {
            if (!VerifyPayload(showErrors: false)) throw new InvalidDataException("Nieprawidłowy pakiet instalacyjny.");
            var fallbackDirectory = DefaultDirectory;
            if (!ResolveInstallDirectory(root, fallbackDirectory).Equals(Path.GetFullPath(root), StringComparison.OrdinalIgnoreCase)
                || !ResolveInstallDirectory(Environment.GetFolderPath(Environment.SpecialFolder.System), fallbackDirectory)
                    .Equals(Path.GetFullPath(fallbackDirectory), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Wykrywanie istniejącej lokalizacji instalacji nie działa poprawnie.");
            Install(root, desktopShortcut: false, autoStart: false, (_, _) => { }, CancellationToken.None, testMode: true);
            var preservedFile = Path.Combine(root, "self-test-user-file.txt");
            File.WriteAllText(preservedFile, "preserve across update and rollback");
            var engineExecutable = Path.Combine(root, "resources", "engine", "Sentinel.Engine.exe");
            File.WriteAllText(engineExecutable, "outdated-payload-marker");
            Install(root, desktopShortcut: false, autoStart: false, (_, _) => { }, CancellationToken.None,
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
                    Install(root, desktopShortcut: false, autoStart: false,
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

            Log("SELF_TEST_SUCCESS payload=true chromiumAcl=true update=true rollback=true appSmoke=true uninstall=true userDataPreserved=true");
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
        Log($"CHROMIUM_ACL exit={process.ExitCode} output={Clean((stdout + " " + stderr).Trim())}");
        if (process.ExitCode != 0) throw new IOException($"Windows nie ustawił uprawnień wymaganych przez Chromium (kod {process.ExitCode}). {Clean(stderr.Trim())}");
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

    internal static void Install(string target, bool desktopShortcut, bool autoStart, Action<string, int> progress,
        CancellationToken cancellationToken, bool testMode = false, string? registeredInstallOverride = null)
    {
        if (!VerifyPayload(showErrors: true)) throw new InvalidDataException("Weryfikacja instalatora nie powiodła się.");
        target = Path.GetFullPath(target);
        var local = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        if (!target.StartsWith(local + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Wybierz folder w swoim profilu użytkownika. Instalacja nie wymaga uprawnień administratora.");
        var registeredInstall = testMode ? registeredInstallOverride : Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI")?.GetValue("InstallLocation") as string;
        if (!string.IsNullOrWhiteSpace(registeredInstall) && !Path.GetFullPath(registeredInstall).Equals(target, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Sentinel AI jest już zainstalowany w folderze {registeredInstall}. Uruchom instalator z tej lokalizacji, aby go zaktualizować.");
        if (Directory.Exists(target) && Directory.EnumerateFileSystemEntries(target).Any() &&
            !Path.GetFullPath(registeredInstall ?? string.Empty).Equals(target, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Wybrany folder zawiera pliki, które nie należą do Sentinel AI. Wybierz pusty folder albo lokalizację istniejącej instalacji.");

        var parent = Path.GetDirectoryName(target) ?? throw new InvalidOperationException("Nieprawidłowy folder instalacji.");
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
            Log($"INSTALL_START target={target} autostart={autoStart} desktop={desktopShortcut}");
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
                        progress($"Kopiowanie plików… {copied / 1_048_576:N0} z {totalBytes / 1_048_576:N0} MB", Math.Min(75, percent));
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
                    CreateShortcut(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "Sentinel AI.lnk"), executable);
                    if (desktopShortcut) CreateShortcut(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Sentinel AI.lnk"), executable);
                    RunHostCommand(Path.Combine(target, "resources", "engine", "Sentinel.UrlHost.exe"), "--register", 8000);
                }
                progress("Gotowe.", 100);
                Log($"INSTALL_SUCCESS target={target} testMode={testMode} autostart={autoStart} desktop={desktopShortcut}");
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
    private readonly TextBox folder = new() { Text = Program.GetPreferredInstallDirectory() };
    private readonly CheckBox desktop = new() { Text = "Utwórz skrót na pulpicie", Checked = true, AutoSize = true };
    private readonly CheckBox start = new() { Text = "Uruchamiaj przy logowaniu do Windows", Checked = true, AutoSize = true };
    private readonly Label status = new() { AutoSize = true, Text = "Gotowy do instalacji" };
    private readonly ProgressBar progress = new() { Minimum = 0, Maximum = 100, Height = 12, Dock = DockStyle.Fill };
    private readonly Button install = new() { Text = "Zainstaluj", Width = 118, Height = 38 };
    private readonly Button cancel = new() { Text = "Anuluj", Location = new Point(383, 381), Size = new Size(92, 38) };
    private readonly PictureBox illustration = new() { Bounds = new Rectangle(454, 18, 150, 112), SizeMode = PictureBoxSizeMode.Zoom, BackColor = Color.Transparent };
    private CancellationTokenSource? installCancellation;
    private bool installationRunning;

    public SetupWizard()
    {
        Text = "Instalator Sentinel AI"; Width = 650; Height = 465; MinimumSize = new Size(650, 465); StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(246, 248, 251); Font = new Font("Segoe UI", 10); FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false;
        try { Icon = Icon.ExtractAssociatedIcon(Environment.ProcessPath!); } catch { }
        var heading = new Label { Text = "Zainstaluj Sentinel AI", Font = new Font("Segoe UI Semibold", 21), ForeColor = Color.FromArgb(24, 41, 64), AutoSize = true, Location = new Point(34, 28) };
        var intro = new Label { Text = "Zajmie to chwilę. Nie potrzebujesz uprawnień administratora.", AutoSize = true, Location = new Point(36, 75) };
        var pathLabel = new Label { Text = "Miejsce instalacji", AutoSize = true, Location = new Point(36, 137) };
        folder.SetBounds(36, 163, 470, 34); var browse = new Button { Text = "Wybierz…", Location = new Point(516, 162), Size = new Size(92, 36) };
        desktop.Location = new Point(38, 224); start.Location = new Point(38, 258); status.Location = new Point(38, 324);
        progress.SetBounds(36, 354, 572, 13); install.Location = new Point(490, 381); install.BackColor = Color.FromArgb(20, 93, 153); install.ForeColor = Color.White; install.FlatStyle = FlatStyle.Flat;
        cancel.DialogResult = DialogResult.Cancel;
        Controls.AddRange([heading, intro, illustration, pathLabel, folder, browse, desktop, start, status, progress, cancel, install]); AcceptButton = install; CancelButton = cancel;
        SetIllustration("welcome");
        browse.Click += (_, _) => { using var dialog = new FolderBrowserDialog { SelectedPath = folder.Text, Description = "Wybierz folder instalacji Sentinel AI" }; if (dialog.ShowDialog(this) == DialogResult.OK) folder.Text = Path.Combine(dialog.SelectedPath, "Sentinel AI"); };
        install.Click += async (_, _) => await InstallAsync();
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
    }

    private async Task InstallAsync()
    {
        installationRunning = true;
        installCancellation = new CancellationTokenSource();
        install.Enabled = false;
        folder.Enabled = false;
        desktop.Enabled = false;
        start.Enabled = false;
        cancel.Enabled = true;
        SetIllustration("prepare");
        try
        {
            await Task.Run(() => Program.Install(folder.Text, desktop.Checked, start.Checked, (message, value) => BeginInvoke(() =>
            {
                status.Text = message;
                progress.Value = value;
                if (value >= 80) cancel.Enabled = false;
                SetIllustration(value >= 100 ? "complete" : value >= 80 ? "configure" : value > 10 ? "installing" : "prepare");
            }), installCancellation.Token));
            installationRunning = false;
            if (MessageBox.Show(this, "Sentinel AI został zainstalowany. Czy uruchomić program teraz?", "Gotowe", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
                Process.Start(new ProcessStartInfo(Path.Combine(folder.Text, "Sentinel AI.exe")) { UseShellExecute = true });
            DialogResult = DialogResult.OK; Close();
        }
        catch (OperationCanceledException)
        {
            status.Text = "Instalacja została anulowana. Zmiany zostały wycofane.";
            cancel.DialogResult = DialogResult.Cancel;
            SetIllustration("cancel");
            cancel.Text = "Zamknij";
            cancel.Enabled = true;
        }
        catch (Exception ex)
        {
            Program.Log($"UI_INSTALL_ERROR type={ex.GetType().Name} message={Program.Clean(ex.Message)}");
            installationRunning = false;
            install.Enabled = true;
            folder.Enabled = true;
            desktop.Enabled = true;
            start.Enabled = true;
            cancel.DialogResult = DialogResult.Cancel;
            cancel.Text = "Anuluj";
            cancel.Enabled = true;
            status.Text = "Instalacja nie została zakończona.";
            SetIllustration("error");
            if (MessageBox.Show(this, $"Nie udało się zainstalować Sentinel AI.\n\n{ex.Message}\n\nLog: {Program.LogPath}\n\nCzy otworzyć log?", "Błąd instalacji", MessageBoxButtons.YesNo, MessageBoxIcon.Error) == DialogResult.Yes)
                Process.Start(new ProcessStartInfo(Program.LogPath) { UseShellExecute = true });
        }
        finally
        {
            installationRunning = false;
            installCancellation?.Dispose();
            installCancellation = null;
        }
    }

    private void SetIllustration(string name)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"installer-{name}.png");
        if (stream is null) return;
        using var source = Image.FromStream(stream);
        illustration.Image?.Dispose();
        illustration.Image = new Bitmap(source);
    }
}
