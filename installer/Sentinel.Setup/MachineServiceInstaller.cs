using System.Diagnostics;
using System.IO.Compression;
using System.IO.Pipes;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sentinel.Setup;

/// <summary>Installs the non-interactive SCM host from the verified embedded payload.</summary>
internal static class MachineServiceInstaller
{
    private const string ServiceName = "Sentinel AI Core";
    private const string PipeName = "SentinelAI.Service.Status.v1";
    private const string PayloadPrefix = "resources/service/";
    private static readonly string ProgramFilesRoot = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    private static string ProductDirectory => Path.Combine(ProgramFilesRoot, "Sentinel AI");
    private static string ServiceDirectory => Path.Combine(ProductDirectory, "Service");
    private static string ServiceExecutable => Path.Combine(ServiceDirectory, "Sentinel.Service.exe");
    private static string ServiceDataDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel AI Service");
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryConfig = 0x0001;

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeServiceConfig
    {
        public uint ServiceType;
        public uint StartType;
        public uint ErrorControl;
        public IntPtr BinaryPathName;
        public IntPtr LoadOrderGroup;
        public uint TagId;
        public IntPtr Dependencies;
        public IntPtr ServiceStartName;
        public IntPtr DisplayName;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "OpenSCManagerW")]
    private static extern IntPtr OpenScManager(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "OpenServiceW")]
    private static extern IntPtr OpenService(IntPtr manager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "QueryServiceConfigW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig(IntPtr service, IntPtr config, uint bufferSize, out uint bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "CloseServiceHandle")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    public static int DispatchHelper(string[] args)
    {
        try
        {
            if (!OperatingSystem.IsWindows()) return 2;
            using var identity = WindowsIdentity.GetCurrent();
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) return 3;
            var operation = args.FirstOrDefault(x => x.StartsWith("--machine-service-helper=", StringComparison.OrdinalIgnoreCase))?
                ["--machine-service-helper=".Length..];
            return operation?.ToLowerInvariant() switch
            {
                "install" => Install(ParseAllowedUserSid(args)),
                "uninstall" => Uninstall(),
                _ => 2
            };
        }
        catch (Exception exception)
        {
            Program.Log($"MACHINE_SERVICE_HELPER_FAILED type={exception.GetType().Name} hresult=0x{exception.HResult:X8} message={Program.Clean(exception.Message)}");
            return 10;
        }
    }

    public static void InstallForCurrentUser()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var sid = identity.User ?? throw new InvalidOperationException("Nie można ustalić konta użytkownika instalacji.");
        RunElevated("install", sid.Value);
    }

    public static void UninstallElevated()
    {
        RunElevated("uninstall", null);
    }

    public static bool VerifyCurrentUserServiceHealth()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut,
                PipeOptions.None, TokenImpersonationLevel.Impersonation);
            pipe.Connect(1000);
            using var reader = new StreamReader(pipe, new UTF8Encoding(false), false, 1024, leaveOpen: true);
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 1024, leaveOpen: true) { AutoFlush = true };
            writer.WriteLine("{\"id\":\"setup-health\",\"version\":1,\"method\":\"status\"}");
            var line = reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();
            if (string.IsNullOrWhiteSpace(line)) return false;
            using var response = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 4 });
            var root = response.RootElement;
            if (!root.TryGetProperty("id", out var id) || id.GetString() != "setup-health" ||
                !root.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True ||
                !root.TryGetProperty("result", out var result) ||
                !result.TryGetProperty("state", out var state) || state.GetString() != "running" ||
                !result.TryGetProperty("lastCollectionAtUtc", out var collected) ||
                !DateTimeOffset.TryParse(collected.GetString(), out var collectedAt)) return false;
            return collectedAt <= DateTimeOffset.UtcNow && DateTimeOffset.UtcNow - collectedAt <= TimeSpan.FromSeconds(30);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException or ArgumentException or TimeoutException)
        {
            return false;
        }
    }

    public static void EnsureNoServiceForIntegrationTest()
    {
        if (QueryService().ExitCode == 0)
            throw new InvalidOperationException("Test instalatora odmówił zmian, ponieważ usługa Sentinel AI Core jest już zarejestrowana.");
    }

    public static void VerifyUninstalledForIntegrationTest()
    {
        if (QueryService().ExitCode != 1060 || Directory.Exists(ServiceDirectory))
            throw new InvalidDataException("Deinstalacja testowa pozostawiła usługę SCM lub jej chronione pliki.");
    }

    private static void RunElevated(string operation, string? userSid)
    {
        var executable = Environment.ProcessPath ?? throw new IOException("Nie można ustalić ścieżki instalatora.");
        var start = new ProcessStartInfo(executable) { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
        start.ArgumentList.Add("--machine-service-helper=" + operation);
        if (userSid is not null) start.ArgumentList.Add("--service-user-sid=" + userSid);
        Process process;
        try { process = Process.Start(start) ?? throw new IOException("Windows nie uruchomił konfiguracji usługi."); }
        catch (System.ComponentModel.Win32Exception exception) when (exception.NativeErrorCode == 1223)
        {
            throw new OperationCanceledException("Konfiguracja ochrony w tle została anulowana w monicie UAC.", exception);
        }
        using (process)
        {
            if (!process.WaitForExit(180_000))
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                throw new TimeoutException("Konfiguracja usługi Sentinel AI przekroczyła limit czasu.");
            }
            if (process.ExitCode != 0)
                throw new IOException($"Windows nie zainstalował usługi Sentinel AI (kod {process.ExitCode}). Szczegóły zapisano w logu instalatora administratora.");
        }
    }

    private static int Install(string userSidText)
    {
        var stage = "validate_user_sid";
        var userSid = new SecurityIdentifier(userSidText);
        if (!userSid.IsAccountSid()) throw new ArgumentException("Nieprawidłowy SID użytkownika instalacji.");
        stage = "validate_program_files";
        if (ProgramFilesRoot.Length == 0 || !Path.IsPathFullyQualified(ProgramFilesRoot))
            throw new IOException("Nie można ustalić chronionej lokalizacji Program Files.");

        stage = "verify_embedded_payload";
        VerifyEmbeddedPayload();
        stage = "inspect_existing_service";
        var serviceExisted = QueryService().ExitCode == 0;
        if (serviceExisted)
        {
            EnsureOwnedService();
            if (!Directory.Exists(ServiceDirectory))
                throw new IOException("Istniejąca usługa Sentinel AI wskazuje na brakujący chroniony payload; przerwano aktualizację.");
        }
        var parent = ProductDirectory;
        var staging = Path.Combine(parent, ".Service.new-" + Guid.NewGuid().ToString("N"));
        var backup = Path.Combine(parent, ".Service.old-" + Guid.NewGuid().ToString("N"));
        var oldMoved = false;
        var createdService = false;
        try
        {
            stage = "prepare_product_directory";
            Directory.CreateDirectory(parent);
            RejectReparsePoint(parent, ProgramFilesRoot);
            var unexpectedEntries = Directory.EnumerateFileSystemEntries(parent)
                .Where(entry => !Path.GetFileName(entry).Equals("Service", StringComparison.OrdinalIgnoreCase))
                .ToArray();
            if (unexpectedEntries.Length > 0 || (!serviceExisted && Directory.Exists(ServiceDirectory)))
                throw new IOException("Katalog Program Files przeznaczony dla Sentinel AI zawiera nieznane pliki; pozostawiono go bez zmian.");
            ApplySecureAcl(parent, allowLocalServiceExecute: true);
            if (serviceExisted)
            {
                stage = "stop_existing_service";
                StopService();
                WaitForServiceState(1, TimeSpan.FromSeconds(30));
            }

            stage = "extract_service_payload";
            Directory.CreateDirectory(staging);
            ApplySecureAcl(staging, allowLocalServiceExecute: true);
            ExtractVerifiedServicePayload(staging);
            if (!File.Exists(Path.Combine(staging, "Sentinel.Service.exe")) ||
                !File.Exists(Path.Combine(staging, "Sentinel.Engine.exe")))
                throw new InvalidDataException("Pakiet nie zawiera kompletnego hosta usługi Sentinel AI.");

            if (Directory.Exists(ServiceDirectory))
            {
                stage = "backup_previous_service_payload";
                RejectReparsePoint(ServiceDirectory, parent);
                MoveDirectoryWithRetry(ServiceDirectory, backup);
                oldMoved = true;
            }
            stage = "activate_service_payload";
            MoveDirectoryWithRetry(staging, ServiceDirectory);
            ApplySecureAcl(ServiceDirectory, allowLocalServiceExecute: true);

            var binaryPath = "\"" + ServiceExecutable + "\" --allowed-user-sid=" + userSid.Value;
            if (serviceExisted)
            {
                stage = "configure_existing_scm_service";
                RunSc("config", ServiceName, "binPath=", binaryPath, "start=", "auto", "obj=", @"NT AUTHORITY\LocalService");
            }
            else
            {
                stage = "create_scm_service";
                RunSc("create", ServiceName, "binPath=", binaryPath, "start=", "auto", "obj=", @"NT AUTHORITY\LocalService");
                createdService = true;
            }
            stage = "configure_scm_recovery";
            RunSc("description", ServiceName, "Usługa monitorowania Sentinel AI działająca w tle.");
            RunSc("failure", ServiceName, "reset=", "86400", "actions=", "restart/60000/restart/60000/none/0");
            RunSc("failureflag", ServiceName, "1");
            stage = "verify_scm_service";
            EnsureOwnedService();
            stage = "start_scm_service";
            RunSc("start", ServiceName);
            WaitForServiceState(4, TimeSpan.FromSeconds(60));
            stage = "wait_for_first_collection";
            WaitForFirstCollection(TimeSpan.FromSeconds(90));
            using (var helperIdentity = WindowsIdentity.GetCurrent())
            {
                if (StringComparer.OrdinalIgnoreCase.Equals(helperIdentity.User?.Value, userSid.Value))
                {
                    stage = "verify_user_service_pipe";
                    if (!WaitForCurrentUserServiceHealth(TimeSpan.FromSeconds(15)))
                        throw new IOException("Usługa nie odpowiedziała przez uwierzytelniony status pipe po pierwszym cyklu.");
                }
                else
                {
                    // UAC may run under separate administrator credentials. The target user's SID is
                    // already bound into the pipe ACL; only that user's unelevated UI can authenticate it.
                    Program.Log("MACHINE_SERVICE_HEALTH_DEFERRED reason=elevated_account_differs");
                }
            }
            Program.Log($"MACHINE_SERVICE_INSTALL_SUCCESS service={ServiceName} serviceExisted={serviceExisted} account=LocalService");
            if (oldMoved) Directory.Delete(backup, recursive: true);
            return 0;
        }
        catch (Exception exception)
        {
            Program.Log($"MACHINE_SERVICE_INSTALL_FAILED stage={stage} type={exception.GetType().Name} hresult=0x{exception.HResult:X8}");
            try { StopService(); } catch { }
            if (createdService) try { RunSc("delete", ServiceName); } catch { }
            if (Directory.Exists(ServiceDirectory)) TryDeleteProtectedDirectory(ServiceDirectory);
            if (oldMoved && Directory.Exists(backup)) MoveDirectoryWithRetry(backup, ServiceDirectory);
            if (serviceExisted) try { RunSc("start", ServiceName); } catch { }
            throw;
        }
        finally
        {
            if (Directory.Exists(staging)) TryDeleteProtectedDirectory(staging);
            if (Directory.Exists(backup) && Directory.Exists(ServiceDirectory)) TryDeleteProtectedDirectory(backup);
        }
    }

    private static int Uninstall()
    {
        var query = QueryService();
        if (query.ExitCode != 0 && query.ExitCode != 1060)
            throw new IOException("Nie można bezpiecznie ustalić stanu usługi Sentinel AI.");
        if (query.ExitCode == 0)
        {
            EnsureOwnedService();
            StopService();
            WaitForServiceState(1, TimeSpan.FromSeconds(30));
            RunSc("delete", ServiceName);
            WaitForServiceRemoval(TimeSpan.FromSeconds(30));
        }
        if (Directory.Exists(ServiceDirectory))
        {
            RejectReparsePoint(ServiceDirectory, ProductDirectory);
            TryDeleteProtectedDirectory(ServiceDirectory);
        }
        // ProgramData is retained to preserve local protection history and diagnostics.
        Program.Log("MACHINE_SERVICE_UNINSTALL_SUCCESS serviceRemoved=true payloadRemoved=true dataRetained=true");
        return 0;
    }

    private static string ParseAllowedUserSid(string[] args)
    {
        const string prefix = "--service-user-sid=";
        var values = args.Where(x => x.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (values.Length != 1) throw new ArgumentException("Wymagany jest dokładnie jeden SID użytkownika.");
        return new SecurityIdentifier(values[0][prefix.Length..]).Value;
    }

    private static void VerifyEmbeddedPayload()
    {
        var expected = Assembly.GetExecutingAssembly().GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(x => x.Key == "SentinelPayloadSha256")?.Value;
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip")
            ?? throw new InvalidDataException("Instalator nie zawiera lokalnego pakietu aplikacji.");
        var actual = Convert.ToHexString(SHA256.HashData(stream));
        if (string.IsNullOrWhiteSpace(expected) || !StringComparer.OrdinalIgnoreCase.Equals(actual, expected))
            throw new InvalidDataException("Osadzony pakiet instalatora nie przeszedł weryfikacji SHA-256.");
    }

    private static void ExtractVerifiedServicePayload(string target)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip")!;
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
        foreach (var entry in archive.Entries)
        {
            var name = entry.FullName.Replace('\\', '/');
            if (!name.StartsWith(PayloadPrefix, StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(entry.Name)) continue;
            var relative = name[PayloadPrefix.Length..].Replace('/', Path.DirectorySeparatorChar);
            var destination = Path.GetFullPath(Path.Combine(target, relative));
            if (!destination.StartsWith(Path.GetFullPath(target).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Pakiet zawiera nieprawidłową ścieżkę pliku usługi.");
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            using var source = entry.Open();
            using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            source.CopyTo(output);
            output.Flush(flushToDisk: true);
            if (output.Length != entry.Length) throw new InvalidDataException("Nie skopiowano kompletnego pliku usługi.");
        }
    }

    private static void ApplySecureAcl(string path, bool allowLocalServiceExecute)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        AddDirectoryRule(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl);
        AddDirectoryRule(security, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl);
        if (allowLocalServiceExecute)
            AddDirectoryRule(security, new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null), FileSystemRights.ReadAndExecute);
        var info = new DirectoryInfo(path);
        info.SetAccessControl(security);
        if (!HasExpectedAcl(info.GetAccessControl(AccessControlSections.Access), allowLocalServiceExecute))
            throw new UnauthorizedAccessException("Nie udało się ochronić katalogu plików usługi.");
    }

    private static bool HasExpectedAcl(DirectorySecurity security, bool allowLocalServiceExecute)
    {
        if (!security.AreAccessRulesProtected) return false;
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).OfType<FileSystemAccessRule>().ToArray();
        var expected = new Dictionary<string, FileSystemRights>(StringComparer.OrdinalIgnoreCase)
        {
            [new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value] = FileSystemRights.FullControl,
            [new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value] = FileSystemRights.FullControl
        };
        if (allowLocalServiceExecute)
            expected[new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null).Value] = FileSystemRights.ReadAndExecute;
        return rules.Length == expected.Count && rules.All(rule =>
            rule.AccessControlType == AccessControlType.Allow &&
            rule.InheritanceFlags == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit) &&
            rule.PropagationFlags == PropagationFlags.None &&
            rule.IdentityReference is SecurityIdentifier sid &&
            expected.TryGetValue(sid.Value, out var rights) && SameDirectoryRights(rights, rule.FileSystemRights) && expected.Remove(sid.Value)) &&
            expected.Count == 0;
    }

    private static bool SameDirectoryRights(FileSystemRights expected, FileSystemRights actual)
    {
        // Windows includes SYNCHRONIZE in returned directory ACE masks even when
        // the requested FileSystemRights value omits it. This bit grants no
        // additional file or directory access, so normalize only that bit.
        const FileSystemRights synchronization = FileSystemRights.Synchronize;
        return (expected & ~synchronization) == (actual & ~synchronization);
    }

    private static void AddDirectoryRule(DirectorySecurity security, SecurityIdentifier sid, FileSystemRights rights) =>
        security.AddAccessRule(new FileSystemAccessRule(sid, rights,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));

    private static void RejectReparsePoint(string path, string trustedParent)
    {
        var full = Path.GetFullPath(path);
        var parent = Path.GetFullPath(trustedParent).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!full.StartsWith(parent, StringComparison.OrdinalIgnoreCase) ||
            (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Odmowa użycia niebezpiecznej ścieżki plików usługi.");
    }

    private static (int ExitCode, string Output) QueryService() => RunScAllowError("query", ServiceName);

    private static void EnsureOwnedService()
    {
        var manager = OpenScManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero) throw new IOException("Nie można odczytać konfiguracji usługi SCM.");
        try
        {
            var service = OpenService(manager, ServiceName, ServiceQueryConfig);
            if (service == IntPtr.Zero) throw new IOException("Nie można odczytać konfiguracji istniejącej usługi Sentinel AI.");
            try
            {
                QueryServiceConfig(service, IntPtr.Zero, 0, out var needed);
                var error = Marshal.GetLastWin32Error();
                if (error != 122 || needed < Marshal.SizeOf<NativeServiceConfig>())
                    throw new IOException("Nie można bezpiecznie określić lokalizacji istniejącej usługi Sentinel AI.");
                var buffer = Marshal.AllocHGlobal(checked((int)needed));
                try
                {
                    if (!QueryServiceConfig(service, buffer, needed, out _))
                        throw new IOException("Nie można bezpiecznie odczytać istniejącej usługi Sentinel AI.");
                    var config = Marshal.PtrToStructure<NativeServiceConfig>(buffer);
                    var binaryPath = Marshal.PtrToStringUni(config.BinaryPathName) ?? string.Empty;
                    var account = Marshal.PtrToStringUni(config.ServiceStartName) ?? string.Empty;
                    var expectedExecutable = "\"" + Path.GetFullPath(ServiceExecutable) + "\"";
                    if (config.StartType != 2 || !binaryPath.StartsWith(expectedExecutable, StringComparison.OrdinalIgnoreCase) ||
                        !account.Equals(@"NT AUTHORITY\LocalService", StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Usługa o nazwie Sentinel AI Core należy do innego programu; pozostawiono ją bez zmian.");
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }

    private static void StopService()
    {
        var state = QueryService();
        if (state.ExitCode == 1060) return;
        var code = ParseServiceState(state.Output);
        if (code == 1) return;
        var stop = RunScAllowError("stop", ServiceName);
        if (stop.ExitCode != 0 && stop.ExitCode != 1062)
            throw new IOException("Windows nie zatrzymał usługi Sentinel AI.");
    }

    private static void WaitForServiceState(int expected, TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            var result = QueryService();
            if (expected == 0 && result.ExitCode == 1060) return;
            if (result.ExitCode == 0 && ParseServiceState(result.Output) == expected) return;
            Thread.Sleep(250);
        }
        throw new TimeoutException("Usługa Sentinel AI nie osiągnęła oczekiwanego stanu SCM.");
    }

    private static void WaitForServiceRemoval(TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (QueryService().ExitCode == 1060) return;
            Thread.Sleep(250);
        }
        throw new TimeoutException("Wpis usługi Sentinel AI pozostał w Service Control Manager.");
    }

    private static void WaitForFirstCollection(TimeSpan timeout)
    {
        var log = Path.Combine(ServiceDataDirectory, "service.log");
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (File.Exists(log) && File.ReadLines(log).TakeLast(100).Any(line => line.Contains("CORE_FIRST_COLLECTION_COMPLETED", StringComparison.Ordinal))) return;
            var state = QueryService();
            if (state.ExitCode != 0 || ParseServiceState(state.Output) != 4)
                throw new IOException("Usługa Sentinel AI zatrzymała się przed pierwszym cyklem monitorowania.");
            Thread.Sleep(500);
        }
        throw new TimeoutException("Silnik Sentinel AI nie zakończył pierwszego cyklu w wyznaczonym czasie.");
    }

    private static bool WaitForCurrentUserServiceHealth(TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        do
        {
            if (VerifyCurrentUserServiceHealth()) return true;
            Thread.Sleep(200);
        } while (DateTimeOffset.UtcNow < deadline);
        return false;
    }

    private static int ParseServiceState(string output)
    {
        var match = Regex.Match(output, @"STATE\s*:\s*(\d+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success && int.TryParse(match.Groups[1].Value, out var state) ? state : -1;
    }

    private static (int ExitCode, string Output) RunScAllowError(params string[] arguments)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "sc.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new IOException("Nie można uruchomić narzędzia Service Control Manager.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(15_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("Operacja Service Control Manager przekroczyła limit czasu.");
        }
        Task.WaitAll(stdout, stderr);
        return (process.ExitCode, (stdout.Result + Environment.NewLine + stderr.Result).Trim());
    }

    private static void RunSc(params string[] arguments)
    {
        var result = RunScAllowError(arguments);
        if (result.ExitCode != 0)
            throw new IOException("Windows nie wykonał wymaganej operacji usługi Sentinel AI (sc.exe, kod " + result.ExitCode + ").");
    }

    private static void TryDeleteProtectedDirectory(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Odmowa usunięcia punktu ponownej analizy podczas sprzątania usługi.");
        for (var attempt = 0; ; attempt++)
        {
            try { Directory.Delete(path, recursive: true); return; }
            catch (IOException exception) when (attempt < 49 && (exception.HResult & 0xFFFF) is 5 or 32 or 33)
            {
                Thread.Sleep(100);
            }
        }
    }

    private static void MoveDirectoryWithRetry(string source, string destination)
    {
        for (var attempt = 0; ; attempt++)
        {
            try { Directory.Move(source, destination); return; }
            catch (IOException exception) when (attempt < 49 && (exception.HResult & 0xFFFF) is 5 or 32 or 33)
            {
                Thread.Sleep(100);
            }
        }
    }
}
