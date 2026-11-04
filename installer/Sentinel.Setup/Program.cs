Warning: truncated output (original token count: 54973)
Total output lines: 3410

using System.Diagnostics;
using System.ComponentModel;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Sentinel.Setup;

internal static class Program
{
    private const string Product = "Sentinel AI";
    private const string FileContextMenuKey = @"Software\Classes\*\shell\SentinelAI.CheckFile";
    private const string FileContextMenuCommandKey = FileContextMenuKey + @"\command";
    private const string FileContextMenuLabel = "Sprawdź w Sentinel AI";
    private const string FileContextMenuSelectionModel = "Document";
    private const string CoreAutoStartValueName = "Sentinel AI Core";
    private static string? selfTestLogPath;
    internal static string LogPath => selfTestLogPath ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), Product, "Logs", "installer.log");
    private const long MaximumLogBytes = 1024 * 1024;
    private const int MaximumLogMessageCharacters = 4096;
    private static readonly object LogGate = new();
    private static readonly string DefaultDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", Product);
    private static string PayloadHash => Assembly.GetExecutingAssembly().GetCustomAttributes<AssemblyMetadataAttribute>()
        .FirstOrDefault(x => x.Key == "SentinelPayloadSha256")?.Value ?? "";
    private const long MinimumFreeSpaceMargin = 32L * 1024 * 1024;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileListDirectory = 0x00000001;
    private const uint FileAddSubdirectory = 0x00000004;
    private const uint DeleteAccess = 0x00010000;
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint SynchronizeAccess = 0x00100000;
    private const uint ShareRead = 0x00000001;
    private const uint ShareWrite = 0x00000002;
    private const uint ShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint CreateNew = 1;
    private const uint OpenIf = 3;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const int FileAttributeTagInfoClass = 9;
    private const int FileIdBothDirectoryInfoClass = 10;
    private const int NtFileRenameInformationClass = 10;
    private const int ErrorNoMoreFiles = 18;
    private const int FileIdBothDirectoryInfoFileNameOffset = 104;
    private const int MaximumTransientDirectoryRenameAttempts = 20;
    private const int DirectoryRenameRetryDelayMilliseconds = 250;
    private const uint ObjectAttributesCaseInsensitive = 0x00000040;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileDirectoryFile = 0x00000001;
    private const uint FileSynchronousIoNonAlert = 0x00000020;
    private const uint FileOpenForBackupIntent = 0x00004000;
    private const uint FileOpenReparsePoint = 0x00200000;
    private const uint NtFileOpen = 1;
    private const uint NtFileOpenIf = 3;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInfo
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool DeleteFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileRenameInfoLayout
    {
        public byte ReplaceIfExists;
        public IntPtr RootDirectory;
        public uint FileNameLength;
        public char FileName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public IntPtr Status;
        public IntPtr Information;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFileHandle(string fileName, uint desiredAccess, uint shareMode,
        IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass,
        out FileAttributeTagInfo information, uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetDirectoryInformationByHandle(SafeFileHandle file, int informationClass,
        IntPtr information, uint bufferSize);

    [DllImport("ntdll.dll", SetLastError = false)]
    private static extern int NtCreateFile(out SafeFileHandle fileHandle, uint desiredAccess,
        ref ObjectAttributes objectAttributes, out IoStatusBlock ioStatusBlock, IntPtr allocationSize,
        uint fileAttributes, uint shareAccess, uint createDisposition, uint createOptions,
        IntPtr eaBuffer, uint eaLength);

    [DllImport("ntdll.dll", SetLastError = false)]
    private static extern uint RtlNtStatusToDosError(int status);

    [DllImport("ntdll.dll", SetLastError = false)]
    private static extern int NtSetInformationFile(SafeFileHandle file, out IoStatusBlock ioStatusBlock,
        IntPtr fileInformation, uint length, int fileInformationClass);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetFinalPathNameByHandleW")]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, uint pathLength, uint flags);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "SetFileInformationByHandle")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file, int informationClass,
        ref FileDispositionInfo information, uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileSizeEx")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileSizeEx(SafeFileHandle file, out long fileSize);

    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Any(x => x.StartsWith("--machine-service-helper=", StringComparison.OrdinalIgnoreCase)))
            return MachineServiceInstaller.DispatchHelper(args);
        if (args.Contains("--integration-test", StringComparer.OrdinalIgnoreCase))
        {
            const string browserE2ePrefix = "--browser-e2e-repo=";
            var browserE2eRepo = args.FirstOrDefault(x => x.StartsWith(browserE2ePrefix, StringComparison.OrdinalIgnoreCase))?[browserE2ePrefix.Length..];
            return IntegrationTest(browserE2eRepo);
        }
        if (args.Contains("--wizard-integration-test", StringComparer.OrdinalIgnoreCase)) return WizardIntegrationTest();
        if (args.Contains("--uninstall-guard-self-test", StringComparer.OrdinalIgnoreCase)) return UninstallRegistrationSelfTest();
        if (args.Contains("--uninstall-cleanup-self-test", StringComparer.OrdinalIgnoreCase)) return UninstallCleanupSelfTest();
        if (args.Contains("--wizard-self-test", StringComparer.OrdinalIgnoreCase)) return WizardSelfTest();
        if (args.Contains("--self-test-no-app", StringComparer.OrdinalIgnoreCase)) return SelfTest(runApplicationSmoke: false);
        if (args.Contains("--self-test", StringComparer.OrdinalIgnoreCase)) return SelfTest();
        InstallGuiExceptionDiagnostics();
        if (IsUninstallInvocation(args, Environment.ProcessPath))
        {
            ApplicationConfiguration.Initialize();
            if (MessageBox.Show($"Czy na pewno odinstalować Sentinel AI?\n\nPliki usługi ochrony zostaną usunięte. Lokalne dane i historia pozostaną na tym komputerze. Windows może poprosić o zgodę administratora.", Product, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return 0;
            try { Uninstall(Path.GetDirectoryName(Environment.ProcessPath!)!); return 0; }
            catch (OperationCanceledException)
            {
                Log("UNINSTALL_CANCELLED stage=machine_service_uac no_machine_changes=true");
                MessageBox.Show("Odinstalowanie anulowano. Sentinel AI i jego usługa nadal są zainstalowane.", Product, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return 0;
            }
            catch (Exception ex)
            {
                if (ex.Data["SentinelUninstallStage"] is not string)
                    Log(FormatUninstallFailureLog("dispatch", ex));
                MessageBox.Show(FormatUninstallErrorMessage(ex), Product, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 1;
            }
        }
        ApplicationConfiguration.Initialize();
        Application.Run(new SetupWizard());
        return 0;
    }

    private static int WizardSelfTest()
    {
        var directory = Path.Combine(Path.GetTempPath(), "SentinelAI-WizardSelfTest-" + Guid.NewGuid().ToString("N"));
        var previousLogPath = selfTestLogPath;
        selfTestLogPath = Path.Combine(directory, "installer.log");
        try
        {
            ApplicationConfiguration.Initialize();
            SetupWizard.ValidateVisualStates();
            var uiFailure = FormatUiThreadException(new InvalidOperationException("simulated UI failure"));
            if (!uiFailure.Contains("type=InvalidOperationException", StringComparison.Ordinal)
                || !uiFailure.Contains("hresult=0x", StringComparison.Ordinal))
                throw new InvalidOperationException("UI exception diagnostic omits its type or HRESULT.");
            var stopAttempts = 0;
            var retryDelays = 0;
            var retriedShutdown = StopAgentWithRetry(() => ++stopAttempts == 1 ? 1 : 0, () => true,
                _ => retryDelays++, _ => { });
            if (!retriedShutdown || stopAttempts != 2 || retryDelays != 1)
                throw new InvalidOperationException("Transient Core shutdown failure was not retried safely.");
            var absentAgentAttempts = 0;
            var alreadyStopped = StopAgentWithRetry(() => { absentAgentAttempts++; return 1; }, () => false,
                _ => { }, _ => { });
            if (!alreadyStopped || absentAgentAttempts != 1)
                throw new InvalidOperationException("An agent that exited during shutdown was not accepted as stopped.");
            var persistentFailureAttempts = 0;
            try
            {
                StopAgentWithRetry(() => { persistentFailureAttempts++; return 1; }, () => true,
                    _ => { }, _ => { });
                throw new InvalidOperationException("A running Core that never acknowledges shutdown was accepted.");
            }
            catch (IOException exception) when (exception.Message.Contains("po ponowieniach", StringComparison.Ordinal))
            {
                if (persistentFailureAttempts != 8)
                    throw new InvalidOperationException("Core shutdown retry was not bounded to eight attempts.");
            }
            Log("WIZARD_SELF_TEST_SUCCESS states=true repairMode=true settingsPreserved=true failureStopsBeforeChanges=true backgroundPreflight=true coreStopRetry=true");
            return 0;
        }
        catch (Exception exception)
        {
            Log($"WIZARD_SELF_TEST_FAILED type={exception.GetType().Name} message={Clean(exception.Message)}");
            try { File.Copy(LogPath, Path.Combine(AppContext.BaseDirectory, "installer-wizard-self-test-failure.log"), overwrite: true); } catch { }
            return 1;
        }
        finally { TryDelete(directory); selfTestLogPath = previousLogPath; }
    }

    private static int UninstallRegistrationSelfTest()
    {
        var target = Path.Combine(Path.GetTempPath(), "SentinelAI-UninstallGuard-SelfTest");
        try
        {
            var missingRejected = false;
            try { ValidateRegisteredUninstallTarget(null, target); }
            catch (InvalidOperationException) { missingRejected = true; }
            var mismatchedRejected = false;
            try { ValidateRegisteredUninstallTarget(Path.Combine(target, "other"), target); }
            catch (InvalidOperationException) { mismatchedRejected = true; }
            ValidateRegisteredUninstallTarget(target, Path.Combine(target, "."));
            var reparseRejected = false;
            try { RejectReparsePointAttributes(FileAttributes.Directory | FileAttributes.ReparsePoint, target); }
            catch (InvalidOperationException) { reparseRejected = true; }
            if (!reparseRejected) throw new InvalidDataException("Punkt ponownej analizy nie został odrzucony.");
            var expectedRunValue = $"\"{Path.Combine(target, "Sentinel AI.exe")}\" --minimized";
            if (!AutoStartValueTargetsExecutable(expectedRunValue, Path.Combine(target, "Sentinel AI.exe"))
                || !AutoStartValueTargetsExecutable(expectedRunValue + " --profile=local", Path.Combine(target, "Sentinel AI.exe"))
                || AutoStartValueTargetsExecutable("\"C:\\Other\\Sentinel AI.exe\" --minimized", Path.Combine(target, "Sentinel AI.exe"))
                || AutoStartValueTargetsExecutable("\"unterminated", Path.Combine(target, "Sentinel AI.exe")))
                throw new InvalidDataException("Ochrona wpisu autostartu nie rozpoznaje własnego pliku ani wpisu obcego.");
            VerifyReparsePointTreeScan();
            if (!missingRejected || !mismatchedRejected)
                throw new InvalidDataException("Brak lub niezgodność ścieżki rejestru nie zablokowała deinstalacji.");
            var uninstallFailure = FormatUninstallFailureLog("remove_payload_files", new IOException("simulated file lock"));
            if (!uninstallFailure.Contains("stage=remove_payload_files", StringComparison.Ordinal)
                || !uninstallFailure.Contains("type=IOException", StringComparison.Ordinal)
                || !uninstallFailure.Contains("hresult=0x", StringComparison.Ordinal)
                || !uninstallFailure.Contains("simulated file lock", StringComparison.Ordinal))
                throw new InvalidDataException("Błąd deinstalacji nie zawiera etapu, typu wyjątku i kodu HRESULT.");
            var uninstallMessageException = new IOException("simulated file lock");
            uninstallMessageException.Data["SentinelUninstallStage"] = "remove_payload_files";
            var uninstallMessage = FormatUninstallErrorMessage(uninstallMessageException);
            if (!uninstallMessage.Contains("Etap: remove_payload_files", StringComparison.Ordinal)
                || !uninstallMessage.Contains("IOException", StringComparison.Ordinal)
                || !uninstallMessage.Contains("0x", StringComparison.Ordinal)
                || !uninstallMessage.Contains("simulated file lock", StringComparison.Ordinal)
                || !uninstallMessage.Contains(LogPath, StringComparison.Ordinal))
                throw new InvalidDataException("Okno błędu deinstalacji pomija etap, typ, HRESULT, przyczynę lub log.");
            Console.WriteLine("UNINSTALL_GUARD_SELF_TEST_SUCCESS missingRegistrationRejected=true mismatchedPathRejected=true matchingPathAccepted=true autostartOwnership=true unrelatedAutostartPreserved=true failureLogging=true reparsePointRejected=true junctionTreeRejected=true handleEnumeration=true paginatedEnumeration=true handleContainment=true safeDirectoryCreation=true safeRename=true transientRenameRetry=true safeFileCreation=true safeCopy=true safeDeletion=true");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"UNINSTALL_GUARD_SELF_TEST_FAILED type={exception.GetType().Name} message={Clean(exception.Message)}");
            return 1;
        }
    }

    private static int UninstallCleanupSelfTest()
    {
        var root = Path.Combine(Path.GetTempPath(), "SentinelAI-UninstallCleanup-SelfTest-" + Guid.NewGuid().ToString("N"));
        var target = Path.Combine(root, "install");
        var uninstallPath = Path.Combine(target, "Uninstall Sentinel AI.exe");
        var logPath = Path.Combine(root, "diagnostics.log");
        try
        {
            Directory.CreateDirectory(target);
            File.WriteAllText(uninstallPath, "temporary cleanup test file");
            var script = BuildUninstallCleanupScript(uninstallPath, target, logPath, parentProcessId: -1, waitTimeoutSeconds: 1, attempts: 4, retryDelayMilliseconds: 25);
            var firstExitCode = RunUninstallCleanupScriptForTest(script);
            if (firstExitCode != 0)
                throw new IOException($"Testowe sprzątanie zakończyło się kodem {firstExitCode}.");
            if (File.Exists(uninstallPath) || Directory.Exists(target))
                throw new InvalidDataException("Testowe sprzątanie nie usunęło wyłącznie wskazanego uninstalatora i pustego katalogu.");
            var result = File.ReadAllText(logPath);
            if (!result.Contains("UNINSTALL_CLEANUP_RESULT status=complete uninstallerRemoved=true installDirectoryRemoved=true remainingEntries=0", StringComparison.Ordinal))
                throw new InvalidDataException("Log nie potwierdził wyniku testowego sprzątania deinstalatora.");

            var preservedTarget = Path.Combine(root, "install-with-user-file");
            var preservedUninstaller = Path.Combine(preservedTarget, "Uninstall Sentinel AI.exe");
            var userFile = Path.Combine(preservedTarget, "user-data.dat");
            var preservedLog = Path.Combine(root, "preserved-diagnostics.log");
            Directory.CreateDirectory(preservedTarget);
            File.WriteAllText(preservedUninstaller, "temporary cleanup test file");
            File.WriteAllText(userFile, "preserve this user file");
            var preservedScript = BuildUninstallCleanupScript(preservedUninstaller, preservedTarget, preservedLog,
                parentProcessId: -1, waitTimeoutSeconds: 1, attempts: 4, retryDelayMilliseconds: 25);
            var preservedExitCode = RunUninstallCleanupScriptForTest(preservedScript);
            if (preservedExitCode != 0 || File.Exists(preservedUninstaller) || !File.Exists(userFile)
                || File.ReadAllText(userFile) != "preserve this user file" || !Directory.Exists(preservedTarget))
                throw new InvalidDataException("Końcowe sprzątanie zmieniło plik użytkownika poza zawartością deinstalatora.");
            var preservedResult = File.ReadAllText(preservedLog);
            if (!preservedResult.Contains("UNINSTALL_CLEANUP_RESULT status=partial uninstallerRemoved=true installDirectoryRemoved=false remainingEntries=1", StringComparison.Ordinal))
                throw new InvalidDataException("Log nie opisał pozostawionego pliku użytkownika.");

            Console.WriteLine("UNINSTALL_CLEANUP_SELF_TEST_SUCCESS temporaryFileRemoved=true emptyInstallDirectoryRemoved=true completionLogged=true userFilePreserved=true partialStateLogged=true");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"UNINSTALL_CLEANUP_SELF_TEST_FAILED type={exception.GetType().Name} message={Clean(exception.Message)}");
            return 1;
        }
        finally { TryDelete(root); }
    }

    private static void VerifyReparsePointTreeScan()
    {
        var root = Path.Combine(Path.GetTempPath(), "SentinelAI-ReparseGuard-" + Guid.NewGuid().ToString("N"));
        var trustedRoot = Path.Combine(root, "trusted");
        var install = Path.Combine(trustedRoot, "install");
        var outside = Path.Combine(root, "outside");
        var junction = Path.Combine(install, "redirected");
        try
        {
            Directory.CreateDirectory(install);
            Directory.CreateDirectory(outside);
            Directory.CreateDirectory(Path.Combine(install, "empty-directory"));
            Directory.CreateDirectory(Path.Combine(outside, "preserve-directory"));
            var safeCreatedDirectoryTree = Path.Combine(install, "safe-created-tree");
            CreateInstallDirectorySafely(Path.Combine(safeCreatedDirectoryTree, "nested"), install, trustedRoot);
            var safeDirectoryCreated = Directory.Exists(Path.Combine(safeCreatedDirectoryTree, "nested"));
            DeleteInstallTreeSafely(safeCreatedDirectoryTree, trustedRoot);
            var renameSource = Path.Combine(install, "rename-source");
            var renameDestination = Path.Combine(install, "rename-destination");
            CreateInstallDirectorySafely(renameSource, install, trustedRoot);
            File.WriteAllText(Path.Combine(renameSource, "marker.txt"), "rename");
            RenameInstallDirectorySafely(renameSource, renameDestination, trustedRoot);
            var safeRenameSucceeded = !Directory.Exists(renameSource)
                && File.ReadAllText(Path.Combine(renameDestination, "marker.txt")) == "rename";
            DeleteInstallTreeSafely(renameDestination, trustedRoot);
            if (!ShouldRetryDirectoryRename(5, 1)
                || !ShouldRetryDirectoryRename(32, 1)
                || !ShouldRetryDirectoryRename(33, 1)
                || ShouldRetryDirectoryRename(5, MaximumTransientDirectoryRenameAttempts)
                || ShouldRetryDirectoryRename(87, 1))
                throw new InvalidDataException("Reguła ponawiania zmiany nazwy katalogu nie ogranicza się do przejściowych błędów Windows.");
            var conflictSource = Path.Combine(install, "rename-conflict-source");
            var conflictDestination = Path.Combine(install, "rename-conflict-destination");
            CreateInstallDirectorySafely(conflictSource, install, trustedRoot);
            CreateInstallDirectorySafely(conflictDestination, install, trustedRoot);
            File.WriteAllText(Path.Combine(conflictSource, "marker.txt"), "source");
            File.WriteAllText(Path.Combine(conflictDestination, "marker.txt"), "destination");
            var renameConflictRejected = false;
            try { RenameInstallDirectorySafely(conflictSource, conflictDestination, trustedRoot); }
            catch (IOException) { renameConflictRejected = true; }
            var renameConflictPreserved = File.ReadAllText(Path.Combine(conflictSource, "marker.txt")) == "source"
                && File.ReadAllText(Path.Combine(conflictDestination, "marker.txt")) == "destination";
            DeleteInstallTreeSafely(conflictSource, trustedRoot);
            DeleteInstallTreeSafely(conflictDestination, trustedRoot);
            var paginationDirectory = Path.Combine(install, "enumeration-buffer");
            Directory.CreateDirectory(paginationDirectory);
            for (var index = 0; index < 1_200; index++)
                File.WriteAllText(Path.Combine(paginationDirectory, $"entry-{index:D4}-{new string('x', 60)}.tmp"), "x");
            File.WriteAllText(Path.Combine(outside, "preserve.txt"), "preserve");
            File.WriteAllText(Path.Combine(install, "inside.txt"), "inside");
            File.WriteAllText(Path.Combine(install, "delete-me.txt"), "delete");
            var paginatedFileCount = EnumerateInstallFiles(install, trustedRoot).Count();
            if (paginatedFileCount != 1_202)
                throw new InvalidDataException($"Enumeracja katalogu nie zachowała wpisów z wielu buforów: {paginatedFileCount}.");
            ValidateInstallTreeHasNoReparsePoints(install, trustedRoot);
            var start = new ProcessStartInfo("cmd.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            foreach (var argument in new[] { "/d", "/c", "mklink", "/J", junction, outside })
                start.ArgumentList.Add(argument);
            using var process = Process.Start(start) ?? throw new IOException("Nie można uruchomić testu junction.");
            if (!process.WaitForExit(10_000))
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit();
                throw new TimeoutException("Test tworzenia junction przekroczył limit czasu.");
            }
            if (process.ExitCode != 0)
                throw new IOException("Windows nie utworzył tymczasowego junction wymaganego do testu ochrony ścieżek.");

            var renameThroughJunctionRejected = false;
            try { RenameInstallDirectorySafely(junction, Path.Combine(install, "junction-rename-target"), trustedRoot); }
            catch (InvalidOperationException exception) when (exception.Message.Contains("ponownej analizy", StringComparison.Ordinal))
            { renameThroughJunctionRejected = true; }

            var junctionRejected = false;
            try { ValidateInstallTreeHasNoReparsePoints(install, trustedRoot); }
            catch (InvalidOperationException exception) when (exception.Message.Contains("ponownej analizy", StringComparison.Ordinal))
            { junctionRejected = true; }
            var fileEnumerationRejected = false;
            try { _ = EnumerateInstallFiles(install, trustedRoot).ToArray(); }
            catch (InvalidOperationException exception) when (exception.Message.Contains("ponownej analizy", StringComparison.Ordinal))
            { fileEnumerationRejected = true; }
            var directoryEnumerationRejected = false;
            try { _ = EnumerateInstallDirectories(install, trustedRoot).ToArray(); }
            catch (InvalidOperationException exception) when (exception.Message.Contains("ponownej analizy", StringComparison.Ordinal))
            { directoryEnumerationRejected = true; }
            var escapedReadRejected = false;
            try { using var escaped = OpenInstallFileRead(Path.Combine(junction, "preserve.txt"), install, trustedRoot); }
            catch (InvalidOperationException exception) when (exception.Message.Contains("zaufany katalog", StringComparison.Ordinal))
            { escapedReadRejected = true; }
            var escapedCopyRejected = false;
            try { CopyInstallFileSafely(Path.Combine(junction, "preserve.txt"), Path.Combine(install, "escaped-copy.txt"), install, install); }
            catch (InvalidOperationException exception) when (exception.Message.Contains("zaufany katalog", StringComparison.Ordinal))
            { escapedCopyRejected = true; }
            var escapedDeleteRejected = false;
            try { DeleteInstallPathSafely(Path.Combine(junction, "preserve.txt"), install, isDirectory: false, trustedRoot: trustedRoot); }
            catch (InvalidOperationException exception) when (exception.Message.Contains("zaufany katalog", StringComparison.Ordinal))
            { escapedDeleteRejected = true; }
            var escapedCreateRejected = false;
            try { using var escaped = CreateInstallFileSafely(Path.Combine(junction, "created-outside.txt"), install, trustedRoot); }
            catch (InvalidOperationException exception) when (exception.Message.Contains("zaufany katalog", StringComparison.Ordinal))
            { escapedCreateRejected = true; }
            var escapedDirectoryRejected = false;
            try { CreateInstallDirectorySafely(Path.Combine(junction, "preserve-directory"), install, trustedRoot); }
            catch (InvalidOperationException)
            { escapedDirectoryRejected = true; }
            var escapedDirectoryCreateRejected = false;
            try { CreateInstallDirectorySafely(Path.Combine(junction, "created-outside"), install, trustedRoot); }
            catch (InvalidOperationException)
            { escapedDirectoryCreateRejected = true; }
            var createdFile = CreateInstallFileSafely(Path.Combine(install, "safe-created.txt"), install, trustedRoot);
            var createdFileHandle = createdFile.SafeFileHandle;
            using (createdFile)
            {
                createdFile.Write(Encoding.UTF8.GetBytes("created safely"));
                createdFile.Flush(flushToDisk: true);
            }
            if (!createdFileHandle.IsClosed) throw new InvalidDataException("Uchwyt utworzonego pliku pozostał otwarty po Dispose.");
            var safeCreatedExists = File.Exists(Path.Combine(install, "safe-created.txt"));
            var safeCreatedLength = GetInstallFileLength(Path.Combine(install, "safe-created.txt"), install, trustedRoot);
            DeleteInstallPathSafely(Path.Combine(install, "safe-created.txt"), install, isDirectory: false, trustedRoot: trustedRoot);
            CopyInstallFileSafely(Path.Combine(install, "inside.txt"), Path.Combine(install, "safe-copy.txt"), install, install);
            var safeCopyLength = GetInstallFileLength(Path.Combine(install, "safe-copy.txt"), install, trustedRoot);
            DeleteInstallPathSafely(Path.Combine(install, "safe-copy.txt"), install, isDirectory: false, trustedRoot: trustedRoot);
            DeleteInstallPathSafely(Path.Combine(install, "delete-me.txt"), install, isDirectory: false, trustedRoot: trustedRoot);
            DeleteInstallPathSafely(Path.Combine(install, "empty-directory"), install, isDirectory: true, trustedRoot: trustedRoot);
            var recursiveCleanupRejected = false;
            try { DeleteInstallTreeSafely(install, trustedRoot); }
            catch (InvalidOperationException exception) when (exception.Message.Contains("ponownej analizy", StringComparison.Ordinal))
            { recursiveCleanupRejected = true; }
            var cleanupTree = Path.Combine(trustedRoot, "cleanup-tree");
            Directory.CreateDirectory(Path.Combine(cleanupTree, "nested"));
            File.WriteAllText(Path.Combine(cleanupTree, "nested", "owned.txt"), "owned");
            DeleteInstallTreeSafely(cleanupTree, trustedRoot);
            using var safeRead = OpenInstallFileRead(Path.Combine(install, "inside.txt"), install, trustedRoot);
            var safeReadContent = new StreamReader(safeRead).ReadToEnd();
            if (!junctionRejected || !fileEnumerationRejected || !directoryEnumerationRejected || !escapedReadRejected || !escapedDeleteRejected
                || !escapedReadRejected || !escapedCopyRejected || !escapedDeleteRejected
                || !escapedCreateRejected || !escapedDirectoryRejected || !escapedDirectoryCreateRejected
                || Directory.Exists(Path.Combine(outside, "created-outside")) || File.Exists(Path.Combine(install, "escaped-copy.txt"))
                || File.Exists(Path.Combine(outside, "created-outside.txt"))
                || !Directory.Exists(Path.Combine(outside, "preserve-directory")) || !safeDirectoryCreated
                || Directory.Exists(safeCreatedDirectoryTree) || !safeRenameSucceeded || !renameConflictRejected
                || !renameConflictPreserved || !renameThroughJunctionRejected
                || !safeCreatedExists || safeCreatedLength != 14 || safeCopyLength != 6
                || !recursiveCleanupRejected || !File.Exists(Path.Combine(install, "inside.txt")) || Directory.Exists(cleanupTree)
                || File.Exists(Path.Combine(install, "delete-me.txt")) || Directory.Exists(Path.Combine(install, "empty-directory"))
                || safeReadContent != "inside" || !File.Exists(Path.Combine(outside, "preserve.txt")))
                throw new InvalidDataException("Skan lub enumeracja drzewa nie odrzuciły junction albo zmieniły plik poza instalacją.");
        }
        finally
        {
            if (Directory.Exists(junction)) Directory.Delete(junction, recursive: false);
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static bool IsUninstallInvocation(string[] args, string? executablePath) =>
        args.Contains("--uninstall", StringComparer.OrdinalIgnoreCase)
        || string.Equals(Path.GetFileName(executablePath), "Uninstall Sentinel AI.exe", StringComparison.OrdinalIgnoreCase);

    private static int IntegrationTest(string? browserE2eRepo = null)
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
            if (Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")?.GetValue(CoreAutoStartValueName) is not null)
                throw new InvalidOperationException("Integration test refused: a Sentinel AI Core autostart value already exists.");
            foreach (var keyPath in new[]
            {
                @"Software\Google\Chrome\NativeMessagingHosts\com.sentinelai.urlcheck",
                @"Software\Microsoft\Edge\NativeMessagingHosts\com.sentinelai.urlcheck"
            })
                using (var key = Registry.CurrentUser.OpenSubKey(keyPath))
                    if (key is not null) throw new InvalidOperationException($"Integration test refused: Native Messaging key already exists ({keyPath}).");
            MachineServiceInstaller.EnsureNoServiceForIntegrationTest();
            var startMenuLink = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "Sentinel AI.lnk");
            var desktopLink = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Sentinel AI.lnk");
            if (File.Exists(startMenuLink) || File.Exists(desktopLink))
                throw new InvalidOperationException("Integration test refused: a Sentinel AI shortcut already exists.");
            if (Directory.Exists(root)) throw new IOException("Generated integration-test folder unexpectedly already exists.");

            Log($"INTEGRATION_TEST_START target={root}");
            Install(root, startMenuShortcut: false, desktopShortcut: false, autoStart: false,
                (_, _) => { }, CancellationToken.None);
            VerifyInstallation(root, startMenuShortcut: false, desktopShortcut: false, autoStart: false, verifyFileContextMenu: false, verifyCoreAutoStart: false, verifyMachineService: true);
            if (!string.IsNullOrWhiteSpace(browserE2eRepo))
                RunInstalledHostBrowserE2E(browserE2eRepo, root);
            var preservedFile = Path.Combine(root, "integration-test-user-file.txt");
            const string preservedContents = "preserve across installed update and uninstall";
            File.WriteAllText(preservedFile, preservedContents);

            Log("INTEGRATION_TEST_ROLLBACK_START");
            try
            {
                Install(root, startMenuShortcut: false, desktopShortcut: false, autoStart: false,
                    (_, _) => { }, CancellationToken.None, injectMachineServiceUpdateFailureForTest: true);
                throw new InvalidDataException("Kontrolowany błąd aktualizacji usługi nie przerwał instalacji.");
            }
            catch (IOException exception) when (exception.Message.Contains("Windows nie zainstalował usługi Sentinel AI (kod 10)", StringComparison.Ordinal))
            {
                Log("INTEGRATION_TEST_ROLLBACK_FAILURE_OBSERVED");
            }
            MachineServiceInstaller.VerifyRollbackForIntegrationTest();
            VerifyInstallation(root, startMenuShortcut: false, desktopShortcut: false, autoStart: false,
                verifyFileContextMenu: false, verifyCoreAutoStart: false, verifyMachineService: true);
            if (!File.Exists(preservedFile) || File.ReadAllText(preservedFile) != preservedContents)
                throw new InvalidDataException("Nieudana aktualizacja nie przywróciła plików użytkownika.");
            Log("INTEGRATION_TEST_ROLLBACK_SUCCESS previousService=true previousApplication=true userFilePreserved=true");

            Log("INTEGRATION_TEST_UPDATE_START");
            Install(root, startMenuShortcut: false, desktopShortcut: false, autoStart: false,
                (_, _) => { }, CancellationToken.None);
            VerifyInstallation(root, startMenuShortcut: false, desktopShortcut: false, autoStart: false, verifyFileContextMenu: false, verifyCoreAutoStart: false, verifyMachineService: true);
            if (!File.Exists(preservedFile) || File.ReadAllText(preservedFile) != preservedContents)
                throw new InvalidDataException("Update did not preserve a file outside the application payload.");
            Log("INTEGRATION_TEST_UPDATE_SUCCESS preservedUserFile=true");

            Uninstall(root);
            MachineServiceInstaller.VerifyUninstalledForIntegrationTest();
            if (!File.Exists(preservedFile) || File.ReadAllText(preservedFile) != preservedContents)
                throw new InvalidDataException("Uninstall did not preserve a user file outside the application payload.");
            DeleteInstallPathSafely(preservedFile, root, isDirectory: false);

            if (Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI") is not null)
                throw new InvalidDataException("Uninstall registration remained after integration-test cleanup.");
            if (Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")?.GetValue("Sentinel AI") is not null)
                throw new InvalidDataException("Autostart remained after integration-test cleanup.");
            if (Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")?.GetValue(CoreAutoStartValueName) is not null)
                throw new InvalidDataException("Core autostart remained after integration-test cleanup.");
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

            Log("INTEGRATION_TEST_SUCCESS install=true update=true verification=true uninstall=true userFilePreserved=true registry=true nativeMessaging=true shortcuts=false autostart=false");
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
                var preservedFile = Path.Combine(root, "integration-test-user-file.txt");
                if (Directory.Exists(root) && File.Exists(preservedFile))
                    DeleteInstallPathSafely(preservedFile, root, isDirectory: false);
                if (Directory.Exists(root) && !Directory.EnumerateFileSystemEntries(root).Any())
                    DeleteInstallPathSafely(root, Path.GetDirectoryName(root)!, isDirectory: true);
            }
            catch (Exception cleanupError) { Log($"INTEGRATION_TEST_CLEANUP_FAILED type={cleanupError.GetType().Name} message={Clean(cleanupError.Message)}"); }
            return 1;
        }
    }

    private static void RunInstalledHostBrowserE2E(string repoRoot, string installRoot)
    {
        repoRoot = Path.GetFullPath(repoRoot);
        var script = Path.Combine(repoRoot, "scripts", "test-chrome-extension-e2e.cjs");
        if (!File.Exists(script)) throw new FileNotFoundException("The browser E2E script was not found.", script);

        var isolatedLocalAppData = Path.Combine(Path.GetTempPath(), ".SentinelAI-InstalledHost-E2E-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(isolatedLocalAppData);
        try
        {
            foreach (var browser in new[] { "chrome", "edge" })
            {
                Log($"INTEGRATION_TEST_BROWSER_E2E_START browser={browser} host=installed");
                var start = new ProcessStartInfo("node")
                {
                    WorkingDirectory = repoRoot,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };
                start.ArgumentList.Add(script);
                start.ArgumentList.Add(browser);
                start.ArgumentList.Add("--allow-headless-browser");
                start.ArgumentList.Add("--allow-local-download-fixtures");
                start.ArgumentList.Add("--use-installed-host");
                start.Environment["SENTINEL_TEST_INSTALL_ROOT"] = installRoot;
                start.Environment["SENTINEL_TEST_STATUS_DIRECTORY"] = Path.Combine(isolatedLocalAppData, "SentinelAI");

                using var process = Process.Start(start) ?? throw new InvalidOperationException($"Could not start {browser} installed-host E2E.");
                var stdout = process.StandardOutput.ReadToEndAsync();
                var stderr = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(300_000))
                {
                    try { process.Kill(entireProcessTree: true); } catch { }
                    throw new TimeoutException($"{browser} installed-host E2E exceeded five minutes.");
                }
                Task.WaitAll(stdout, stderr);
                var output = Clean((stdout.Result + Environment.NewLine + stderr.Result).Trim());
                if (output.Length > MaximumLogMessageCharacters) output = output[^MaximumLogMessageCharacters..];
                Log($"INTEGRATION_TEST_BROWSER_E2E_OUTPUT browser={browser} output={output}");
                if (process.ExitCode != 0)
                    throw new InvalidOperationException($"{browser} installed-host E2E failed with exit code {process.ExitCode}.");
                Log($"INTEGRATION_TEST_BROWSER_E2E_SUCCESS browser={browser} host=installed");
            }
        }
        finally
        {
            var temporaryRoot = Path.GetFullPath(Path.GetTempPath());
            var isolatedRoot = Path.GetFullPath(isolatedLocalAppData);
            if (!isolatedRoot.StartsWith(temporaryRoot, StringComparison.OrdinalIgnoreCase) ||
                !Path.GetFileName(isolatedRoot).StartsWith(".SentinelAI-InstalledHost-E2E-", StringComparison.Ordinal))
                throw new InvalidOperationException("Refusing to remove the browser E2E data folder outside its generated temporary location.");
            if (Directory.Exists(isolatedRoot)) Directory.Delete(isolatedRoot, recursive: true);
        }
    }

    private static int WizardIntegrationTest()
    {
        Log("WIZARD_INTEGRATION_TEST_REQUESTED");
        if (!OperatingSystem.IsWindows()) return 2;
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Programs", ".SentinelAI-WizardIntegration-Test-" + Guid.NewGuid().ToString("N"));
        var preservedFile = Path.Combine(root, "wizard-integration-user-file.txt");
        const string preservedContents = "preserve across GUI repair and uninstall";
        try
        {
            using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI"))
                if (key is not null) throw new InvalidOperationException("Wizard integration test refused: a Sentinel AI installation is already registered.");
            if (Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")?.GetValue("Sentinel AI") is not null)
                throw new InvalidOperationException("Wizard integration test refused: a Sentinel AI autostart value already exists.");
            foreach (var keyPath in new[]
            {
                @"Software\Google\Chrome\NativeMessagingHosts\com.sentinelai.urlcheck",
                @"Software\Microsoft\Edge\NativeMessagingHosts\com.sentinelai.urlcheck"
            })
                using (var key = Registry.CurrentUser.OpenSubKey(keyPath))
                    if (key is not null) throw new InvalidOperationException($"Wizard integration test refused: Native Messaging key already exists ({keyPath}).");
            MachineServiceInstaller.EnsureNoServiceForIntegrationTest();
            var startMenuLink = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "Sentinel AI.lnk");
            var desktopLink = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Sentinel AI.lnk");
            if (File.Exists(startMenuLink) || File.Exists(desktopLink))
                throw new InvalidOperationException("Wizard integration test refused: a Sentinel AI shortcut already exists.");
            if (Directory.Exists(root)) throw new IOException("Generated wizard integration-test folder unexpectedly already exists.");

            ApplicationConfiguration.Initialize();
            using (var wizard = new SetupWizard(repairModeOverride: false, integrationTestTarget: root))
            {
                RunWizardIntegrationFlow(wizard, repairExpected: false);
            }

            VerifyInstallation(root, startMenuShortcut: false, desktopShortcut: false, autoStart: false, verifyFileContextMenu: false, verifyCoreAutoStart: false, verifyMachineService: true);
            File.WriteAllText(preservedFile, preservedContents);
            using (var wizard = new SetupWizard(integrationTestTarget: root))
            {
                RunWizardIntegrationFlow(wizard, repairExpected: true);
            }
            VerifyInstallation(root, startMenuShortcut: false, desktopShortcut: false, autoStart: false, verifyFileContextMenu: false, verifyCoreAutoStart: false, verifyMachineService: true);
            if (!File.Exists(preservedFile) || File.ReadAllText(preservedFile) != preservedContents)
                throw new InvalidDataException("GUI repair/update did not preserve a file outside the application payload.");
            Uninstall(root);
            MachineServiceInstaller.VerifyUninstalledForIntegrationTest();
            using (var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip")!)
            using (var archive = new ZipArchive(resource, ZipArchiveMode.Read))
                foreach (var entry in archive.Entries.Where(x => !string.IsNullOrEmpty(x.Name)))
                {
                    var installedPath = Path.GetFullPath(Path.Combine(root, entry.FullName.Replace('/', Path.DirectorySeparatorChar)));
                    if (File.Exists(installedPath)) throw new InvalidDataException($"Wizard integration test left an application file: {entry.FullName}.");
                }
            if (!File.Exists(preservedFile) || File.ReadAllText(preservedFile) != preservedContents)
                throw new InvalidDataException("GUI uninstall did not preserve a file outside the application payload.");
            DeleteInstallPathSafely(preservedFile, root, isDirectory: false);
            using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI"))
                if (key is not null) throw new InvalidDataException("Wizard integration test left an uninstall registration behind.");
            if (Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")?.GetValue("Sentinel AI") is not null)
                throw new InvalidDataException("Wizard integration test left autostart behind.");
            foreach (var keyPath in new[]
            {
                @"Software\Google\Chrome\NativeMessagingHosts\com.sentinelai.urlcheck",
                @"Software\Microsoft\Edge\NativeMessagingHosts\com.sentinelai.urlcheck"
            })
                using (var key = Registry.CurrentUser.OpenSubKey(keyPath))
                    if (key is not null) throw new InvalidDataException($"Wizard integration test left Native Messaging registration behind ({keyPath}).");
            if (File.Exists(startMenuLink) || File.Exists(desktopLink))
                throw new InvalidDataException("Wizard integration test left a Sentinel AI shortcut behind.");
            Log("WIZARD_INTEGRATION_TEST_SUCCESS form=true install=true repairUpdate=true verification=true uninstall=true userFilePreserved=true shortcuts=false autostart=false");
            return 0;
        }
        catch (Exception exception)
        {
            Log($"WIZARD_INTEGRATION_TEST_FAILED type={exception.GetType().Name} message={Clean(exception.Message)}");
            try
            {
                var registered = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI")?.GetValue("InstallLocation") as string;
                if (Directory.Exists(root) && PathsEqual(registered, root))
                {
                    Uninstall(root);
                    if (Directory.Exists(root) && File.Exists(preservedFile))
                        DeleteInstallPathSafely(preservedFile, root, isDirectory: false);
                }
                if (Directory.Exists(root) && !Directory.EnumerateFileSystemEntries(root).Any())
                    DeleteInstallPathSafely(root, Path.GetDirectoryName(root)!, isDirectory: true);
            }
            catch (Exception cleanupError) { Log($"WIZARD_INTEGRATION_TEST_CLEANUP_FAILED type={cleanupError.GetType().Name} message={Clean(cleanupError.Message)}"); }
            return 1;
        }
    }

    private static void RunWizardIntegrationFlow(SetupWizard wizard, bool repairExpected)
    {
        if (wizard.IsRepairMode != repairExpected)
            throw new InvalidOperationException($"Wizard opened in the wrong mode. Expected repairMode={repairExpected}.");
        Application.Run(wizard);
        if (!string.IsNullOrWhiteSpace(wizard.IntegrationTestFailure))
            throw new InvalidOperationException($"Wizard flow failed: {wizard.IntegrationTestFailure}");
        if (wizard.DialogResult != DialogResult.OK)
            throw new InvalidOperationException($"Wizard flow closed with result {wizard.DialogResult}.");
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
                || !archive.Entries.Any(e => e.FullName.Replace('\\', '/').Equals("resources/engine/Sentinel.Engine.exe", StringComparison.OrdinalIgnoreCase))
                || !archive.Entries.Any(e => e.FullName.Replace('\\', '/').Equals("resources/engine/Sentinel.Agent.exe", StringComparison.OrdinalIgnoreCase))
                || !archive.Entries.Any(e => e.FullName.Replace('\\', '/').Equals("resources/service/Sentinel.Service.exe", StringComparison.OrdinalIgnoreCase))
                || !archive.Entries.Any(e => e.FullName.Replace('\\', '/').Equals("resources/service/Sentinel.Engine.exe", StringComparison.OrdinalIgnoreCase))
                || !archive.Entries.Any(e => e.FullName.Replace('\\', '/').Equals("resources/engine/Sentinel.Core.dll", StringComparison.OrdinalIgnoreCase))
                || !archive.Entries.Any(e => e.FullName.Replace('\\', '/').Equals("resources/engine/Sentinel.Contracts.dll", StringComparison.OrdinalIgnoreCase)))
                throw new InvalidDataException("Pakiet jest niekompletny.");
            return true;
        }
        catch (Exception ex)
        {
            Log($"PAYLOAD_VERIFY_FAILED type={ex.GetType().Name} message={Clean(ex.Message)} expected={PayloadHash}");
            if (showErrors) MessageBox.Show(FormatPayloadVerificationError(ex), Product, MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
    }

    internal static string FormatPayloadVerificationError(Exception exception) =>
        $"Nie można zweryfikować pakietu aplikacji osadzonego w tym instalatorze. Instalator nie pobiera aplikacji z internetu.\r\n\r\n" +
        $"Jeśli chcesz ponowić instalację lub naprawę, pobierz nową kopię instalatora ze strony Sentinel AI.\r\n\r\n{exception.Message}";

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

    private static int SelfTest(bool runApplicationSmoke = true)
    {
        var previousLogPath = selfTestLogPath;
        var testId = Guid.NewGuid().ToString("N");
        var diagnosticDirectory = Path.Combine(Path.GetTempPath(), "SentinelAI-Setup-SelfTest-" + testId);
        var testDirectory = Path.Combine(Path.GetTempPath(), "SentinelAI-Setup-SelfTestData-" + testId);
        selfTestLogPath = Path.Combine(diagnosticDirectory, "installer.log");
        var root = string.Empty;
        var data = string.Empty;
        try
        {
            ApplicationConfiguration.Initialize();
            root = Path.Combine(testDirectory, "Programs", ".SentinelAI-Setup-SelfTest-" + testId);
            data = Path.Combine(testDirectory, "data");
            selfTestLogPath = Path.Combine(data, "installer.log");
            if (Directory.Exists(root)
                || !PathsEqual(ValidateInstallSelection(root), root)
                || Directory.Exists(root))
                throw new InvalidDataException("Nowa, nieistniejąca lokalizacja instalacji nie została zaakceptowana bez tworzenia folderu.");
            VerifyLogRotation(Path.Combine(data, "installer-log-rotation-test.log"));
            var failureLog = FormatInstallFailureLog("copy", "extract_payload", new IOException("controlled install failure"));
            if (!failureLog.Contains("stage=copy", StringComparison.Ordinal)
                || !failureLog.Contains("operation=extract_payload", StringComparison.Ordinal)
                || !failureLog.Contains("type=IOException", StringComparison.Ordinal))
                throw new InvalidDataException("Log błędu instalacji nie zawiera etapu, operacji i typu wyjątku.");
            var taggedFailure = new IOException("controlled install failure");
            taggedFailure.Data["SentinelInstallStage"] = "copy";
            taggedFailure.Data["SentinelInstallOperation"] = "extract_payload";
            var failureMessage = FormatInstallErrorMessage(taggedFailure);
            if (!failureMessage.Contains("Etap: copy", StringComparison.Ordinal)
                || !failureMessage.Contains("Operacja: extract_payload", StringComparison.Ordinal))
                throw new InvalidDataException("Ekran błędu instalacji nie pokazuje etapu i opera…24973 tokens truncated…lue(runKeyPath, "Sentinel AI", oldRunValue);
                    RestoreRegistryValue(runKeyPath, CoreAutoStartValueName, oldCoreRunValue);
                    RestoreRegistry(FileContextMenuKey, oldFileContextMenuValues);
                    RestoreRegistry(FileContextMenuCommandKey, oldFileContextMenuCommandValues);
                    RestoreShortcuts(linkBackups);
                }
                if (!testMode && oldMoved && Directory.Exists(target))
                    try { RunHostCommand(Path.Combine(target, "resources", "engine", "Sentinel.UrlHost.exe"), "--register", 8000); } catch (Exception restoreError) { Log($"ROLLBACK_HOST_REGISTER_FAILED message={Clean(restoreError.Message)}"); }
                if (!testMode && backgroundAgentWasRunning && Directory.Exists(target))
                    try { StartBackgroundAgent(target); } catch (Exception restartError) { Log($"CORE_AGENT_RESTART_FAILED message={Clean(restartError.Message)}"); }
                throw;
            }
            if (oldMoved) TryDeleteInstallTree(backup);
            if (!testMode)
                try { StartBackgroundAgent(target); } catch (Exception startError) { Log($"CORE_AGENT_START_FAILED message={Clean(startError.Message)}"); }
        }
        finally { TryDeleteInstallTree(staging); if (Directory.Exists(backup) && Directory.Exists(target)) TryDeleteInstallTree(backup); TryDelete(integrationBackup); }
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
        var stage = "resolve_target";
        try
        {
            target = Path.GetFullPath(target);
            var local = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
            stage = "validate_install_location";
            Log($"UNINSTALL_STAGE stage={stage} status=started");
            if (!target.StartsWith(local + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Odmowa usunięcia folderu poza profilem użytkownika.");
            ValidateInstallTreeHasNoReparsePoints(target, local);
            var registered = testMode ? null : Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI")?.GetValue("InstallLocation") as string;
            if (!testMode) ValidateRegisteredUninstallTarget(registered, target);
            Log($"UNINSTALL_START target={target}");
            Log($"UNINSTALL_STAGE stage={stage} status=complete");
            if (!testMode)
            {
                stage = "remove_machine_service";
                Log($"UNINSTALL_STAGE stage={stage} status=started");
                MachineServiceInstaller.UninstallElevated();
                Log($"UNINSTALL_STAGE stage={stage} status=complete");
                stage = "unregister_native_messaging";
                Log($"UNINSTALL_STAGE stage={stage} status=started");
                StopBackgroundAgent(target);
                RunHostCommand(Path.Combine(target, "resources", "engine", "Sentinel.UrlHost.exe"), "--unregister", 5000);
                Log($"UNINSTALL_STAGE stage={stage} status=complete");

                stage = "remove_owned_autostart";
                Log($"UNINSTALL_STAGE stage={stage} status=started");
                DeleteAutoStartIfOwned(target);
                DeleteCoreAutoStartIfOwned(target);
                Log($"UNINSTALL_STAGE stage={stage} status=complete");

                stage = "remove_owned_file_context_menu";
                Log($"UNINSTALL_STAGE stage={stage} status=started");
                RemoveFileContextMenuIfOwned(target);
                Log($"UNINSTALL_STAGE stage={stage} status=complete");

                stage = "remove_uninstall_registration";
                Log($"UNINSTALL_STAGE stage={stage} status=started");
                Registry.CurrentUser.DeleteSubKeyTree(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI", false);
                Log($"UNINSTALL_STAGE stage={stage} status=complete");

                stage = "remove_start_menu_shortcut";
                Log($"UNINSTALL_STAGE stage={stage} status=started");
                DeleteShortcutIfOwned(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "Sentinel AI.lnk"), target);
                Log($"UNINSTALL_STAGE stage={stage} status=complete");

                stage = "remove_desktop_shortcut";
                Log($"UNINSTALL_STAGE stage={stage} status=started");
                DeleteShortcutIfOwned(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Sentinel AI.lnk"), target);
                Log($"UNINSTALL_STAGE stage={stage} status=complete");
            }

            stage = "remove_embedded_payload_files";
            Log($"UNINSTALL_STAGE stage={stage} status=started");
            var deletedFiles = 0;
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip")!)
            using (var archive = new ZipArchive(stream, ZipArchiveMode.Read))
            {
                foreach (var entry in archive.Entries.Where(x => !string.IsNullOrEmpty(x.Name)))
                {
                    var path = Path.GetFullPath(Path.Combine(target, entry.FullName.Replace('/', Path.DirectorySeparatorChar)));
                    if (!path.StartsWith(target + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("Pakiet zawiera nieprawidłową ścieżkę podczas odinstalowania.");
                    if (File.Exists(path)) { DeleteInstallPathSafely(path, target, isDirectory: false); deletedFiles++; }
                }
            }
            Log($"UNINSTALL_STAGE stage={stage} status=complete files={deletedFiles}");

            stage = "remove_install_directories";
            Log($"UNINSTALL_STAGE stage={stage} status=started");
            var deferredDirectories = 0;
            if (Directory.Exists(target))
                foreach (var directory in EnumerateInstallDirectories(target).OrderByDescending(x => x.Length))
                    try { DeleteInstallPathSafely(directory, target, isDirectory: true); }
                    catch (IOException exception) { deferredDirectories++; Log($"UNINSTALL_DIRECTORY_DEFERRED type={exception.GetType().Name}"); }
            Log($"UNINSTALL_STAGE stage={stage} status=complete deferred={deferredDirectories}");

            var uninstallPath = Path.Combine(target, "Uninstall Sentinel AI.exe");
            if (testMode)
            {
                stage = "remove_test_uninstaller";
                Log($"UNINSTALL_STAGE stage={stage} status=started");
                if (File.Exists(uninstallPath)) DeleteInstallPathSafely(uninstallPath, target, isDirectory: false);
                foreach (var directory in EnumerateInstallDirectories(target).OrderByDescending(x => x.Length))
                    try { DeleteInstallPathSafely(directory, target, isDirectory: true); }
                    catch (IOException exception) { deferredDirectories++; Log($"UNINSTALL_DIRECTORY_DEFERRED type={exception.GetType().Name}"); }
                Log($"UNINSTALL_STAGE stage={stage} status=complete deferred={deferredDirectories}");
                Log("UNINSTALL_SUCCESS testMode=true appFilesRemoved=true userFilesPreserved=true");
                return;
            }

            stage = "schedule_uninstaller_cleanup";
            Log($"UNINSTALL_STAGE stage={stage} status=started");
            var script = BuildUninstallCleanupScript(uninstallPath, target, LogPath, Environment.ProcessId);
            var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            var cleanup = new ProcessStartInfo("powershell.exe") { UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden };
            cleanup.ArgumentList.Add("-NoProfile"); cleanup.ArgumentList.Add("-EncodedCommand"); cleanup.ArgumentList.Add(encoded);
            using var cleanupProcess = Process.Start(cleanup) ?? throw new IOException("Nie udało się uruchomić bezpiecznego czyszczenia deinstalatora.");
            Log($"UNINSTALL_STAGE stage={stage} status=complete cleanupProcessId={cleanupProcess.Id}");
            Log($"UNINSTALL_SUCCESS appFilesRemoved=true cleanupPending=true userFilesPreserved=true");
        }
        catch (Exception exception)
        {
            exception.Data["SentinelUninstallStage"] = stage;
            Log(FormatUninstallFailureLog(stage, exception));
            throw;
        }
    }

    private static string BuildUninstallCleanupScript(string uninstallPath, string target, string logPath,
        int parentProcessId, int waitTimeoutSeconds = 120, int attempts = 30, int retryDelayMilliseconds = 500)
    {
        if (waitTimeoutSeconds < 1 || attempts < 1 || retryDelayMilliseconds < 0)
            throw new ArgumentOutOfRangeException(nameof(waitTimeoutSeconds));
        return "$id=" + parentProcessId + "; try { Wait-Process -Id $id -Timeout " + waitTimeoutSeconds + " -ErrorAction Stop } catch {}; " +
            "$p=" + PowerShellQuote(uninstallPath) + "; $r=" + PowerShellQuote(target) + "; $l=" + PowerShellQuote(logPath) + "; $removed=$false; " +
            "for($i=0;$i -lt " + attempts + ";$i++){if(-not(Test-Path -LiteralPath $p)){$removed=$true;break}; try{Remove-Item -LiteralPath $p -Force -ErrorAction Stop; if(-not(Test-Path -LiteralPath $p)){$removed=$true;break}}catch{}; Start-Sleep -Milliseconds " + retryDelayMilliseconds + "}; " +
            "$directoryRemoved=$false; if($removed){if(-not(Test-Path -LiteralPath $r)){$directoryRemoved=$true}else{try{if((Get-ChildItem -LiteralPath $r -Force | Measure-Object).Count -eq 0){Remove-Item -LiteralPath $r -Force -ErrorAction Stop; $directoryRemoved=-not(Test-Path -LiteralPath $r)}}catch{}}}; " +
            "$remaining=0; if(Test-Path -LiteralPath $r){try{$remaining=(Get-ChildItem -LiteralPath $r -Force | Measure-Object).Count}catch{$remaining=-1}}; " +
            "$status='partial'; if($removed -and $directoryRemoved){$status='complete'} elseif(-not $removed){$status='failed'}; " +
            "$line=(Get-Date -Format o)+' UNINSTALL_CLEANUP_RESULT status='+$status+' uninstallerRemoved='+$removed.ToString().ToLowerInvariant()+' installDirectoryRemoved='+$directoryRemoved.ToString().ToLowerInvariant()+' remainingEntries='+$remaining+[Environment]::NewLine; " +
            "try{[IO.File]::AppendAllText($l,$line,[Text.UTF8Encoding]::new($false))}catch{}; if(-not $removed){exit 1}";
    }

    private static int RunUninstallCleanupScriptForTest(string script)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var start = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-EncodedCommand");
        start.ArgumentList.Add(encoded);
        using var process = Process.Start(start) ?? throw new IOException("Nie uruchomiono testu sprzątania deinstalatora.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(15_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("Testowe sprzątanie deinstalatora przekroczyło limit czasu.");
        }
        var stdout = stdoutTask.GetAwaiter().GetResult();
        var stderr = stderrTask.GetAwaiter().GetResult();
        if (process.ExitCode != 0) Log($"UNINSTALL_CLEANUP_SELF_TEST_PROCESS_ERROR type=ProcessExit code={process.ExitCode} message={Clean(stdout + " " + stderr)}");
        return process.ExitCode;
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

    private static void TryDeleteInstallTree(string path)
    {
        try
        {
            var target = Path.GetFullPath(path);
            var trustedRoot = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
            DeleteInstallTreeSafely(target, trustedRoot);
        }
        catch { }
    }

    private static void DeleteInstallTreeSafely(string target, string trustedRoot)
    {
        target = Path.GetFullPath(target);
        trustedRoot = Path.GetFullPath(trustedRoot);
        if (!target.StartsWith(trustedRoot.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Nie można sprzątać poza zaufanym katalogiem instalacji.");
        if (!Directory.Exists(target)) return;

        var files = EnumerateInstallFiles(target, trustedRoot).ToArray();
        var directories = EnumerateInstallDirectories(target, trustedRoot).ToArray();
        foreach (var file in files) DeleteInstallPathSafely(file, target, isDirectory: false, trustedRoot: trustedRoot);
        foreach (var directory in directories.OrderByDescending(x => x.Length))
            DeleteInstallPathSafely(directory, target, isDirectory: true, trustedRoot: trustedRoot);
        var parent = Path.GetDirectoryName(target);
        if (parent is not null) DeleteInstallPathSafely(target, parent, isDirectory: true, trustedRoot: trustedRoot);
    }
}

internal sealed class SetupWizard : Form
{
    private enum WizardPage { Welcome, Location, Options, Summary, Installing, Verify, Complete, Error }
    private readonly bool repairMode;
    private readonly Func<string, string> spaceSummaryProvider;

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
    private readonly Button advancedOptions = new() { Text = "Opcje zaawansowane", AutoSize = true, FlatStyle = FlatStyle.Flat, ForeColor = Color.FromArgb(190, 204, 222), BackColor = Color.Transparent };
    private readonly Button cancel = new() { Text = "Anuluj", Size = new Size(100, 38), Location = new Point(400, 408), Anchor = AnchorStyles.Bottom | AnchorStyles.Right };
    private readonly Button openLog = new() { Text = "Otwórz log", Size = new Size(110, 38), Location = new Point(270, 408), Anchor = AnchorStyles.Bottom | AnchorStyles.Right };
    private readonly PictureBox illustration = new() { Bounds = new Rectangle(475, 82, 180, 170), SizeMode = PictureBoxSizeMode.Zoom, BackColor = Color.Transparent, Anchor = AnchorStyles.Top | AnchorStyles.Right };
    private CancellationTokenSource? installCancellation;
    private int spaceRefreshGeneration;
    private string spaceSummary = "Sprawdzanie dostępnego miejsca…";
    private bool navigationRunning;
    private bool installationRunning;
    private WizardPage page = WizardPage.Welcome;
    private string lastError = string.Empty;
    private bool errorCanRetry;
    private bool repairSettingsReadFailed;
    private bool visualAssetFailureShown;
    private readonly string? integrationTestTarget;
    private System.Windows.Forms.Timer? integrationTestTimer;
    private DateTime integrationTestStartedAt;
    internal string? IntegrationTestFailure { get; private set; }
    internal bool IsRepairMode => repairMode;

    public SetupWizard(bool? repairModeOverride = null, (bool StartMenu, bool Desktop, bool AutoStart)? existingOptionsOverride = null,
        Exception? repairOptionsErrorOverride = null, string? integrationTestTarget = null,
        Func<string, string>? spaceSummaryProviderOverride = null)
    {
        this.integrationTestTarget = integrationTestTarget;
        spaceSummaryProvider = spaceSummaryProviderOverride ?? Program.GetInstallSpaceSummary;
        if (integrationTestTarget is not null)
        {
            folder.Text = integrationTestTarget;
            startMenu.Checked = desktop.Checked = start.Checked = launchAfter.Checked = false;
            ShowInTaskbar = false;
        }
        repairMode = repairModeOverride ?? Program.IsRegisteredInstall(folder.Text);
        if (repairMode)
        {
            launchAfter.Text = "Uruchom Sentinel AI po &naprawie / aktualizacji";
            try
            {
                if (repairOptionsErrorOverride is not null) throw repairOptionsErrorOverride;
                var options = existingOptionsOverride ?? Program.ReadRegisteredInstallOptions(folder.Text);
                startMenu.Checked = options.StartMenu;
                desktop.Checked = options.Desktop;
                start.Checked = options.AutoStart;
                launchAfter.Checked = false;
            }
            catch (Exception exception)
            {
                repairSettingsReadFailed = true;
                Program.Log($"REPAIR_PREFLIGHT_FAILED type={exception.GetType().Name} message={Program.Clean(exception.Message)}");
            }
        }
        Text = "Sentinel AI — Instalator"; ClientSize = new Size(700, 480); MinimumSize = new Size(680, 500); StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi; BackColor = Color.FromArgb(19, 28, 42); Font = new Font("Segoe UI", 10); FormBorderStyle = FormBorderStyle.Sizable; MaximizeBox = false;
        try { Icon = Icon.ExtractAssociatedIcon(Environment.ProcessPath!); } catch { }
        folder.BackColor = Color.FromArgb(26, 37, 54); folder.ForeColor = Color.White; folder.BorderStyle = BorderStyle.FixedSingle;
        foreach (var option in new[] { startMenu, desktop, start, launchAfter })
        {
            option.FlatStyle = FlatStyle.Flat;
            option.FlatAppearance.BorderColor = Color.FromArgb(93, 112, 137);
            option.FlatAppearance.CheckedBackColor = Color.FromArgb(47, 61, 80);
        }
        next.BackColor = Color.FromArgb(238, 126, 42); next.ForeColor = Color.White; next.FlatStyle = FlatStyle.Flat; next.FlatAppearance.BorderSize = 0;
        next.FlatAppearance.MouseOverBackColor = Color.FromArgb(255, 151, 69); next.FlatAppearance.MouseDownBackColor = Color.FromArgb(215, 104, 30);
        back.BackColor = Color.FromArgb(47, 61, 80); back.ForeColor = Color.White; back.FlatStyle = FlatStyle.Flat;
        cancel.BackColor = Color.FromArgb(47, 61, 80); cancel.ForeColor = Color.White; cancel.FlatStyle = FlatStyle.Flat;
        openLog.BackColor = Color.FromArgb(47, 61, 80); openLog.ForeColor = Color.White; openLog.FlatStyle = FlatStyle.Flat;
        folder.SetBounds(34, 197, 430, 32); browse.Location = new Point(475, 197);
        startMenu.Location = new Point(36, 185); desktop.Location = new Point(36, 223); start.Location = new Point(36, 261);
        launchAfter.Location = new Point(36, 299); summary.Location = new Point(34, 178);
        advancedOptions.Location = new Point(285, 366);
        Controls.AddRange([heading, step, intro, pathLabel, folder, browse, spaceInfo, startMenu, desktop, start, launchAfter, summary, status, errorDetails, progress, illustration, back, next, advancedOptions, cancel, openLog]);
        AcceptButton = next;
        CancelButton = cancel;
        browse.Click += async (_, _) => { using var dialog = new FolderBrowserDialog { SelectedPath = folder.Text, Description = "Wybierz folder instalacji Sentinel AI" }; if (dialog.ShowDialog(this) == DialogResult.OK) { folder.Text = Path.Combine(dialog.SelectedPath, "Sentinel AI"); await RefreshSpaceInfoAsync(); } };
        next.Click += async (_, _) => await MoveNextAsync();
        advancedOptions.Click += (_, _) => ShowPage(WizardPage.Location);
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
        folder.Validated += async (_, _) => await RefreshSpaceInfoAsync();
        if (integrationTestTarget is not null)
        {
            Shown += (_, _) => StartIntegrationTestDriver();
            FormClosed += (_, _) => integrationTestTimer?.Dispose();
        }
        if (repairSettingsReadFailed)
        {
            lastError = $"Nie można bezpiecznie odczytać obecnych ustawień Sentinel AI. Nie rozpoczęto żadnych zmian.\r\n\r\nLog diagnostyczny: {Program.LogPath}";
            ShowPage(WizardPage.Error, retryable: false);
            back.Visible = false;
        }
        else ShowPage(WizardPage.Welcome);
    }

    private void StartIntegrationTestDriver()
    {
        integrationTestStartedAt = DateTime.UtcNow;
        integrationTestTimer = new System.Windows.Forms.Timer { Interval = 100 };
        integrationTestTimer.Tick += (_, _) =>
        {
            if (DateTime.UtcNow - integrationTestStartedAt > TimeSpan.FromMinutes(10))
            {
                IntegrationTestFailure ??= "The interactive installer flow exceeded its 10-minute limit.";
                if (installationRunning) installCancellation?.Cancel();
                else { integrationTestTimer.Stop(); Close(); }
                return;
            }

            switch (page)
            {
                case WizardPage.Welcome:
                    next.PerformClick();
                    break;
                case WizardPage.Installing:
                case WizardPage.Verify:
                    break;
                case WizardPage.Location:
                    folder.Text = integrationTestTarget!;
                    next.PerformClick();
                    break;
                case WizardPage.Options:
                    startMenu.Checked = desktop.Checked = start.Checked = launchAfter.Checked = false;
                    next.PerformClick();
                    break;
                case WizardPage.Summary:
                    next.PerformClick();
                    break;
                case WizardPage.Complete:
                    next.PerformClick();
                    break;
                case WizardPage.Error:
                    IntegrationTestFailure ??= lastError;
                    integrationTestTimer.Stop();
                    if (!installationRunning) Close();
                    break;
            }
        };
        integrationTestTimer.Start();
    }

    private async Task MoveNextAsync()
    {
        if (navigationRunning || installationRunning) return;
        navigationRunning = true;
        next.Enabled = false;
        try
        {
            switch (page)
            {
                case WizardPage.Welcome:
                    if (repairMode) ShowPage(WizardPage.Location);
                    else await InstallAsync();
                    break;
                case WizardPage.Location:
                    await RefreshSpaceInfoAsync();
                    ShowPage(WizardPage.Options);
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
        finally
        {
            navigationRunning = false;
            if (!IsDisposed) next.Enabled = next.Visible && !installationRunning;
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
            var requestedPath = folder.Text;
            var selectedPath = await Task.Run(() => Program.ValidateInstallSelection(requestedPath), installCancellation.Token);
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
            status.Text = repairMode
                ? "Sprawdzam naprawione pliki, ustawienia, skróty i rejestrację przeglądarki…"
                : "Sprawdzam pliki, ustawienia, skróty i rejestrację przeglądarki…";
            await Task.Run(() => Program.VerifyInstallation(selectedPath, startMenu.Checked, desktop.Checked, start.Checked, verifyMachineService: true));
            Program.Log($"INSTALL_VERIFIED repair={repairMode} files=true registration=true shortcuts=true autostart={start.Checked} target={selectedPath}");
            status.Text = repairMode ? "Naprawa została zweryfikowana." : "Instalacja została zweryfikowana.";
            progress.Value = 100;
            ShowPage(WizardPage.Complete);
        }
        catch (OperationCanceledException)
        {
            ShowCancellationError();
        }
        catch (Exception ex)
        {
            Program.Log($"UI_INSTALL_ERROR type={ex.GetType().Name} message={Program.Clean(ex.Message)}");
            installationRunning = false;
            lastError = Program.FormatInstallErrorMessage(ex);
            ShowPage(WizardPage.Error, retryable: true);
        }
        finally
        {
            installationRunning = false;
            installCancellation?.Dispose();
            installCancellation = null;
        }
    }

    private void ShowCancellationError()
    {
        installationRunning = false;
        lastError = "Instalacja została anulowana. Poprzedni stan został przywrócony.";
        Program.Log("UI_INSTALL_CANCELLED rollback=true");
        ShowPage(WizardPage.Error, retryable: false);
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
        advancedOptions.Visible = !repairMode && target == WizardPage.Welcome;
        illustration.Visible = target is WizardPage.Welcome or WizardPage.Options or WizardPage.Installing or WizardPage.Verify or WizardPage.Complete or WizardPage.Error;
        back.Visible = target is WizardPage.Location or WizardPage.Options or WizardPage.Summary or WizardPage.Error;
        cancel.Visible = target is WizardPage.Location or WizardPage.Options or WizardPage.Summary or WizardPage.Installing or WizardPage.Verify;
        cancel.Enabled = target != WizardPage.Verify && !(target == WizardPage.Installing && progress.Value >= 80);
        next.Visible = target is not (WizardPage.Installing or WizardPage.Verify);
        next.Enabled = !installationRunning;
        next.Text = target switch
        {
            WizardPage.Welcome => repairMode ? "Dalej" : "ZAINSTALUJ",
            WizardPage.Location or WizardPage.Options => "Dalej",
            WizardPage.Summary => repairMode ? "Zastosuj" : "Zainstaluj",
            WizardPage.Error when errorCanRetry => repairMode ? "Ponów naprawę" : "Ponów instalację",
            WizardPage.Error => "Zakończ",
            WizardPage.Complete => "Zakończ",
            _ => "Dalej"
        };
        if (!repairMode && target == WizardPage.Welcome) next.SetBounds(205, 286, 290, 58);
        else next.SetBounds(518, 408, 136, 38);
        back.Enabled = !installationRunning;
        ActiveControl = next.Visible && next.Enabled ? next : cancel.Visible && cancel.Enabled ? cancel : null;
        step.Text = target switch
        {
            WizardPage.Welcome => "KROK 1 Z 7  •  POWITANIE",
            WizardPage.Location => "KROK 2 Z 7  •  LOKALIZACJA",
            WizardPage.Options => "KROK 3 Z 7  •  USTAWIENIA",
            WizardPage.Summary => "KROK 4 Z 7  •  PODSUMOWANIE",
            WizardPage.Installing => repairMode ? "KROK 5 Z 7  •  NAPRAWA / AKTUALIZACJA" : "KROK 5 Z 7  •  INSTALOWANIE",
            WizardPage.Verify => "KROK 6 Z 7  •  WERYFIKACJA",
            WizardPage.Complete => "KROK 7 Z 7  •  GOTOWE",
            _ => "BŁĄD INSTALACJI"
        };
        heading.Text = target switch
        {
            WizardPage.Welcome => repairMode ? "Napraw / aktualizuj Sentinel AI" : "Sentinel AI",
            WizardPage.Location => "Wybierz lokalizację",
            WizardPage.Options => repairMode ? "Zachowaj ustawienia" : "Dostosuj instalację",
            WizardPage.Summary => repairMode ? "Sprawdź naprawę / aktualizację" : "Sprawdź ustawienia",
            WizardPage.Installing => repairMode ? "Naprawiam / aktualizuję Sentinel AI" : "Instaluję Sentinel AI",
            WizardPage.Verify => "Weryfikuję instalację",
            WizardPage.Complete => repairMode ? "Naprawa / aktualizacja zakończona" : "Instalacja zakończona",
            _ => "Wystąpił problem"
        };
        intro.Text = target switch
        {
            WizardPage.Welcome => repairMode
                ? "Wykryto istniejącą instalację. Naprawa lub aktualizacja odtworzy pliki z tego pakietu i zachowa wykryte skróty oraz autostart."
                : "Inteligentna ochrona Twojego komputera. Aplikacja zainstaluje się w profilu użytkownika. Windows poprosi o zgodę na skonfigurowanie chronionej usługi działającej w tle.",
            WizardPage.Location => repairMode
                ? "Wybierz istniejący folder instalacji. Operacja zachowa ustawienia oraz pliki użytkownika spoza pakietu aplikacji."
                : "Wybierz bezpieczny folder w swoim profilu. Istniejąca instalacja zostanie zaktualizowana w tym samym miejscu.",
            WizardPage.Options => repairMode
                ? "Wykryte skróty i autostart są zaznaczone zgodnie z bieżącą konfiguracją. Uruchomienie po naprawie lub aktualizacji jest domyślnie wyłączone."
                : "Wybierz skróty i zachowanie aplikacji. Możesz zmienić te ustawienia później.",
            WizardPage.Summary => repairMode
                ? "Naprawa lub aktualizacja odtworzy pliki aplikacji, zweryfikuje wynik i zastosuje pokazane ustawienia."
                : "Instalator sprawdzi pakiet, skopiuje pliki, skonfiguruje wybrane opcje i zweryfikuje wynik.",
            WizardPage.Installing => "Rozpakowuję aplikację z pakietu osadzonego w instalatorze; pobieranie nie jest wymagane.",
            WizardPage.Verify => "Sprawdzam pliki aplikacji, usługę ochrony, autostart, skróty i host przeglądarki.",
            WizardPage.Complete => repairMode ? "Pliki i konfiguracja naprawionej instalacji zostały sprawdzone." : "Pliki i konfiguracja instalacji zostały sprawdzone.",
            _ => "Instalator nie zgłosi sukcesu, jeśli konfiguracja lub weryfikacja się nie powiedzie."
        };
        step.Visible = target != WizardPage.Welcome || repairMode;
        status.Text = target switch
        {
            WizardPage.Installing => repairMode ? "Przygotowuję naprawę / aktualizację…" : "Przygotowuję instalację…",
            WizardPage.Verify => "Weryfikuję pliki i konfigurację…",
            WizardPage.Complete => repairMode ? "Sentinel AI został naprawiony / zaktualizowany i zweryfikowany." : "Sentinel AI został zainstalowany i zweryfikowany.",
            _ => status.Text
        };
        if (showSummary)
        {
            var path = folder.Text.Trim();
            summary.Text = $"{(repairMode ? "Folder naprawy / aktualizacji" : "Lokalizacja")}: {path}\r\n\r\nSkrót menu Start: {(startMenu.Checked ? "tak" : "nie")}\r\nSkrót na pulpicie: {(desktop.Checked ? "tak" : "nie")}\r\nAutostart Windows: {(start.Checked ? "tak" : "nie")}\r\n{(repairMode ? "Uruchom po naprawie / aktualizacji" : "Uruchom po instalacji")}: {(launchAfter.Checked ? "tak" : "nie")}\r\n\r\n{spaceSummary}";
        }
        if (showError) errorDetails.Text = lastError;
        SetIllustration(target switch
        {
            WizardPage.Welcome => "welcome",
            WizardPage.Options or WizardPage.Summary => "configure",
            WizardPage.Location => "prepare",
            WizardPage.Installing => progress.Value < 10 ? "prepare" : "installing",
            WizardPage.Verify => "system-check",
            WizardPage.Complete => "complete",
            WizardPage.Error when lastError.Contains("anulowana", StringComparison.OrdinalIgnoreCase) => "rollback-ready",
            _ => "error"
        });
        if (showLocation) _ = RefreshSpaceInfoAsync();
    }

    private async Task<string> RefreshSpaceInfoAsync()
    {
        var requestedPath = folder.Text;
        var generation = ++spaceRefreshGeneration;
        spaceInfo.ForeColor = Color.FromArgb(190, 204, 222);
        spaceInfo.Text = "Sprawdzam folder instalacji i dostępne miejsce…";
        try
        {
            var result = await Task.Run(() => spaceSummaryProvider(requestedPath));
            if (!IsDisposed && generation == spaceRefreshGeneration && string.Equals(folder.Text, requestedPath, StringComparison.Ordinal))
            {
                spaceSummary = result;
                spaceInfo.ForeColor = Color.FromArgb(190, 204, 222);
                spaceInfo.Text = result;
            }
            return result;
        }
        catch (Exception ex)
        {
            var error = ex.Message;
            if (!IsDisposed && generation == spaceRefreshGeneration && string.Equals(folder.Text, requestedPath, StringComparison.Ordinal))
            {
                spaceInfo.ForeColor = Color.FromArgb(255, 185, 185);
                spaceInfo.Text = error;
                spaceSummary = error;
            }
            return error;
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
        try
        {
            using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"installer-{name}.png")
                ?? throw new FileNotFoundException($"Brak osadzonego zasobu ilustracji: installer-{name}.png");
            using var source = Image.FromStream(stream);
            illustration.Image?.Dispose();
            illustration.Image = new Bitmap(source);
        }
        catch (Exception exception)
        {
            Program.Log($"INSTALLER_RESOURCE_LOAD_FAILED resource=installer-{Program.Clean(name)}.png type={exception.GetType().Name} hresult=0x{exception.HResult:X8}");
            illustration.Image?.Dispose();
            illustration.Image = null;
            next.Enabled = false;
            status.Text = $"Nie można załadować zasobów instalatora. Zamknij instalator i pobierz plik ponownie. Log: {Program.LogPath}";
            if (!visualAssetFailureShown)
            {
                visualAssetFailureShown = true;
                MessageBox.Show(this, status.Text, "Sentinel AI — błąd instalatora", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    internal static void ValidateVisualStates()
    {
        var contextMenuExecutable = Path.Combine(Path.GetTempPath(), "Sentinel AI.exe");
        var contextMenuCommand = Program.BuildFileContextMenuCommand(contextMenuExecutable);
        if (!contextMenuCommand.Contains("--check-file \"%1\"", StringComparison.Ordinal)
            || !Program.IsFileContextMenuCommandOwned(contextMenuCommand, contextMenuExecutable)
            || Program.IsFileContextMenuCommandOwned(contextMenuCommand.Replace("--check-file", "--open", StringComparison.Ordinal), contextMenuExecutable)
            || !Program.IsFileContextMenuSelectionModelOwned("Document")
            || Program.IsFileContextMenuSelectionModelOwned("Single"))
            throw new InvalidDataException("Polecenie menu kontekstowego nie cytuje bezpiecznie ścieżki pliku lub nie jest poprawnie rozpoznawane jako własne.");
        using var wizard = new SetupWizard(repairModeOverride: false);
        wizard.ShowInTaskbar = false;
        wizard.StartPosition = FormStartPosition.Manual;
        wizard.Location = new Point(-32_000, -32_000);
        wizard.Opacity = 0;
        wizard.Show();
        Application.DoEvents();
        if (wizard.ShowWithoutActivation)
            throw new InvalidDataException("Kreator instalatora nie może blokować aktywacji okna.");
        if (!ReferenceEquals(wizard.AcceptButton, wizard.next) || !ReferenceEquals(wizard.CancelButton, wizard.cancel))
            throw new InvalidDataException("Kreator nie udostępnia klawiaturowych przycisków Dalej i Anuluj.");
        if (wizard.next.Text != "ZAINSTALUJ" || !wizard.advancedOptions.Visible || wizard.folder.Visible
            || wizard.startMenu.Visible || wizard.desktop.Visible || wizard.start.Visible || wizard.step.Visible
            || wizard.next.Width < 250)
            throw new InvalidDataException("Ekran startowy nie pokazuje prostego instalowania z opcjonalnym obszarem zaawansowanym.");
        if (wizard.folder.BackColor != Color.FromArgb(26, 37, 54) || wizard.folder.ForeColor != Color.White
            || wizard.folder.BorderStyle != BorderStyle.FixedSingle
            || new[] { wizard.startMenu, wizard.desktop, wizard.start, wizard.launchAfter }.Any(option => option.FlatStyle != FlatStyle.Flat)
            || wizard.next.FlatStyle != FlatStyle.Flat || wizard.next.FlatAppearance.BorderSize != 0)
            throw new InvalidDataException("Kontrolki kreatora nie zachowały stylu Sentinel AI.");
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
        wizard.installationRunning = true;
        wizard.cancel.Enabled = false;
        wizard.ShowCancellationError();
        if (wizard.next.Text != "Zakończ" || !wizard.next.Enabled || wizard.installationRunning)
            throw new InvalidDataException("Po rollbacku anulowana instalacja nie udostępnia aktywnego przycisku Zakończ.");

        using var repairWizard = new SetupWizard(repairModeOverride: true, existingOptionsOverride: (false, true, false));
        if (repairWizard.heading.Text != "Napraw / aktualizuj Sentinel AI" || repairWizard.next.Text != "Dalej"
            || !repairWizard.intro.Text.Contains("istniejącą instalację", StringComparison.Ordinal))
            throw new InvalidDataException("Kreator nie pokazuje jednoznacznej ścieżki naprawy.");
        repairWizard.ShowPage(WizardPage.Options);
        if (repairWizard.startMenu.Checked || !repairWizard.desktop.Checked || repairWizard.start.Checked || repairWizard.launchAfter.Checked
            || !repairWizard.launchAfter.Text.Contains("naprawie / aktualizacji", StringComparison.Ordinal))
            throw new InvalidDataException("Naprawa nie zachowuje wykrytych ustawień istniejącej instalacji.");
        repairWizard.ShowPage(WizardPage.Summary);
        if (!repairWizard.intro.Text.Contains("Naprawa lub aktualizacja odtworzy pliki", StringComparison.Ordinal)
            || repairWizard.next.Text != "Zastosuj"
            || !repairWizard.summary.Text.Contains("Uruchom po naprawie / aktualizacji", StringComparison.Ordinal))
            throw new InvalidDataException("Podsumowanie trybu naprawy jest niejednoznaczne.");

        using var failedRepairWizard = new SetupWizard(repairModeOverride: true,
            repairOptionsErrorOverride: new IOException("controlled settings read failure"));
        if (failedRepairWizard.page != WizardPage.Error || failedRepairWizard.next.Text != "Zakończ"
            || failedRepairWizard.back.Visible || !failedRepairWizard.errorDetails.Text.Contains("Nie rozpoczęto żadnych zmian", StringComparison.Ordinal))
            throw new InvalidDataException("Błąd odczytu ustawień naprawy nie blokuje bezpiecznie dalszych zmian.");
        ValidateSpacePreflightRunsOffUiThread();
    }

    internal static void ValidateSpacePreflightRunsOffUiThread()
    {
        using var workStarted = new ManualResetEventSlim();
        using var allowWorkToFinish = new ManualResetEventSlim();
        using var wizard = new SetupWizard(repairModeOverride: false, spaceSummaryProviderOverride: _ =>
        {
            workStarted.Set();
            if (!allowWorkToFinish.Wait(TimeSpan.FromSeconds(4)))
                throw new TimeoutException("The UI thread did not release the controlled disk-space check.");
            return "Kontrola testowa zakończona.";
        });
        wizard.ShowInTaskbar = false;
        wizard.StartPosition = FormStartPosition.Manual;
        wizard.Location = new Point(-32_000, -32_000);
        wizard.Opacity = 0;
        wizard.Show();
        Application.DoEvents();
        wizard.page = WizardPage.Location;
        try
        {
            var refresh = wizard.MoveNextAsync();
            if (!workStarted.Wait(TimeSpan.FromSeconds(2)))
                throw new InvalidDataException("Background disk-space check did not start.");
            if (refresh.IsCompleted)
                throw new InvalidDataException("Location navigation blocked the UI thread during disk-space preflight.");
            if (wizard.next.Enabled)
                throw new InvalidDataException("Next remained enabled while location preflight was in progress.");
            allowWorkToFinish.Set();
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
            while (!refresh.IsCompleted && DateTime.UtcNow < deadline)
            {
                Application.DoEvents();
                Thread.Sleep(5);
            }
            if (!refresh.IsCompleted)
                throw new TimeoutException("Location navigation did not resume after background disk-space preflight.");
            refresh.GetAwaiter().GetResult();
            if (wizard.page != WizardPage.Options || wizard.spaceInfo.Text != "Kontrola testowa zakończona.")
                throw new InvalidDataException("The background disk-space result was not applied to the wizard.");
        }
        finally { allowWorkToFinish.Set(); }
    }
}

