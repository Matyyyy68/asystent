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
    private static readonly string DefaultDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", Product);
    private static string PayloadHash => Assembly.GetExecutingAssembly().GetCustomAttributes<AssemblyMetadataAttribute>()
        .FirstOrDefault(x => x.Key == "SentinelPayloadSha256")?.Value ?? "";

    [STAThread]
    private static int Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        if (args.Contains("--self-test", StringComparer.OrdinalIgnoreCase)) return VerifyPayload(showErrors: false) ? 0 : 1;
        if (args.Contains("--uninstall", StringComparer.OrdinalIgnoreCase))
        {
            if (MessageBox.Show($"Czy na pewno odinstalować Sentinel AI?\n\nTwoje lokalne dane i historia pozostaną na tym komputerze.", Product, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return 0;
            try { Uninstall(Path.GetDirectoryName(Environment.ProcessPath!)!); return 0; }
            catch (Exception ex) { MessageBox.Show($"Nie udało się odinstalować Sentinel AI.\n\n{ex.Message}", Product, MessageBoxButtons.OK, MessageBoxIcon.Error); return 1; }
        }
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
            if (!archive.Entries.Any(e => e.FullName.Equals("Sentinel AI.exe", StringComparison.OrdinalIgnoreCase))
                || !archive.Entries.Any(e => e.FullName.Equals("resources/engine/Sentinel.Engine.exe", StringComparison.OrdinalIgnoreCase)))
                throw new InvalidDataException("Pakiet jest niekompletny.");
            return true;
        }
        catch (Exception ex)
        {
            if (showErrors) MessageBox.Show($"Nie można zweryfikować instalatora. Pobierz go ponownie ze strony Sentinel AI.\n\n{ex.Message}", Product, MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
    }

    internal static void Install(string target, bool desktopShortcut, bool autoStart, Action<string, int> progress)
    {
        if (!VerifyPayload(showErrors: true)) throw new InvalidDataException("Weryfikacja instalatora nie powiodła się.");
        target = Path.GetFullPath(target);
        var local = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        if (!target.StartsWith(local + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Wybierz folder w swoim profilu użytkownika. Instalacja nie wymaga uprawnień administratora.");

        var parent = Path.GetDirectoryName(target) ?? throw new InvalidOperationException("Nieprawidłowy folder instalacji.");
        Directory.CreateDirectory(parent);
        var staging = Path.Combine(parent, ".sentinel-install-" + Guid.NewGuid().ToString("N"));
        var backup = Path.Combine(parent, ".sentinel-backup-" + Guid.NewGuid().ToString("N"));
        var oldMoved = false;
        try
        {
            Directory.CreateDirectory(staging);
            progress("Przygotowuję pliki programu…", 10);
            using (var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip")!)
            using (var archive = new ZipArchive(resource, ZipArchiveMode.Read))
            {
                int count = 0;
                foreach (var entry in archive.Entries)
                {
                    var destination = Path.GetFullPath(Path.Combine(staging, entry.FullName.Replace('/', Path.DirectorySeparatorChar)));
                    if (!destination.StartsWith(staging + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("Pakiet zawiera nieprawidłową ścieżkę.");
                    if (string.IsNullOrEmpty(entry.Name)) { Directory.CreateDirectory(destination); continue; }
                    Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                    entry.ExtractToFile(destination, overwrite: true);
                    count++;
                    if (count % 25 == 0) progress("Rozpakowuję Sentinel AI…", Math.Min(75, 10 + (int)(count * 65.0 / Math.Max(1, archive.Entries.Count))));
                }
            }
            progress("Sprawdzam pliki programu…", 80);
            if (!File.Exists(Path.Combine(staging, "Sentinel AI.exe")) || !File.Exists(Path.Combine(staging, "resources", "engine", "Sentinel.Engine.exe")))
                throw new InvalidDataException("Brakuje wymaganych plików aplikacji.");
            File.Copy(Environment.ProcessPath!, Path.Combine(staging, "Uninstall Sentinel AI.exe"), overwrite: true);

            if (Directory.Exists(target)) { Directory.Move(target, backup); oldMoved = true; }
            Directory.Move(staging, target);
            try
            {
                progress("Kończę konfigurację…", 90);
                var executable = Path.Combine(target, "Sentinel AI.exe");
                SetUninstallRegistration(target);
                using var run = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
                if (autoStart) run.SetValue("Sentinel AI", $"\"{executable}\" --minimized"); else run.DeleteValue("Sentinel AI", false);
                CreateShortcut(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "Sentinel AI.lnk"), executable);
                if (desktopShortcut) CreateShortcut(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Sentinel AI.lnk"), executable);
                try { Process.Start(new ProcessStartInfo(Path.Combine(target, "resources", "engine", "Sentinel.UrlHost.exe"), "--register") { UseShellExecute = false, CreateNoWindow = true })?.WaitForExit(8000); } catch { }
                progress("Gotowe.", 100);
            }
            catch
            {
                TryDelete(target);
                if (oldMoved && Directory.Exists(backup)) Directory.Move(backup, target);
                throw;
            }
            if (oldMoved) TryDelete(backup);
        }
        finally { TryDelete(staging); if (Directory.Exists(backup) && Directory.Exists(target)) TryDelete(backup); }
    }

    private static void SetUninstallRegistration(string target)
    {
        using var key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI");
        key.SetValue("DisplayName", Product); key.SetValue("DisplayVersion", "0.15.0");
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

    private static void Uninstall(string target)
    {
        target = Path.GetFullPath(target);
        if (!target.StartsWith(Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Odmowa usunięcia folderu poza profilem użytkownika.");
        try { Process.Start(new ProcessStartInfo(Path.Combine(target, "resources", "engine", "Sentinel.UrlHost.exe"), "--unregister") { UseShellExecute = false, CreateNoWindow = true })?.WaitForExit(5000); } catch { }
        using (var run = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")) run.DeleteValue("Sentinel AI", false);
        Registry.CurrentUser.DeleteSubKeyTree(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI", false);
        TryDelete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "Sentinel AI.lnk"));
        TryDelete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Sentinel AI.lnk"));
        var script = "$p=" + PowerShellQuote(target) + "; for($i=0;$i -lt 30 -and (Test-Path -LiteralPath $p);$i++){try{Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction Stop;break}catch{Start-Sleep -Milliseconds 500}}";
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var cleanup = new ProcessStartInfo("powershell.exe") { UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden };
        cleanup.ArgumentList.Add("-NoProfile"); cleanup.ArgumentList.Add("-EncodedCommand"); cleanup.ArgumentList.Add(encoded);
        Process.Start(cleanup);
    }

    private static string PowerShellQuote(string value) => "'" + value.Replace("'", "''") + "'";
    private static void TryDelete(string path) { try { if (Directory.Exists(path)) Directory.Delete(path, true); else if (File.Exists(path)) File.Delete(path); } catch { } }
}

internal sealed class SetupWizard : Form
{
    private readonly TextBox folder = new() { Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Sentinel AI") };
    private readonly CheckBox desktop = new() { Text = "Utwórz skrót na pulpicie", Checked = true, AutoSize = true };
    private readonly CheckBox start = new() { Text = "Uruchamiaj przy logowaniu do Windows", Checked = true, AutoSize = true };
    private readonly Label status = new() { AutoSize = true, Text = "Gotowy do instalacji" };
    private readonly ProgressBar progress = new() { Minimum = 0, Maximum = 100, Height = 12, Dock = DockStyle.Fill };
    private readonly Button install = new() { Text = "Zainstaluj", Width = 118, Height = 38 };

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
        var cancel = new Button { Text = "Anuluj", Location = new Point(383, 381), Size = new Size(92, 38), DialogResult = DialogResult.Cancel };
        Controls.AddRange([heading, intro, pathLabel, folder, browse, desktop, start, status, progress, cancel, install]); AcceptButton = install; CancelButton = cancel;
        browse.Click += (_, _) => { using var dialog = new FolderBrowserDialog { SelectedPath = folder.Text, Description = "Wybierz folder instalacji Sentinel AI" }; if (dialog.ShowDialog(this) == DialogResult.OK) folder.Text = Path.Combine(dialog.SelectedPath, "Sentinel AI"); };
        install.Click += async (_, _) => await InstallAsync();
    }

    private async Task InstallAsync()
    {
        install.Enabled = false;
        try
        {
            await Task.Run(() => Program.Install(folder.Text, desktop.Checked, start.Checked, (message, value) => BeginInvoke(() => { status.Text = message; progress.Value = value; })));
            if (MessageBox.Show(this, "Sentinel AI został zainstalowany. Czy uruchomić program teraz?", "Gotowe", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
                Process.Start(new ProcessStartInfo(Path.Combine(folder.Text, "Sentinel AI.exe")) { UseShellExecute = true });
            DialogResult = DialogResult.OK; Close();
        }
        catch (Exception ex) { install.Enabled = true; status.Text = "Instalacja nie została zakończona."; MessageBox.Show(this, "Nie udało się zainstalować Sentinel AI.\n\n" + ex.Message, "Błąd instalacji", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }
}
