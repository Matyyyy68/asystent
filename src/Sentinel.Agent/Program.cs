using System.Diagnostics;
using System.IO.Pipes;
using System.Media;
using System.Text;
using System.Text.Json;
using Sentinel.Core;
using Sentinel.Core.Analysis;

namespace Sentinel.Agent;

internal static class Program
{
    private static string PipeName => "SentinelAI.Engine.v1." + ResolveSessionSuffix(Environment.GetEnvironmentVariable("SESSIONNAME"));
    private static Mutex? singleInstance;
    private const int AgentShutdownExitCode = 42;
    private const int AgentAlreadyRunningExitCode = 43;

    [STAThread]
    private static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows()) return 2;
        if (args.Contains("--shutdown", StringComparer.OrdinalIgnoreCase)) return await RequestShutdownAsync();
        if (!args.Contains("--agent-process", StringComparer.OrdinalIgnoreCase)) return await RunWatchdogAsync();
        singleInstance = new Mutex(initiallyOwned: true, "Local\\SentinelAI.CoreAgent.v1", out var created);
        if (!created) return AgentAlreadyRunningExitCode;
        ApplicationConfiguration.Initialize();
        using var agent = new AgentContext();
        Application.Run(agent);
        GC.KeepAlive(singleInstance);
        return Environment.ExitCode;
    }

    private static async Task<int> RunWatchdogAsync()
    {
        using var watchdogLock = new Semaphore(1, 1, "Local\\SentinelAI.CoreWatchdog.v1");
        if (!watchdogLock.WaitOne(0)) return 0;
        var restartDelaySeconds = 1;
        while (true)
        {
            var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Nie można ustalić ścieżki Sentinel.Agent.exe.");
            using var agent = Process.Start(new ProcessStartInfo(executable)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                ArgumentList = { "--agent-process" }
            }) ?? throw new IOException("Nie można uruchomić procesu Sentinel Core.");
            await agent.WaitForExitAsync();
            if (agent.ExitCode == AgentShutdownExitCode || agent.ExitCode == AgentAlreadyRunningExitCode) return 0;
            await Task.Delay(TimeSpan.FromSeconds(restartDelaySeconds));
            restartDelaySeconds = Math.Min(restartDelaySeconds * 2, 30);
        }
    }

    private static async Task<int> RequestShutdownAsync()
    {
        try
        {
            await using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(3000);
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };
            using var reader = new StreamReader(pipe, new UTF8Encoding(false), false, 4096, leaveOpen: true);
            await writer.WriteLineAsync("{\"id\":\"core-shutdown\",\"version\":1,\"method\":\"agentShutdown\"}");
            var response = await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5));
            return response?.Contains("\"ok\":true", StringComparison.Ordinal) == true ? 0 : 1;
        }
        catch (TimeoutException) { return 1; }
        catch (IOException) { return 0; }
        catch { return 1; }
    }

    private static string ResolveSessionSuffix(string? sessionName)
    {
        var suffix = new string((sessionName ?? string.Empty).Take(40)
            .Select(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '.' or '-' ? character : '_').ToArray());
        return suffix.Length == 0 ? "Default" : suffix;
    }

    private sealed class AgentContext : ApplicationContext
    {
        private readonly EngineProxy engine;
        private readonly NotifyIcon tray;
        private readonly CancellationTokenSource shutdown = new();
        private readonly Control dispatcher = new();
        private readonly Task server;
        private readonly System.Windows.Forms.Timer collector = new() { Interval = 1000 };
        private readonly NotificationDeduplicator notificationDeduplicator = new(TimeSpan.FromMinutes(10), capacity: 8);
        private readonly Icon normalIcon;
        private DateTimeOffset alertUntil;
        private DateTimeOffset lastWindowsSecurityCheckAtUtc;
        private bool collecting;

        public AgentContext()
        {
            var appRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", ".."));
            engine = new EngineProxy(Path.Combine(AppContext.BaseDirectory, "Sentinel.Engine.exe"));
            _ = dispatcher.Handle;
            var menu = new ContextMenuStrip();
            menu.Items.Add("Otwórz Sentinel AI", null, (_, _) => OpenUi(appRoot));
            menu.Items.Add("Stan ochrony", null, async (_, _) => await ShowStatusAsync());
            menu.Items.Add("Zamknij interfejs (ochrona działa dalej)", null, (_, _) => CloseUi(appRoot));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Sentinel działa w tle", null, (_, _) => { });
            normalIcon = TryLoadIcon(Path.Combine(appRoot, "Sentinel AI.exe"));
            tray = new NotifyIcon
            {
                Text = "Sentinel AI — uruchamianie ochrony",
                Icon = normalIcon,
                ContextMenuStrip = menu,
                Visible = true
            };
            tray.DoubleClick += (_, _) => OpenUi(appRoot);
            collector.Tick += async (_, _) => await CollectAsync();
            collector.Start();
            server = Task.Run(() => ServeClientsAsync(shutdown.Token));
        }

        private static Icon TryLoadIcon(string appPath)
        {
            try { return Icon.ExtractAssociatedIcon(appPath) ?? SystemIcons.Shield; }
            catch { return SystemIcons.Shield; }
        }

        private static void OpenUi(string appRoot)
        {
            var appPath = Path.Combine(appRoot, "Sentinel AI.exe");
            try { Process.Start(new ProcessStartInfo(appPath) { UseShellExecute = true }); }
            catch (Exception exception) { MessageBox.Show($"Nie można otworzyć Sentinel AI ({exception.GetType().Name}).", "Sentinel AI", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        }

        private static void CloseUi(string appRoot)
        {
            var appPath = Path.Combine(appRoot, "Sentinel AI.exe");
            try { Process.Start(new ProcessStartInfo(appPath) { UseShellExecute = true, Arguments = "--quit-ui" }); }
            catch (Exception exception) { MessageBox.Show($"Nie można zamknąć interfejsu ({exception.GetType().Name}).", "Sentinel AI", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        }

        private async Task CollectAsync()
        {
            if (collecting || shutdown.IsCancellationRequested) return;
            collecting = true;
            try
            {
                using var response = await engine.SendAsync(JsonSerializer.Serialize(new { id = "core-collect", version = 1, method = "collect" }), shutdown.Token);
                if (!response.RootElement.TryGetProperty("ok", out var ok) || !ok.GetBoolean())
                {
                    tray.Text = "Sentinel AI — silnik wymaga uwagi";
                    tray.Icon = SystemIcons.Warning;
                    alertUntil = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(10);
                    return;
                }
                var result = response.RootElement.GetProperty("result");
                tray.Text = "Sentinel AI — silnik działa w tle";
                var notifications = result.TryGetProperty("notifications", out var enabled) && enabled.GetBoolean();
                var detections = result.TryGetProperty("detections", out var count) && count.TryGetInt32(out var total) ? total : 0;
                if (notifications && detections > 0)
                    NotifyOnce("dns-reputation", "Sentinel AI — ostrzeżenie", "W cache DNS wykryto adres z lokalnie sprawdzanej listy reputacji. Ruch nie został zablokowany.", ToolTipIcon.Warning, SystemSounds.Exclamation);
                var fileMatches = result.TryGetProperty("downloadedFileMatches", out var fileCount) && fileCount.TryGetInt32(out var matched) ? matched : 0;
                if (notifications && fileMatches > 0)
                    NotifyOnce("file-reputation", "Sentinel AI — sprawdź plik", "SHA-256 nowego pliku dopasował się do lokalnej listy. Źródło listy nie jest niezależnie zweryfikowane.", ToolTipIcon.Warning, SystemSounds.Exclamation);
                var ipMatches = result.TryGetProperty("tcpIpReputationMatches", out var ipCount) && ipCount.TryGetInt32(out var matchedIps) ? matchedIps : 0;
                if (notifications && ipMatches > 0)
                    NotifyOnce("tcp-ip-reputation", "Sentinel AI — sprawdź połączenie",
                        "Nowe połączenie TCP pasuje do lokalnej listy adresów IP. Źródło listy nie jest niezależnie zweryfikowane; Sentinel nie zablokował ruchu.",
                        ToolTipIcon.Warning, SystemSounds.Exclamation);
                var processImageMatches = result.TryGetProperty("processImageReputationMatches", out var processImageCount) && processImageCount.TryGetInt32(out var matchedImages) ? matchedImages : 0;
                if (notifications && processImageMatches > 0)
                    NotifyOnce("running-process-image-reputation", "Sentinel AI — sprawdź uruchomiony plik",
                        "SHA-256 obrazu uruchomionego procesu dopasował się do lokalnej listy. Źródło listy nie jest niezależnie zweryfikowane; Sentinel nie zatrzymał procesu.",
                        ToolTipIcon.Warning, SystemSounds.Exclamation);
                var persistenceMatches = result.TryGetProperty("persistenceSuspiciousChanges", out var persistenceCount) && persistenceCount.TryGetInt32(out var matchedPersistence) ? matchedPersistence : 0;
                if (notifications && persistenceMatches > 0)
                    NotifyOnce("persistence-writable-location", "Sentinel AI — sprawdź autostart Windows",
                        "Wykryto zmianę autostartu lub trwałości w lokalizacji zapisywalnej przez użytkownika. To sygnał do sprawdzenia, nie werdykt malware; Sentinel niczego nie zmienił.",
                        ToolTipIcon.Warning, SystemSounds.Exclamation);
                if (notifications && DateTimeOffset.UtcNow - lastWindowsSecurityCheckAtUtc >= TimeSpan.FromMinutes(1))
                    await CheckWindowsSecurityCenterAsync();
                if (detections == 0 && fileMatches == 0 && DateTimeOffset.UtcNow >= alertUntil) tray.Icon = normalIcon;
            }
            catch
            {
                tray.Text = "Sentinel AI — ponawianie połączenia z silnikiem";
                tray.Icon = SystemIcons.Warning;
                alertUntil = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(10);
            }
            finally { collecting = false; }
        }

        private async Task CheckWindowsSecurityCenterAsync()
        {
            lastWindowsSecurityCheckAtUtc = DateTimeOffset.UtcNow;
            try
            {
                using var response = await engine.SendAsync(JsonSerializer.Serialize(new { id = "core-security-center", version = 1, method = "status" }), shutdown.Token);
                if (!response.RootElement.TryGetProperty("ok", out var ok) || !ok.GetBoolean()) return;
                var result = response.RootElement.GetProperty("result");
                if (!result.TryGetProperty("windowsSecurityCenter", out var center)) return;
                foreach (var provider in new[] { (Name: "antywirus", Property: "antivirus"), (Name: "zapora", Property: "firewall") })
                {
                    if (!center.TryGetProperty(provider.Property, out var health) || health.ValueKind != JsonValueKind.String) continue;
                    var message = health.GetString();
                    if (SecurityCenterAlertPolicy.RequiresAttention(message))
                        NotifyOnce("windows-security-center-" + provider.Property, "Sentinel AI — stan zabezpieczeń Windows",
                            $"Windows Security Center: {provider.Name} — {message}. Sentinel AI tylko odczytuje ten stan i niczego nie zmienia.",
                            ToolTipIcon.Warning, SystemSounds.Exclamation);
                }
            }
            catch { /* Security Center is informative; failure must not interrupt local collection. */ }
        }

        private void NotifyOnce(string key, string title, string message, ToolTipIcon icon, SystemSound sound)
        {
            if (!notificationDeduplicator.TryMark(key, DateTimeOffset.UtcNow)) return;
            alertUntil = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(10);
            tray.Icon = SystemIcons.Warning;
            tray.ShowBalloonTip(6000, title, message, icon);
            try { sound.Play(); } catch { /* Windows may have system sounds disabled. */ }
        }

        private async Task ShowStatusAsync()
        {
            try
            {
                using var response = await engine.SendAsync(JsonSerializer.Serialize(new { id = "core-status", version = 1, method = "status" }), shutdown.Token);
                var root = response.RootElement;
                if (!root.TryGetProperty("ok", out var ok) || !ok.GetBoolean()) throw new IOException("Silnik nie odpowiedział.");
                var result = root.GetProperty("result");
                var settings = result.GetProperty("settings");
                var paused = settings.TryGetProperty("paused", out var pauseValue) && pauseValue.GetBoolean();
                MessageBox.Show(paused
                    ? "Silnik Sentinel AI działa. Monitorowanie DNS jest wstrzymane; inne źródła mają osobne ustawienia."
                    : "Silnik Sentinel AI działa i wykonuje lokalne cykle monitorowania. Nie blokuje ruchu ani nie zastępuje Microsoft Defender.",
                    "Stan Sentinel AI", MessageBoxButtons.OK, paused ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
            }
            catch (Exception exception)
            {
                MessageBox.Show($"Nie można potwierdzić stanu ochrony ({exception.GetType().Name}).", "Stan Sentinel AI", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private async Task ServeClientsAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await using var pipe = new NamedPipeServerStream(PipeName, PipeDirection.InOut, 1,
                        PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, 24_576, 24_576);
                    await pipe.WaitForConnectionAsync(cancellationToken);
                    using var reader = new StreamReader(pipe, new UTF8Encoding(false), false, 4096, leaveOpen: true);
                    await using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };
                    var request = await reader.ReadLineAsync(cancellationToken);
                    if (request is null || request.Length > 24_000) continue;
                    using (var parsed = JsonDocument.Parse(request))
                    {
                        if (parsed.RootElement.TryGetProperty("method", out var method) && method.GetString() == "agentShutdown")
                        {
                            await writer.WriteLineAsync("{\"id\":\"core-shutdown\",\"ok\":true,\"result\":{\"stopping\":true}}");
                            dispatcher.BeginInvoke((Action)(() =>
                            {
                                Environment.ExitCode = AgentShutdownExitCode;
                                shutdown.Cancel();
                                collector.Stop();
                                tray.Visible = false;
                                ExitThread();
                            }));
                            continue;
                        }
                    }
                    var response = await engine.SendAsync(request, cancellationToken);
                    await writer.WriteLineAsync(response.RootElement.GetRawText());
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
                catch { await Task.Delay(500, cancellationToken).ContinueWith(_ => { }, TaskScheduler.Default); }
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                shutdown.Cancel();
                collector.Stop();
                tray.Visible = false;
                tray.Dispose();
                dispatcher.Dispose();
                engine.Dispose();
                shutdown.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    private sealed class EngineProxy : IDisposable
    {
        private readonly string executable;
        private readonly SemaphoreSlim gate = new(1, 1);
        private Process? process;
        private StreamWriter? input;
        private StreamReader? output;

        public EngineProxy(string executable) => this.executable = executable;

        public async Task<JsonDocument> SendAsync(string request, CancellationToken cancellationToken)
        {
            if (request.Length > 24_000) throw new InvalidDataException("Żądanie przekracza limit.");
            await gate.WaitAsync(cancellationToken);
            try
            {
                EnsureStarted();
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(50));
                await input!.WriteLineAsync(request.AsMemory(), timeout.Token);
                await input.FlushAsync(timeout.Token);
                var line = await output!.ReadLineAsync(timeout.Token) ?? throw new EndOfStreamException("Silnik zakończył działanie.");
                if (line.Length > 1_000_000) throw new InvalidDataException("Odpowiedź silnika przekracza limit.");
                return JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 16 });
            }
            catch
            {
                StopEngine();
                throw;
            }
            finally { gate.Release(); }
        }

        private void EnsureStarted()
        {
            if (process is { HasExited: false }) return;
            StopEngine();
            var start = new ProcessStartInfo(executable)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(executable)!
            };
            process = Process.Start(start) ?? throw new IOException("Nie można uruchomić lokalnego silnika.");
            input = process.StandardInput;
            output = process.StandardOutput;
            process.ErrorDataReceived += (_, _) => { };
            process.BeginErrorReadLine();
        }

        private void StopEngine()
        {
            try { if (process is { HasExited: false }) process.Kill(entireProcessTree: true); } catch { }
            process?.Dispose();
            process = null;
            input = null;
            output = null;
        }

        public void Dispose()
        {
            try { input?.Close(); } catch { }
            try { if (process is { HasExited: false }) process.WaitForExit(5000); } catch { }
            StopEngine();
            gate.Dispose();
        }
    }
}
