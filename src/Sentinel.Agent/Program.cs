using System.Diagnostics;
using System.Globalization;
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
    private static readonly object AgentLogGate = new();

    private static void AgentLog(string message)
    {
        try
        {
            var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sentinel AI", "Logs");
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, "agent.log");
            lock (AgentLogGate)
            {
                if (File.Exists(path) && new FileInfo(path).Length > 256 * 1024) File.WriteAllText(path, string.Empty);
                File.AppendAllText(path, $"{DateTimeOffset.UtcNow:O} pid={Environment.ProcessId} {message}{Environment.NewLine}", Encoding.UTF8);
            }
        }
        catch { /* Diagnostics must never prevent protection startup or shutdown. */ }
    }

    [STAThread]
    private static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows()) return 2;
        if (args.Contains("--self-test-service-events", StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                _ = await SystemServiceEventsClient.ReadRecentAsync(0, CancellationToken.None);
                _ = await SystemServiceEventsClient.ReadLatestAsync(CancellationToken.None);
                return 0;
            }
            catch (Exception exception)
            {
                var message = exception.Message.Replace('\r', ' ').Replace('\n', ' ');
                Console.Error.WriteLine($"SELF_TEST_FAILED service-event-read type={exception.GetType().Name} hresult=0x{exception.HResult:X8} message={message[..Math.Min(message.Length, 300)]}");
                return 1;
            }
        }
        if (args.Contains("--self-test-service-event-forwarding", StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var sourceRowId = DateTimeOffset.UtcNow.Ticks;
                var item = new ForwardedSecurityEvent(sourceRowId, DateTimeOffset.UtcNow, RiskLevel.Moderate,
                    "Agent forwarding self-test", "Sentinel.Agent", "Synthetic pipe integration event", "No action required",
                    EventStatus.New, Guid.NewGuid(), "agent-forwarding-self-test", "self-test-v1", null, 1,
                    null, null, null, ["test.agent-service-forwarding"], []);
                var acknowledged = await SystemServiceEventsClient.ForwardEventsAsync([item], CancellationToken.None);
                return acknowledged.SequenceEqual([sourceRowId]) ? 0 : 1;
            }
            catch (Exception exception)
            {
                var message = exception.Message.Replace('\r', ' ').Replace('\n', ' ');
                Console.Error.WriteLine($"SELF_TEST_FAILED service-event-forwarding type={exception.GetType().Name} hresult=0x{exception.HResult:X8} message={message[..Math.Min(message.Length, 300)]}");
                return 1;
            }
        }
        if (args.Contains("--shutdown", StringComparer.OrdinalIgnoreCase)) return await RequestShutdownAsync();
        if (!args.Contains("--agent-process", StringComparer.OrdinalIgnoreCase)) return await RunWatchdogAsync();
        AgentLog("AGENT_PROCESS_START");
        singleInstance = new Mutex(initiallyOwned: true, "Local\\SentinelAI.CoreAgent.v1", out var created);
        if (!created) { AgentLog("AGENT_DUPLICATE_INSTANCE"); return AgentAlreadyRunningExitCode; }
        ApplicationConfiguration.Initialize();
        using var agent = new AgentContext();
        Application.Run(agent);
        AgentLog($"AGENT_MESSAGE_LOOP_EXIT exitCode={Environment.ExitCode}");
        GC.KeepAlive(singleInstance);
        return Environment.ExitCode;
    }

    private static async Task<int> RunWatchdogAsync()
    {
        AgentLog("WATCHDOG_START");
        using var watchdogLock = new Semaphore(1, 1, "Local\\SentinelAI.CoreWatchdog.v1");
        if (!watchdogLock.WaitOne(0)) { AgentLog("WATCHDOG_DUPLICATE_INSTANCE"); return 0; }
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
            AgentLog($"WATCHDOG_CHILD_START pid={agent.Id}");
            await agent.WaitForExitAsync();
            AgentLog($"WATCHDOG_CHILD_EXIT pid={agent.Id} exitCode={agent.ExitCode}");
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

    private static class NotificationSoundPlayer
    {
        private static readonly SoundPlayer?[] Players = CreatePlayers();

        private static SoundPlayer?[] CreatePlayers()
        {
            var players = new SoundPlayer?[Enum.GetValues<NotificationToneKind>().Length];
            foreach (var kind in Enum.GetValues<NotificationToneKind>())
            {
                try
                {
                    var player = new SoundPlayer(new MemoryStream(NotificationTone.CreateWave(kind), writable: false));
                    player.Load();
                    players[(int)kind] = player;
                }
                catch { /* Malformed or unavailable audio support must not prevent agent startup. */ }
            }
            return players;
        }

        public static void Play(NotificationToneKind kind)
        {
            try { Players[(int)kind]?.Play(); }
            catch { /* Audio output may be unavailable or disabled; never stop protection. */ }
        }
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
        private readonly System.Windows.Forms.Timer serviceEventCollector = new() { Interval = 30_000 };
        private readonly NotificationDeduplicator notificationDeduplicator = new(TimeSpan.FromMinutes(10), capacity: 8);
        private readonly NotificationDeduplicator serviceEventNotificationDeduplicator = new(TimeSpan.FromDays(7), capacity: 512);
        private readonly ServiceEventPollingGate serviceEventPollingGate = new();
        private readonly ServiceEventNotificationPreferences serviceEventNotificationPreferences = new(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sentinel AI", "State", "service-event-notifications.enabled"));
        private readonly ServiceEventNotificationCursor serviceEventNotificationCursor = new(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sentinel AI", "State", "service-event-notification.cursor"));
        private readonly ServiceEventTransferCursor serviceEventTransferCursor = new(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sentinel AI", "State", "service-event-transfer.cursor"));
        private readonly InitialAnalysisCompletionMarker initialAnalysisCompletion = new(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sentinel AI", "State", "first-analysis-completed.v1"));
        private readonly List<(string Key, string Title, string Message, ToolTipIcon Icon, NotificationToneKind Tone)> pendingNotifications = [];
        private readonly Icon normalIcon;
        private DateTimeOffset alertUntil;
        private DateTimeOffset lastWindowsSecurityCheckAtUtc;
        private bool notificationsEnabled;
        private bool serviceEventNotificationPreferenceKnown;
        private bool collecting;
        private bool disposed;

        public AgentContext()
        {
            var appRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", ".."));
            engine = new EngineProxy(Path.Combine(AppContext.BaseDirectory, "Sentinel.Engine.exe"));
            var savedNotificationPreference = serviceEventNotificationPreferences.Read();
            notificationsEnabled = savedNotificationPreference ?? false;
            serviceEventNotificationPreferenceKnown = savedNotificationPreference.HasValue;
            _ = dispatcher.Handle;
            var menu = new ContextMenuStrip();
            menu.Items.Add("Otwórz Sentinel AI", null, (_, _) => OpenUi(appRoot));
            menu.Items.Add("Stan ochrony", null, async (_, _) => await ShowStatusAsync());
            menu.Items.Add("Ostatnie alerty", null, (_, _) => OpenUi(appRoot, "--alerts"));
            menu.Items.Add("Sprawdź aktualizacje", null, async (_, _) => await CheckForUpdatesAsync());
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
            tray.BalloonTipClicked += (_, _) => OpenUi(appRoot);
            collector.Tick += async (_, _) => await CollectAsync();
            serviceEventCollector.Tick += async (_, _) => await CheckSystemServiceEventsAsync();
            collector.Start();
            serviceEventCollector.Start();
            server = Task.Run(() => ServeClientsAsync(shutdown.Token));
            AgentLog("AGENT_CONTEXT_READY");
        }

        private static Icon TryLoadIcon(string appPath)
        {
            try { return Icon.ExtractAssociatedIcon(appPath) ?? SystemIcons.Shield; }
            catch { return SystemIcons.Shield; }
        }

        private static void OpenUi(string appRoot, string? argument = null)
        {
            var appPath = Path.Combine(appRoot, "Sentinel AI.exe");
            try
            {
                var startInfo = new ProcessStartInfo(appPath) { UseShellExecute = true };
                if (argument is not null) startInfo.ArgumentList.Add(argument);
                Process.Start(startInfo);
            }
            catch (Exception exception) { MessageBox.Show($"Nie można otworzyć Sentinel AI ({exception.GetType().Name}).", "Sentinel AI", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        }

        private static void CloseUi(string appRoot)
        {
            var appPath = Path.Combine(appRoot, "Sentinel AI.exe");
            try { Process.Start(new ProcessStartInfo(appPath) { UseShellExecute = true, Arguments = "--quit-ui" }); }
            catch (Exception exception) { MessageBox.Show($"Nie można zamknąć interfejsu ({exception.GetType().Name}).", "Sentinel AI", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        }

        private async Task CheckForUpdatesAsync()
        {
            try
            {
                using var handler = new HttpClientHandler { AllowAutoRedirect = false };
                using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
                var version = typeof(Program).Assembly.GetName().Version
                    ?? throw new InvalidOperationException("Nie można ustalić wersji Sentinel AI.");
                var result = await GitHubReleaseUpdateChecker.CheckAsync(client, version, shutdown.Token);
                if (result.UpdateAvailable)
                {
                    var choice = MessageBox.Show(
                        $"Dostępna jest wersja {result.LatestVersion}; używasz {result.InstalledVersion}.\n\nOtworzyć oficjalną stronę wydania? Aktualizacja nie zostanie pobrana ani zainstalowana automatycznie.",
                        "Aktualizacja Sentinel AI", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
                    if (choice == DialogResult.Yes)
                        Process.Start(new ProcessStartInfo(result.ReleaseUrl) { UseShellExecute = true });
                }
                else
                {
                    MessageBox.Show($"Masz aktualną wersję Sentinel AI ({result.InstalledVersion}).", "Aktualizacja Sentinel AI", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            catch (Exception exception)
            {
                MessageBox.Show($"Nie udało się sprawdzić aktualizacji ({exception.GetType().Name}). Sprawdź połączenie i spróbuj ponownie.",
                    "Aktualizacja Sentinel AI", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private async Task CollectAsync()
        {
            if (collecting || shutdown.IsCancellationRequested) return;
            collecting = true;
            var playAnalysisCompleteTone = false;
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
                playAnalysisCompleteTone = initialAnalysisCompletion.TryMarkCompleted();
                var result = response.RootElement.GetProperty("result");
                tray.Text = "Sentinel AI — silnik działa w tle";
                var notifications = result.TryGetProperty("notifications", out var enabled) && enabled.GetBoolean();
                notificationsEnabled = notifications;
                serviceEventNotificationPreferenceKnown = true;
                _ = serviceEventNotificationPreferences.TryWrite(notifications);
                await CheckSystemServiceEventsAsync();
                var detections = result.TryGetProperty("detections", out var count) && count.TryGetInt32(out var total) ? total : 0;
                if (notifications && detections > 0)
                    NotifyOnce("dns-reputation", "Sentinel AI — ostrzeżenie", "W cache DNS wykryto adres z lokalnie sprawdzanej listy reputacji. Ruch nie został zablokowany.", ToolTipIcon.Warning);
                var fileMatches = result.TryGetProperty("downloadedFileMatches", out var fileCount) && fileCount.TryGetInt32(out var matched) ? matched : 0;
                if (notifications && fileMatches > 0)
                    NotifyOnce("file-reputation", "Sentinel AI — sprawdź plik", "SHA-256 nowego pliku dopasował się do lokalnej listy. Źródło listy nie jest niezależnie zweryfikowane.", ToolTipIcon.Warning, NotificationToneKind.Information);
                var ipMatches = result.TryGetProperty("tcpIpReputationMatches", out var ipCount) && ipCount.TryGetInt32(out var matchedIps) ? matchedIps : 0;
                if (notifications && ipMatches > 0)
                    NotifyOnce("tcp-ip-reputation", "Sentinel AI — sprawdź połączenie",
                        "Nowe połączenie TCP pasuje do lokalnej listy adresów IP. Źródło listy nie jest niezależnie zweryfikowane; Sentinel nie zablokował ruchu.",
                        ToolTipIcon.Warning, NotificationToneKind.Information);
                var processImageMatches = result.TryGetProperty("processImageReputationMatches", out var processImageCount) && processImageCount.TryGetInt32(out var matchedImages) ? matchedImages : 0;
                if (notifications && processImageMatches > 0)
                    NotifyOnce("running-process-image-reputation", "Sentinel AI — sprawdź uruchomiony plik",
                        "SHA-256 obrazu uruchomionego procesu dopasował się do lokalnej listy. Źródło listy nie jest niezależnie zweryfikowane; Sentinel nie zatrzymał procesu.",
                        ToolTipIcon.Warning, NotificationToneKind.Information);
                var suspiciousLaunches = result.TryGetProperty("suspiciousProcessLaunches", out var launchCount) && launchCount.TryGetInt32(out var matchedLaunches) ? matchedLaunches : 0;
                if (notifications && suspiciousLaunches > 0)
                    NotifyOnce("suspicious-parent-child-process", "Sentinel AI — sprawdź uruchomiony program",
                        "Aplikacja Office uruchomiła interpreter poleceń lub host skryptów. Może to być legalne; Sentinel nie zatrzymał procesu.",
                        ToolTipIcon.Warning);
                var persistenceMatches = result.TryGetProperty("persistenceSuspiciousChanges", out var persistenceCount) && persistenceCount.TryGetInt32(out var matchedPersistence) ? matchedPersistence : 0;
                if (notifications && persistenceMatches > 0)
                    NotifyOnce("persistence-writable-location", "Sentinel AI — sprawdź autostart Windows",
                        "Wykryto zmianę autostartu lub trwałości w lokalizacji zapisywalnej przez użytkownika. To sygnał do sprawdzenia, nie werdykt malware; Sentinel niczego nie zmienił.",
                        ToolTipIcon.Warning);
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
            finally
            {
                var hadNotifications = pendingNotifications.Count != 0;
                FlushNotifications();
                if (playAnalysisCompleteTone && !hadNotifications)
                    NotificationSoundPlayer.Play(NotificationToneKind.AnalysisComplete);
                collecting = false;
            }
        }

        private async Task CheckSystemServiceEventsAsync()
        {
            if (!serviceEventPollingGate.TryBegin(DateTimeOffset.UtcNow, serviceEventNotificationPreferenceKnown, shutdown.IsCancellationRequested)) return;
            try
            {
                await ForwardPendingAgentEventsAsync();
                var notifyForNewEvents = notificationsEnabled && serviceEventNotificationCursor.CanNotifyForNewEvents;
                var initializeNotificationCursor = notificationsEnabled && !notifyForNewEvents;
                var batch = notifyForNewEvents
                    ? await SystemServiceEventsClient.ReadRecentAsync(serviceEventNotificationCursor.LastEventId, shutdown.Token)
                    : await SystemServiceEventsClient.ReadLatestAsync(shutdown.Token);
                var historyReset = notifyForNewEvents && batch.LatestEventId < serviceEventNotificationCursor.LastEventId;
                if (historyReset)
                    _ = serviceEventNotificationCursor.TryResetToLatest(batch.LatestEventId);
                else if (notifyForNewEvents)
                {
                    foreach (var eventId in batch.Events.Where(item => item.Status == "New").Select(item => item.Id).Distinct())
                    {
                        if (!serviceEventNotificationDeduplicator.TryMark("service-event-" + eventId, DateTimeOffset.UtcNow)) continue;
                        NotifyOnce("service-event-" + eventId, "Sentinel AI — nowe zdarzenie",
                            "Usługa ochrony systemowej wykryła zdarzenie wymagające sprawdzenia. Otwórz Sentinel AI, aby zobaczyć szczegóły.",
                            ToolTipIcon.Warning);
                    }
                }
                if (!notificationsEnabled)
                    _ = serviceEventNotificationCursor.TryResetToLatest(batch.LatestEventId);
                else if (batch.Events.Count > 0 && !historyReset)
                    _ = serviceEventNotificationCursor.TryAdvance(batch.Events.Max(item => item.Id));
                else if (initializeNotificationCursor)
                    _ = serviceEventNotificationCursor.TryResetToLatest(batch.LatestEventId);
            }
            catch { /* Service event notifications are best-effort and never interrupt user-session collection. */ }
            finally { serviceEventPollingGate.Complete(); }
        }

        private async Task ForwardPendingAgentEventsAsync()
        {
            var cursor = serviceEventTransferCursor.Read();
            var cursorReset = false;
            for (var pageNumber = 0; pageNumber < 2; pageNumber++)
            {
                using var response = await engine.SendAsync(JsonSerializer.Serialize(new { id = "agent-history-forward", version = 1, method = "historyAfter", afterId = cursor }), shutdown.Token);
                if (!response.RootElement.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True ||
                    !response.RootElement.TryGetProperty("result", out var result) || result.ValueKind != JsonValueKind.Object ||
                    !result.TryGetProperty("latestEventRowId", out var latestElement) || !latestElement.TryGetInt64(out var latestEventRowId) || latestEventRowId < 0 ||
                    !result.TryGetProperty("events", out var events) || events.ValueKind != JsonValueKind.Array || events.GetArrayLength() > 4)
                    throw new InvalidDataException("User Engine returned an invalid forwarded history page.");
                if (!cursorReset && latestEventRowId < cursor)
                {
                    if (!serviceEventTransferCursor.TryReset(0)) throw new IOException("Could not reset the acknowledged cursor after the local history was reset.");
                    cursor = 0;
                    cursorReset = true;
                    pageNumber--;
                    continue;
                }
                var batch = new List<ForwardedSecurityEvent>(events.GetArrayLength());
                foreach (var item in events.EnumerateArray())
                {
                    var eventId = item.TryGetProperty("eventId", out var id) && id.ValueKind == JsonValueKind.String && id.TryGetGuid(out var parsedId) ? parsedId : Guid.Empty;
                    if (eventId == Guid.Empty || !item.TryGetProperty("id", out var rowId) || !rowId.TryGetInt64(out var sourceRowId))
                        throw new InvalidDataException("User Engine returned an event without stable identifiers.");
                    batch.Add(new ForwardedSecurityEvent(sourceRowId,
                        item.GetProperty("timestamp").GetDateTimeOffset(),
                        Enum.Parse<RiskLevel>(item.GetProperty("risk").GetString()!, ignoreCase: false),
                        item.GetProperty("category").GetString()!, item.GetProperty("application").GetString()!,
                        item.GetProperty("explanation").GetString()!, item.GetProperty("recommendation").GetString()!,
                        Enum.Parse<EventStatus>(item.GetProperty("status").GetString()!, ignoreCase: false), eventId,
                        item.TryGetProperty("source", out var source) && source.ValueKind == JsonValueKind.String ? source.GetString() : null,
                        item.TryGetProperty("ruleVersion", out var rule) && rule.ValueKind == JsonValueKind.String ? rule.GetString() : null,
                        item.TryGetProperty("confidence", out var confidence) && confidence.TryGetInt32(out var confidenceValue) ? confidenceValue : null,
                        item.TryGetProperty("schemaVersion", out var schema) && schema.TryGetInt32(out var schemaValue) ? schemaValue : 1,
                        item.TryGetProperty("processId", out var pid) && pid.TryGetInt32(out var processId) ? processId : null,
                        item.TryGetProperty("processName", out var process) && process.ValueKind == JsonValueKind.String ? process.GetString() : null,
                        item.TryGetProperty("correlationId", out var correlation) && correlation.ValueKind == JsonValueKind.String && correlation.TryGetGuid(out var correlationId) ? correlationId : null,
                        ReadStringArray(item, "evidenceCodes", 32), ReadStringArray(item, "analysisLimitations", 16)));
                }
                if (batch.Count == 0) return;
                var acknowledged = await SystemServiceEventsClient.ForwardEventsAsync(batch, shutdown.Token);
                if (acknowledged.Count != batch.Count || !serviceEventTransferCursor.TryAdvance(acknowledged.Max()))
                    throw new IOException("Could not persist the acknowledged system-service event cursor.");
                cursor = acknowledged.Max();
            }
        }

        private static IReadOnlyList<string> ReadStringArray(JsonElement item, string property, int maximum)
        {
            if (!item.TryGetProperty(property, out var values) || values.ValueKind != JsonValueKind.Array) return [];
            return values.EnumerateArray().Where(value => value.ValueKind == JsonValueKind.String).Take(maximum)
                .Select(value => value.GetString() ?? string.Empty).ToArray();
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
                            ToolTipIcon.Warning);
                }
            }
            catch { /* Security Center is informative; failure must not interrupt local collection. */ }
        }

        private void NotifyOnce(string key, string title, string message, ToolTipIcon icon,
            NotificationToneKind tone = NotificationToneKind.Warning)
        {
            if (!notificationDeduplicator.TryMark(key, DateTimeOffset.UtcNow)) return;
            alertUntil = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(10);
            tray.Icon = SystemIcons.Warning;
            pendingNotifications.Add((key, title, message, icon, tone));
        }

        private void FlushNotifications()
        {
            if (pendingNotifications.Count == 0) return;
            var notifications = pendingNotifications.ToArray();
            pendingNotifications.Clear();
            if (notifications.Length == 1)
            {
                var notification = notifications[0];
                try
                {
                    tray.ShowBalloonTip(6000, notification.Title, notification.Message, notification.Icon);
                    NotificationSoundPlayer.Play(notification.Tone);
                }
                catch { /* Notification UI or system audio can be unavailable without stopping collection. */ }
                return;
            }

            var categories = notifications.Select(notification => NotificationCategory(notification.Key)).ToArray();
            try
            {
                tray.ShowBalloonTip(6000, "Sentinel AI — kilka sygnałów", NotificationBatchSummary.Compose(categories), ToolTipIcon.Warning);
                NotificationSoundPlayer.Play(NotificationTonePolicy.Select(notifications.Select(notification => notification.Tone)));
            }
            catch { /* Notification UI or system audio can be unavailable without stopping collection. */ }
        }

        private static string NotificationCategory(string key) => key switch
        {
            "dns-reputation" => "domena z lokalnej listy reputacji",
            "file-reputation" => "nowy plik z dopasowanym hashem",
            "tcp-ip-reputation" => "połączenie TCP z dopasowanym adresem IP",
            "running-process-image-reputation" => "uruchomiony plik z dopasowanym hashem",
            "suspicious-parent-child-process" => "nietypowe uruchomienie procesu",
            "persistence-writable-location" => "zmiana autostartu Windows",
            "windows-security-center-antivirus" => "stan antywirusa Windows",
            "windows-security-center-firewall" => "stan zapory Windows",
            _ => "sygnał wymagający sprawdzenia"
        };

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
                            AgentLog("AGENT_SHUTDOWN_REQUEST_RECEIVED");
                            await writer.WriteLineAsync("{\"id\":\"core-shutdown\",\"ok\":true,\"result\":{\"stopping\":true}}");
                            AgentLog("AGENT_SHUTDOWN_ACK_SENT");
                            try { dispatcher.BeginInvoke((Action)(() =>
                            {
                                AgentLog("AGENT_SHUTDOWN_UI_BEGIN");
                                Environment.ExitCode = AgentShutdownExitCode;
                                try { shutdown.Cancel(); } catch (Exception exception) { AgentLog("AGENT_SHUTDOWN_CANCEL_FAILED type=" + exception.GetType().Name); }
                                try { collector.Stop(); } catch (Exception exception) { AgentLog("AGENT_SHUTDOWN_TIMER_STOP_FAILED type=" + exception.GetType().Name); }
                                try { serviceEventCollector.Stop(); } catch (Exception exception) { AgentLog("AGENT_SHUTDOWN_SERVICE_TIMER_STOP_FAILED type=" + exception.GetType().Name); }
                                try { tray.Visible = false; } catch (Exception exception) { AgentLog("AGENT_SHUTDOWN_TRAY_STOP_FAILED type=" + exception.GetType().Name); }
                                AgentLog("AGENT_SHUTDOWN_EXIT_THREAD");
                                ExitThread();
                            })); }
                            catch (Exception exception) { AgentLog("AGENT_SHUTDOWN_DISPATCH_FAILED type=" + exception.GetType().Name); throw; }
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
            if (disposing && !disposed)
            {
                disposed = true;
                AgentLog("AGENT_CONTEXT_DISPOSE_BEGIN");
                shutdown.Cancel();
                collector.Stop();
                serviceEventCollector.Stop();
                serviceEventCollector.Dispose();
                tray.Visible = false;
                tray.Dispose();
                dispatcher.Dispose();
                engine.Dispose();
                shutdown.Dispose();
                AgentLog("AGENT_CONTEXT_DISPOSE_END");
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
            var startedProcess = Process.Start(start) ?? throw new IOException("Nie można uruchomić lokalnego silnika.");
            process = startedProcess;
            input = startedProcess.StandardInput;
            output = startedProcess.StandardOutput;
            startedProcess.ErrorDataReceived += (_, line) =>
            {
                if (string.IsNullOrWhiteSpace(line.Data)) return;
                var fatalType = EngineFatalDiagnostic.ReadExceptionType(line.Data);
                AgentLog(fatalType is null ? "ENGINE_STDERR_DIAGNOSTIC" : "ENGINE_FATAL type=" + fatalType);
            };
            startedProcess.EnableRaisingEvents = true;
            startedProcess.Exited += (_, _) =>
            {
                try { AgentLog("ENGINE_PROCESS_EXIT exitCode=" + startedProcess.ExitCode.ToString(CultureInfo.InvariantCulture)); }
                catch { AgentLog("ENGINE_PROCESS_EXIT exitCode=unavailable"); }
            };
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

