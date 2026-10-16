using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using System.Collections.ObjectModel;
using Sentinel.Core;
using Sentinel.Core.Analysis;
using Sentinel.Core.Context;
using Sentinel.Core.Enterprise;

namespace Sentinel.Desktop;

public sealed class MonitoringViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly LocalStore store;
    private readonly ContextCollector collector;
    private readonly IForegroundEventSource events;
    private readonly AnalysisOrchestrator analysis;
    private readonly IAIProvider aiProvider;
    private AppSettings applied = new();
    private AppSettings? enterpriseBaseSettings;
    private CancellationTokenSource session = new();
    private bool collecting;
    private bool autoActive;
    private int eventPending;
    public Func<Task>? HistoryChanged { get; set; }
    public event Action<string, string, string>? NotificationRequested;
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Changed([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new(name));
    private string message = "Zbieranie kontekstu jest domyślnie wstrzymane.";
    public string Message { get => message; private set { message = value; Changed(); } }
    private string alertBackground = "#DBEAFE";
    public string AlertBackground { get => alertBackground; private set { alertBackground = value; Changed(); } }
    private string details = "Nie wykonano analizy. Wyniki reguł nie gwarantują bezpieczeństwa.";
    public string Details { get => details; private set { details = value; Changed(); } }
    public bool Paused => applied.Paused;
    public string ProtectionStatus => Paused ? "Analiza wstrzymana" : autoActive ? "Analiza automatyczna aktywna" : "Analiza dostępna na żądanie";
    public string ProtectionDescription => Paused
        ? "Analiza lokalna jest wstrzymana. Włącz ją, aby sprawdzić aktywne okno; możesz też wkleić treść do analizy ręcznej."
        : autoActive
            ? "Analiza lokalna działa przy zmianie aktywnego okna. Sprawdza dostępne etykiety, pomijając pola edycyjne i hasła. Nie zastępuje ochrony antywirusowej."
            : "Analiza lokalna jest dostępna na żądanie. Automatyczna analiza zmiany aktywnego okna jest wyłączona. Nie jest to stała ochrona antywirusowa.";
    public string PauseLabel => Paused ? "Włącz analizę okien" : "Wstrzymaj zbieranie";
    private int interval = 10;
    public int MinimumIntervalSeconds { get => interval; set { interval = value; Changed(); } }
    private string excludedApplications = "";
    public string ExcludedApplications { get => excludedApplications; set { excludedApplications = value; Changed(); } }
    private string excludedTitles = "";
    public string ExcludedWindowTitles { get => excludedTitles; set { excludedTitles = value; Changed(); } }
    private bool excludeBrowsers;
    public bool ExcludeBrowsers { get => excludeBrowsers; set { excludeBrowsers = value; Changed(); } }
    private bool excludeMessaging;
    public bool ExcludeMessaging { get => excludeMessaging; set { excludeMessaging = value; Changed(); } }
    private bool collectStaticText = true;
    public bool CollectStaticText { get => collectStaticText; set { collectStaticText = value; Changed(); } }
    private bool monitorForegroundChanges;
    public bool MonitorForegroundChanges { get => monitorForegroundChanges; set { monitorForegroundChanges = value; Changed(); } }
    private string manualText = "";
    public string ManualText { get => manualText; set { manualText = value; Changed(); } }
    private string manualUrl = "";
    public string ManualUrl { get => manualUrl; set { manualUrl = value; Changed(); } }
    private string displayedUrl = "";
    public string DisplayedUrl { get => displayedUrl; set { displayedUrl = value; Changed(); } }
    public ICommand TogglePause { get; }
    public ICommand Capture { get; }
    public ICommand AnalyzeManual { get; }
    public ICommand DiscoverLocalModels { get; }
    public ICommand TestLocalModel { get; }
    public ObservableCollection<LocalAIModel> LocalModels { get; } = [];
    private bool useLocalAI;
    public bool UseLocalAI { get => useLocalAI; set { useLocalAI = value; Changed(); } }
    private string localAIEndpoint = "http://127.0.0.1:11434";
    public string LocalAIEndpoint { get => localAIEndpoint; set { localAIEndpoint = value; Changed(); } }
    private string localAIModel = "";
    public string LocalAIModel { get => localAIModel; set { localAIModel = value; Changed(); } }
    private int localAITimeoutSeconds = 30;
    public int LocalAITimeoutSeconds { get => localAITimeoutSeconds; set { localAITimeoutSeconds = value; Changed(); } }
    private AsyncCommand Command(Func<Task> action) => new(action, ReportError);
    private void ReportError(Exception ex)
    {
        if (ex is OperationCanceledException) { Message = "Analiza anulowana."; return; }
        Message = $"Operacja nie powiodła się ({ex.GetType().Name}). Nie zapisano treści kontekstu.";
    }
    public MonitoringViewModel(LocalStore store, ContextCollector collector, IForegroundEventSource events, AnalysisOrchestrator analysis, IAIProvider aiProvider)
    {
        this.store = store; this.collector = collector; this.events = events; this.analysis = analysis; this.aiProvider = aiProvider;
        TogglePause = Command(async () =>
        {
            var settings = await store.LoadSettingsAsync();
            settings = settings with { Paused = !Paused };
            await store.SaveSettingsAsync(settings); ApplySettings(settings);
            Message = Paused ? "Zbieranie wstrzymane. Analiza ręcznie wklejonego tekstu pozostaje dostępna." : "UI Automation włączone. Nie odczytujemy pól edycyjnych ani haseł. Zapisujemy tylko opis reguł.";
        });
        Capture = Command(async () =>
        {
            if (Paused) { Message = "Najpierw jawnie włącz analizę okien."; return; }
            await CaptureAsync(true);
        });
        AnalyzeManual = Command(async () =>
        {
            var input = new AnalysisContext("Manual", ManualText, DateTimeOffset.UtcNow,
                string.IsNullOrWhiteSpace(ManualUrl) ? null : new(ManualUrl.Trim(), string.IsNullOrWhiteSpace(DisplayedUrl) ? null : DisplayedUrl.Trim()));
            ManualText = ""; ManualUrl = ""; DisplayedUrl = "";
            var assessment = await analysis.AnalyzeAsync(input, applied.UseLocalAI, applied.LocalAIEndpoint, applied.LocalAIModel, applied.LocalAITimeoutSeconds, session.Token);
            await PresentAsync(assessment, "Manual");
        });
        DiscoverLocalModels = Command(async () =>
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var found = await aiProvider.ListModelsAsync(LocalAIEndpoint, timeout.Token);
            LocalModels.Clear(); foreach (var item in found) LocalModels.Add(item);
            if (LocalModels.Count == 0) { Message = "Lokalny serwer działa, ale nie ma zainstalowanych modeli. Nie pobrano żadnego modelu."; return; }
            if (!LocalModels.Any(item => item.Name == LocalAIModel)) LocalAIModel = LocalModels[0].Name;
            Message = $"Wykryto {LocalModels.Count} lokalnych modeli. Model nie jest używany, dopóki go nie włączysz i zapiszesz ustawień.";
        });
        TestLocalModel = Command(async () =>
        {
            if (string.IsNullOrWhiteSpace(LocalAIModel)) { Message = "Najpierw wykryj i wybierz lokalny model."; return; }
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(Math.Clamp(LocalAITimeoutSeconds, 3, 120)));
            var sample = new AnalysisContext("Synthetic self-test", "Pilnie: blokada konta. Zaloguj się, aby potwierdzić dane.", DateTimeOffset.UtcNow);
            var response = await aiProvider.AnalyzeAsync(LocalAIEndpoint, LocalAIModel, sample, [], timeout.Token);
            Message = $"Test modelu zakończony. Odpowiedź: {EnumLabelConverter.Label(response.Risk)} / {EnumLabelConverter.Label(response.Category)}. Wysłano wyłącznie syntetyczny tekst testowy do lokalnego endpointu.";
        });
        events.ForegroundChanged += ForegroundChanged;
    }
    public AppSettings CreateSettings(AppSettings settings) => settings with
    {
        Paused = Paused, MinimumIntervalSeconds = MinimumIntervalSeconds, ExcludedApplications = ExcludedApplications,
        ExcludedWindowTitles = ExcludedWindowTitles, ExcludeBrowsers = ExcludeBrowsers, ExcludeMessaging = ExcludeMessaging,
        CollectStaticText = CollectStaticText, MonitorForegroundChanges = MonitorForegroundChanges,
        UseLocalAI = UseLocalAI, LocalAIEndpoint = LocalAIEndpoint, LocalAIModel = LocalAIModel, LocalAITimeoutSeconds = LocalAITimeoutSeconds
    };
    public void Activate() => ApplySettings(applied);
    public void ApplyUserSettings(AppSettings settings)
    {
        enterpriseBaseSettings = settings;
        ApplySettings(settings);
    }
    public void ApplyEnterprisePolicy(EnterprisePolicy policy)
    {
        enterpriseBaseSettings ??= applied;
        var baseSettings = enterpriseBaseSettings;
        var excluded = (baseSettings.ExcludedApplications + ";" + string.Join(';', policy.ExcludedApplications))
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase);
        var remoteMode = policy.AnalysisMode is "server" or "hybrid";
        var enforced = applied with
        {
            MinimumIntervalSeconds = Math.Max(baseSettings.MinimumIntervalSeconds, policy.AnalysisIntervalSeconds),
            ExcludedApplications = string.Join(';', excluded),
            MonitorForegroundChanges = remoteMode ? false : baseSettings.MonitorForegroundChanges,
            Notifications = policy.NotificationLevel != "history"
        };
        ApplySettings(enforced with { RetentionDays = baseSettings.RetentionDays, Theme = baseSettings.Theme,
            StartMinimized = baseSettings.StartMinimized, UseLocalAI = baseSettings.UseLocalAI,
            LocalAIEndpoint = baseSettings.LocalAIEndpoint, LocalAIModel = baseSettings.LocalAIModel,
            LocalAITimeoutSeconds = baseSettings.LocalAITimeoutSeconds });
        Message = remoteMode
            ? $"Polityka Enterprise v{policy.Version}: automatyczne wysyłanie treści jest wyłączone; tryb serwerowy wymaga jawnej zgody użytkownika. Analiza lokalna pozostaje dostępna na żądanie."
            : $"Zastosowano politykę Enterprise v{policy.Version}: odstęp co najmniej {policy.AnalysisIntervalSeconds}s i wykluczenia administratora.";
    }
    public void ApplySettings(AppSettings settings, bool activate = true)
    {
        // In-flight work is cancelled when privacy policy or pause state changes.
        session.Cancel(); session.Dispose(); session = new();
        applied = settings;
        MinimumIntervalSeconds = settings.MinimumIntervalSeconds; ExcludedApplications = settings.ExcludedApplications;
        ExcludedWindowTitles = settings.ExcludedWindowTitles; ExcludeBrowsers = settings.ExcludeBrowsers;
        ExcludeMessaging = settings.ExcludeMessaging; CollectStaticText = settings.CollectStaticText; MonitorForegroundChanges = settings.MonitorForegroundChanges;
        UseLocalAI = settings.UseLocalAI; LocalAIEndpoint = settings.LocalAIEndpoint; LocalAIModel = settings.LocalAIModel; LocalAITimeoutSeconds = settings.LocalAITimeoutSeconds;
        events.Stop(); autoActive = false;
        if (activate && !Paused && settings.MonitorForegroundChanges)
        {
            try { events.Start(); autoActive = true; }
            catch (System.ComponentModel.Win32Exception) { Message = "Nie udało się włączyć zdarzeń Windows; dostępna pozostaje analiza na żądanie."; }
        }
        Changed(nameof(Paused)); Changed(nameof(ProtectionStatus)); Changed(nameof(ProtectionDescription)); Changed(nameof(PauseLabel));
    }
    private void ForegroundChanged(object? sender, EventArgs e)
    {
        if (System.Windows.Application.Current.Dispatcher.HasShutdownStarted || Interlocked.Exchange(ref eventPending, 1) != 0) return;
        System.Windows.Application.Current.Dispatcher.BeginInvoke(async () =>
        {
            try { if (!Paused && autoActive) await CaptureAsync(false); }
            catch (Exception ex) { ReportError(ex); }
            finally { Volatile.Write(ref eventPending, 0); }
        });
    }
    private async Task CaptureAsync(bool delayed)
    {
        if (collecting) { Message = "Poprzednia analiza jeszcze trwa."; return; }
        collecting = true;
        var token = session.Token;
        try
        {
            if (delayed)
            {
                Message = "Za 3 sekundy odczytam aktywne okno. Przełącz się do okna, które chcesz sprawdzić.";
                await Task.Delay(TimeSpan.FromSeconds(3), token);
            }
            var capture = await collector.CaptureAsync(applied, token);
            token.ThrowIfCancellationRequested();
            if (capture.Context is not { } context)
            {
                Message = capture.Status switch
                {
                    CaptureStatus.Paused => "Zbieranie jest wstrzymane.",
                    CaptureStatus.Excluded => "Okno wykluczone — treści UI Automation nie odczytano.",
                    CaptureStatus.RateLimited => "Pominięto zbieranie ze względu na limit częstotliwości.",
                    CaptureStatus.Busy => "Dostawca UI Automation jest zajęty.",
                    _ => "Nie można odczytać aktywnego okna. Może to być okno Sentinel AI, ekran chroniony lub niedostępna aplikacja."
                };
                return;
            }
            var assessment = await analysis.AnalyzeAsync(context, applied.UseLocalAI, applied.LocalAIEndpoint, applied.LocalAIModel, applied.LocalAITimeoutSeconds, token);
            token.ThrowIfCancellationRequested();
            if (capture.Truncated) assessment = assessment with { Uncertainties = [.. assessment.Uncertainties, "UI Automation osiągnęło limit czasu, głębokości lub rozmiaru; odczyt jest częściowy."] };
            if (string.IsNullOrWhiteSpace(context.Text)) assessment = assessment with { Uncertainties = [.. assessment.Uncertainties, "Brak dostępnego statycznego tekstu; analiza nie obejmuje zawartości okna."] };
            await PresentAsync(assessment, context.Application);
        }
        finally { collecting = false; }
    }
    private async Task PresentAsync(ThreatAssessment assessment, string application)
    {
        AlertBackground = assessment.Risk == RiskLevel.Critical ? "#FEE2E2" : assessment.Risk == RiskLevel.High ? "#FFEDD5" : "#DBEAFE";
        Details = $"Ryzyko: {EnumLabelConverter.Label(assessment.Risk)} · Kategoria: {EnumLabelConverter.Label(assessment.Category)}\n\n{assessment.Explanation}\n\nZalecenia:\n" +
            string.Join("\n", assessment.Recommendations) + "\n\nNiepewności:\n" + string.Join("\n", assessment.Uncertainties);
        if (assessment.Indicators.Count > 0)
        {
            var explanation = assessment.Explanation + " " + string.Join(" ", assessment.Uncertainties);
            await store.AddAsync(new(0, DateTimeOffset.UtcNow, assessment.Risk, assessment.Category.ToString(), application,
                explanation[..Math.Min(explanation.Length, 2000)], string.Join(" ", assessment.Recommendations), EventStatus.New));
            await store.ApplyRetentionAsync(applied.RetentionDays);
            if (HistoryChanged is not null) await HistoryChanged();
        }
        if (applied.Notifications && assessment.Risk >= RiskLevel.High && assessment.Indicators.Count > 0)
        {
            var key = $"{assessment.Category}:{string.Join(',', assessment.Indicators.Select(i => i.Id).Order(StringComparer.Ordinal))}";
            NotificationRequested?.Invoke($"Sentinel AI — {EnumLabelConverter.Label(assessment.Risk)} ryzyko",
                Limit(string.Join(" ", assessment.Indicators.Select(i => i.Description).Distinct()), 220), key);
        }
        Message = !applied.Notifications ? "Analiza zakończona; powiadomienia wyłączone. Wynik jest dostępny poniżej." :
            assessment.Risk == RiskLevel.Critical ? "KRYTYCZNE OSTRZEŻENIE: wiele powiązanych sygnałów ryzyka. Wstrzymaj działanie i zweryfikuj prośbę." :
            assessment.Risk >= RiskLevel.High ? "OSTRZEŻENIE: wiele sygnałów ryzyka. Wstrzymaj działanie i zweryfikuj prośbę niezależnie." : "Analiza zakończona. Przeczytaj wynik i jego ograniczenia.";
    }
    private static string Limit(string value, int max) => value.Length <= max ? value : value[..(max - 1)] + "…";
    public void Dispose() { events.ForegroundChanged -= ForegroundChanged; events.Stop(); session.Cancel(); session.Dispose(); }
}
