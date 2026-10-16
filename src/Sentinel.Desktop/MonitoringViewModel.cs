using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using Sentinel.Core;
using Sentinel.Core.Analysis;
using Sentinel.Core.Context;

namespace Sentinel.Desktop;

public sealed class MonitoringViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly LocalStore store;
    private readonly ContextCollector collector;
    private readonly IForegroundEventSource events;
    private readonly ThreatAnalysisEngine engine;
    private AppSettings applied = new();
    private CancellationTokenSource session = new();
    private bool collecting;
    private bool autoActive;
    private int eventPending;
    public Func<Task>? HistoryChanged { get; set; }
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Changed([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new(name));
    private string message = "Zbieranie kontekstu jest domyślnie wstrzymane.";
    public string Message { get => message; private set { message = value; Changed(); } }
    private string alertBackground = "#DBEAFE";
    public string AlertBackground { get => alertBackground; private set { alertBackground = value; Changed(); } }
    private string details = "Nie wykonano analizy. Wyniki reguł nie gwarantują bezpieczeństwa.";
    public string Details { get => details; private set { details = value; Changed(); } }
    public bool Paused => applied.Paused;
    public string ProtectionStatus => Paused ? "Pauza — kontekst nie jest zbierany" : autoActive ? "Aktywne: analiza przy zmianie okna (UI Automation)" : "Aktywne: analiza wyłącznie na żądanie (UI Automation)";
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
    private AsyncCommand Command(Func<Task> action) => new(action, ReportError);
    private void ReportError(Exception ex)
    {
        if (ex is OperationCanceledException) { Message = "Analiza anulowana."; return; }
        Message = $"Operacja nie powiodła się ({ex.GetType().Name}). Nie zapisano treści kontekstu.";
    }
    public MonitoringViewModel(LocalStore store, ContextCollector collector, IForegroundEventSource events, ThreatAnalysisEngine engine)
    {
        this.store = store; this.collector = collector; this.events = events; this.engine = engine;
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
            var assessment = await Task.Run(() => engine.Analyze(input));
            await PresentAsync(assessment, "Manual");
        });
        events.ForegroundChanged += ForegroundChanged;
    }
    public AppSettings CreateSettings(AppSettings settings) => settings with
    {
        Paused = Paused, MinimumIntervalSeconds = MinimumIntervalSeconds, ExcludedApplications = ExcludedApplications,
        ExcludedWindowTitles = ExcludedWindowTitles, ExcludeBrowsers = ExcludeBrowsers, ExcludeMessaging = ExcludeMessaging,
        CollectStaticText = CollectStaticText, MonitorForegroundChanges = MonitorForegroundChanges
    };
    public void Activate() => ApplySettings(applied);
    public void ApplySettings(AppSettings settings, bool activate = true)
    {
        // In-flight work is cancelled when privacy policy or pause state changes.
        session.Cancel(); session.Dispose(); session = new();
        applied = settings;
        MinimumIntervalSeconds = settings.MinimumIntervalSeconds; ExcludedApplications = settings.ExcludedApplications;
        ExcludedWindowTitles = settings.ExcludedWindowTitles; ExcludeBrowsers = settings.ExcludeBrowsers;
        ExcludeMessaging = settings.ExcludeMessaging; CollectStaticText = settings.CollectStaticText; MonitorForegroundChanges = settings.MonitorForegroundChanges;
        events.Stop(); autoActive = false;
        if (activate && !Paused && settings.MonitorForegroundChanges)
        {
            try { events.Start(); autoActive = true; }
            catch (System.ComponentModel.Win32Exception) { Message = "Nie udało się włączyć zdarzeń Windows; dostępna pozostaje analiza na żądanie."; }
        }
        Changed(nameof(Paused)); Changed(nameof(ProtectionStatus)); Changed(nameof(PauseLabel));
    }
    private void ForegroundChanged(object? sender, EventArgs e)
    {
        if (Application.Current.Dispatcher.HasShutdownStarted || Interlocked.Exchange(ref eventPending, 1) != 0) return;
        Application.Current.Dispatcher.BeginInvoke(async () =>
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
            var assessment = await Task.Run(() => engine.Analyze(context), token);
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
        Message = !applied.Notifications ? "Analiza zakończona; powiadomienia wyłączone. Wynik jest dostępny poniżej." :
            assessment.Risk == RiskLevel.Critical ? "KRYTYCZNE OSTRZEŻENIE: wiele powiązanych sygnałów ryzyka. Wstrzymaj działanie i zweryfikuj prośbę." :
            assessment.Risk >= RiskLevel.High ? "OSTRZEŻENIE: wiele sygnałów ryzyka. Wstrzymaj działanie i zweryfikuj prośbę niezależnie." : "Analiza zakończona. Przeczytaj wynik i jego ograniczenia.";
    }
    public void Dispose() { events.ForegroundChanged -= ForegroundChanged; events.Stop(); session.Cancel(); session.Dispose(); }
}
