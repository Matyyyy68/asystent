using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using Sentinel.Core;
using Sentinel.Core.Configuration;
namespace Sentinel.Desktop;
public sealed class AsyncCommand(Func<Task> action, Action<Exception> error) : ICommand
{
    private bool running;
    public event EventHandler? CanExecuteChanged;
    public bool CanExecute(object? parameter) => !running;
    public async void Execute(object? parameter)
    {
        if (running) return; running = true; CanExecuteChanged?.Invoke(this, EventArgs.Empty);
        try { await action(); } catch (Exception ex) { error(ex); }
        finally { running = false; CanExecuteChanged?.Invoke(this, EventArgs.Empty); }
    }
}
public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly LocalStore store;
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Changed([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new(name));
    public ObservableCollection<SecurityEvent> Events { get; } = [];
    public ObservableCollection<SecurityEvent> RecentEvents { get; } = [];
    private string message = "";
    public string Message { get => message; private set { message = value; Changed(); } }
    private int retentionDays = 30;
    public int RetentionDays { get => retentionDays; set { retentionDays = value; Changed(); } }
    private bool notifications = true;
    public bool Notifications { get => notifications; set { notifications = value; Changed(); } }
    private string theme = "System";
    public string Theme { get => theme; set { theme = value; Changed(); } }
    private bool startMinimized;
    public bool StartMinimized { get => startMinimized; set { startMinimized = value; Changed(); } }
    private int selectedTabIndex;
    public int SelectedTabIndex { get => selectedTabIndex; set { selectedTabIndex = value; Changed(); } }
    private string eventCount = "Brak danych";
    public string EventCount { get => eventCount; private set { eventCount = value; Changed(); } }
    private string threatCount = "Brak danych";
    public string ThreatCount { get => threatCount; private set { threatCount = value; Changed(); } }
    private string lastWarning = "Brak danych";
    public string LastWarning { get => lastWarning; private set { lastWarning = value; Changed(); } }
    public string VersionText => $"Wersja {typeof(MainViewModel).Assembly.GetName().Version?.ToString(3) ?? "—"}";
    private string productVariant = "Sentinel AI User";
    public string ProductVariant { get => productVariant; private set { productVariant = value; Changed(); } }
    public event Action<string>? ThemeChanged;
    public SecurityEvent? SelectedEvent { get; set; }
    public string DataPath => store.DatabasePath;
    public MonitoringViewModel Monitoring { get; }
    public KnowledgeViewModel Knowledge { get; }
    public EnterpriseViewModel Enterprise { get; }
    private bool isEnterprise;
    private Sentinel.Core.Enterprise.EnterprisePolicy? enterprisePolicy;
    public bool IsEnterprise { get => isEnterprise; private set { isEnterprise = value; Changed(); } }
    public ICommand Save { get; }
    public ICommand Refresh { get; }
    public ICommand TestNotification { get; }
    public ICommand FalsePositive { get; }
    public ICommand Clear { get; }
    public ICommand Export { get; }
    public ICommand Backup { get; }
    public ICommand OpenHistory { get; }
    public ICommand OpenSettings { get; }
    private AsyncCommand Command(Func<Task> action) => new(action, ex => Message = $"Operacja nie powiodła się ({ex.GetType().Name}). Dane nie zostały wysłane.");
    public MainViewModel(LocalStore store, MonitoringViewModel monitoring, KnowledgeViewModel knowledge, EnterpriseViewModel enterprise)
    {
        this.store = store; Monitoring = monitoring; Knowledge = knowledge; Enterprise = enterprise; Monitoring.HistoryChanged = Reload;
        Enterprise.PolicyReceived += policy => System.Windows.Application.Current.Dispatcher.BeginInvoke(() => { enterprisePolicy = policy; Monitoring.ApplyEnterprisePolicy(policy); });
        Save = Command(async () => { var settings = Monitoring.CreateSettings((await store.LoadSettingsAsync()) with { RetentionDays = RetentionDays, Notifications = Notifications, Theme = Theme, StartMinimized = StartMinimized }); await store.SaveSettingsAsync(settings); Monitoring.ApplyUserSettings(settings); if (enterprisePolicy is not null) Monitoring.ApplyEnterprisePolicy(enterprisePolicy); await store.ApplyRetentionAsync(RetentionDays); await Reload(); ThemeChanged?.Invoke(Theme); Message = "Ustawienia zapisane; retencja zastosowana."; });
        Refresh = Command(Reload);
        TestNotification = Command(async () =>
        {
            await store.AddAsync(new(0, DateTimeOffset.UtcNow, RiskLevel.Information, "Test powiadomienia", "Sentinel AI", "Użytkownik uruchomił test — to nie wykrycie zagrożenia.", "Brak wymaganych działań.", EventStatus.New));
            await Reload(); Message = Notifications ? "Powiadomienie testowe. Zdarzenie zapisano lokalnie." : "Test zapisano; powiadomienia są wyłączone.";
        });
        FalsePositive = Command(async () => { if (SelectedEvent is not { } item) { Message = "Wybierz zdarzenie."; return; } await store.SetStatusAsync(item.Id, EventStatus.FalsePositive); await Reload(); Message = "Oznaczono jako fałszywy alarm."; });
        Clear = Command(async () => { if (System.Windows.MessageBox.Show("Usunąć całą historię?", "Sentinel AI", System.Windows.MessageBoxButton.YesNo) != System.Windows.MessageBoxResult.Yes) return; await store.DeleteHistoryAsync(); await Reload(); Message = "Historia usunięta."; });
        Export = Command(async () => { var d = new Microsoft.Win32.SaveFileDialog { Filter = "JSON|*.json", FileName = "sentinel-events.json", OverwritePrompt = true }; if (d.ShowDialog() == true) { if (System.IO.File.Exists(d.FileName)) { Message = "Wybierz nową nazwę pliku eksportu."; return; } await store.ExportAsync(d.FileName); Message = "Eksport zakończony."; } });
        Backup = Command(async () => { var d = new Microsoft.Win32.SaveFileDialog { Filter = "SQLite|*.db", FileName = "sentinel-backup.db", OverwritePrompt = false }; if (d.ShowDialog() == true) { await store.BackupAsync(d.FileName); Message = "Kopia bazy utworzona."; } });
        OpenHistory = Command(() => { SelectedTabIndex = 3; return Task.CompletedTask; });
        OpenSettings = Command(() => { SelectedTabIndex = 4; return Task.CompletedTask; });
    }
    public async Task InitializeAsync() { var s = await store.LoadSettingsAsync(); var profile = await store.GetInstallationProfileAsync(); IsEnterprise = profile.Variant == Sentinel.Core.Configuration.ProductVariant.EnterpriseClient; ProductVariant = IsEnterprise ? "Sentinel AI Enterprise Client" : "Sentinel AI User"; Monitoring.ApplySettings(s, false); RetentionDays = s.RetentionDays; Notifications = s.Notifications; Theme = s.Theme; StartMinimized = s.StartMinimized; await store.ApplyRetentionAsync(s.RetentionDays); await Reload(); await Knowledge.InitializeAsync(); await Enterprise.InitializeAsync(); }
    private async Task Reload()
    {
        var rows = await store.ReadAsync(); Events.Clear(); RecentEvents.Clear();
        foreach (var row in rows) Events.Add(row);
        foreach (var row in rows.Take(3)) RecentEvents.Add(row);
        EventCount = Events.Count == 0 ? "0" : Events.Count.ToString(System.Globalization.CultureInfo.CurrentCulture);
        ThreatCount = Events.Count(e => e.Risk >= RiskLevel.High).ToString(System.Globalization.CultureInfo.CurrentCulture);
        LastWarning = Events.FirstOrDefault(e => e.Risk >= RiskLevel.High)?.Timestamp.ToLocalTime().ToString("g") ?? "Brak ostrzeżeń";
    }
}
