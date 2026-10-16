using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using Sentinel.Core;
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
    private string message = "";
    public string Message { get => message; private set { message = value; Changed(); } }
    private int retentionDays = 30;
    public int RetentionDays { get => retentionDays; set { retentionDays = value; Changed(); } }
    private bool notifications = true;
    public bool Notifications { get => notifications; set { notifications = value; Changed(); } }
    public SecurityEvent? SelectedEvent { get; set; }
    public string DataPath => store.DatabasePath;
    public MonitoringViewModel Monitoring { get; }
    public ICommand Save { get; }
    public ICommand Refresh { get; }
    public ICommand TestNotification { get; }
    public ICommand FalsePositive { get; }
    public ICommand Clear { get; }
    public ICommand Export { get; }
    public ICommand Backup { get; }
    private AsyncCommand Command(Func<Task> action) => new(action, ex => Message = $"Operacja nie powiodła się ({ex.GetType().Name}). Dane nie zostały wysłane.");
    public MainViewModel(LocalStore store, MonitoringViewModel monitoring)
    {
        this.store = store; Monitoring = monitoring; Monitoring.HistoryChanged = Reload;
        Save = Command(async () => { var settings = Monitoring.CreateSettings((await store.LoadSettingsAsync()) with { RetentionDays = RetentionDays, Notifications = Notifications }); await store.SaveSettingsAsync(settings); Monitoring.ApplySettings(settings); await store.ApplyRetentionAsync(RetentionDays); await Reload(); Message = "Ustawienia zapisane; retencja zastosowana."; });
        Refresh = Command(Reload);
        TestNotification = Command(async () =>
        {
            await store.AddAsync(new(0, DateTimeOffset.UtcNow, RiskLevel.Information, "Test powiadomienia", "Sentinel AI", "Użytkownik uruchomił test — to nie wykrycie zagrożenia.", "Brak wymaganych działań.", EventStatus.New));
            await Reload(); Message = Notifications ? "Powiadomienie testowe. Zdarzenie zapisano lokalnie." : "Test zapisano; powiadomienia są wyłączone.";
        });
        FalsePositive = Command(async () => { if (SelectedEvent is not { } item) { Message = "Wybierz zdarzenie."; return; } await store.SetStatusAsync(item.Id, EventStatus.FalsePositive); await Reload(); Message = "Oznaczono jako fałszywy alarm."; });
        Clear = Command(async () => { if (System.Windows.MessageBox.Show("Usunąć całą historię?", "Sentinel AI", System.Windows.MessageBoxButton.YesNo) != System.Windows.MessageBoxResult.Yes) return; await store.DeleteHistoryAsync(); await Reload(); Message = "Historia usunięta."; });
        Export = Command(async () => { var d = new Microsoft.Win32.SaveFileDialog { Filter = "JSON|*.json", FileName = "sentinel-events.json", OverwritePrompt = true }; if (d.ShowDialog() == true) { if (System.IO.File.Exists(d.FileName)) { Message = "Wybierz nową nazwę pliku eksportu."; return; } await store.ExportAsync(d.FileName); Message = "Eksport zakończony."; } });
        Backup = Command(async () => { var d = new Microsoft.Win32.SaveFileDialog { Filter = "SQLite|*.db", FileName = "sentinel-backup.db" }; if (d.ShowDialog() == true) { await store.BackupAsync(d.FileName); Message = "Kopia bazy utworzona."; } });
    }
    public async Task InitializeAsync() { var s = await store.LoadSettingsAsync(); Monitoring.ApplySettings(s, false); RetentionDays = s.RetentionDays; Notifications = s.Notifications; await store.ApplyRetentionAsync(s.RetentionDays); await Reload(); }
    private async Task Reload() { var rows = await store.ReadAsync(); Events.Clear(); foreach (var row in rows) Events.Add(row); }
}
