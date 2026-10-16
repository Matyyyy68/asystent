using System.Windows;
using System.IO;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Core;
using Sentinel.Core.Context;
using Sentinel.Core.Analysis;
using Sentinel.Desktop.Context;
namespace Sentinel.Desktop;
public partial class App : Application
{
    private ServiceProvider? services;
    private Mutex? instanceMutex;
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ShutdownMode = ShutdownMode.OnExplicitShutdown;
        try
        {
            instanceMutex = new Mutex(false, @"Local\SentinelAI.Desktop", out bool firstInstance);
            if (!firstInstance)
            {
                MessageBox.Show("Sentinel AI jest już otwarty lub trwa jego instalacja. Przejdź do otwartego okna albo poczekaj na zakończenie instalacji.", "Sentinel AI", MessageBoxButton.OK, MessageBoxImage.Information);
                Shutdown(); return;
            }
            var bootstrap = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelAI");
            Directory.CreateDirectory(bootstrap); var pointer = Path.Combine(bootstrap, "data-path.txt");
            string directory;
            if (File.Exists(pointer)) directory = File.ReadAllText(pointer).Trim();
            else
            {
                var setup = new FirstRunWindow(Path.Combine(bootstrap, "Data"));
                if (setup.ShowDialog() != true) { Shutdown(); return; }
                directory = setup.SelectedDirectory;
            }
            var drive = new DriveInfo(Path.GetPathRoot(Path.GetFullPath(directory))!);
            if (drive.DriveType == DriveType.Network || !drive.IsReady || drive.AvailableFreeSpace < 50 * 1024 * 1024)
                throw new IOException("Wymagany lokalny, dostępny dysk z co najmniej 50 MB wolnego miejsca.");
            var store = new LocalStore(directory); await store.InitializeAsync();
            await File.WriteAllTextAsync(pointer, directory);
            services = new ServiceCollection().AddSingleton(store).AddSingleton<IEventRepository>(store)
                .AddSingleton<ISettingsRepository>(store)
                .AddSingleton<WindowsContextProvider>()
                .AddSingleton<IContextProvider>(s => s.GetRequiredService<WindowsContextProvider>())
                .AddSingleton<IForegroundEventSource>(s => s.GetRequiredService<WindowsContextProvider>())
                .AddSingleton(TimeProvider.System).AddSingleton<ContextCollector>()
                .AddSingleton<DomainNames>().AddSingleton<UrlAnalyzer>().AddSingleton<ThreatAnalysisEngine>()
                .AddSingleton<MonitoringViewModel>().AddSingleton<MainViewModel>().AddSingleton<MainWindow>().BuildServiceProvider();
            var vm = services.GetRequiredService<MainViewModel>(); await vm.InitializeAsync();
            MainWindow = services.GetRequiredService<MainWindow>();
            ShutdownMode = ShutdownMode.OnMainWindowClose;
            MainWindow.Show();
            vm.Monitoring.Activate();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Nie można uruchomić Sentinel AI ({ex.GetType().Name}). Sprawdź katalog, uprawnienia i bazę. Nie usuwaj uszkodzonej bazy bez kopii.", "Sentinel AI", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }
    protected override void OnExit(ExitEventArgs e) { services?.Dispose(); instanceMutex?.Dispose(); base.OnExit(e); }
}
