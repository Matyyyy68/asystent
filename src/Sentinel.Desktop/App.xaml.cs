using System.Windows;
using System.IO;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Core;
using Sentinel.Core.Context;
using Sentinel.Core.Analysis;
using Sentinel.Desktop.Context;
using Microsoft.Win32;
using System.IO.Pipes;
namespace Sentinel.Desktop;
public partial class App : System.Windows.Application
{
    private ServiceProvider? services;
    private Mutex? instanceMutex;
    private TrayController? tray;
    private CancellationTokenSource? activationCancellation;
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ShutdownMode = ShutdownMode.OnExplicitShutdown;
        try
        {
            instanceMutex = new Mutex(false, @"Local\SentinelAI.Desktop", out bool firstInstance);
            if (!firstInstance)
            {
                await ActivateExistingInstanceAsync();
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
            ApplyTheme(vm.Theme); vm.ThemeChanged += ApplyTheme;
            MainWindow = services.GetRequiredService<MainWindow>();
            tray = new TrayController((MainWindow)MainWindow, vm);
            activationCancellation = new CancellationTokenSource();
            _ = ServeActivationPipeAsync(activationCancellation.Token);
            if (vm.StartMinimized) tray.StartMinimized();
            else MainWindow.Show();
            vm.Monitoring.Activate();
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"Nie można uruchomić Sentinel AI ({ex.GetType().Name}). Sprawdź katalog, uprawnienia i bazę. Nie usuwaj uszkodzonej bazy bez kopii.", "Sentinel AI", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }
    private static async Task ActivateExistingInstanceAsync()
    {
        for (var attempt = 0; attempt < 4; attempt++)
        {
            try
            {
                await using var client = new NamedPipeClientStream(".", "SentinelAI.Desktop.Activation", PipeDirection.Out, PipeOptions.Asynchronous);
                await client.ConnectAsync(350);
                await client.WriteAsync(new byte[] { 1 });
                return;
            }
            catch (TimeoutException) { await Task.Delay(150); }
            catch (IOException) { await Task.Delay(150); }
        }
    }
    private async Task ServeActivationPipeAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await using var server = new NamedPipeServerStream("SentinelAI.Desktop.Activation", PipeDirection.In, 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await server.WaitForConnectionAsync(cancellationToken);
                var signal = new byte[1];
                if (await server.ReadAsync(signal, cancellationToken) == 1 && signal[0] == 1)
                    _ = Dispatcher.BeginInvoke(new Action(() => tray?.ShowWindow()));
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (IOException) when (cancellationToken.IsCancellationRequested) { }
    }
    private void ApplyTheme(string theme)
    {
        var selected = theme switch
        {
            "Dark" => "Dark",
            "Light" => "Light",
            _ => ReadSystemTheme()
        };
        var uri = new Uri($"/Sentinel.Desktop;component/Themes/{selected}.xaml", UriKind.Relative);
        var dictionaries = Resources.MergedDictionaries;
        var index = -1;
        for (var i = 0; i < dictionaries.Count; i++)
            if (dictionaries[i].Source?.OriginalString.Contains("Themes/", StringComparison.Ordinal) == true) { index = i; break; }
        var replacement = new ResourceDictionary { Source = uri };
        if (index >= 0) dictionaries[index] = replacement;
        else dictionaries.Insert(0, replacement);
    }
    private static string ReadSystemTheme()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int value && value == 0 ? "Dark" : "Light";
        }
        catch (System.Security.SecurityException) { return "Light"; }
        catch (IOException) { return "Light"; }
    }
    protected override void OnExit(ExitEventArgs e) { activationCancellation?.Cancel(); activationCancellation?.Dispose(); tray?.Dispose(); services?.Dispose(); instanceMutex?.Dispose(); base.OnExit(e); }
}
