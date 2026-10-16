using System.Windows;
using Sentinel.Core;
using Sentinel.Core.Analysis;
using Sentinel.Core.Configuration;

namespace Sentinel.Desktop;

public partial class FirstRunWindow : Window
{
    public string SelectedDirectory { get; private set; }
    private readonly SystemSnapshot system;
    private readonly InstalledProductProfile profile;
    public FirstRunWindow(string recommendedDirectory, SystemSnapshot system, InstalledProductProfile profile)
    {
        this.system = system;
        this.profile = profile.Validate();
        InitializeComponent();
        SelectedDirectory = recommendedDirectory;
        DirectoryLabel.Text = SelectedDirectory;
        var recommendation = new ConfigurationRecommendationEngine().Recommend(system, profile.Variant);
        VariantLabel.Text = profile.Variant == ProductVariant.User ? "Sentinel AI User · lokalnie i offline" : "Sentinel AI Enterprise Client";
        RecommendationLabel.Text = recommendation.Summary;
        var memory = system.TotalMemoryBytes is { } total ? $"{total / 1024d / 1024 / 1024:N1} GB" : "nieznana";
        var available = system.AvailableMemoryBytes is { } freeMemory ? $"{freeMemory / 1024d / 1024 / 1024:N1} GB wolne" : "wolna pamięć nieznana";
        var disk = system.FreeDiskBytes is { } freeDisk ? $"{freeDisk / 1024d / 1024 / 1024:N1} GB" : "nieznane";
        var cpu = system.ProcessorName ?? "Model procesora nieznany";
        var cores = system.LogicalProcessors is { } count ? $" · {count} procesorów logicznych" : "";
        var network = system.NetworkAvailable switch { true => "dostępna", false => "niedostępna", _ => "nieznana" };
        SystemSummary.Text = $"System: {system.OperatingSystem}{(system.Edition is null ? "" : " · " + system.Edition)} · {system.Architecture}\nProcesor: {cpu}{cores}\nPamięć RAM: {memory} łącznie · {available}\nWolne miejsce: {disk} na dysku danych · Sieć: {network} (nie jest wymagana do lokalnej analizy)";
        var detected = system.DetectedSecurityProducts.Take(5).ToArray();
        var protection = system.DetectedSecurityProducts.Count == 0
            ? "Nie znaleziono wpisów innych programów ochronnych w rejestrze odinstalowania."
            : "Wykryto wpisy programów ochronnych: " + string.Join(", ", detected) + (system.DetectedSecurityProducts.Count > detected.Length ? $" (+{system.DetectedSecurityProducts.Count - detected.Length})" : "") + ". Sentinel AI nie zmienia ich ustawień.";
        var adapters = system.DisplayAdapters is null ? "Adaptery graficzne: nieznane" : system.DisplayAdapters.Count == 0 ? "Adaptery graficzne: nie wykryto" : "Adaptery graficzne: " + string.Join(", ", system.DisplayAdapters.Take(3));
        InstalledProtectionSummary.Text = protection;
        ModelSummary.Text = $"{adapters}. Możesz opcjonalnie podłączyć wcześniej zainstalowany lokalny serwer Ollama w ustawieniach. Model i jego zgodność sprzętowa wymagają osobnej weryfikacji; Sentinel AI nie pobiera modeli. NPU: {system.Npu switch { NpuAvailability.Detected => "wykryto", NpuAvailability.NotDetected => "nie wykryto", _ => "nieznane" }}.";
    }
    private void ChooseDirectory(object sender, RoutedEventArgs e)
    {
        var picker = new Microsoft.Win32.OpenFolderDialog { Title = "Wybierz folder na ustawienia i historię Sentinel AI" };
        if (picker.ShowDialog(this) != true) return;
        SelectedDirectory = picker.FolderName;
        DirectoryLabel.Text = SelectedDirectory;
    }
    private void Continue(object sender, RoutedEventArgs e) => DialogResult = true;
    private void RunSelfTest(object sender, RoutedEventArgs e)
    {
        try
        {
            var engine = new ThreatAnalysisEngine(new UrlAnalyzer(new DomainNames()));
            var result = engine.Analyze(new AnalysisContext("SelfTest", "Pilnie: blokada konta. Zaloguj się, aby potwierdzić dane.", DateTimeOffset.UtcNow,
                new NavigationSignal("https://paypal.com.evil.test/login")));
            SelfTestStatus.Text = result.Risk >= RiskLevel.High && result.Indicators.Count > 0
                ? "Test zaliczony: lokalne reguły wykryły znany syntetyczny przykład. Test nie wysyła danych i nie jest oceną ochrony całego komputera."
                : "Test nie został zaliczony. Nie włączono automatycznie dodatkowych funkcji.";
        }
        catch (Exception ex)
        {
            SelfTestStatus.Text = $"Test nie powiódł się ({ex.GetType().Name}). Konfiguracja nie została zmieniona.";
        }
    }
}
