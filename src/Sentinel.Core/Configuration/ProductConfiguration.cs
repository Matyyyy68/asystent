namespace Sentinel.Core.Configuration;

public enum ProductVariant { User, EnterpriseClient }
public enum SystemFactStatus { Available, Unknown, Unsupported }
public enum NpuAvailability { Detected, NotDetected, Unknown }

/// <summary>Installation identity is provisioned by the installer or explicit Enterprise pairing, not an ordinary preference.</summary>
public sealed record InstalledProductProfile(ProductVariant Variant = ProductVariant.User, string? EnterpriseServerUri = null, int SchemaVersion = 1, bool ShareSecurityMetadata = false)
{
    public InstalledProductProfile Validate()
    {
        if (!Enum.IsDefined(Variant) || SchemaVersion != 1) throw new ArgumentException("Nieobsługiwany profil produktu.");
        if (Variant == ProductVariant.User && EnterpriseServerUri is not null)
            throw new ArgumentException("Wariant User nie może zawierać adresu serwera.");
        if (Variant == ProductVariant.User && ShareSecurityMetadata)
            throw new ArgumentException("Wariant User nie może włączać synchronizacji Enterprise.");
        if (EnterpriseServerUri is { } address)
        {
            if (address.Length > 2048 || !Uri.TryCreate(address, UriKind.Absolute, out var uri) ||
                uri.Scheme != Uri.UriSchemeHttps || string.IsNullOrEmpty(uri.Host) || uri.UserInfo.Length > 0 ||
                uri.Query.Length > 0 || uri.Fragment.Length > 0 || uri.AbsolutePath != "/")
                throw new ArgumentException("Adres serwera Enterprise musi być bezpiecznym adresem HTTPS bez poświadczeń ani ścieżki API.");
            if (Variant != ProductVariant.EnterpriseClient)
                throw new ArgumentException("Adres serwera wymaga wariantu Enterprise Client.");
        }
        return this;
    }
}

public static class ProductProfileArguments
{
    /// <summary>Installer bootstrap arguments contain configuration only, never passwords, tokens or enrollment codes.</summary>
    public static InstalledProductProfile Parse(IEnumerable<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var variant = ProductVariant.User;
        var variantSeen = false;
        string? server = null;
        foreach (var argument in arguments)
        {
            if (argument.Equals("--sentinel-variant=user", StringComparison.OrdinalIgnoreCase)) { if (variantSeen) throw new ArgumentException("Powtórzony wariant produktu."); variant = ProductVariant.User; variantSeen = true; }
            else if (argument.Equals("--sentinel-variant=enterprise-client", StringComparison.OrdinalIgnoreCase)) { if (variantSeen) throw new ArgumentException("Powtórzony wariant produktu."); variant = ProductVariant.EnterpriseClient; variantSeen = true; }
            else if (argument.StartsWith("--sentinel-server=", StringComparison.OrdinalIgnoreCase))
            {
                if (server is not null) throw new ArgumentException("Powtórzony adres serwera.");
                server = argument["--sentinel-server=".Length..];
            }
            else throw new ArgumentException("Nieznany parametr instalatora Sentinel AI.");
        }
        return new InstalledProductProfile(variant, server).Validate();
    }
}

/// <summary>Facts collected locally from Windows. Null means that the value could not be verified.</summary>
public sealed record SystemSnapshot(
    string OperatingSystem,
    string? Edition,
    string Architecture,
    string? ProcessorName,
    int? LogicalProcessors,
    ulong? TotalMemoryBytes,
    ulong? AvailableMemoryBytes,
    long? FreeDiskBytes,
    IReadOnlyList<string>? DisplayAdapters,
    NpuAvailability Npu,
    bool? NetworkAvailable,
    IReadOnlyList<string> DetectedSecurityProducts,
    bool IsWindows,
    bool Is64Bit);

public sealed record RecommendedConfiguration(
    ProductVariant Variant,
    IReadOnlyList<string> AvailableModules,
    IReadOnlyList<string> UnavailableModules,
    string AnalysisMode,
    bool RequiresNetworkForBasicAnalysis,
    string Summary,
    IReadOnlyList<string> Notices);

/// <summary>Only recommends capabilities that exist in this build; it never infers GPU compatibility from its name.</summary>
public sealed class ConfigurationRecommendationEngine
{
    public RecommendedConfiguration Recommend(SystemSnapshot system, ProductVariant variant)
    {
        ArgumentNullException.ThrowIfNull(system);
        if (!Enum.IsDefined(variant)) throw new ArgumentOutOfRangeException(nameof(variant));
        var available = new List<string>
        {
            "Lokalny silnik reguł",
            "Lokalna historia SQLite",
            "Lokalna baza pełnotekstowa FTS5 (TXT, MD, DOCX i tekstowy PDF)",
            "Integracja Chrome/Edge przez ręcznie instalowane rozszerzenie MV3; ostrzega, ale nie blokuje nawigacji",
            "Opcjonalna analiza przez wcześniej zainstalowany Ollama loopback"
        };
        var unavailable = new List<string>
        {
            "Pełne wyszukiwanie semantyczne w całej bazie i OCR PDF",
            "Automatyczny dobór modelu do GPU/RAM/NPU — brak zweryfikowanego katalogu wymagań"
        };
        var notices = new List<string>();
        if (!system.IsWindows) notices.Add("Pełny klient desktopowy wymaga Windows 10/11 x64; wykrywanie nie potwierdziło Windows.");
        if (!system.Is64Bit) notices.Add("System nie jest 64-bitowy; instalator x64 nie może być użyty.");
        if (system.TotalMemoryBytes is null) notices.Add("Nie można wiarygodnie ustalić pamięci RAM.");
        if (system.FreeDiskBytes is null) notices.Add("Nie można ustalić wolnego miejsca na dysku.");
        else if (system.FreeDiskBytes < 50L * 1024 * 1024) notices.Add("Na dysku jest mniej niż 50 MB wolnego miejsca wymaganego przez lokalną bazę.");
        if (system.DisplayAdapters is null) notices.Add("Nie można odczytać nazw adapterów graficznych; ich zgodność z backendem AI pozostaje nieznana.");
        else if (system.DisplayAdapters.Count > 0) notices.Add("Wykryto adaptery graficzne, ale zgodność z modelem i backendem nie została zweryfikowana. Nazwa karty nie wystarcza do rekomendacji.");
        if (system.Npu == NpuAvailability.Unknown) notices.Add("Dostępność NPU pozostaje nieznana; ten build nie ma zweryfikowanego interfejsu detekcji NPU.");
        if (system.DetectedSecurityProducts.Count > 0)
            notices.Add("Wykryto lokalnie inne składniki ochrony. Sentinel AI ich nie wyłączy ani nie zmieni ich ustawień.");
        if (variant == ProductVariant.EnterpriseClient)
        {
            available.Add("Parowanie Enterprise przez HTTPS, poświadczenie chronione DPAPI, heartbeat i synchronizacja wyłącznie metadanych po świadomej zgodzie");
            available.Add("Pobieranie lokalnej polityki organizacji i dostarczenie ograniczonych zdarzeń offline po odzyskaniu połączenia");
            unavailable.Add("Serwerowa analiza treści i automatyczne przyjęcie/odwołanie urządzenia z poziomu klienta");
            unavailable.Add("Automatyczna aktualizacja klienta z podpisaną paczką; urządzenia oczekujące na zatwierdzenie wymagają weryfikacji w panelu administratora");
            notices.Add("Wariant Enterprise pozostaje lokalny do czasu HTTPS parowania z jednorazowym zaproszeniem i osobnej zgody na przesyłanie metadanych zdarzeń.");
            if (system.NetworkAvailable == false) notices.Add("Nie wykryto połączenia sieciowego. Lokalna analiza reguł nadal działa offline.");
        }
        return new(variant, available, unavailable, "Lokalne reguły + opcjonalny Ollama loopback", false,
            "Podstawowa analiza i wyszukiwanie dokumentów działają lokalnie. Model AI jest opcjonalny i wymaga wcześniej zainstalowanego, przetestowanego Ollama oraz wyboru użytkownika; model nie jest automatycznie pobierany. Podstawowe wyszukiwanie wiedzy jest pełnotekstowe; opcjonalny reranking embeddingami porządkuje tylko kandydatów znalezionych przez FTS5.", notices);
    }
}
