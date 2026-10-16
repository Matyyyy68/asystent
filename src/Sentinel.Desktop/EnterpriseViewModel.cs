using System.ComponentModel;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;
using Sentinel.Core;
using Sentinel.Core.Configuration;
using Sentinel.Core.Enterprise;

namespace Sentinel.Desktop;

public sealed class EnterpriseViewModel : INotifyPropertyChanged
{
    private readonly LocalStore store;
    private readonly EnterpriseAgentClient client;
    private readonly IDeviceCredentialStore credentials;
    private string serverAddress = "";
    private string invitationCode = "";
    private string status = "Nie skonfigurowano połączenia.";
    private string deviceStatus = "Nie sparowano urządzenia.";
    private bool isPaired;
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Changed([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new(name));
    public string ServerAddress { get => serverAddress; set { serverAddress = value; Changed(); } }
    public string InvitationCode { get => invitationCode; set { invitationCode = value; Changed(); } }
    public string Status { get => status; private set { status = value; Changed(); } }
    public string DeviceStatus { get => deviceStatus; private set { deviceStatus = value; Changed(); } }
    public bool IsPaired { get => isPaired; private set { isPaired = value; Changed(); } }
    public AsyncCommand Pair { get; }
    public AsyncCommand Synchronize { get; }

    public EnterpriseViewModel(LocalStore store, EnterpriseAgentClient client, IDeviceCredentialStore credentials)
    {
        this.store = store; this.client = client; this.credentials = credentials;
        Pair = new AsyncCommand(PairAsync, ShowSafeError);
        Synchronize = new AsyncCommand(SynchronizeAsync, ShowSafeError);
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        var profile = await store.GetInstallationProfileAsync(cancellationToken);
        ServerAddress = profile.EnterpriseServerUri ?? "";
        string? token;
        try { token = await credentials.ReadAsync(cancellationToken); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException)
        {
            IsPaired = false; DeviceStatus = "Nie można odczytać poświadczenia Enterprise.";
            Status = "Lokalna analiza działa. Ponów parowanie lub poproś administratora o unieważnienie poprzedniego urządzenia.";
            return;
        }
        IsPaired = profile.Variant == ProductVariant.EnterpriseClient && profile.EnterpriseServerUri is not null && token is not null;
        DeviceStatus = IsPaired ? "Urządzenie ma zapisane poświadczenie Windows." : "Nie sparowano urządzenia.";
        if (profile.Variant != ProductVariant.EnterpriseClient)
            Status = "Połączenie Enterprise jest dostępne tylko w wariancie Enterprise Client.";
    }

    private async Task PairAsync()
    {
        var profile = await store.GetInstallationProfileAsync();
        if (profile.Variant != ProductVariant.EnterpriseClient) throw new InvalidOperationException("To urządzenie nie jest zainstalowane jako Enterprise Client.");
        if (string.IsNullOrWhiteSpace(InvitationCode)) throw new ArgumentException("Wpisz kod jednorazowego zaproszenia administratora.");
        var server = EnterpriseAgentClient.ValidateServer(ServerAddress);
        Status = "Trwa bezpieczne parowanie przez HTTPS…";
        var enrollment = await client.EnrollAsync(server, InvitationCode, Environment.MachineName, typeof(EnterpriseViewModel).Assembly.GetName().Version?.ToString(3) ?? "0.0.0");
        await store.UpdateEnterpriseServerAsync(server.ToString());
        await credentials.WriteAsync(enrollment.DeviceToken);
        ServerAddress = server.ToString().TrimEnd('/'); InvitationCode = ""; IsPaired = true;
        DeviceStatus = $"Połączono urządzenie z grupą „{enrollment.Group}”.";
        Status = "Parowanie zakończone. Poświadczenie jest chronione przez Windows DPAPI dla tego konta.";
    }

    private async Task SynchronizeAsync()
    {
        var profile = await store.GetInstallationProfileAsync();
        if (profile.Variant != ProductVariant.EnterpriseClient || profile.EnterpriseServerUri is null)
            throw new InvalidOperationException("Najpierw zapisz poprawny adres serwera i sparuj urządzenie.");
        var token = await credentials.ReadAsync() ?? throw new InvalidOperationException("Urządzenie nie jest sparowane.");
        var server = EnterpriseAgentClient.ValidateServer(profile.EnterpriseServerUri);
        Status = "Sprawdzam połączenie i pobieram efektywną politykę…";
        using var configuration = await client.ReadConfigurationAsync(server, token);
        if (!configuration.RootElement.TryGetProperty("effective", out var effective) || effective.ValueKind != System.Text.Json.JsonValueKind.Object)
            throw new InvalidDataException("Serwer zwrócił nieprawidłową konfigurację.");
        var pending = await store.ReadPendingEnterpriseEventsAsync(100);
        if (pending.Count > 0)
        {
            var result = await client.SendEventsAsync(server, token, pending);
            if (result.Accepted + result.Duplicates != pending.Count)
                throw new InvalidDataException("Serwer nie potwierdził wszystkich zdarzeń; pozostawiono je w lokalnej kolejce do ponowienia.");
            await store.MarkEnterpriseEventsSentAsync(pending.Select(item => item.EventId));
        }
        await client.SendHeartbeatAsync(server, token);
        Status = $"Połączenie sprawdzone. Wysłano {pending.Count} zdarzeń zawierających wyłącznie kategorię, poziom ryzyka i kod reguły. Efektywna polityka została pobrana; jej egzekwowanie w kliencie pozostaje nieaktywne.";
    }

    private void ShowSafeError(Exception exception)
    {
        Status = exception switch
        {
            HttpRequestException http when http.StatusCode is not null => $"Serwer odrzucił operację (HTTP {(int)http.StatusCode}). Sprawdź adres, zaproszenie lub uprawnienia polityki.",
            HttpRequestException => "Nie można połączyć się z serwerem. Sprawdź adres, certyfikat HTTPS i połączenie sieciowe.",
            ArgumentException => exception.Message,
            InvalidOperationException => exception.Message,
            _ => $"Operacja Enterprise nie powiodła się ({exception.GetType().Name}). Połączenie lokalne nadal działa."
        };
    }
}
