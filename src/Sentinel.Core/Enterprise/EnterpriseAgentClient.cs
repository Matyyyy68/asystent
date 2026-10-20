using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.Core.Enterprise;

public sealed record EnterpriseEnrollment(string DeviceId, string DeviceToken, string Group, DateTimeOffset RegisteredAt);
public sealed record PendingEnterpriseEvent(Guid EventId, DateTimeOffset OccurredAt, string Category, int RiskLevel, string RuleCode,
    string Source = "unknown", string? RuleVersion = null, int SchemaVersion = 1);

/// <summary>Stores the per-device bearer credential in the platform's protected credential store.</summary>
public interface IDeviceCredentialStore
{
    Task<string?> ReadAsync(CancellationToken cancellationToken = default);
    Task WriteAsync(string token, CancellationToken cancellationToken = default);
    Task DeleteAsync(CancellationToken cancellationToken = default);
}

/// <summary>Small HTTPS-only client for pairing and privacy-minimal Enterprise synchronization.</summary>
public sealed class EnterpriseAgentClient(HttpClient httpClient)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static Uri ValidateServer(string value)
    {
        if (value.Length is < 9 or > 2048 || !Uri.TryCreate(value.TrimEnd('/'), UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps || string.IsNullOrWhiteSpace(uri.Host) || uri.UserInfo.Length != 0 ||
            uri.Query.Length != 0 || uri.Fragment.Length != 0 || uri.AbsolutePath != "/")
            throw new ArgumentException("Adres serwera musi być adresem HTTPS bez ścieżki, parametrów ani danych logowania.", nameof(value));
        return new Uri(uri.GetLeftPart(UriPartial.Authority) + "/", UriKind.Absolute);
    }

    public async Task<EnterpriseEnrollment> EnrollAsync(Uri server, string invitationCode, string deviceName,
        string clientVersion, CancellationToken cancellationToken = default)
    {
        EnsureServer(server);
        if (string.IsNullOrWhiteSpace(invitationCode) || invitationCode.Length > 100 || invitationCode.Any(char.IsControl))
            throw new ArgumentException("Nieprawidłowy kod zaproszenia.", nameof(invitationCode));
        if (string.IsNullOrWhiteSpace(deviceName) || deviceName.Length > 120 || deviceName.Any(char.IsControl))
            throw new ArgumentException("Nieprawidłowa nazwa urządzenia.", nameof(deviceName));
        if (string.IsNullOrWhiteSpace(clientVersion) || clientVersion.Length > 40 || clientVersion.Any(char.IsControl))
            throw new ArgumentException("Nieprawidłowa wersja klienta.", nameof(clientVersion));

        using var response = await httpClient.PostAsJsonAsync(new Uri(server, "api/v1/agents/enroll"),
            new { invitationCode = invitationCode.Trim(), deviceName = deviceName.Trim(), clientVersion }, JsonOptions, cancellationToken);
        await EnsureSuccess(response, cancellationToken);
        var enrollment = await response.Content.ReadFromJsonAsync<EnterpriseEnrollment>(JsonOptions, cancellationToken)
            ?? throw new InvalidDataException("Serwer zwrócił pustą odpowiedź rejestracji.");
        if (enrollment.DeviceToken is null || enrollment.DeviceToken.Length is < 40 or > 100 || enrollment.DeviceToken.Any(char.IsControl) ||
            enrollment.DeviceId is null || enrollment.DeviceId.Length is < 1 or > 100 || enrollment.DeviceId.Any(char.IsControl) ||
            string.IsNullOrWhiteSpace(enrollment.Group) || enrollment.Group.Length > 120 || enrollment.Group.Any(char.IsControl) ||
            enrollment.RegisteredAt == default)
            throw new InvalidDataException("Serwer zwrócił nieprawidłowe poświadczenie urządzenia.");
        return enrollment;
    }

    public async Task<JsonDocument> ReadConfigurationAsync(Uri server, string credential, CancellationToken cancellationToken = default)
    {
        using var request = CreateRequest(server, "api/v1/agents/configuration", credential);
        using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        await EnsureSuccess(response, cancellationToken);
        if (response.Content.Headers.ContentLength is > 64 * 1024) throw new InvalidDataException("Konfiguracja serwera przekracza limit rozmiaru.");
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var bounded = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken);
            if (read == 0) break;
            if (bounded.Length + read > 64 * 1024) throw new InvalidDataException("Konfiguracja serwera przekracza limit rozmiaru.");
            await bounded.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
        bounded.Position = 0;
        return await JsonDocument.ParseAsync(bounded, new JsonDocumentOptions { MaxDepth = 24 }, cancellationToken);
    }

    public async Task SendHeartbeatAsync(Uri server, string credential, string? lastError = null, CancellationToken cancellationToken = default)
    {
        if (lastError is not (null or "local_store" or "sync_failed" or "configuration_invalid" or "client_update"))
            throw new ArgumentException("Nieobsługiwany kod błędu.", nameof(lastError));
        using var request = CreateRequest(server, "api/v1/agents/heartbeat", credential);
        request.Method = HttpMethod.Post;
        request.Content = JsonContent.Create(new { lastError }, options: JsonOptions);
        using var response = await httpClient.SendAsync(request, cancellationToken);
        await EnsureSuccess(response, cancellationToken);
    }

    public async Task RotateCredentialAsync(Uri server, string currentCredential, string newCredential, CancellationToken cancellationToken = default)
    {
        using var request = CreateRequest(server, "api/v1/agents/credentials/rotate", currentCredential);
        if (newCredential.Length is < 40 or > 100 || newCredential.Any(char.IsControl))
            throw new ArgumentException("Nieprawidłowe nowe poświadczenie urządzenia.", nameof(newCredential));
        request.Method = HttpMethod.Post;
        request.Content = JsonContent.Create(new { newDeviceToken = newCredential }, options: JsonOptions);
        using var response = await httpClient.SendAsync(request, cancellationToken);
        await EnsureSuccess(response, cancellationToken);
    }

    public async Task<EnterpriseEventBatchResultV1> SendEventsAsync(Uri server, string credential,
        IReadOnlyList<PendingEnterpriseEvent> events, CancellationToken cancellationToken = default)
    {
        if (events.Count is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(events), "Batch musi zawierać 1–100 zdarzeń.");
        var contractEvents = events.Select(e => new EnterpriseEventV1(e.EventId, e.OccurredAt, e.Category, e.RiskLevel, e.RuleCode,
            EnterpriseEventV1Rules.NormalizeSource(e.Source), EnterpriseEventV1Rules.NormalizeRuleVersion(e.RuleVersion), e.SchemaVersion)).ToArray();
        foreach (var item in contractEvents)
            if (EnterpriseEventV1Rules.Validate(item, DateTimeOffset.UtcNow) is { } validation)
                throw new InvalidDataException(validation);
        using var request = CreateRequest(server, "api/v1/agents/events", credential);
        request.Method = HttpMethod.Post;
        request.Content = JsonContent.Create(new EnterpriseEventBatchV1(contractEvents), options: JsonOptions);
        using var response = await httpClient.SendAsync(request, cancellationToken);
        await EnsureSuccess(response, cancellationToken);
        var result = await response.Content.ReadFromJsonAsync<EnterpriseEventBatchResultV1>(JsonOptions, cancellationToken)
            ?? throw new InvalidDataException("Serwer zwrócił pusty wynik synchronizacji.");
        if (result.Accepted < 0 || result.Duplicates < 0 || result.Accepted + result.Duplicates != events.Count)
            throw new InvalidDataException("Serwer zwrócił niezgodny wynik synchronizacji zdarzeń.");
        return result;
    }

    private static HttpRequestMessage CreateRequest(Uri server, string path, string credential)
    {
        EnsureServer(server);
        if (credential.Length is < 40 or > 100 || credential.Any(char.IsControl)) throw new ArgumentException("Nieprawidłowe poświadczenie urządzenia.", nameof(credential));
        var request = new HttpRequestMessage(HttpMethod.Get, new Uri(server, path));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential);
        return request;
    }

    private static void EnsureServer(Uri server)
    {
        if (!server.IsAbsoluteUri || server.Scheme != Uri.UriSchemeHttps || server.UserInfo.Length != 0 ||
            server.Query.Length != 0 || server.Fragment.Length != 0 || server.AbsolutePath != "/")
            throw new ArgumentException("Komunikacja z serwerem Enterprise wymaga poprawnego adresu HTTPS.", nameof(server));
    }

    private static async Task EnsureSuccess(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode) return;
        var status = (int)response.StatusCode;
        var safe = response.StatusCode switch
        {
            HttpStatusCode.Unauthorized => "Serwer odrzucił poświadczenie lub zaproszenie.",
            HttpStatusCode.Forbidden => "Polityka serwera nie zezwala na tę operację.",
            HttpStatusCode.ServiceUnavailable => "Serwer lub jego lokalny model jest niedostępny.",
            _ => $"Serwer Enterprise zwrócił błąd HTTP {status}."
        };
        throw new HttpRequestException(safe, null, response.StatusCode);
    }
}
