using System.Security.Cryptography;

namespace Sentinel.Core.Enterprise;

/// <summary>Rotates Enterprise credentials without losing the currently working credential on staging failure.</summary>
public sealed class EnterpriseCredentialRotator
{
    public static readonly TimeSpan AutomaticRotationInterval = TimeSpan.FromDays(90);
    private readonly EnterpriseAgentClient client;
    private readonly IDeviceCredentialStore credentialStore;
    private readonly TimeProvider timeProvider;

    public EnterpriseCredentialRotator(EnterpriseAgentClient client, IDeviceCredentialStore credentialStore, TimeProvider? timeProvider = null)
    {
        this.client = client ?? throw new ArgumentNullException(nameof(client));
        this.credentialStore = credentialStore ?? throw new ArgumentNullException(nameof(credentialStore));
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<bool> RotateIfDueAsync(Uri server, CancellationToken cancellationToken = default)
    {
        var current = await credentialStore.ReadAsync(cancellationToken);
        if (string.IsNullOrEmpty(current)) return false;
        var lastUpdated = await credentialStore.GetLastUpdatedAtUtcAsync(cancellationToken);
        var now = timeProvider.GetUtcNow();
        if (lastUpdated is { } updated && updated <= now && now - updated < AutomaticRotationInterval) return false;
        await RotateAsync(server, cancellationToken);
        return true;
    }

    public async Task RotateAsync(Uri server, CancellationToken cancellationToken = default)
    {
        var current = await credentialStore.ReadAsync(cancellationToken)
            ?? throw new InvalidOperationException("Brak poświadczenia urządzenia; sparuj je ponownie.");
        if (current.Length is < 40 or > 100 || current.Any(char.IsControl))
            throw new InvalidDataException("Zapisane poświadczenie urządzenia jest nieprawidłowe.");

        var replacement = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        await client.RotateCredentialAsync(server, current, replacement, cancellationToken);
        await credentialStore.WriteAsync(replacement, cancellationToken);

        // The server promotes the staged token on its first authenticated request.
        // Keep the new token locally before that request so a lost response is recoverable on next sync.
        await client.SendHeartbeatAsync(server, replacement, cancellationToken: cancellationToken);
    }
}
