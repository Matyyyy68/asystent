using System.Security.Cryptography;

namespace Sentinel.Core.Enterprise;

/// <summary>Rotates an Enterprise credential without losing the currently working credential on staging failure.</summary>
public sealed class EnterpriseCredentialRotator(EnterpriseAgentClient client, IDeviceCredentialStore credentialStore)
{
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
