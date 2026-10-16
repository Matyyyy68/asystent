using System.Security.Cryptography;
using System.Text;
using System.IO;
using Sentinel.Core.Enterprise;

namespace Sentinel.Desktop;

/// <summary>Protects the device token with Windows DPAPI for the current user.</summary>
public sealed class WindowsDeviceCredentialStore : IDeviceCredentialStore
{
    private readonly string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelAI", "enterprise-credential.bin");

    public async Task<string?> ReadAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(path)) return null;
        var protectedBytes = await File.ReadAllBytesAsync(path, cancellationToken);
        try
        {
            var clear = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(clear);
        }
        catch (CryptographicException ex) { throw new InvalidDataException("Nie można odszyfrować poświadczenia urządzenia dla tego konta Windows.", ex); }
    }

    public async Task WriteAsync(string token, CancellationToken cancellationToken = default)
    {
        if (token.Length is < 40 or > 100 || token.Any(char.IsControl)) throw new ArgumentException("Nieprawidłowe poświadczenie urządzenia.", nameof(token));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var protectedBytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(token), null, DataProtectionScope.CurrentUser);
        var temporary = path + ".new";
        await File.WriteAllBytesAsync(temporary, protectedBytes, cancellationToken);
        File.Move(temporary, path, overwrite: true);
    }

    public Task DeleteAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (File.Exists(path)) File.Delete(path);
        return Task.CompletedTask;
    }
}
