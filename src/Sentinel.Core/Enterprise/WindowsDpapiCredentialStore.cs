using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Core.Enterprise;

/// <summary>Stores the Enterprise bearer token protected for the current Windows user by DPAPI.</summary>
public sealed class WindowsDpapiCredentialStore(string directory) : IDeviceCredentialStore
{
    private const int UiForbidden = 0x1;
    private const string Description = "Sentinel AI Enterprise device credential";
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("SentinelAI/EnterpriseCredential/v1");
    private readonly string path = Path.Combine(Path.GetFullPath(directory), "enterprise-credential.bin");

    public async Task<string?> ReadAsync(CancellationToken cancellationToken = default)
    {
        EnsureWindows();
        if (!File.Exists(path)) return null;
        var encrypted = await File.ReadAllBytesAsync(path, cancellationToken);
        if (encrypted.Length is < 1 or > 4096) throw new InvalidDataException("Nieprawidłowy zapis poświadczenia Enterprise.");
        var clear = Unprotect(encrypted);
        try
        {
            var token = new UTF8Encoding(false, true).GetString(clear);
            ValidateToken(token);
            return token;
        }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }

    public async Task WriteAsync(string token, CancellationToken cancellationToken = default)
    {
        EnsureWindows();
        ValidateToken(token);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var clear = Encoding.UTF8.GetBytes(token);
        byte[] encrypted;
        try { encrypted = Protect(clear); }
        finally { CryptographicOperations.ZeroMemory(clear); }
        var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(encrypted, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encrypted);
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    public Task DeleteAsync(CancellationToken cancellationToken = default)
    {
        EnsureWindows(); cancellationToken.ThrowIfCancellationRequested();
        if (File.Exists(path)) File.Delete(path);
        return Task.CompletedTask;
    }

    private static void ValidateToken(string token)
    {
        if (token is null || token.Length is < 40 or > 100 || token.Any(char.IsControl))
            throw new ArgumentException("Nieprawidłowe poświadczenie urządzenia.", nameof(token));
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Poświadczenia Enterprise wymagają Windows DPAPI.");
    }

    private static byte[] Protect(byte[] input) => Transform(input, protect: true);
    private static byte[] Unprotect(byte[] input) => Transform(input, protect: false);

    private static byte[] Transform(byte[] input, bool protect)
    {
        var inputPointer = Marshal.AllocHGlobal(input.Length);
        var entropyPointer = Marshal.AllocHGlobal(Entropy.Length);
        try
        {
            Marshal.Copy(input, 0, inputPointer, input.Length);
            Marshal.Copy(Entropy, 0, entropyPointer, Entropy.Length);
            var inputBlob = new DataBlob(input.Length, inputPointer);
            var entropyBlob = new DataBlob(Entropy.Length, entropyPointer);
            DataBlob output;
            var success = protect
                ? CryptProtectData(ref inputBlob, Description, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, UiForbidden, out output)
                : CryptUnprotectData(ref inputBlob, IntPtr.Zero, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, UiForbidden, out output);
            if (!success) throw new CryptographicException($"Windows DPAPI failed with error {Marshal.GetLastWin32Error()}.");
            try
            {
                if (output.Length is < 1 or > 4096) throw new CryptographicException("DPAPI zwróciło nieprawidłową długość danych.");
                var result = new byte[output.Length]; Marshal.Copy(output.Data, result, 0, output.Length); return result;
            }
            finally
            {
                if (!protect && output.Data != IntPtr.Zero && output.Length is > 0 and <= 4096)
                    Marshal.Copy(new byte[output.Length], 0, output.Data, output.Length);
                LocalFree(output.Data);
            }
        }
        finally
        {
            Marshal.Copy(new byte[input.Length], 0, inputPointer, input.Length);
            Marshal.Copy(new byte[Entropy.Length], 0, entropyPointer, Entropy.Length);
            Marshal.FreeHGlobal(inputPointer); Marshal.FreeHGlobal(entropyPointer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob(int length, IntPtr data) { public int Length = length; public IntPtr Data = data; }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref DataBlob input, string description, ref DataBlob optionalEntropy,
        IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, ref DataBlob optionalEntropy,
        IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
