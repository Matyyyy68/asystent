using Sentinel.Core.Enterprise;
using System.Security.Cryptography;
using Xunit;

namespace Sentinel.Tests;

/// <summary>Marks integration tests that need a working current-user Windows DPAPI profile.</summary>
public sealed class WindowsDpapiFactAttribute : FactAttribute
{
    public WindowsDpapiFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Windows DPAPI integration requires Windows.";
            return;
        }

        try
        {
            var directory = Path.Combine(Path.GetTempPath(), "sentinel-dpapi-probe-" + Guid.NewGuid().ToString("N"));
            try
            {
                new WindowsDpapiCredentialStore(directory).WriteAsync("dpapi-profile-probe-0123456789012345678901234567890123456789")
                    .GetAwaiter().GetResult();
            }
            finally
            {
                if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
            }
        }
        catch (CryptographicException)
        {
            Skip = "Windows DPAPI integration requires an available current-user profile.";
        }
    }
}

/// <summary>Marks tests that change Windows filesystem ACLs.</summary>
public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
            Skip = "This integration test requires Windows.";
    }
}
