using System.Runtime.InteropServices;

public sealed record WindowsSecurityCenterStatus(string Antivirus, string Firewall, DateTimeOffset CheckedAtUtc);

/// <summary>Reads aggregate Windows Security Center health. It does not identify a product or change system settings.</summary>
public static class WindowsSecurityCenterReader
{
    private const uint AntivirusProvider = 0x4;
    private const uint FirewallProvider = 0x1;
    private static readonly object Gate = new();
    private static DateTimeOffset cachedAt;
    private static WindowsSecurityCenterStatus? cached;

    [DllImport("wscapi.dll", EntryPoint = "WscGetSecurityProviderHealth", ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
    private static extern int GetProviderHealth(uint providers, out uint health);

    public static WindowsSecurityCenterStatus Read()
    {
        lock (Gate)
        {
            var now = DateTimeOffset.UtcNow;
            if (cached is not null && now - cachedAt < TimeSpan.FromMinutes(1)) return cached;
            cachedAt = now;
            cached = !OperatingSystem.IsWindows()
                ? new("wymaga Windows", "wymaga Windows", now)
                : new(ReadProvider(AntivirusProvider), ReadProvider(FirewallProvider), now);
            return cached;
        }
    }

    private static string ReadProvider(uint provider)
    {
        try
        {
            var hresult = GetProviderHealth(provider, out var health);
            if (hresult == 1) return "Windows Security Center niedostępne";
            if (hresult != 0) return $"odczyt niedostępny (0x{hresult:X8})";
            return health switch
            {
                0 => "stan dobry według Windows Security Center",
                1 => "nie jest monitorowane przez Windows Security Center",
                2 => "wymaga uwagi według Windows Security Center",
                3 => "wstrzymane według Windows Security Center",
                _ => "nieznany stan Windows Security Center"
            };
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            return "API Windows Security Center niedostępne";
        }
    }
}
