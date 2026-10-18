using System.IO;
using Microsoft.Win32;

namespace Sentinel.Desktop;

internal static class AutostartRegistration
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "SentinelAI";

    public static void SetEnabled(bool enabled)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Autostart Sentinel AI wymaga Windows.");
        if (!enabled)
        {
            using var existing = Registry.CurrentUser.OpenSubKey(RunKey, writable: true);
            existing?.DeleteValue(ValueName, throwOnMissingValue: false);
            return;
        }

        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable) || !Path.IsPathFullyQualified(executable) || !File.Exists(executable))
            throw new InvalidOperationException("Nie można bezpiecznie ustalić ścieżki programu do autostartu.");

        using var key = Registry.CurrentUser.CreateSubKey(RunKey, writable: true)
            ?? throw new UnauthorizedAccessException("Nie można zapisać autostartu bieżącego użytkownika.");
        key.SetValue(ValueName, $"\"{executable}\"", RegistryValueKind.String);
    }
}
