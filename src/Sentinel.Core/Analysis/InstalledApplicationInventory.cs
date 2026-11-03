using System.Runtime.Versioning;
using Microsoft.Win32;

namespace Sentinel.Core.Analysis;

public sealed record InstalledApplication(string Name, string? Version, string? Publisher);
public sealed record InstalledApplicationInventorySnapshot(
    IReadOnlyList<InstalledApplication> Applications,
    bool Complete,
    DateTimeOffset ScannedAtUtc);

/// <summary>Reads only installed-app display metadata; it never executes uninstall commands or scans files.</summary>
public static class InstalledApplicationInventoryReader
{
    private const int MaximumApplications = 4096;
    private const int MaximumValueLength = 200;
    private const string UninstallSubkey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    public static InstalledApplicationInventorySnapshot Read()
    {
        if (!OperatingSystem.IsWindows())
            return new([], false, DateTimeOffset.UtcNow);

        var entries = new List<InstalledApplication>(512);
        var complete = true;
        foreach (var (hive, view) in RegistryLocations())
        {
            try { ReadLocation(hive, view, entries); }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            { complete = false; }
            if (entries.Count >= MaximumApplications)
            {
                entries.RemoveRange(MaximumApplications, entries.Count - MaximumApplications);
                complete = false;
                break;
            }
        }

        var normalized = Normalize(entries);
        return new(normalized, complete, DateTimeOffset.UtcNow);
    }

    public static async Task<InstalledApplicationInventorySnapshot> ReadAvailableAsync(
        Task<InstalledApplicationInventorySnapshot> inventoryTask, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inventoryTask);
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(timeout));
        try { return await inventoryTask.WaitAsync(timeout, cancellationToken).ConfigureAwait(false); }
        catch (TimeoutException) { return new([], false, DateTimeOffset.UtcNow); }
    }

    public static IReadOnlyList<InstalledApplication> Normalize(IEnumerable<InstalledApplication> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        return entries
            .Where(entry => !string.IsNullOrWhiteSpace(entry.Name))
            .Select(entry => new InstalledApplication(
                Bound(entry.Name)!, Bound(entry.Version), Bound(entry.Publisher)))
            .DistinctBy(entry => (entry.Name, entry.Version, entry.Publisher), InstalledApplicationKeyComparer.Instance)
            .Take(MaximumApplications)
            .ToArray();
    }

    [SupportedOSPlatform("windows")]
    private static IEnumerable<(RegistryHive Hive, RegistryView View)> RegistryLocations()
    {
        yield return (RegistryHive.LocalMachine, RegistryView.Registry64);
        yield return (RegistryHive.LocalMachine, RegistryView.Registry32);
        yield return (RegistryHive.CurrentUser, RegistryView.Default);
    }

    [SupportedOSPlatform("windows")]
    private static void ReadLocation(RegistryHive hive, RegistryView view, List<InstalledApplication> entries)
    {
        using var baseKey = RegistryKey.OpenBaseKey(hive, view);
        using var uninstall = baseKey.OpenSubKey(UninstallSubkey, writable: false);
        if (uninstall is null) return;
        foreach (var subkeyName in uninstall.GetSubKeyNames())
        {
            if (entries.Count >= MaximumApplications) return;
            try
            {
                using var application = uninstall.OpenSubKey(subkeyName, writable: false);
                if (application is null || ReadDword(application, "SystemComponent") == 1 ||
                    !string.IsNullOrWhiteSpace(ReadString(application, "ParentKeyName"))) continue;
                var name = ReadString(application, "DisplayName");
                if (string.IsNullOrWhiteSpace(name)) continue;
                entries.Add(new(name, ReadString(application, "DisplayVersion"), ReadString(application, "Publisher")));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            { /* One inaccessible or concurrently removed entry does not hide the rest of the inventory. */ }
        }
    }

    [SupportedOSPlatform("windows")]
    private static int? ReadDword(RegistryKey key, string name)
    {
        try { return key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is int value ? value : null; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException) { return null; }
    }

    [SupportedOSPlatform("windows")]
    private static string? ReadString(RegistryKey key, string name)
    {
        try
        {
            var value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            return value is string text ? text : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException) { return null; }
    }

    private static string? Bound(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var normalized = new string(value.Where(character => !char.IsControl(character)).Take(MaximumValueLength).ToArray()).Trim();
        return normalized.Length == 0 ? null : normalized;
    }

    private sealed class InstalledApplicationKeyComparer : IEqualityComparer<(string Name, string? Version, string? Publisher)>
    {
        public static InstalledApplicationKeyComparer Instance { get; } = new();
        public bool Equals((string Name, string? Version, string? Publisher) x, (string Name, string? Version, string? Publisher) y) =>
            StringComparer.OrdinalIgnoreCase.Equals(x.Name, y.Name) &&
            StringComparer.OrdinalIgnoreCase.Equals(x.Version, y.Version) &&
            StringComparer.OrdinalIgnoreCase.Equals(x.Publisher, y.Publisher);
        public int GetHashCode((string Name, string? Version, string? Publisher) value) =>
            HashCode.Combine(StringComparer.OrdinalIgnoreCase.GetHashCode(value.Name),
                value.Version is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(value.Version),
                value.Publisher is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(value.Publisher));
    }
}
