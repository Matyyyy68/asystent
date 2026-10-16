using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Sentinel.Core.Configuration;

namespace Sentinel.Desktop;

/// <summary>Reads only Windows metadata locally. It does not inspect user documents, browser data or mailboxes.</summary>
public static class WindowsSystemProbe
{
    private static readonly string[] SecurityProductNames =
    ["Defender", "Avast", "AVG", "McAfee", "Norton", "ESET", "Kaspersky", "Bitdefender", "Malwarebytes", "Trend Micro", "Sophos", "CrowdStrike", "SentinelOne"];

    public static SystemSnapshot Read()
    {
        var windows = OperatingSystem.IsWindows();
        return new(
            RuntimeInformation.OSDescription,
            windows ? ReadEdition() : null,
            RuntimeInformation.OSArchitecture.ToString(),
            windows ? ReadProcessorName() : null,
            Environment.ProcessorCount,
            ReadMemory(static s => s.TotalPhysical),
            ReadMemory(static s => s.AvailablePhysical),
            ReadFreeDisk(),
            windows ? ReadDisplayAdapters() : null,
            NpuAvailability.Unknown,
            ReadNetworkStatus(),
            windows ? ReadSecurityProducts() : [],
            windows,
            Environment.Is64BitOperatingSystem);
    }

    private static string? ReadEdition()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var product = key?.GetValue("ProductName") as string;
            var edition = key?.GetValue("EditionID") as string;
            var display = key?.GetValue("DisplayVersion") as string;
            return string.Join(" · ", new[] { product, edition, display }.Where(static s => !string.IsNullOrWhiteSpace(s)));
        }
        catch (Exception ex) when (ex is IOException or System.Security.SecurityException or UnauthorizedAccessException) { return null; }
    }

    private static string? ReadProcessorName()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            return (key?.GetValue("ProcessorNameString") as string)?.Trim();
        }
        catch (Exception ex) when (ex is IOException or System.Security.SecurityException or UnauthorizedAccessException) { return null; }
    }

    private static ulong? ReadMemory(Func<MemoryStatus, ulong> select)
    {
        try
        {
            var status = new MemoryStatus { Length = (uint)Marshal.SizeOf<MemoryStatus>() };
            return GlobalMemoryStatusEx(ref status) ? select(status) : null;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException) { return null; }
    }

    private static long? ReadFreeDisk()
    {
        try
        {
            var path = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var root = Path.GetPathRoot(path);
            return root is null ? null : new DriveInfo(root).AvailableFreeSpace;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { return null; }
    }

    private static IReadOnlyList<string>? ReadDisplayAdapters()
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            var adapters = new List<string>();
            for (uint index = 0; index < 32; index++)
            {
                var device = new DisplayDevice { Size = Marshal.SizeOf<DisplayDevice>() };
                if (!EnumDisplayDevices(null, index, ref device, 0)) break;
                if ((device.StateFlags & 0x1) != 0 && !string.IsNullOrWhiteSpace(device.DeviceString))
                    adapters.Add(device.DeviceString.Trim());
            }
            return adapters.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException) { return null; }
    }

    private static bool? ReadNetworkStatus()
    {
        try { return NetworkInterface.GetIsNetworkAvailable(); }
        catch (NetworkInformationException) { return null; }
    }

    private static IReadOnlyList<string> ReadSecurityProducts()
    {
        var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var root = RegistryKey.OpenBaseKey(hive, view).OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                if (root is null) continue;
                foreach (var subName in root.GetSubKeyNames())
                {
                    using var item = root.OpenSubKey(subName);
                    var display = item?.GetValue("DisplayName") as string;
                    if (display is null || display.Length > 160) continue;
                    if (SecurityProductNames.Any(name => display.Contains(name, StringComparison.OrdinalIgnoreCase))) results.Add(display.Trim());
                    if (results.Count >= 24) return results.Order(StringComparer.OrdinalIgnoreCase).ToArray();
                }
            }
            catch (Exception ex) when (ex is IOException or System.Security.SecurityException or UnauthorizedAccessException) { }
        }
        return results.Order(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct MemoryStatus
    {
        public uint Length; public uint MemoryLoad; public ulong TotalPhysical; public ulong AvailablePhysical;
        public ulong TotalPageFile; public ulong AvailablePageFile; public ulong TotalVirtual; public ulong AvailableVirtual;
        public ulong AvailableExtendedVirtual;
    }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GlobalMemoryStatusEx(ref MemoryStatus buffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DisplayDevice
    {
        public int Size;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string DeviceName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceString;
        public uint StateFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceKey;
    }
    [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "EnumDisplayDevicesW", SetLastError = true)]
    private static extern bool EnumDisplayDevices(string? device, uint deviceNumber, ref DisplayDevice displayDevice, uint flags);
}
