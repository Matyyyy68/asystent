using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Sentinel.Engine;

public sealed record ProcessParentObservation(int ProcessId, string ProcessName);
public sealed record ProcessLaunchBehavior(string RuleCode, string Summary);

public static class ProcessLaunchBehaviorRules
{
    private static readonly HashSet<string> OfficeParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword", "excel", "powerpnt", "outlook", "onenote", "msaccess"
    };

    private static readonly HashSet<string> ScriptChildren = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32"
    };

    public static ProcessLaunchBehavior? Evaluate(string? parentName, string? childName)
    {
        var parent = Normalize(parentName);
        var child = Normalize(childName);
        if (OfficeParents.Contains(parent) && ScriptChildren.Contains(child))
            return new("process.behavior.office-spawned-script-host",
                "Proces pakietu Office uruchomił interpreter poleceń lub host skryptów.");
        return null;
    }

    private static string Normalize(string? name)
    {
        var normalized = Path.GetFileNameWithoutExtension(name ?? string.Empty);
        return normalized.Length <= 64 && normalized.All(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-')
            ? normalized
            : string.Empty;
    }
}

internal static class WindowsProcessParentReader
{
    private const uint SnapshotProcesses = 0x00000002;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public IntPtr DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int BasePriority;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string ExecutableFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "Process32FirstW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32First(SafeFileHandle snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "Process32NextW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32Next(SafeFileHandle snapshot, ref ProcessEntry32 entry);

    public static IReadOnlyDictionary<int, ProcessParentObservation> ReadMany(
        IReadOnlyCollection<(int ProcessId, string ProcessName)> processes)
    {
        if (!OperatingSystem.IsWindows() || processes.Count == 0) return new Dictionary<int, ProcessParentObservation>();
        using var snapshot = CreateToolhelp32Snapshot(SnapshotProcesses, 0);
        if (snapshot.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        var entries = new Dictionary<int, (string Name, int ParentProcessId)>();
        var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
        if (!Process32First(snapshot, ref entry)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        do
        {
            if (entry.ProcessId != 0)
                entries[(int)entry.ProcessId] = (entry.ExecutableFile, (int)entry.ParentProcessId);
        }
        while (Process32Next(snapshot, ref entry));

        var observations = new Dictionary<int, ProcessParentObservation>();
        foreach (var (processId, expectedName) in processes)
        {
            if (!entries.TryGetValue(processId, out var child) ||
                !string.Equals(Path.GetFileNameWithoutExtension(child.Name), expectedName, StringComparison.OrdinalIgnoreCase) ||
                child.ParentProcessId <= 0 || child.ParentProcessId == processId ||
                !entries.TryGetValue(child.ParentProcessId, out var parent) || string.IsNullOrWhiteSpace(parent.Name)) continue;
            observations[processId] = new(child.ParentProcessId, Path.GetFileNameWithoutExtension(parent.Name));
        }
        return observations;
    }
}
