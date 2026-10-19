using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

/// <summary>Reads Windows TCP/UDP owner-PID tables without launching PowerShell.</summary>
public static class WindowsConnectionTableReader
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const int ErrorInsufficientBuffer = 122;
    private const int MaximumTableBytes = 16 * 1024 * 1024;

    public static ConnectionSnapshot[] Read(int maximumTcp = 800, int maximumUdp = 200)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Migawka TCP/UDP wymaga Windows.");
        if (maximumTcp is < 1 or > 10_000 || maximumUdp is < 1 or > 10_000) throw new ArgumentOutOfRangeException();

        var processNames = ReadProcessNames();
        var result = new List<ConnectionSnapshot>(maximumTcp + maximumUdp);
        foreach (var row in ReadRows<TcpRowOwnerPidV4>(ReadTcpV4).Take(maximumTcp))
            result.Add(new("TCP", Address(row.LocalAddress), Port(row.LocalPort), Address(row.RemoteAddress), Port(row.RemotePort),
                TcpState(row.State), unchecked((int)row.OwningPid), Name(row.OwningPid, processNames)));
        var remainingTcp = maximumTcp - result.Count;
        if (remainingTcp > 0)
            foreach (var row in ReadRows<TcpRowOwnerPidV6>(ReadTcpV6).Take(remainingTcp))
                result.Add(new("TCP", Address(row.LocalAddress), Port(row.LocalPort), Address(row.RemoteAddress), Port(row.RemotePort),
                    TcpState(row.State), unchecked((int)row.OwningPid), Name(row.OwningPid, processNames)));

        var udpCount = 0;
        foreach (var row in ReadRows<UdpRowOwnerPidV4>(ReadUdpV4).Take(maximumUdp))
        {
            result.Add(new("UDP", Address(row.LocalAddress), Port(row.LocalPort), null, null, "Endpoint",
                unchecked((int)row.OwningPid), Name(row.OwningPid, processNames)));
            udpCount++;
        }
        var remainingUdp = maximumUdp - udpCount;
        if (remainingUdp > 0)
            foreach (var row in ReadRows<UdpRowOwnerPidV6>(ReadUdpV6).Take(remainingUdp))
                result.Add(new("UDP", Address(row.LocalAddress), Port(row.LocalPort), null, null, "Endpoint",
                    unchecked((int)row.OwningPid), Name(row.OwningPid, processNames)));
        return result.ToArray();
    }

    private static Dictionary<int, string> ReadProcessNames()
    {
        var names = new Dictionary<int, string>();
        var processes = Process.GetProcesses();
        try
        {
            foreach (var process in processes)
                try { names[process.Id] = process.ProcessName; } catch { }
        }
        finally { foreach (var process in processes) process.Dispose(); }
        return names;
    }

    private static string Name(uint pid, Dictionary<int, string> names) => names.TryGetValue(unchecked((int)pid), out var value) ? value : "unknown";
    private static string Address(uint value) => new IPAddress(BitConverter.GetBytes(value)).ToString();
    private static string Address(byte[] value) => new IPAddress(value).ToString();
    private static int Port(uint networkOrderValue)
    {
        var bytes = BitConverter.GetBytes(networkOrderValue);
        return (bytes[0] << 8) | bytes[1];
    }
    private static string TcpState(uint state) => state switch
    {
        1 => "Closed", 2 => "Listen", 3 => "SynSent", 4 => "SynReceived", 5 => "Established",
        6 => "FinWait1", 7 => "FinWait2", 8 => "CloseWait", 9 => "Closing", 10 => "LastAck",
        11 => "TimeWait", 12 => "DeleteTcb", _ => "Unknown"
    };

    private delegate uint TableReader(IntPtr table, ref int size);
    private static T[] ReadRows<T>(TableReader readTable) where T : struct
    {
        var size = 0;
        var result = readTable(IntPtr.Zero, ref size);
        if (result != ErrorInsufficientBuffer && result != 0) throw new Win32Exception((int)result);
        if (size is <= 0 or > MaximumTableBytes) throw new InvalidDataException("Rozmiar tabeli Windows poza limitem.");

        for (var attempt = 0; attempt < 3; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                result = readTable(buffer, ref size);
                if (result == ErrorInsufficientBuffer)
                {
                    if (size is <= 0 or > MaximumTableBytes) throw new InvalidDataException("Rozmiar tabeli Windows poza limitem.");
                    continue;
                }
                if (result != 0) throw new Win32Exception((int)result);
                var count = Marshal.ReadInt32(buffer);
                var rowSize = Marshal.SizeOf<T>();
                if (count < 0 || count > 100_000 || 4L + (long)count * rowSize > size)
                    throw new InvalidDataException("Nieprawidłowa tabela punktów końcowych Windows.");
                var rows = new T[count];
                for (var index = 0; index < count; index++)
                    rows[index] = Marshal.PtrToStructure<T>(IntPtr.Add(buffer, 4 + index * rowSize));
                return rows;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        throw new InvalidDataException("Tabela punktów końcowych zmieniała się zbyt szybko.");
    }

    private static uint ReadTcpV4(IntPtr table, ref int size) => GetExtendedTcpTable(table, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
    private static uint ReadTcpV6(IntPtr table, ref int size) => GetExtendedTcpTable(table, ref size, false, AfInet6, TcpTableOwnerPidAll, 0);
    private static uint ReadUdpV4(IntPtr table, ref int size) => GetExtendedUdpTable(table, ref size, false, AfInet, UdpTableOwnerPid);
    private static uint ReadUdpV6(IntPtr table, ref int size) => GetExtendedUdpTable(table, ref size, false, AfInet6, UdpTableOwnerPid);

    [DllImport("iphlpapi.dll", SetLastError = false)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order,
        int addressFamily, int tableClass, int reserved);
    [DllImport("iphlpapi.dll", SetLastError = false)]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order,
        int addressFamily, int tableClass);

    [StructLayout(LayoutKind.Sequential)]
    private struct TcpRowOwnerPidV4 { public uint State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningPid; }
    [StructLayout(LayoutKind.Sequential)]
    private struct TcpRowOwnerPidV6
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddress;
        public uint LocalScopeId, LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] RemoteAddress;
        public uint RemoteScopeId, RemotePort, State, OwningPid;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct UdpRowOwnerPidV4 { public uint LocalAddress, LocalPort, OwningPid; }
    [StructLayout(LayoutKind.Sequential)]
    private struct UdpRowOwnerPidV6
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddress;
        public uint LocalScopeId, LocalPort, OwningPid;
    }
}
