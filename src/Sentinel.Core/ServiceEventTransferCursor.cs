using System.Globalization;
using System.Text;

namespace Sentinel.Core;

public sealed class ServiceEventTransferCursor(string path)
{
    private readonly object gate = new();
    public long Read()
    {
        lock (gate)
        {
            try
            {
                var text = File.ReadAllText(path, Encoding.ASCII);
                return long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value) && value >= 0 ? value : 0;
            }
            catch { return 0; }
        }
    }

    public bool TryAdvance(long value)
    {
        if (value < 0) return false;
        lock (gate)
        {
            var current = Read();
            if (value < current) return false;
            var directory = Path.GetDirectoryName(path);
            if (string.IsNullOrWhiteSpace(directory)) return false;
            try
            {
                Directory.CreateDirectory(directory);
                var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
                File.WriteAllText(temporary, value.ToString(CultureInfo.InvariantCulture), new UTF8Encoding(false));
                try { File.Move(temporary, path, overwrite: true); }
                finally { try { File.Delete(temporary); } catch { } }
                return true;
            }
            catch { return false; }
        }
    }

    public bool TryReset(long value)
    {
        if (value < 0) return false;
        lock (gate)
        {
            var directory = Path.GetDirectoryName(path);
            if (string.IsNullOrWhiteSpace(directory)) return false;
            try
            {
                Directory.CreateDirectory(directory);
                var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
                File.WriteAllText(temporary, value.ToString(CultureInfo.InvariantCulture), new UTF8Encoding(false));
                try { File.Move(temporary, path, overwrite: true); }
                finally { try { File.Delete(temporary); } catch { } }
                return true;
            }
            catch { return false; }
        }
    }
}
