using System.Text;

namespace Sentinel.Core;

/// <summary>Stores only the user's service-event notification preference for agent recovery.</summary>
public sealed class ServiceEventNotificationPreferences
{
    private readonly string path;

    public ServiceEventNotificationPreferences(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        this.path = Path.GetFullPath(path);
    }

    public bool? Read()
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            Span<byte> value = stackalloc byte[2];
            var length = stream.Read(value);
            if (length != 1 || stream.ReadByte() != -1) return null;
            return value[0] switch { (byte)'1' => true, (byte)'0' => false, _ => null };
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    public bool TryWrite(bool enabled)
    {
        var directory = Path.GetDirectoryName(path) ?? throw new InvalidOperationException("Preference path has no parent directory.");
        var temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(temporaryPath, enabled ? "1" : "0", new UTF8Encoding(false));
            File.Move(temporaryPath, path, overwrite: true);
            return true;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
        finally
        {
            try { File.Delete(temporaryPath); } catch { }
        }
    }
}
