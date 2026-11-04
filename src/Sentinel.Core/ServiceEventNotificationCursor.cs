using System.Globalization;
using System.Text;

namespace Sentinel.Core;

/// <summary>Persists only the highest system-service event ID already observed by the user agent.</summary>
public sealed class ServiceEventNotificationCursor
{
    private readonly string path;
    public long LastEventId { get; private set; }

    public ServiceEventNotificationCursor(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        this.path = Path.GetFullPath(path);
        try
        {
            using var stream = new FileStream(this.path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var buffer = new byte[25];
            var length = stream.Read(buffer, 0, buffer.Length);
            var value = Encoding.ASCII.GetString(buffer, 0, length);
            if (length <= 24 && long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) && parsed >= 0)
                LastEventId = parsed;
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    public bool TryAdvance(long eventId)
    {
        if (eventId < 0) throw new ArgumentOutOfRangeException(nameof(eventId));
        if (eventId <= LastEventId) return true;
        var directory = Path.GetDirectoryName(path) ?? throw new InvalidOperationException("Cursor path has no parent directory.");
        var temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(temporaryPath, eventId.ToString(CultureInfo.InvariantCulture), new UTF8Encoding(false));
            File.Move(temporaryPath, path, overwrite: true);
            LastEventId = eventId;
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
