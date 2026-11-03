namespace Sentinel.Core.Analysis;

/// <summary>Persists that the first successful monitoring cycle has completed for this user profile.</summary>
public sealed class InitialAnalysisCompletionMarker(string markerPath)
{
    private readonly object gate = new();
    private bool handled;

    public bool TryMarkCompleted()
    {
        lock (gate)
        {
            if (handled) return false;
            handled = true;
            try
            {
                var directory = Path.GetDirectoryName(Path.GetFullPath(markerPath))
                    ?? throw new InvalidDataException("Nie można ustalić katalogu znacznika analizy.");
                Directory.CreateDirectory(directory);
                using var marker = new FileStream(markerPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
                marker.Write("completed"u8);
                marker.Flush(flushToDisk: true);
                return true;
            }
            catch (IOException) when (File.Exists(markerPath)) { return false; }
            catch { return false; }
        }
    }
}
