namespace Sentinel.Core;

/// <summary>In-memory notification rate limiter. It never persists message contents.</summary>
public sealed class NotificationDeduplicator(TimeSpan? interval = null, int capacity = 256)
{
    private readonly object gate = new();
    private readonly Dictionary<string, DateTimeOffset> recent = new(StringComparer.Ordinal);
    private readonly TimeSpan interval = interval ?? TimeSpan.FromMinutes(10);

    public bool TryMark(string key, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        if (key.Length > 256) throw new ArgumentOutOfRangeException(nameof(key));
        if (capacity < 1) throw new ArgumentOutOfRangeException(nameof(capacity));
        lock (gate)
        {
            foreach (var expired in recent.Where(x => now < x.Value || now - x.Value >= interval).Select(x => x.Key).ToArray()) recent.Remove(expired);
            if (recent.ContainsKey(key)) return false;
            if (recent.Count >= capacity) recent.Remove(recent.MinBy(x => x.Value).Key);
            recent[key] = now;
            return true;
        }
    }
}
