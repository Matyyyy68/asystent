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

/// <summary>Creates a short notification summary without persisting event details.</summary>
public static class NotificationBatchSummary
{
    public static string Compose(IEnumerable<string> categories, int maximumLength = 220)
    {
        ArgumentNullException.ThrowIfNull(categories);
        if (maximumLength is < 32 or > 1024) throw new ArgumentOutOfRangeException(nameof(maximumLength));

        var unique = categories.Where(category => !string.IsNullOrWhiteSpace(category))
            .Select(category => category.Trim())
            .Distinct(StringComparer.Ordinal)
            .Take(32)
            .ToArray();
        if (unique.Length == 0) return string.Empty;
        if (unique.Length == 1) return Truncate(unique[0], maximumLength);

        const string prefix = "Kilka sygnałów wymaga uwagi: ";
        const string suffix = ". Otwórz Sentinel AI, aby sprawdzić szczegóły.";
        var visible = new List<string>();
        for (var index = 0; index < unique.Length; index++)
        {
            var remaining = unique.Length - index - 1;
            var more = remaining > 0 ? $" i {remaining} innych" : string.Empty;
            var candidate = prefix + string.Join(", ", visible.Append(unique[index])) + more + suffix;
            if (candidate.Length > maximumLength) break;
            visible.Add(unique[index]);
        }

        if (visible.Count == 0)
            return Truncate(prefix + unique.Length + " sygnałów wymaga sprawdzenia.", maximumLength);
        var omitted = unique.Length - visible.Count;
        return prefix + string.Join(", ", visible) + (omitted > 0 ? $" i {omitted} innych" : string.Empty) + suffix;
    }

    private static string Truncate(string value, int maximumLength)
        => value.Length <= maximumLength ? value : value[..(maximumLength - 1)].TrimEnd() + "…";
}
