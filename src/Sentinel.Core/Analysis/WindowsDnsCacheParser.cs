namespace Sentinel.Core.Analysis;

/// <summary>Extracts DNS names from the user-readable output of ipconfig /displaydns.</summary>
public static class WindowsDnsCacheParser
{
    public static IReadOnlyList<string> Parse(string output, int maximumEntries = 2000)
    {
        ArgumentNullException.ThrowIfNull(output);
        if (maximumEntries is < 1 or > 2000) throw new ArgumentOutOfRangeException(nameof(maximumEntries));

        var names = new List<string>(Math.Min(maximumEntries, 2000));
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var line in output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = line.Trim();
            if (candidate.Length is 0 or > 253 || !candidate.Contains('.')) continue;
            try
            {
                var normalized = DomainReputation.Normalize(candidate);
                if (seen.Add(normalized)) names.Add(normalized);
                if (names.Count == maximumEntries) break;
            }
            catch (ArgumentException) { }
            catch (InvalidDataException) { }
        }
        return names;
    }
}
