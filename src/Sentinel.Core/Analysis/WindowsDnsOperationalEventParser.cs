using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace Sentinel.Core.Analysis;

public sealed record WindowsDnsOperationalEvent(long RecordId, DateTimeOffset? Timestamp, string? QueryName,
    uint QueryType, uint QueryStatus);

/// <summary>Parses only DNS Client Operational query-completed events; result payloads are discarded.</summary>
public static class WindowsDnsOperationalEventParser
{
    private const string Provider = "Microsoft-Windows-DNS-Client";
    private const string Channel = "Microsoft-Windows-DNS-Client/Operational";
    private const int MaximumXmlCharacters = 2 * 1024 * 1024;
    private static readonly Regex XmlDeclaration = new("<\\?xml[^?]*\\?>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>Resumes from the stored cursor, or replays the current log after Windows resets its record IDs.</summary>
    public static long ResolveCursorAfterLogReset(long savedCursor, long latestRecordId)
    {
        if (savedCursor < 0) throw new ArgumentOutOfRangeException(nameof(savedCursor));
        if (latestRecordId < 0) throw new ArgumentOutOfRangeException(nameof(latestRecordId));
        return latestRecordId < savedCursor ? 0 : savedCursor;
    }

    /// <summary>Builds an idempotent identity for one DNS log record, including fields that change across log resets.</summary>
    public static Guid CreateEventId(WindowsDnsOperationalEvent item)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (item.Timestamp is not { } timestamp) throw new ArgumentException("Zdarzenie DNS musi zawierać czas.", nameof(item));
        var canonical = string.Join('\n', "sentinel-dns-operational-v2",
            item.RecordId.ToString(CultureInfo.InvariantCulture),
            timestamp.UtcDateTime.Ticks.ToString(CultureInfo.InvariantCulture),
            item.QueryName ?? string.Empty,
            item.QueryType.ToString(CultureInfo.InvariantCulture),
            item.QueryStatus.ToString(CultureInfo.InvariantCulture));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return new Guid(hash.AsSpan(0, 16));
    }

    public static IReadOnlyList<WindowsDnsOperationalEvent> Parse(string xml, long afterRecordId = 0, int maximumEvents = 256)
    {
        ArgumentNullException.ThrowIfNull(xml);
        if (xml.Length > MaximumXmlCharacters) throw new InvalidDataException("Dziennik DNS przekracza limit odczytu.");
        if (afterRecordId < 0) throw new ArgumentOutOfRangeException(nameof(afterRecordId));
        if (maximumEvents is < 1 or > 2000) throw new ArgumentOutOfRangeException(nameof(maximumEvents));

        var fragment = XmlDeclaration.Replace(xml, string.Empty);
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null,
            MaxCharactersInDocument = MaximumXmlCharacters };
        using var stringReader = new StringReader(fragment);
        using var reader = XmlReader.Create(stringReader, settings);
        var document = XDocument.Load(reader, LoadOptions.None);
        var root = document.Root;
        if (root is null) return [];
        IEnumerable<XElement> nodes = root.Name.LocalName == "Event" ? [root] : root.Descendants().Where(element => element.Name.LocalName == "Event");
        var events = new List<WindowsDnsOperationalEvent>();
        foreach (var item in nodes)
        {
            var system = item.Elements().FirstOrDefault(element => element.Name.LocalName == "System");
            if (system is null ||
                system.Elements().FirstOrDefault(element => element.Name.LocalName == "Provider")?.Attribute("Name")?.Value != Provider ||
                system.Elements().FirstOrDefault(element => element.Name.LocalName == "Channel")?.Value != Channel ||
                system.Elements().FirstOrDefault(element => element.Name.LocalName == "EventID")?.Value != "3008") continue;
            if (!long.TryParse(system.Elements().FirstOrDefault(element => element.Name.LocalName == "EventRecordID")?.Value,
                    NumberStyles.None, CultureInfo.InvariantCulture, out var recordId) || recordId <= afterRecordId) continue;
            var timestampText = system.Elements().FirstOrDefault(element => element.Name.LocalName == "TimeCreated")?.Attribute("SystemTime")?.Value;
            DateTimeOffset? timestamp = DateTimeOffset.TryParse(timestampText, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsedTimestamp) ? parsedTimestamp : null;
            var data = item.Elements().FirstOrDefault(element => element.Name.LocalName == "EventData")?.Elements()
                .Where(element => element.Name.LocalName == "Data")
                .GroupBy(element => element.Attribute("Name")?.Value ?? string.Empty, StringComparer.Ordinal)
                .ToDictionary(group => group.Key, group => group.First().Value, StringComparer.Ordinal);
            string? queryName = data is not null && data.TryGetValue("QueryName", out var rawName) && TryNormalizeDomain(rawName, out var normalizedName)
                ? normalizedName : null;
            if (data is null) data = new Dictionary<string, string>(StringComparer.Ordinal);
            _ = uint.TryParse(data.GetValueOrDefault("QueryType"), NumberStyles.None, CultureInfo.InvariantCulture, out var queryType);
            _ = uint.TryParse(data.GetValueOrDefault("QueryStatus"), NumberStyles.None, CultureInfo.InvariantCulture, out var queryStatus);
            events.Add(new(recordId, timestamp, queryName, queryType, queryStatus));
        }
        return events.OrderBy(item => item.RecordId).Take(maximumEvents).ToArray();
    }

    private static bool TryNormalizeDomain(string value, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(value) || value.Length > 255) return false;
        try { normalized = DomainNames.Ascii(value.Trim().TrimEnd('.')); }
        catch (ArgumentException) { return false; }
        return normalized.Length is > 0 and <= 253 && !IPAddress.TryParse(normalized, out _) &&
            normalized.Split('.').All(label => label.Length is > 0 and <= 63 &&
                label[0] != '-' && label[^1] != '-' && label.All(character => char.IsAsciiLetterOrDigit(character) || character == '-'));
    }
}
