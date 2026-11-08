using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Sentinel.Core.Analysis;

public sealed record WindowsDefenderOperationalEvent(long RecordId, DateTimeOffset Timestamp, int EventId,
    string? ThreatName, string? SeverityName, string? CategoryName, string? ActionName, string? ActionStatus);

/// <summary>Parses only selected Defender event fields; file paths, account names and config values are discarded.</summary>
public static class WindowsDefenderOperationalEventParser
{
    private const string Provider = "Microsoft-Windows-Windows Defender";
    private const string Channel = "Microsoft-Windows-Windows Defender/Operational";
    private const int MaximumXmlCharacters = 2 * 1024 * 1024;
    private static readonly HashSet<int> SupportedEventIds = [1116, 1117, 1118, 1119, 5007, 5008];

    public static long ResolveCursorAfterLogReset(long savedCursor, long latestRecordId)
    {
        if (savedCursor < 0) throw new ArgumentOutOfRangeException(nameof(savedCursor));
        if (latestRecordId < 0) throw new ArgumentOutOfRangeException(nameof(latestRecordId));
        return latestRecordId < savedCursor ? 0 : savedCursor;
    }

    public static Guid CreateEventId(WindowsDefenderOperationalEvent item)
    {
        ArgumentNullException.ThrowIfNull(item);
        var canonical = string.Join('\n', "sentinel-defender-operational-v1",
            item.RecordId.ToString(CultureInfo.InvariantCulture),
            item.Timestamp.UtcDateTime.Ticks.ToString(CultureInfo.InvariantCulture),
            item.EventId.ToString(CultureInfo.InvariantCulture),
            item.ThreatName ?? string.Empty, item.SeverityName ?? string.Empty,
            item.CategoryName ?? string.Empty, item.ActionName ?? string.Empty, item.ActionStatus ?? string.Empty);
        return new Guid(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)).AsSpan(0, 16));
    }

    public static IReadOnlyList<WindowsDefenderOperationalEvent> Parse(string xml, long afterRecordId = 0, int maximumEvents = 64)
    {
        ArgumentNullException.ThrowIfNull(xml);
        if (xml.Length > MaximumXmlCharacters) throw new InvalidDataException("Dziennik Microsoft Defender przekracza limit odczytu.");
        if (afterRecordId < 0) throw new ArgumentOutOfRangeException(nameof(afterRecordId));
        if (maximumEvents is < 1 or > 256) throw new ArgumentOutOfRangeException(nameof(maximumEvents));

        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null,
            MaxCharactersInDocument = MaximumXmlCharacters };
        using var stringReader = new StringReader(xml);
        using var reader = XmlReader.Create(stringReader, settings);
        var document = XDocument.Load(reader, LoadOptions.None);
        var root = document.Root;
        if (root is null) return [];
        IEnumerable<XElement> nodes = root.Name.LocalName == "Event" ? [root] :
            root.Descendants().Where(element => element.Name.LocalName == "Event");
        var events = new List<WindowsDefenderOperationalEvent>();
        foreach (var item in nodes)
        {
            var system = item.Elements().FirstOrDefault(element => element.Name.LocalName == "System");
            if (system is null ||
                system.Elements().FirstOrDefault(element => element.Name.LocalName == "Provider")?.Attribute("Name")?.Value != Provider ||
                system.Elements().FirstOrDefault(element => element.Name.LocalName == "Channel")?.Value != Channel ||
                !int.TryParse(system.Elements().FirstOrDefault(element => element.Name.LocalName == "EventID")?.Value,
                    NumberStyles.None, CultureInfo.InvariantCulture, out var eventId) || !SupportedEventIds.Contains(eventId) ||
                !long.TryParse(system.Elements().FirstOrDefault(element => element.Name.LocalName == "EventRecordID")?.Value,
                    NumberStyles.None, CultureInfo.InvariantCulture, out var recordId) || recordId <= afterRecordId)
                continue;
            var timestampText = system.Elements().FirstOrDefault(element => element.Name.LocalName == "TimeCreated")?.Attribute("SystemTime")?.Value;
            if (!DateTimeOffset.TryParse(timestampText, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var timestamp))
                continue;

            var data = item.Elements().FirstOrDefault(element => element.Name.LocalName == "EventData")?.Elements()
                .Where(element => element.Name.LocalName == "Data")
                .GroupBy(element => element.Attribute("Name")?.Value ?? string.Empty, StringComparer.Ordinal)
                .ToDictionary(group => group.Key, group => group.First().Value, StringComparer.Ordinal)
                ?? new Dictionary<string, string>(StringComparer.Ordinal);
            events.Add(new(recordId, timestamp, eventId,
                ReadSafe(data, "Threat Name", 128), ReadSafe(data, "Severity Name", 32),
                ReadSafe(data, "Category Name", 64), ReadSafe(data, "Action Name", 64),
                ReadSafe(data, "Action Status", 64)));
        }
        return events.OrderBy(item => item.RecordId).Take(maximumEvents).ToArray();
    }

    private static string? ReadSafe(IReadOnlyDictionary<string, string> data, string name, int maximumLength)
    {
        if (!data.TryGetValue(name, out var value) || string.IsNullOrWhiteSpace(value) ||
            value.Length > maximumLength || value.Any(char.IsControl)) return null;
        return value.Trim();
    }
}
