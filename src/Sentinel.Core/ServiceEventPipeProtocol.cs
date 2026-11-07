using System.Text.Json;

namespace Sentinel.Core;

public sealed record SystemServiceEvent(long Id, string Risk, string Status);

public sealed record SystemServiceEventBatch(long LatestEventId, IReadOnlyList<SystemServiceEvent> Events);

/// <summary>Strictly parses the bounded, versioned Agent-to-Service event-history response.</summary>
public static class ServiceEventPipeProtocol
{
    public const int MaximumResponseChars = 32_768;
    public const int MaximumEvents = 12;

    public static SystemServiceEventBatch ParseResponse(string response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.Length > MaximumResponseChars)
            throw new InvalidDataException("System service event response exceeded its size limit.");

        using var document = JsonDocument.Parse(response, new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !ReadString(root, "id", out var id) || id != "agent-events" ||
            !root.TryGetProperty("version", out var version) || version.ValueKind != JsonValueKind.Number ||
            !version.TryGetInt32(out var protocolVersion) || protocolVersion != 1 ||
            !root.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True ||
            !root.TryGetProperty("result", out var result) || result.ValueKind != JsonValueKind.Object ||
            !result.TryGetProperty("latestEventId", out var latestEventId) ||
            latestEventId.ValueKind != JsonValueKind.Number || !latestEventId.TryGetInt64(out var latestId) || latestId < 0 ||
            !result.TryGetProperty("events", out var events) || events.ValueKind != JsonValueKind.Array ||
            events.GetArrayLength() > MaximumEvents)
            throw new InvalidDataException("System service returned an invalid event response.");

        var parsed = new List<SystemServiceEvent>(events.GetArrayLength());
        foreach (var item in events.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object ||
                !item.TryGetProperty("id", out var eventId) || eventId.ValueKind != JsonValueKind.Number ||
                !eventId.TryGetInt64(out var value) || value <= 0 ||
                !ReadString(item, "risk", out var risk) ||
                !ReadString(item, "status", out var status))
                throw new InvalidDataException("System service returned a malformed event.");

            if (risk is not ("Information" or "Low" or "Moderate" or "High" or "Critical"))
                throw new InvalidDataException("System service returned an unknown risk level.");
            if (status is not ("New" or "Reviewed" or "FalsePositive"))
                throw new InvalidDataException("System service returned an unknown event status.");

            parsed.Add(new SystemServiceEvent(value, risk, status));
        }

        return new SystemServiceEventBatch(latestId, parsed);
    }

    private static bool ReadString(JsonElement element, string property, out string value)
    {
        value = string.Empty;
        if (!element.TryGetProperty(property, out var candidate) || candidate.ValueKind != JsonValueKind.String ||
            candidate.GetString() is not { } text) return false;
        value = text;
        return true;
    }
}
