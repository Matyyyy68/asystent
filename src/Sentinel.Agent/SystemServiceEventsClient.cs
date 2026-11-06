using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.Agent;

internal static class SystemServiceEventsClient
{
    private const string PipeName = "SentinelAI.Service.Status.v1";
    private const int MaximumRequestChars = 24_000;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    public static async Task<IReadOnlyList<long>> ForwardEventsAsync(IReadOnlyList<ForwardedSecurityEvent> events, CancellationToken cancellationToken)
    {
        if (events.Count is < 1 or > 4) throw new ArgumentOutOfRangeException(nameof(events));
        var request = JsonSerializer.Serialize(new { id = "agent-forward-events", version = 1, method = "ingestEvents", events }, JsonOptions);
        if (request.Length > MaximumRequestChars) throw new InvalidDataException("Forwarded event page exceeds its request size limit.");
        await using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut,
            PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation);
        await pipe.ConnectAsync(1_500, cancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        using var reader = new StreamReader(pipe, new UTF8Encoding(false), false, 1024, leaveOpen: true);
        await using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 1024, leaveOpen: true) { AutoFlush = true };
        await writer.WriteLineAsync(request.AsMemory(), timeout.Token);
        var line = await reader.ReadLineAsync(timeout.Token) ?? throw new EndOfStreamException("System service returned no ingest acknowledgement.");
        if (line.Length > ServiceEventPipeProtocol.MaximumResponseChars) throw new InvalidDataException("System service ingest acknowledgement exceeded its size limit.");
        using var document = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement;
        if (!root.TryGetProperty("id", out var id) || id.GetString() != "agent-forward-events" ||
            !root.TryGetProperty("version", out var version) || version.GetInt32() != 1 ||
            !root.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True ||
            !root.TryGetProperty("result", out var result) || !result.TryGetProperty("acknowledgedSourceRowIds", out var ids) ||
            ids.ValueKind != JsonValueKind.Array || ids.GetArrayLength() != events.Count)
            throw new InvalidDataException("System service returned an invalid ingest acknowledgement.");
        var acknowledged = ids.EnumerateArray().Select(item => item.GetInt64()).ToArray();
        var expected = events.Select(item => item.SourceRowId).Order().ToArray();
        if (!acknowledged.SequenceEqual(expected)) throw new InvalidDataException("System service acknowledged a different event page.");
        return acknowledged;
    }

    public static async Task<SystemServiceEventBatch> ReadRecentAsync(long afterEventId, CancellationToken cancellationToken)
    {
        if (afterEventId < 0) throw new ArgumentOutOfRangeException(nameof(afterEventId));
        return await ReadAsync(new { id = "agent-events", version = 1, method = "recentEvents", afterEventId }, cancellationToken);
    }

    public static async Task<SystemServiceEventBatch> ReadLatestAsync(CancellationToken cancellationToken) =>
        await ReadAsync(new { id = "agent-events", version = 1, method = "recentEvents" }, cancellationToken);

    private static async Task<SystemServiceEventBatch> ReadAsync(object requestPayload, CancellationToken cancellationToken)
    {
        await using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut,
            PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation);
        await pipe.ConnectAsync(1_500, cancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(2));
        using var reader = new StreamReader(pipe, new UTF8Encoding(false), false, 1024, leaveOpen: true);
        await using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 1024, leaveOpen: true) { AutoFlush = true };
        var request = JsonSerializer.Serialize(requestPayload);
        await writer.WriteLineAsync(request.AsMemory(), timeout.Token);
        var line = await reader.ReadLineAsync(timeout.Token) ?? throw new EndOfStreamException("System service returned no event response.");
        return ServiceEventPipeProtocol.ParseResponse(line);
    }
}

