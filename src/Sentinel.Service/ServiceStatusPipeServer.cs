using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace Sentinel.Service;

internal sealed class ServiceStatusPipeServer(SecurityIdentifier allowedUserSid, ServiceHealthSnapshot health,
    string? pipeName = null, Action<Exception>? onError = null,
    Func<long?, CancellationToken, Task<IReadOnlyList<ServiceEventSummary>>>? readRecentEvents = null,
    Func<long, string, CancellationToken, Task<bool>>? updateEventStatus = null)
{
    public const string PipeName = "SentinelAI.Service.Status.v1";
    private const int MaximumRequestChars = 1024;
    private const int MaximumResponseChars = 32_768;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(3);
    private static readonly JsonSerializerOptions ResponseJsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string pipeName = pipeName ?? PipeName;
    private readonly Action<Exception>? onError = onError;
    private readonly PipeSecurity pipeSecurity = CreatePipeSecurity(allowedUserSid);

    public static PipeSecurity CreatePipeSecurity(SecurityIdentifier allowedSid)
    {
        ArgumentNullException.ThrowIfNull(allowedSid);
        if (IsReservedSid(allowedSid)) throw new ArgumentException("The allowed client SID must identify an interactive user.", nameof(allowedSid));

        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        AddFullControl(security, new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null));
        AddFullControl(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        AddFullControl(security, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        security.AddAccessRule(new PipeAccessRule(allowedSid, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return security;
    }

    public static bool ValidatePipeSecurity(SecurityIdentifier allowedSid)
    {
        try
        {
            var security = CreatePipeSecurity(allowedSid);
            if (!security.AreAccessRulesProtected) return false;
            var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, targetType: typeof(SecurityIdentifier))
                .OfType<PipeAccessRule>().ToArray();
            var expected = new Dictionary<string, PipeAccessRights>(StringComparer.OrdinalIgnoreCase)
            {
                [new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null).Value] = PipeAccessRights.FullControl,
                [new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value] = PipeAccessRights.FullControl,
                [new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value] = PipeAccessRights.FullControl,
                [allowedSid.Value] = PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize
            };
            return rules.Length == expected.Count && rules.All(rule =>
                rule.AccessControlType == AccessControlType.Allow &&
                rule.IdentityReference is SecurityIdentifier sid &&
                expected.TryGetValue(sid.Value, out var rights) && rights == rule.PipeAccessRights && expected.Remove(sid.Value)) &&
                expected.Count == 0;
        }
        catch { return false; }
    }

    public static bool SelfTest()
    {
        var testSid = new SecurityIdentifier("S-1-5-21-111111111-222222222-333333333-1001");
        if (!ValidatePipeSecurity(testSid))
        {
            Console.Error.WriteLine("SELF_TEST_FAILED status-pipe-acl");
            try
            {
                foreach (PipeAccessRule rule in CreatePipeSecurity(testSid).GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    Console.Error.WriteLine($"STATUS_PIPE_ACL sid={rule.IdentityReference.Value} type={rule.AccessControlType} rights={rule.PipeAccessRights}");
            }
            catch (Exception exception) { Console.Error.WriteLine("STATUS_PIPE_ACL_INSPECTION_FAILED type=" + exception.GetType().Name); }
            return false;
        }
        var health = new ServiceHealthSnapshot();
        if (!health.SelfTest())
        {
            Console.Error.WriteLine("SELF_TEST_FAILED status-pipe-health");
            return false;
        }
        if (ReadPipeRequest("{\"id\":\"self_test-1\",\"version\":1,\"method\":\"status\"}")?.Method != "status" ||
            ReadPipeRequest("{\"id\":\"self_test-2\",\"version\":1,\"method\":\"recentEvents\"}")?.Method != "recentEvents" ||
            ReadPipeRequest("{\"id\":\"self_test-5\",\"version\":1,\"method\":\"recentEvents\",\"afterEventId\":7}")?.AfterEventId != 7 ||
            ReadPipeRequest("{\"id\":\"self_test-6\",\"version\":1,\"method\":\"recentEvents\",\"afterEventId\":-1}") is not null ||
            ReadPipeRequest("{\"id\":\"self_test-3\",\"version\":1,\"method\":\"eventStatus\",\"eventId\":1,\"status\":\"Reviewed\"}")?.EventId != 1 ||
            ReadPipeRequest("{\"id\":\"self_test-1\",\"version\":1,\"method\":\"status\",\"extra\":true}") is not null ||
            ReadPipeRequest("{\"id\":\"bad id\",\"version\":1,\"method\":\"status\"}") is not null ||
            ReadPipeRequest("{\"id\":\"self_test-4\",\"version\":1,\"method\":\"eventStatus\",\"eventId\":1,\"status\":\"New\"}") is not null ||
            ReadPipeRequest("not-json") is not null)
        {
            Console.Error.WriteLine("SELF_TEST_FAILED status-pipe-protocol-validation");
            return false;
        }
        try
        {
            _ = CreatePipeSecurity(new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null));
            Console.Error.WriteLine("SELF_TEST_FAILED status-pipe-reserved-sid");
            return false;
        }
        catch (ArgumentException) { }

        try { return SelfTestPipeAsync().GetAwaiter().GetResult(); }
        catch (Exception exception)
        {
            Console.Error.WriteLine("SELF_TEST_FAILED status-pipe-runtime type=" + exception.GetType().Name);
            return false;
        }
    }

    private static async Task<bool> SelfTestPipeAsync()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var userSid = identity.User ?? throw new InvalidOperationException("Current Windows identity has no user SID.");
        var testPipeName = PipeName + ".selftest." + Guid.NewGuid().ToString("N");
        var health = new ServiceHealthSnapshot();
        health.MarkCollectionSucceeded(DateTimeOffset.UtcNow);
        var stage = "start-server";
        var changedEventStatus = false;
        var server = new ServiceStatusPipeServer(userSid, health, testPipeName,
            exception => Console.Error.WriteLine($"SELF_TEST_STATUS_PIPE_SERVER_ERROR {exception.Message} type={exception.InnerException?.GetType().Name} hresult=0x{exception.InnerException?.HResult:X8} message={exception.InnerException?.Message.Replace('\r', ' ').Replace('\n', ' ')}"),
            (afterEventId, _) => Task.FromResult<IReadOnlyList<ServiceEventSummary>>(afterEventId is null or < 1
                ? Enumerable.Range(1, 12).Select(id => new ServiceEventSummary(id, DateTimeOffset.UtcNow, "Low",
                    new string('ż', 128), new string('ą', 128), new string('ł', 768), new string('ź', 512), "New", null,
                    "service", "test", null, 1, null, null, null, [], [])).ToArray()
                : []),
            (id, status, _) => { changedEventStatus = id == 1 && status == "Reviewed"; return Task.FromResult(changedEventStatus); });
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var serverTask = server.RunAsync(cancellation.Token);
        bool Fail(string check) { Console.Error.WriteLine("SELF_TEST_FAILED status-pipe-runtime-" + check); return false; }
        try
        {
            stage = "connect-client";
            stage = "write-request";
            var responseLine = await SendSelfTestRequestAsync(testPipeName,
                "{\"id\":\"runtime-self-test\",\"version\":1,\"method\":\"status\"}", cancellation.Token);
            stage = "read-response";
            if (responseLine is null) return Fail(stage);
            stage = "validate-response";
            using var response = JsonDocument.Parse(responseLine, new JsonDocumentOptions { MaxDepth = 4 });
            var root = response.RootElement;
            if (!root.TryGetProperty("id", out var id) || id.GetString() != "runtime-self-test" ||
                !root.TryGetProperty("version", out var version) || version.GetInt32() != 1 ||
                !root.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True ||
                !root.TryGetProperty("result", out var result) ||
                !result.TryGetProperty("state", out var state) || state.GetString() != "running" ||
                !result.TryGetProperty("lastCollectionAtUtc", out var timestamp) || timestamp.ValueKind != JsonValueKind.String)
            {
                Console.Error.WriteLine("SELF_TEST_FAILED status-pipe-runtime-response");
                return Fail(stage);
            }
            stage = "events-request";
            var eventsLine = await SendSelfTestRequestAsync(testPipeName,
                "{\"id\":\"events-self-test\",\"version\":1,\"method\":\"recentEvents\",\"afterEventId\":0}", cancellation.Token);
            if (eventsLine is null) return Fail(stage);
            using (var eventsResponse = JsonDocument.Parse(eventsLine, new JsonDocumentOptions { MaxDepth = 8 }))
            {
                var eventsRoot = eventsResponse.RootElement;
                if (!eventsRoot.TryGetProperty("id", out var eventsId) || eventsId.GetString() != "events-self-test" ||
                    !eventsRoot.TryGetProperty("ok", out var eventsOk) || eventsOk.ValueKind != JsonValueKind.True ||
                    !eventsRoot.TryGetProperty("result", out var eventsResult) ||
                    !eventsResult.TryGetProperty("events", out var eventItems) || eventItems.ValueKind != JsonValueKind.Array ||
                    eventItems.GetArrayLength() is < 1 or > 12 || eventsLine.Length > MaximumResponseChars)
                {
                    Console.Error.WriteLine("SELF_TEST_STATUS_PIPE_EVENTS_RESPONSE " + eventsLine[..Math.Min(eventsLine.Length, 512)]);
                    return Fail(stage);
                }
            }
            stage = "events-cursor-request";
            var cursorLine = await SendSelfTestRequestAsync(testPipeName,
                "{\"id\":\"events-cursor-self-test\",\"version\":1,\"method\":\"recentEvents\",\"afterEventId\":12}", cancellation.Token);
            if (cursorLine is null) return Fail(stage);
            using (var cursorResponse = JsonDocument.Parse(cursorLine, new JsonDocumentOptions { MaxDepth = 8 }))
            {
                var cursorRoot = cursorResponse.RootElement;
                if (!cursorRoot.TryGetProperty("ok", out var cursorOk) || cursorOk.ValueKind != JsonValueKind.True ||
                    !cursorRoot.TryGetProperty("result", out var cursorResult) || !cursorResult.TryGetProperty("events", out var cursorItems) ||
                    cursorItems.ValueKind != JsonValueKind.Array || cursorItems.GetArrayLength() != 0)
                    return Fail(stage);
            }
            stage = "event-status-request";
            var updateLine = await SendSelfTestRequestAsync(testPipeName,
                "{\"id\":\"event-status-self-test\",\"version\":1,\"method\":\"eventStatus\",\"eventId\":1,\"status\":\"Reviewed\"}", cancellation.Token);
            if (updateLine is null) return Fail(stage);
            using (var updateResponse = JsonDocument.Parse(updateLine, new JsonDocumentOptions { MaxDepth = 8 }))
            {
                var updateRoot = updateResponse.RootElement;
                if (!updateRoot.TryGetProperty("ok", out var updateOk) || updateOk.ValueKind != JsonValueKind.True ||
                    !updateRoot.TryGetProperty("result", out var updateResult) || !updateResult.TryGetProperty("updated", out var updated) || updated.ValueKind != JsonValueKind.True)
                    return Fail(stage);
            }
            return changedEventStatus || Fail(stage);
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"SELF_TEST_STATUS_PIPE_CLIENT_ERROR stage={stage} type={exception.GetType().Name}");
            throw;
        }
        finally
        {
            cancellation.Cancel();
            try { await serverTask; }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        }
    }

    private static async Task<string?> SendSelfTestRequestAsync(string pipeName, string request, CancellationToken cancellationToken)
    {
        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut,
            PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation);
        await pipe.ConnectAsync(cancellationToken);
        using var reader = new StreamReader(pipe, new UTF8Encoding(false), false, 1024, leaveOpen: true);
        await using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 1024, leaveOpen: true) { AutoFlush = true };
        await writer.WriteLineAsync(request.AsMemory(), cancellationToken);
        return await reader.ReadLineAsync(cancellationToken);
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var stage = "create-pipe";
            try
            {
                await using var pipe = NamedPipeServerStreamAcl.Create(
                    pipeName,
                    PipeDirection.InOut,
                    maxNumberOfServerInstances: 1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
                    inBufferSize: 4096,
                    outBufferSize: 4096,
                    pipeSecurity,
                    HandleInheritability.None,
                    default);
                stage = "wait-for-client";
                await pipe.WaitForConnectionAsync(cancellationToken);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(RequestTimeout);
                using var reader = new StreamReader(pipe, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true);
                await using var writer = new StreamWriter(pipe, new UTF8Encoding(false), bufferSize: 1024, leaveOpen: true) { AutoFlush = true };
                stage = "read-request";
                var request = await ReadBoundedLineAsync(reader, timeout.Token);
                if (request is null) continue;

                string? clientSid = null;
                stage = "impersonate-client";
                pipe.RunAsClient(() =>
                {
                    using var identity = WindowsIdentity.GetCurrent();
                    clientSid = identity.User?.Value;
                });
                if (!StringComparer.OrdinalIgnoreCase.Equals(clientSid, allowedUserSid.Value))
                {
                    await WriteResponseAsync(writer, new { id = "", version = 1, ok = false, error = "unauthorized" }, timeout.Token);
                    continue;
                }

                var pipeRequest = ReadPipeRequest(request);
                if (pipeRequest is null)
                {
                    await WriteResponseAsync(writer, new { id = "", version = 1, ok = false, error = "unsupported-request" }, timeout.Token);
                    continue;
                }
                stage = "write-response";
                object response = pipeRequest.Method switch
                {
                    "status" => StatusResponse(pipeRequest.Id),
                    "recentEvents" when readRecentEvents is not null => await EventsResponseAsync(pipeRequest.Id, pipeRequest.AfterEventId, timeout.Token),
                    "eventStatus" when updateEventStatus is not null => await EventStatusResponseAsync(pipeRequest, timeout.Token),
                    _ => new { id = pipeRequest.Id, version = 1, ok = false, error = "unsupported-request" }
                };
                await WriteResponseAsync(writer, response, timeout.Token);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            {
                if (onError is not null) onError(new IOException("stage=" + stage, exception));
                else
                {
                    var cause = exception.InnerException ?? exception;
                    ServiceLog.Write("STATUS_PIPE_REQUEST_FAILED stage=" + stage + " type=" + exception.GetType().Name +
                        " causeType=" + cause.GetType().Name + " causeHResult=0x" + cause.HResult.ToString("X8", System.Globalization.CultureInfo.InvariantCulture));
                }
                try { await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken); }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
            }
        }
    }

    private static async Task<string?> ReadBoundedLineAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        var builder = new StringBuilder();
        var buffer = new char[1];
        while (builder.Length <= MaximumRequestChars)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (read == 0) return null;
            if (buffer[0] == '\n') return builder.ToString().TrimEnd('\r');
            builder.Append(buffer[0]);
        }
        throw new InvalidDataException("Status pipe request exceeded the size limit.");
    }

    private object StatusResponse(string requestId)
    {
        var snapshot = health.GetResponse(DateTimeOffset.UtcNow);
        return new { id = requestId, version = 1, ok = true, result = new { state = snapshot.State, lastCollectionAtUtc = snapshot.LastCollectionAtUtc } };
    }

    private async Task<object> EventsResponseAsync(string requestId, long? afterEventId, CancellationToken cancellationToken)
    {
        var events = (await readRecentEvents!(afterEventId, cancellationToken)).Take(12).ToArray();
        while (true)
        {
            var response = new { id = requestId, version = 1, ok = true, result = new { events } };
            if (JsonSerializer.Serialize(response, ResponseJsonOptions).Length <= MaximumResponseChars) return response;
            if (events.Length == 0) return new { id = requestId, version = 1, ok = false, error = "response-too-large" };
            events = events[..^1];
        }
    }

    private async Task<object> EventStatusResponseAsync(PipeRequest request, CancellationToken cancellationToken)
    {
        var updated = await updateEventStatus!(request.EventId!.Value, request.Status!, cancellationToken);
        return new { id = request.Id, version = 1, ok = true, result = new { updated } };
    }

    private static PipeRequest? ReadPipeRequest(string request)
    {
        try
        {
            using var document = JsonDocument.Parse(request, new JsonDocumentOptions { MaxDepth = 4 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("version", out var version) || version.ValueKind != JsonValueKind.Number || !version.TryGetInt32(out var versionNumber) || versionNumber != 1 ||
                !root.TryGetProperty("method", out var method) || method.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String) return null;
            var value = id.GetString();
            if (value is null || value.Length is 0 or > 64 || !value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_')) return null;
            var methodName = method.GetString();
            if (methodName == "status")
                return root.EnumerateObject().Count() == 3 ? new PipeRequest(value, methodName, null, null, null) : null;
            if (methodName == "recentEvents" && (root.EnumerateObject().Count() == 3 ||
                (root.EnumerateObject().Count() == 4 && root.TryGetProperty("afterEventId", out var cursorProperty) &&
                 cursorProperty.TryGetInt64(out var cursor) && cursor >= 0)))
                return new PipeRequest(value, methodName, null, null,
                    root.TryGetProperty("afterEventId", out var requestedCursorProperty) && requestedCursorProperty.TryGetInt64(out var requestedCursor) ? requestedCursor : null);
            if (methodName == "eventStatus" && root.EnumerateObject().Count() == 5 &&
                root.TryGetProperty("eventId", out var eventId) && eventId.TryGetInt64(out var numericId) && numericId > 0 &&
                root.TryGetProperty("status", out var status) && status.ValueKind == JsonValueKind.String && status.GetString() is "Reviewed" or "FalsePositive")
                return new PipeRequest(value, methodName, numericId, status.GetString(), null);
            return null;
        }
        catch (JsonException) { return null; }
    }

    private static async Task WriteResponseAsync<T>(StreamWriter writer, T response, CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(response, ResponseJsonOptions);
        if (json.Length > MaximumResponseChars)
            json = "{\"id\":\"\",\"version\":1,\"ok\":false,\"error\":\"response-too-large\"}";
        await writer.WriteLineAsync(json.AsMemory(), cancellationToken);
    }

    private static bool IsReservedSid(SecurityIdentifier sid) =>
        sid.Value.Equals(new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null).Value, StringComparison.OrdinalIgnoreCase) ||
        sid.Value.Equals(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value, StringComparison.OrdinalIgnoreCase) ||
        sid.Value.Equals(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value, StringComparison.OrdinalIgnoreCase);

    private static void AddFullControl(PipeSecurity security, SecurityIdentifier sid) =>
        security.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.FullControl, AccessControlType.Allow));
}

internal sealed record PipeRequest(string Id, string Method, long? EventId, string? Status, long? AfterEventId);
internal sealed record ServiceEventSummary(long Id, DateTimeOffset Timestamp, string Risk, string Category,
    string Application, string Explanation, string Recommendation, string Status, Guid? EventId,
    string? Source, string? RuleVersion, int? Confidence, int SchemaVersion, int? ProcessId,
    string? ProcessName, Guid? CorrelationId, IReadOnlyList<string> EvidenceCodes,
    IReadOnlyList<string> AnalysisLimitations);
