using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace Sentinel.Service;

internal sealed class ServiceStatusPipeServer(SecurityIdentifier allowedUserSid, ServiceHealthSnapshot health)
{
    public const string PipeName = "SentinelAI.Service.Status.v1";
    private const int MaximumRequestChars = 1024;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(3);
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
        try
        {
            _ = CreatePipeSecurity(new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null));
            Console.Error.WriteLine("SELF_TEST_FAILED status-pipe-reserved-sid");
            return false;
        }
        catch (ArgumentException) { return true; }
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = NamedPipeServerStreamAcl.Create(
                    PipeName,
                    PipeDirection.InOut,
                    maxNumberOfServerInstances: 1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    inBufferSize: 4096,
                    outBufferSize: 4096,
                    pipeSecurity,
                    HandleInheritability.None,
                    PipeAccessRights.ReadWrite);
                await pipe.WaitForConnectionAsync(cancellationToken);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(RequestTimeout);
                using var reader = new StreamReader(pipe, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true);
                await using var writer = new StreamWriter(pipe, new UTF8Encoding(false), bufferSize: 1024, leaveOpen: true) { AutoFlush = true };
                var request = await ReadBoundedLineAsync(reader, timeout.Token);
                if (request is null) continue;

                string? clientSid = null;
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

                var requestId = ReadStatusRequestId(request);
                if (requestId is null)
                {
                    await WriteResponseAsync(writer, new { id = "", version = 1, ok = false, error = "unsupported-request" }, timeout.Token);
                    continue;
                }
                var snapshot = health.GetResponse(DateTimeOffset.UtcNow);
                await WriteResponseAsync(writer, new
                {
                    id = requestId,
                    version = 1,
                    ok = true,
                    result = new { state = snapshot.State, lastCollectionAtUtc = snapshot.LastCollectionAtUtc }
                }, timeout.Token);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            {
                ServiceLog.Write("STATUS_PIPE_REQUEST_FAILED type=" + exception.GetType().Name);
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

    private static string? ReadStatusRequestId(string request)
    {
        try
        {
            using var document = JsonDocument.Parse(request, new JsonDocumentOptions { MaxDepth = 4 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 3 ||
                !root.TryGetProperty("version", out var version) || version.ValueKind != JsonValueKind.Number || !version.TryGetInt32(out var versionNumber) || versionNumber != 1 ||
                !root.TryGetProperty("method", out var method) || method.ValueKind != JsonValueKind.String || method.GetString() != "status" ||
                !root.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String) return null;
            var value = id.GetString();
            return value is not null && value.Length is > 0 and <= 64 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_')
                ? value
                : null;
        }
        catch (JsonException) { return null; }
    }

    private static Task WriteResponseAsync<T>(StreamWriter writer, T response, CancellationToken cancellationToken) =>
        writer.WriteLineAsync(JsonSerializer.Serialize(response).AsMemory(), cancellationToken);

    private static bool IsReservedSid(SecurityIdentifier sid) =>
        sid.Value.Equals(new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null).Value, StringComparison.OrdinalIgnoreCase) ||
        sid.Value.Equals(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value, StringComparison.OrdinalIgnoreCase) ||
        sid.Value.Equals(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value, StringComparison.OrdinalIgnoreCase);

    private static void AddFullControl(PipeSecurity security, SecurityIdentifier sid) =>
        security.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.FullControl, AccessControlType.Allow));
}
