using System.Text.Json;
using Sentinel.Core.Analysis;

namespace Sentinel.UrlHost;

public static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        MaxDepth = 8
    };

    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args is ["--register"])
            {
                if (!OperatingSystem.IsWindows()) return 2;
                NativeHostRegistration.Register();
                return 0;
            }
            if (args is ["--unregister"])
            {
                if (!OperatingSystem.IsWindows()) return 2;
                NativeHostRegistration.Unregister();
                return 0;
            }
            if (args.Length != 0) return 2;
            await ServeAsync(Console.OpenStandardInput(), Console.OpenStandardOutput());
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Sentinel Native Messaging host failed: {ex.GetType().Name}");
            return 1;
        }
    }

    public static async Task ServeAsync(Stream input, Stream output, CancellationToken cancellationToken = default, bool enableHostSideEffects = true)
    {
        var processor = new UrlRequestProcessor();
        var history = new BrowserHistoryRecorder();
        while (!cancellationToken.IsCancellationRequested)
        {
            byte[]? payload;
            try { payload = await NativeMessagingProtocol.ReadAsync(input, cancellationToken); }
            catch (EndOfStreamException) { throw; }
            if (payload is null) return;
            BrowserResponse response;
            string requestId = "invalid";
            try
            {
                var request = JsonSerializer.Deserialize<BrowserRequest>(payload, JsonOptions)
                    ?? throw new InvalidDataException("Puste żądanie.");
                requestId = request.Id;
                response = processor.Process(request);
            }
            catch (Exception ex) when (ex is JsonException or InvalidDataException or ArgumentException)
            {
                response = new BrowserResponse(requestId, false, ThreatAnalysisEngine.RulesVersion, "Information", "None", false,
                    [], "Nie można przeanalizować adresu; przeglądarka działa dalej.");
            }
            var bytes = JsonSerializer.SerializeToUtf8Bytes(response);
            await NativeMessagingProtocol.WriteAsync(output, bytes, cancellationToken);
            if (enableHostSideEffects)
            {
                try
                {
                    await BrowserStatusMarker.TouchAsync(cancellationToken);
                    await BrowserDesktopNotifier.NotifyAsync(3, cancellationToken);
                }
                catch (Exception ex)
                { Console.Error.WriteLine($"Browser integration status was not updated: {ex.GetType().Name}"); }
                if (response.ShouldWarn)
                {
                    using var writeTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    writeTimeout.CancelAfter(TimeSpan.FromSeconds(2));
                    try
                    {
                        if (await history.RecordAsync(response, writeTimeout.Token))
                            await BrowserDesktopNotifier.NotifyAsync(2, writeTimeout.Token);
                    }
                    catch (Exception ex)
                    { Console.Error.WriteLine($"Local browser history was not updated: {ex.GetType().Name}"); }
                }
            }
        }
    }
}
