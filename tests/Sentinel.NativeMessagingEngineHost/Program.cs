using System.Text.Json;
using Sentinel.UrlHost;

var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
var processor = new UrlRequestProcessor();
var input = Console.OpenStandardInput();
var output = Console.OpenStandardOutput();
var requestLog = Path.Combine(AppContext.BaseDirectory, "native-host-requests.log");

while (true)
{
    var payload = await NativeMessagingProtocol.ReadAsync(input);
    if (payload is null) return;

    var request = JsonSerializer.Deserialize<BrowserRequest>(payload, options)
        ?? throw new InvalidDataException("Native Messaging request was empty.");
    File.AppendAllText(requestLog, request.Type + Environment.NewLine);

    // This exercises the production URL rules without writing to the user's
    // Sentinel profile, history database, notifications, or reputation store.
    var response = processor.Process(request);
    await NativeMessagingProtocol.WriteAsync(output, JsonSerializer.SerializeToUtf8Bytes(response));
}
