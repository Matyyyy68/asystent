using System.Buffers.Binary;
using System.Text.Json;

const int MaximumMessageBytes = 1024 * 1024;
var input = Console.OpenStandardInput();
var output = Console.OpenStandardOutput();
var requestLog = Path.Combine(AppContext.BaseDirectory, "mock-requests.log");

while (true)
{
    var header = new byte[sizeof(int)];
    if (!TryReadExactly(input, header)) return;

    var messageLength = BinaryPrimitives.ReadInt32LittleEndian(header);
    if (messageLength is <= 0 or > MaximumMessageBytes) return;

    var messageBytes = new byte[messageLength];
    if (!TryReadExactly(input, messageBytes)) return;

    using var document = JsonDocument.Parse(messageBytes);
    var root = document.RootElement;
    var id = root.TryGetProperty("id", out var idElement) ? idElement.GetString() : null;
    var type = root.TryGetProperty("type", out var typeElement) ? typeElement.GetString() ?? "unknown" : "unknown";
    File.AppendAllText(requestLog, type + Environment.NewLine);

    var response = JsonSerializer.SerializeToUtf8Bytes(new
    {
        id,
        available = true,
        shouldWarn = true,
        risk = "high",
        rulesVersion = "test-mock",
        indicators = new[]
        {
            new
            {
                code = "TEST_MOCK",
                description = "Wynik kontrolowany testu integracyjnego — nie jest analizą reputacji."
            }
        }
    });
    BinaryPrimitives.WriteInt32LittleEndian(header, response.Length);
    output.Write(header);
    output.Write(response);
    output.Flush();
}

static bool TryReadExactly(Stream stream, byte[] buffer)
{
    var offset = 0;
    while (offset < buffer.Length)
    {
        var read = stream.Read(buffer, offset, buffer.Length - offset);
        if (read == 0) return false;
        offset += read;
    }
    return true;
}
