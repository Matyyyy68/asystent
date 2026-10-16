using System.Buffers.Binary;

namespace Sentinel.UrlHost;

/// <summary>Chrome/Edge Native Messaging length-prefixed UTF-8 framing.</summary>
public static class NativeMessagingProtocol
{
    public const int MaximumMessageBytes = 1024 * 1024;

    public static async Task<byte[]?> ReadAsync(Stream input, CancellationToken cancellationToken = default)
    {
        var header = new byte[sizeof(uint)];
        var first = await input.ReadAsync(header.AsMemory(0, 1), cancellationToken);
        if (first == 0) return null;
        await ReadExactlyAsync(input, header.AsMemory(1), cancellationToken);
        var length = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (length is 0 or > MaximumMessageBytes) throw new InvalidDataException("Nieprawidłowy rozmiar komunikatu Native Messaging.");
        var payload = new byte[checked((int)length)];
        await ReadExactlyAsync(input, payload, cancellationToken);
        return payload;
    }

    public static async Task WriteAsync(Stream output, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
    {
        if (payload.Length is 0 or > MaximumMessageBytes) throw new InvalidDataException("Nieprawidłowy rozmiar odpowiedzi Native Messaging.");
        var header = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(header, checked((uint)payload.Length));
        await output.WriteAsync(header, cancellationToken);
        await output.WriteAsync(payload, cancellationToken);
        await output.FlushAsync(cancellationToken);
    }

    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        while (!buffer.IsEmpty)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken);
            if (read == 0) throw new EndOfStreamException("Niekompletny komunikat Native Messaging.");
            buffer = buffer[read..];
        }
    }
}
