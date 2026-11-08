namespace Sentinel.Engine;

public sealed record DownloadedFileTypeResult(string? DetectedType, bool ExtensionMismatch);

/// <summary>Recognizes a small set of common file signatures without executing or retaining file content.</summary>
public static class DownloadedFileTypeInspector
{
    private const int MaximumHeaderBytes = 4096;

    public static async Task<DownloadedFileTypeResult> InspectAsync(Stream stream, string fileName, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(fileName);
        if (!stream.CanRead || !stream.CanSeek) throw new ArgumentException("Stream musi umożliwiać odczyt i przewijanie.", nameof(stream));

        var originalPosition = stream.Position;
        var remaining = stream.Length > originalPosition ? stream.Length - originalPosition : 0;
        var header = new byte[checked((int)Math.Min(remaining, MaximumHeaderBytes))];
        try
        {
            var read = 0;
            while (read < header.Length)
            {
                var count = await stream.ReadAsync(header.AsMemory(read), cancellationToken);
                if (count == 0) break;
                read += count;
            }
            var detected = Detect(header.AsSpan(0, read));
            var extension = Path.GetExtension(fileName);
            var expected = ExpectedType(extension);
            return new(detected, detected is not null && expected is not null && !expected.Contains(detected));
        }
        finally
        {
            stream.Position = originalPosition;
        }
    }

    private static string? Detect(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length >= 64 && bytes[0] == (byte)'M' && bytes[1] == (byte)'Z')
        {
            var peOffset = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(0x3c, 4));
            if (peOffset >= 64 && peOffset <= bytes.Length - 4 && bytes.Slice(peOffset, 4).SequenceEqual("PE\0\0"u8))
                return "pe";
        }
        if (bytes.StartsWith("%PDF-"u8)) return "pdf";
        if (bytes.StartsWith("PK\x03\x04"u8) || bytes.StartsWith("PK\x05\x06"u8) || bytes.StartsWith("PK\x07\x08"u8)) return "zip";
        if (bytes.StartsWith(new byte[] { 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1 })) return "ole";
        if (bytes.StartsWith(new byte[] { 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a })) return "png";
        if (bytes.StartsWith(new byte[] { 0xff, 0xd8, 0xff })) return "jpeg";
        if (bytes.StartsWith("GIF87a"u8) || bytes.StartsWith("GIF89a"u8)) return "gif";
        if (bytes.StartsWith("{\\rtf"u8)) return "rtf";
        if (bytes.StartsWith(new byte[] { 0x7f, 0x45, 0x4c, 0x46 })) return "elf";
        return null;
    }

    private static HashSet<string>? ExpectedType(string extension) => extension.ToLowerInvariant() switch
    {
        ".exe" or ".dll" or ".sys" or ".scr" or ".com" => ["pe"],
        ".pdf" => ["pdf"],
        ".zip" or ".docx" or ".xlsx" or ".pptx" or ".jar" or ".apk" => ["zip"],
        ".doc" or ".xls" or ".ppt" => ["ole"],
        ".png" => ["png"],
        ".jpg" or ".jpeg" => ["jpeg"],
        ".gif" => ["gif"],
        ".rtf" => ["rtf"],
        _ => null
    };
}

