using Sentinel.Engine;
using Xunit;

namespace Sentinel.Tests;

public sealed class DownloadedFileTypeInspectorTests
{
    [Fact]
    public async Task RecognizesPortableExecutableAndFlagsMismatchedExtensionWithoutChangingPosition()
    {
        var bytes = new byte[135];
        const int fileStart = 7;
        bytes[fileStart] = (byte)'M';
        bytes[fileStart + 1] = (byte)'Z';
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(fileStart + 0x3c, 4), 64);
        "PE\0\0"u8.CopyTo(bytes.AsSpan(fileStart + 64));
        using var stream = new MemoryStream(bytes);
        stream.Position = fileStart;

        var result = await DownloadedFileTypeInspector.InspectAsync(stream, "invoice.pdf");

        Assert.Equal("pe", result.DetectedType);
        Assert.True(result.ExtensionMismatch);
        Assert.Equal(fileStart, stream.Position);
    }

    [Fact]
    public async Task RecognizesMatchingAndUnknownFileExtensionsWithoutFalseMismatch()
    {
        using var pdf = new MemoryStream("%PDF-1.7"u8.ToArray());
        var matching = await DownloadedFileTypeInspector.InspectAsync(pdf, "report.PDF");
        Assert.Equal("pdf", matching.DetectedType);
        Assert.False(matching.ExtensionMismatch);

        using var unknown = new MemoryStream("%PDF-1.7"u8.ToArray());
        var unknownExtension = await DownloadedFileTypeInspector.InspectAsync(unknown, "report.custom");
        Assert.Equal("pdf", unknownExtension.DetectedType);
        Assert.False(unknownExtension.ExtensionMismatch);
    }

    [Fact]
    public async Task EmptyOrPositionPastEndStreamIsHandledAndPositionIsPreserved()
    {
        using var empty = new MemoryStream();
        empty.Position = 5;

        var result = await DownloadedFileTypeInspector.InspectAsync(empty, "unknown.bin");

        Assert.Null(result.DetectedType);
        Assert.False(result.ExtensionMismatch);
        Assert.Equal(5, empty.Position);
    }

    [Fact]
    public async Task RejectsNullFileName()
    {
        using var stream = new MemoryStream("%PDF-1.7"u8.ToArray());
        await Assert.ThrowsAsync<ArgumentNullException>(() => DownloadedFileTypeInspector.InspectAsync(stream, null!));
    }
}
