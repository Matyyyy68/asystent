using Sentinel.Engine;
using Xunit;

namespace Sentinel.Tests;

public sealed class WindowsDefenderStatusReaderTests
{
    [Fact]
    public void ParsesReadOnlyDefenderStatusAndSignatureMetadata()
    {
        var readAt = DateTimeOffset.Parse("2026-11-03T19:00:00Z");
        var result = WindowsDefenderStatusReader.Parse("""
            {"antivirusEnabled":true,"realTimeProtectionEnabled":true,"signatureVersion":"1.451.2.0","signatureAgeDays":2,"signatureLastUpdatedUtc":"2026-11-01T18:30:00Z"}
            """, readAt);

        Assert.True(result.Available);
        Assert.True(result.AntivirusEnabled);
        Assert.True(result.RealTimeProtectionEnabled);
        Assert.Equal("1.451.2.0", result.SignatureVersion);
        Assert.Equal(2, result.SignatureAgeDays);
        Assert.Equal(DateTimeOffset.Parse("2026-11-01T18:30:00Z"), result.SignatureLastUpdatedUtc);
        Assert.Equal(readAt, result.ReadAtUtc);
    }

    [Fact]
    public void PreservesDisabledDefenderStateAndTreatsNeverUpdatedSignatureAsUnknown()
    {
        var result = WindowsDefenderStatusReader.Parse("""
            {"antivirusEnabled":false,"realTimeProtectionEnabled":false,"signatureVersion":"","signatureAgeDays":65535,"signatureLastUpdatedUtc":null}
            """);

        Assert.True(result.Available);
        Assert.False(result.AntivirusEnabled);
        Assert.False(result.RealTimeProtectionEnabled);
        Assert.Null(result.SignatureVersion);
        Assert.Null(result.SignatureAgeDays);
        Assert.Null(result.SignatureLastUpdatedUtc);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-json")]
    [InlineData("{\"antivirusEnabled\":true}")]
    public void MalformedOrIncompleteOutputIsUnavailable(string output)
    {
        Assert.False(WindowsDefenderStatusReader.Parse(output).Available);
    }

    [Fact]
    public void RejectsOversizedOrUntrustedVersionOutput()
    {
        Assert.False(WindowsDefenderStatusReader.Parse(new string('x', 4097)).Available);

        var result = WindowsDefenderStatusReader.Parse("""
            {"antivirusEnabled":true,"realTimeProtectionEnabled":true,"signatureVersion":"$(bad)","signatureAgeDays":0,"signatureLastUpdatedUtc":null}
            """);
        Assert.True(result.Available);
        Assert.Null(result.SignatureVersion);
    }
}
