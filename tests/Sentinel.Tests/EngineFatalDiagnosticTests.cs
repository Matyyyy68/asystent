using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests;

public sealed class EngineFatalDiagnosticTests
{
    [Theory]
    [InlineData("SENTINEL_ENGINE_FATAL type=System.IO.IOException", "System.IO.IOException")]
    [InlineData("SENTINEL_ENGINE_FATAL type=Sentinel.Engine.DataStoreException", "Sentinel.Engine.DataStoreException")]
    public void ReadsOnlyTheRedactedEngineFatalType(string line, string expected)
        => Assert.Equal(expected, EngineFatalDiagnostic.ReadExceptionType(line));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("unhandled exception at C:\\Users\\Alice\\secret.txt")]
    public void DoesNotForwardUnrecognizedOrSensitiveDiagnosticText(string? line)
        => Assert.Null(EngineFatalDiagnostic.ReadExceptionType(line));

    [Fact]
    public void ReplacesAnInvalidOrOversizedTypeWithAGenericType()
    {
        Assert.Equal("System.Exception", EngineFatalDiagnostic.ReadExceptionType("SENTINEL_ENGINE_FATAL type=Type with path"));
        Assert.Equal("System.Exception", EngineFatalDiagnostic.ReadExceptionType("SENTINEL_ENGINE_FATAL type=System.IO.IOException C:\\Users\\Alice\\secret.txt"));
        Assert.Equal("System.Exception", EngineFatalDiagnostic.ReadExceptionType("SENTINEL_ENGINE_FATAL type=" + new string('A', 161)));
        Assert.Equal("System.Exception", EngineFatalDiagnostic.SanitizeExceptionType("CustomException\rpath=C:\\Users\\Alice"));
        Assert.Equal("System.Exception", EngineFatalDiagnostic.SanitizeExceptionType(null));
    }
}
