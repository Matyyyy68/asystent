extern alias UrlHostAssembly;

using Sentinel.UrlHost;
using Xunit;

using UrlHostProgram = UrlHostAssembly::Sentinel.UrlHost.Program;

namespace Sentinel.Tests;

public class NativeLaunchTests
{
    [Theory]
    [InlineData("chrome-extension://nakmencmekkefmcddpihiiohjgabfemg/", true)]
    [InlineData("chrome-extension://untrusted/", false)]
    [InlineData("https://example.com/", false)]
    public void ValidatesCaller(string origin, bool expected) =>
        Assert.Equal(expected, UrlHostProgram.IsAllowedLaunch([origin]));

    [Fact]
    public void AcceptsChromiumWindowArgument() => Assert.True(UrlHostProgram.IsAllowedLaunch(
        ["chrome-extension://nakmencmekkefmcddpihiiohjgabfemg/", "--parent-window=0"]));

    [Theory]
    [InlineData("--parent-window=-1")]
    [InlineData("--parent-window=abc")]
    [InlineData("--unknown")]
    public void RejectsInvalidArguments(string argument) => Assert.False(UrlHostProgram.IsAllowedLaunch(
        ["chrome-extension://nakmencmekkefmcddpihiiohjgabfemg/", argument]));

    [Fact]
    public void RejectsMissingOrigin() => Assert.False(UrlHostProgram.IsAllowedLaunch([]));
}
