using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests;

public sealed class ServiceEventNotificationPolicyTests
{
    [Theory]
    [InlineData("Information", false)]
    [InlineData("Low", true)]
    [InlineData("Moderate", true)]
    [InlineData("High", true)]
    [InlineData("Critical", true)]
    [InlineData("Unknown", false)]
    [InlineData(null, false)]
    public void OnlyNonInformationalKnownRiskLevelsNotify(string? risk, bool expected)
        => Assert.Equal(expected, ServiceEventNotificationPolicy.ShouldNotify(risk));
}
