using Sentinel.Core.Analysis;
using Xunit;

namespace Sentinel.Tests;

public sealed class SecurityCenterAlertPolicyTests
{
    [Theory]
    [InlineData("wymaga uwagi według Windows Security Center")]
    [InlineData("nie jest monitorowane przez Windows Security Center")]
    [InlineData("wstrzymane według Windows Security Center")]
    [InlineData("Windows Security Center niedostępne")]
    [InlineData("API Windows Security Center niedostępne")]
    public void ReportsAttentionForExplicitUnhealthyOrUnavailableStates(string health) =>
        Assert.True(SecurityCenterAlertPolicy.RequiresAttention(health));

    [Theory]
    [InlineData("stan dobry według Windows Security Center")]
    [InlineData("nieznany stan Windows Security Center")]
    [InlineData("odczyt niedostępny (0x80004005)")]
    [InlineData(null)]
    [InlineData("")]
    public void DoesNotReportAttentionForHealthyUnknownOrUnparsedStates(string? health) =>
        Assert.False(SecurityCenterAlertPolicy.RequiresAttention(health));
}
