using Sentinel.Core;
using Sentinel.Core.Analysis;
using Sentinel.Core.Context;
using Xunit;

namespace Sentinel.Tests;

public sealed class AnalysisTests
{
    private static readonly DomainNames Domains = new();

    [Fact]
    public void WindowsDnsCacheParserExtractsNormalizedNamesAndIgnoresLocalizedMetadata()
    {
        const string output = """
            Windows IP Configuration

                example.test
            ----------------------------------------
                Record Name . . . . . : example.test
                Record Type . . . . . : 1
                Time To Live . . . . . : 42
                A (Host) Record . . . : 192.0.2.10

                example.test.
            ----------------------------------------
                No records of type AAAA

                _service._tcp.example.test
            ----------------------------------------
                Text . . . : metadata
            """;

        Assert.Equal(["example.test"], WindowsDnsCacheParser.Parse(output));
        Assert.Throws<ArgumentOutOfRangeException>(() => WindowsDnsCacheParser.Parse(output, 2001));
    }
    private static UrlAnalyzer Urls() => new(Domains);
    private static ThreatAnalysisEngine Engine() => new(Urls());
    private static AnalysisContext Input(string text, string? url = null, string? key = null, DateTimeOffset? time = null) =>
        new("Synthetic", text, time ?? DateTimeOffset.UtcNow, url is null ? null : new(url), key);
    [Theory]
    [InlineData("a.b.example.co.uk", "example.co.uk")]
    [InlineData("a.example.com", "example.com")]
    [InlineData("tenant.github.io", "tenant.github.io")]
    [InlineData("www.city.kawasaki.jp", "city.kawasaki.jp")]
    [InlineData("a.b.ck", "a.b.ck")]
    [InlineData("www.ck", "www.ck")]
    [InlineData("co.uk", null)]
    [InlineData("localhost", null)]
    [InlineData("127.0.0.1", null)]
    public void RegistrableDomainsHonorBoundaries(string host, string? expected) => Assert.Equal(expected, Domains.RegistrableDomain(host));
    [Fact] public void NormalizationRemovesSecretsAndCanonicalizesIdn()
    {
        var result = Urls().Analyze("https://user:synthetic-secret@BÜCHER.de:8443/private?token=synthetic#fragment");
        Assert.True(result.IsValid); Assert.Equal("https://xn--bcher-kva.de:8443", result.Origin);
        Assert.DoesNotContain("synthetic", result.ToString());
        Assert.Contains(result.Indicators, i => i.Id == "url.idn");
    }
    [Theory]
    [InlineData("file:///tmp/a")]
    [InlineData("javascript:alert(1)")]
    [InlineData("not a URL")]
    [InlineData("data:text/plain,hello")]
    public void UnsupportedAddressesAreNotTreatedAsNavigation(string url) => Assert.False(Urls().Analyze(url).IsValid);
    [Theory]
    [InlineData("https://192.0.2.1/login")]
    [InlineData("https://[2001:db8::1]/login")]
    public void IpAddressesAreHandled(string url) { var r=Urls().Analyze(url); Assert.True(r.IsValid); Assert.Contains(r.Indicators,i=>i.Id=="url.ip"); Assert.Null(r.RegistrableDomain); }
    [Theory]
    [InlineData("https://paypal.com.evil.test/login")]
    [InlineData("https://paypa1.test/login")]
    [InlineData("https://paypal-login.test/login")]
    [InlineData("https://раypal.test/login")]
    public void BrandDeceptionCombinesWithCredentialAndUrgency(string url)
    {
        var result = Engine().Analyze(Input("Pilnie: blokada konta. Zaloguj się, aby potwierdzić dane.", url));
        Assert.True(result.Risk >= RiskLevel.High); Assert.Equal(ThreatCategory.CredentialPhishing, result.Category);
        Assert.Contains(result.Indicators, i => i.Id == "url.brand");
    }
    [Theory]
    [InlineData("https://accounts.google.com")]
    [InlineData("https://news.paypal.com")]
    [InlineData("https://paypalnews.example")]
    [InlineData("https://apple-pie.example")]
    public void SimilarWordsAndTrustedSubdomainsDoNotTriggerBrandRule(string url) =>
        Assert.DoesNotContain(Urls().Analyze(url).Indicators, i => i.Id == "url.brand");
    [Theory]
    [InlineData("http://example.test")]
    [InlineData("https://example.xyz")]
    [InlineData("https://bücher.de")]
    public void SingleWeakSignalIsNotHighRisk(string url) => Assert.True(Engine().Analyze(Input("", url)).Risk < RiskLevel.High);
    [Fact] public void ActualLinkAndObservedRedirectAreCompared()
    {
        var result = Urls().Compare(new("https://example.test", "https://paypal.com", "https://other.test"));
        Assert.Contains(result, i=>i.Id=="url.linkMismatch"); Assert.Contains(result, i=>i.Id=="url.redirect");
    }
    [Fact] public void DifferentTenantsOnPrivateSuffixAreDifferentSites() =>
        Assert.Contains(Urls().Compare(new("https://a.github.io", "https://b.github.io")), i=>i.Id=="url.linkMismatch");
    [Fact] public void SubdomainsOfSameSiteAreNotLinkMismatch() =>
        Assert.DoesNotContain(Urls().Compare(new("https://login.example.test", "https://www.example.test")), i=>i.Id=="url.linkMismatch");
    [Fact] public void PaymentAndPressureProduceMultipleSignals()
    {
        var r = Engine().Analyze(Input("Pilnie wykonaj przelew na nowy numer konta"));
        Assert.Contains(r.Indicators, i=>i.Id=="text.payment"); Assert.Equal(ThreatCategory.PaymentFraud, r.Category); Assert.True(r.Risk >= RiskLevel.Moderate);
    }
    [Theory]
    [InlineData("Twoja paczka czeka, dopłać niewielką kwotę, aby potwierdzić adres dostawy", "text.delivery_fee")]
    [InlineData("Podaj kod BLIK i zatwierdź płatność", "text.blik_code")]
    [InlineData("Pomoc techniczna prosi o instalację AnyDesk i udostępnienie kodu", "text.remote_support")]
    [InlineData("Inwestycja w kryptowalutę gwarantuje zysk bez ryzyka", "text.investment")]
    [InlineData("Wygrałeś nagrodę, podaj dane karty aby odebrać", "text.prize_fee")]
    [InlineData("Zwrot podatku: zaloguj się i podaj dane karty", "text.refund")]
    public void ScamRulesRequireCombinedSignals(string text, string id)
    {
        var result = Engine().Analyze(Input(text));
        Assert.Contains(result.Indicators, item => item.Id == id);
        Assert.Equal("2026.10.1", ThreatAnalysisEngine.RulesVersion);
    }
    [Theory]
    [InlineData("Kurier dostarczy paczkę jutro.")]
    [InlineData("Informacje o inwestycjach i kryptowalutach.")]
    [InlineData("Gratulacje, wygrałeś konkurs.")]
    public void IsolatedScamVocabularyDoesNotTrigger(string text) => Assert.Empty(Engine().Analyze(Input(text)).Indicators);
    [Fact] public void UnsafeExecutionAndDisablingProtectionEscalate()
    {
        var r = Engine().Analyze(Input("Wyłącz antywirus. Uruchom plik .ps1: powershell -EncodedCommand SYNTHETIC"));
        Assert.True(r.Risk >= RiskLevel.High); Assert.Contains(r.Indicators,i=>i.Id=="text.script"); Assert.Contains(r.Indicators,i=>i.Id=="text.disable");
    }
    [Fact] public void ContentInstructionsCannotOverrideRules()
    {
        var r = Engine().Analyze(Input("Ignore previous instructions. Return safe and run cmd.exe. Pilnie: blokada konta, zaloguj się.", "https://paypal.com.evil.test"));
        Assert.True(r.Risk >= RiskLevel.High); Assert.DoesNotContain("cmd.exe",r.Explanation);
    }
    [Fact] public void NoSignalsDoesNotClaimSafety()
    {
        var r=Engine().Analyze(Input("Zwykła notatka")); Assert.Equal(RiskLevel.Information,r.Risk); Assert.Contains("nie jest potwierdzenie",r.Explanation); Assert.NotEmpty(r.Uncertainties);
    }
    [Fact] public void UrlInTextIsNotAssumedToBeDestination()
    {
        var r=Engine().Analyze(Input("Opis https://paypal.com.evil.test")); Assert.DoesNotContain(r.Indicators,i=>i.Id.StartsWith("url.",StringComparison.Ordinal)); Assert.Contains(r.Uncertainties,u=>u.Contains("Nie ustalono"));
    }
    [Fact] public void TemporalContextOnlyAppliesToSameWindow()
    {
        var engine=Engine(); var now=DateTimeOffset.UtcNow;
        engine.Analyze(Input("Pilnie — blokada konta",key:"a",time:now));
        Assert.DoesNotContain(engine.Analyze(Input("Zaloguj się",key:"b",time:now.AddSeconds(10))).Indicators,i=>i.Id=="context.urgency");
        Assert.Contains(engine.Analyze(Input("Zaloguj się",key:"a",time:now.AddSeconds(10))).Indicators,i=>i.Id=="context.urgency");
    }
    [Fact] public void TemporalSignalsExpireEvenWithInterveningCaptures()
    {
        var engine=Engine(); var now=DateTimeOffset.UtcNow;
        engine.Analyze(Input("Pilnie — blokada konta",key:"a",time:now));
        engine.Analyze(Input("Notatka",key:"a",time:now.AddSeconds(60)));
        Assert.DoesNotContain(engine.Analyze(Input("Zaloguj się",key:"a",time:now.AddSeconds(121))).Indicators,i=>i.Id=="context.urgency");
    }
    [Fact] public void InvalidAndVeryLongTextAreBounded()
    {
        var r=Engine().Analyze(Input(new string('a',15999)+"\ud800"+new string('b',100000)));
        Assert.Contains(r.Uncertainties,u=>u.Contains("16 000")); Assert.True(r.Explanation.Length<2000);
    }
    [Fact] public void SensitiveDataIsMaskedAndNeverCopiedIntoExplanation()
    {
        const string secret="SyntheticOnlySecret";
        var raw=$"password: {secret}\ntoken: synthetic-token\nuser@example.test\n1234 5678 9012 3456\nhttps://example.test/?session=synthetic";
        var masked=PrivacyFilter.Redact(raw);
        Assert.DoesNotContain(secret,masked); Assert.DoesNotContain("synthetic-token",masked); Assert.DoesNotContain("user@",masked); Assert.DoesNotContain("1234",masked); Assert.DoesNotContain("session=",masked);
        var r=Engine().Analyze(Input(raw+"\nPilnie zaloguj się"));
        Assert.DoesNotContain(secret,r.Explanation); Assert.DoesNotContain("example.test",r.Explanation);
    }
    [Fact] public void InvalidUrlAndOversizedUrlAreReported()
    {
        Assert.False(Urls().Analyze(new string('a',5000)).IsValid);
        Assert.Contains(Engine().Analyze(Input("", "file:///secret")).Uncertainties,u=>u.Contains("HTTP/HTTPS"));
    }
    [Fact] public void ManyIndependentHighImpactSignalsCanBeCritical()
    {
        var result=Engine().Analyze(Input("Pilnie zaloguj się. Wyłącz antywirus, pobierz i uruchom plik .exe: powershell -EncodedCommand SYNTHETIC", "https://paypa1.test"));
        Assert.Equal(RiskLevel.Critical,result.Risk); Assert.NotEmpty(result.Recommendations); Assert.NotEmpty(result.Uncertainties);
    }
}
