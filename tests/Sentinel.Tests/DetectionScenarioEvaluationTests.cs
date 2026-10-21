using Sentinel.Core;
using Sentinel.Core.Analysis;
using Sentinel.Core.Context;
using Xunit;

namespace Sentinel.Tests;

public sealed class DetectionScenarioEvaluationTests
{
    private sealed record Scenario(string Name, string Text, string? Url, bool ExpectedElevatedRisk, string? DisplayedUrl = null);

    private static readonly Scenario[] Scenarios =
    [
        new("urgent credential lure and brand typo", "Pilnie: blokada konta. Zaloguj się, aby potwierdzić dane.", "https://paypa1.test/login", true),
        new("delivery fee and sign-in request", "Pilnie dopłać za paczkę i zaloguj się, aby potwierdzić adres dostawy.", null, true),
        new("BLIK code request", "Pilnie podaj kod BLIK i zatwierdź przelew.", null, true),
        new("remote support asks for access", "Pilnie zainstaluj AnyDesk i podaj kod zdalnego dostępu.", null, true),
        new("investment guarantees risk-free return", "Inwestycja w kryptowalutę gwarantuje zysk bez ryzyka.", null, true),
        new("prize requires card data", "Wygrałeś nagrodę, podaj dane karty aby odebrać.", null, true),
        new("refund asks for credentials and card", "Zwrot podatku: zaloguj się i podaj dane karty.", null, true),
        new("message asks to disable Defender", "Wyłącz zabezpieczenia Windows i uruchom załączony program.", null, true),
        new("encoded PowerShell download", "Uruchom polecenie powershell -EncodedCommand SYNTHETIC.", null, true),
        new("HTTP IP destination", "", "http://192.0.2.10:8080/login", true),
        new("visible link and actual target differ", "Sprawdź link przed kliknięciem.", "https://example.test", true, "https://paypal.com"),
        new("hosted brand name outside official domain", "", "https://login.paypal.com.attacker.test", true),
        new("userinfo masks the actual destination host", "", "https://paypal.com@attacker.test/login", true),

        new("ordinary work urgency", "Pilnie wyślij raport do zespołu przed spotkaniem.", null, false),
        new("routine intranet sign-in", "Zaloguj się do firmowego intranetu, aby sprawdzić grafik.", null, false),
        new("known payee transfer", "Wykonaj przelew na zapisany rachunek zgodnie z fakturą.", null, false),
        new("parcel delivery update", "Kurier dostarczy paczkę jutro. Sprawdź domofon.", null, false),
        new("informational crypto article", "Artykuł porównuje inwestycje w kryptowaluty i ryzyko.", null, false),
        new("contest announcement", "Gratulacje, wygrałeś konkurs organizowany przez szkołę.", null, false),
        new("installed remote-support tool", "AnyDesk jest już zainstalowany na komputerze służbowym.", null, false),
        new("routine PowerShell help", "Użyj PowerShell Get-Process do diagnostyki wydajności.", null, false),
        new("known provider subdomain", "", "https://accounts.google.com", false),
        new("neutral test domain", "", "https://example.test", false),
        new("brand-like but distinct word", "", "https://paypalnews.example", false),
        new("ordinary HTTP site", "", "http://example.test", false),
    ];

    [Fact]
    public void SyntheticDetectionScenariosMeetTheirElevatedRiskLabels()
    {
        int truePositives = 0, falsePositives = 0, trueNegatives = 0, falseNegatives = 0;
        var failures = new List<string>();
        foreach (var scenario in Scenarios)
        {
            var engine = new ThreatAnalysisEngine(new UrlAnalyzer(new DomainNames()));
            var navigation = scenario.Url is null ? null : new NavigationSignal(scenario.Url, scenario.DisplayedUrl);
            var assessment = engine.Analyze(new AnalysisContext("synthetic-scenario", scenario.Text,
                DateTimeOffset.UnixEpoch, navigation));
            var predictedElevatedRisk = assessment.Risk >= RiskLevel.Moderate;

            if (scenario.ExpectedElevatedRisk && predictedElevatedRisk) truePositives++;
            else if (scenario.ExpectedElevatedRisk) { falseNegatives++; failures.Add($"FN: {scenario.Name} → {assessment.Risk}"); }
            else if (predictedElevatedRisk) { falsePositives++; failures.Add($"FP: {scenario.Name} → {assessment.Risk}"); }
            else trueNegatives++;
        }

        Assert.True(failures.Count == 0,
            $"Synthetic scenario mismatches (TP={truePositives}, FP={falsePositives}, TN={trueNegatives}, FN={falseNegatives}): {string.Join("; ", failures)}");
        Assert.Equal(13, truePositives);
        Assert.Equal(12, trueNegatives);
        Assert.Equal(25, Scenarios.Length);
    }
}
