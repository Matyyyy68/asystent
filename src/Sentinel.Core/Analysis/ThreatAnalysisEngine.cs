using System.Globalization;
using System.Text;
using Sentinel.Core.Context;

namespace Sentinel.Core.Analysis;

/// <summary>Deterministic rules; untrusted content cannot invoke tools or alter the rules.</summary>
public sealed class ThreatAnalysisEngine(UrlAnalyzer urls)
{
    public const string RulesVersion = "2026.10.5";
    private readonly object gate = new();
    private readonly Dictionary<string, (DateTimeOffset Seen, DateTimeOffset? UrgencyAt)> sessions = new(StringComparer.Ordinal);
    public ThreatAssessment Analyze(AnalysisContext context)
    {
        var text = Fold(PrivacyFilter.Redact(context.Text));
        var indicators = new List<ThreatIndicator>();
        bool Has(params string[] phrases) => phrases.Any(p => text.Contains(p, StringComparison.Ordinal));
        void Add(string id, string description, int weight, ThreatCategory category) => indicators.Add(new(id, description, weight, category));
        var urgency = Has("pilnie", "natychmiast", "ostatnia szansa", "blokad", "urgent", "immediately", "suspend", "within 24 hours");
        if (urgency) Add("text.urgency", "Wiadomość wywiera presję czasu lub grozi blokadą konta.", 2, ThreatCategory.SocialEngineering);
        if (Has("zaloguj", "logowanie", "potwierdz dane", "verify your account", "sign in", "enter your password", "podaj haslo"))
            Add("text.credentials", "Treść nakłania do uwierzytelnienia lub potwierdzenia danych.", 2, ThreatCategory.CredentialPhishing);
        if (Has("przelew", "zmiana rachunku", "zmieniony rachunek", "nowy numer konta", "bank transfer", "wire transfer", "new bank account"))
            Add("text.payment", "Treść dotyczy przelewu lub zmiany rachunku odbiorcy.", 2, ThreatCategory.PaymentFraud);
        if (Has("paczka", "przesylk", "kurier", "delivery", "parcel") &&
            Has("doplata", "oplac", "platnosc", "payment", "aktualizuj adres", "adres dostawy"))
            Add("text.delivery_fee", "Prośba o dopłatę lub dane dostawy jest powiązana z przesyłką.", 3, ThreatCategory.PaymentFraud);
        if (Has("blik") && Has("kod") && Has("podaj", "przekaz", "wyslij", "potwierdz", "zatwierdz", "send", "share"))
            Add("text.blik_code", "Treść prosi o przekazanie lub zatwierdzenie kodu BLIK.", 4, ThreatCategory.PaymentFraud);
        if (Has("anydesk", "teamviewer", "quick assist", "zdalny dostep", "pomoc techniczna", "technical support") &&
            Has("zainstaluj", "udostepn", "podaj kod", "install", "access code", "remote access"))
            Add("text.remote_support", "Prośba o zdalny dostęp jest połączona z działaniem użytkownika.", 3, ThreatCategory.UnsafeExecution);
        if (Has("bitcoin", "kryptowalut", "crypto", "inwestycj") &&
            Has("gwarantowany zysk", "bez ryzyka", "podwoj", "guaranteed return", "no risk"))
            Add("text.investment", "Obietnica zysku bez ryzyka to sygnał potencjalnego oszustwa inwestycyjnego.", 3, ThreatCategory.SocialEngineering);
        if (Has("wygra", "nagrod", "prize", "winner") &&
            Has("doplata", "oplata", "dane karty", "podaj dane", "claim fee", "card details"))
            Add("text.prize_fee", "Odbiór nagrody jest powiązany z opłatą lub przekazaniem danych.", 3, ThreatCategory.PaymentFraud);
        if (Has("zwrot", "refund", "zwrot podatku") &&
            Has("dane karty", "podaj haslo", "zaloguj", "oplat", "card details", "password"))
            Add("text.refund", "Prośba o zwrot jest powiązana z danymi płatniczymi lub logowaniem.", 3, ThreatCategory.PaymentFraud);
        if (Has("wylacz antywirus", "wylacz zabezpieczenia", "disable antivirus", "disable defender", "set-mppreference -disablerealtimemonitoring"))
            Add("text.disable", "Treść nakłania do wyłączenia zabezpieczeń.", 4, ThreatCategory.SecurityTampering);
        if (Has("-encodedcommand", "-enc ", "invoke-expression", "iex(", "iex (", "curl ", "wget ") &&
            Has("powershell", "pwsh", "| sh", "| bash", "invoke-expression", "iex"))
            Add("text.script", "Polecenie może pobierać lub wykonywać skrypt albo ukrywać jego treść.", 4, ThreatCategory.UnsafeExecution);
        if (Has("uruchom plik", "zainstaluj program", "pobierz i uruchom", "run this file", "install this application", ".exe", ".ps1", ".scr"))
            Add("text.download", "Treść zachęca do uruchomienia pliku lub instalacji programu.", 2, ThreatCategory.UnsafeExecution);
        if (context.Navigation is { } navigation) indicators.AddRange(urls.Compare(navigation));
        bool priorUrgency = false;
        if (context.CorrelationKey is { Length: > 0 and <= 200 } key)
        {
            lock (gate)
            {
                foreach (var old in sessions.Where(s => context.Timestamp - s.Value.Seen > TimeSpan.FromMinutes(2) || context.Timestamp < s.Value.Seen).Select(s => s.Key).ToArray()) sessions.Remove(old);
                priorUrgency = sessions.TryGetValue(key, out var previous) && previous.UrgencyAt is { } urgentAt && context.Timestamp - urgentAt <= TimeSpan.FromMinutes(2);
                if (sessions.Count >= 32 && !sessions.ContainsKey(key)) sessions.Remove(sessions.MinBy(s => s.Value.Seen).Key);
                sessions[key] = (context.Timestamp, urgency ? context.Timestamp : priorUrgency ? previous.UrgencyAt : null);
            }
        }
        if (!urgency && priorUrgency && indicators.Any(s => s.Id == "text.credentials"))
            Add("context.urgency", "W tym samym oknie niedawno wystąpiła presja czasu, a teraz prośba o logowanie.", 2, ThreatCategory.CredentialPhishing);
        indicators = indicators.DistinctBy(i => i.Id).ToList();
        int score = indicators.Sum(i => i.Weight);
        // Explicit aggregation, not a calibrated probability. A single weak signal is never a high alert.
        var risk = score == 0 ? RiskLevel.Information : score <= 2 ? RiskLevel.Low : score < 7 || indicators.Count < 2 ? RiskLevel.Moderate : score < 12 || indicators.Count < 3 ? RiskLevel.High : RiskLevel.Critical;
        var category = indicators.OrderByDescending(i => i.Weight).Select(i => i.Category).FirstOrDefault();
        if (indicators.Any(i => i.Id == "text.payment") && !indicators.Any(i => i.Id == "text.credentials") && !indicators.Any(i => i.Weight >= 4)) category = ThreatCategory.PaymentFraud;
        if (indicators.Any(i => i.Id == "text.credentials") && indicators.Any(i => i.Id.StartsWith("url.", StringComparison.Ordinal) && i.Weight >= 3)) category = ThreatCategory.CredentialPhishing;
        var uncertainty = new List<string> { "Reguły nie potwierdzają intencji nadawcy ani bezpieczeństwa strony. Brak sygnałów nie oznacza bezpieczeństwa." };
        if (context.Navigation is null) uncertainty.Add("Nie ustalono wiarygodnego adresu docelowego ani przekierowań; UI Automation nie potwierdza nawigacji.");
        else if (!urls.Analyze(context.Navigation.Target).IsValid) uncertainty.Add("Podany adres nie jest poprawnym adresem HTTP/HTTPS.");
        if (context.Navigation?.DisplayedUrl is { } displayed && !urls.Analyze(displayed).IsValid)
            uncertainty.Add("Widoczny tekst linku nie jest poprawnym adresem HTTP/HTTPS; nie można porównać adresów.");
        if (context.Navigation?.VerifiedRedirectTarget is { } redirect && !urls.Analyze(redirect).IsValid)
            uncertainty.Add("Podany cel przekierowania nie jest poprawnym adresem HTTP/HTTPS.");
        if (context.Text.Length > PrivacyFilter.MaximumTextLength) uncertainty.Add("Treść została ograniczona do 16 000 znaków.");
        string[] recommendations = risk == RiskLevel.Information ? ["Zachowaj ostrożność i niezależnie zweryfikuj nietypowe prośby."] :
            ["Nie podawaj danych, nie wykonuj przelewu ani polecenia przed weryfikacją.", "Otwórz usługę ze znanego adresu i skontaktuj się z nadawcą niezależnym kanałem."];
        var explanation = indicators.Count == 0 ? "Nie wykryto sygnałów obsługiwanych przez reguły. To nie jest potwierdzenie bezpieczeństwa." :
            string.Join(" ", indicators.Select(i => i.Description)) + " Możliwe konsekwencje obejmują utratę danych, pieniędzy lub kontroli nad urządzeniem.";
        return new(category, risk, indicators, uncertainty, recommendations, explanation);
    }
    private static string Fold(string value)
    {
        var builder = new StringBuilder();
        var wellFormed = string.Concat(value.EnumerateRunes().Select(r => r.ToString()));
        foreach (char c in wellFormed.ToLowerInvariant().Normalize(NormalizationForm.FormD))
            if (CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark) builder.Append(c == 'ł' ? 'l' : c);
        return builder.ToString();
    }
}
