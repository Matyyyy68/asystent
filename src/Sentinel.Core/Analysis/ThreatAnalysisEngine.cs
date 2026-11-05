using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Sentinel.Core.Context;

namespace Sentinel.Core.Analysis;

/// <summary>Deterministic rules; untrusted content cannot invoke tools or alter the rules.</summary>
public sealed class ThreatAnalysisEngine(UrlAnalyzer urls)
{
    public const string RulesVersion = "2026.11.03";
    private const int MaximumEmbeddedUrls = 10;
    private static readonly Regex EmbeddedHttpUrl = new(
        @"\bhttps?://[^\s<>""']{1,4096}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex EmbeddedDefangedHttpUrl = new(
        @"\bhxxps?(?:\[:\]//|://|\[://\])[^\s<>""']{1,4096}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex DefangedScheme = new(
        @"^hxxps?(?:\[:\]//|://|\[://\])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex DefangedHostSeparator = new(
        @"(?i)(?:\[\.\]|\(\.\)|\{\.\}|\[dot\])", RegexOptions.CultureInvariant);
    private readonly object gate = new();
    private readonly Dictionary<string, (DateTimeOffset Seen, DateTimeOffset? UrgencyAt)> sessions = new(StringComparer.Ordinal);
    public ThreatAssessment Analyze(AnalysisContext context)
    {
        var text = Fold(PrivacyFilter.Redact(context.Text));
        var indicators = new List<ThreatIndicator>();
        bool Has(params string[] phrases) => phrases.Any(p => text.Contains(p, StringComparison.Ordinal));
        void Add(string id, string description, int weight, ThreatCategory category) => indicators.Add(new(id, description, weight, category));
        var urgency = Has("pilnie", "natychmiast", "ostatnia szansa", "blokad", "urgent", "immediately", "suspend", "within 24 hours");
        if (urgency) Add("text.urgency", "WiadomoÅ›Ä‡ wywiera presjÄ™ czasu lub grozi blokadÄ… konta.", 2, ThreatCategory.SocialEngineering);
        if (Has("zaloguj", "logowanie", "potwierdz dane", "verify your account", "sign in", "enter your password", "podaj haslo"))
            Add("text.credentials", "TreÅ›Ä‡ nakÅ‚ania do uwierzytelnienia lub potwierdzenia danych.", 2, ThreatCategory.CredentialPhishing);
        if (Has("przelew", "zmiana rachunku", "zmieniony rachunek", "nowy numer konta", "bank transfer", "wire transfer", "new bank account"))
            Add("text.payment", "TreÅ›Ä‡ dotyczy przelewu lub zmiany rachunku odbiorcy.", 2, ThreatCategory.PaymentFraud);
        if (Has("paczka", "przesylk", "kurier", "delivery", "parcel") &&
            Has("doplata", "oplac", "platnosc", "payment", "aktualizuj adres", "adres dostawy"))
            Add("text.delivery_fee", "ProÅ›ba o dopÅ‚atÄ™ lub dane dostawy jest powiÄ…zana z przesyÅ‚kÄ….", 3, ThreatCategory.PaymentFraud);
        if (Has("blik") && Has("kod") && Has("podaj", "przekaz", "wyslij", "potwierdz", "zatwierdz", "send", "share"))
            Add("text.blik_code", "TreÅ›Ä‡ prosi o przekazanie lub zatwierdzenie kodu BLIK.", 4, ThreatCategory.PaymentFraud);
        if (Has("anydesk", "teamviewer", "quick assist", "zdalny dostep", "pomoc techniczna", "technical support") &&
            Has("zainstaluj", "udostepn", "podaj kod", "install", "access code", "remote access"))
            Add("text.remote_support", "ProÅ›ba o zdalny dostÄ™p jest poÅ‚Ä…czona z dziaÅ‚aniem uÅ¼ytkownika.", 3, ThreatCategory.UnsafeExecution);
        if (Has("bitcoin", "kryptowalut", "crypto", "inwestycj") &&
            Has("gwarantowany zysk", "bez ryzyka", "podwoj", "guaranteed return", "no risk"))
            Add("text.investment", "Obietnica zysku bez ryzyka to sygnaÅ‚ potencjalnego oszustwa inwestycyjnego.", 3, ThreatCategory.SocialEngineering);
        if (Has("wygra", "nagrod", "prize", "winner") &&
            Has("doplata", "oplata", "dane karty", "podaj dane", "claim fee", "card details"))
            Add("text.prize_fee", "OdbiÃ³r nagrody jest powiÄ…zany z opÅ‚atÄ… lub przekazaniem danych.", 3, ThreatCategory.PaymentFraud);
        if (Has("zwrot", "refund", "zwrot podatku") &&
            Has("dane karty", "podaj haslo", "zaloguj", "oplat", "card details", "password"))
            Add("text.refund", "ProÅ›ba o zwrot jest powiÄ…zana z danymi pÅ‚atniczymi lub logowaniem.", 3, ThreatCategory.PaymentFraud);
        if (Has("wylacz antywirus", "wylacz zabezpieczenia", "disable antivirus", "disable defender", "set-mppreference -disablerealtimemonitoring"))
            Add("text.disable", "TreÅ›Ä‡ nakÅ‚ania do wyÅ‚Ä…czenia zabezpieczeÅ„.", 4, ThreatCategory.SecurityTampering);
        if (Has("-encodedcommand", "-enc ", "invoke-expression", "iex(", "iex (", "curl ", "wget ") &&
            Has("powershell", "pwsh", "| sh", "| bash", "invoke-expression", "iex"))
            Add("text.script", "Polecenie moÅ¼e pobieraÄ‡ lub wykonywaÄ‡ skrypt albo ukrywaÄ‡ jego treÅ›Ä‡.", 4, ThreatCategory.UnsafeExecution);
        if (Has("uruchom plik", "zainstaluj program", "pobierz i uruchom", "run this file", "install this application", ".exe", ".ps1", ".scr"))
            Add("text.download", "TreÅ›Ä‡ zachÄ™ca do uruchomienia pliku lub instalacji programu.", 2, ThreatCategory.UnsafeExecution);
        if (context.Navigation is { } navigation) indicators.AddRange(urls.Compare(navigation));
        var extractedUrls = ExtractEmbeddedUrls(context.Text);
        foreach (var embeddedUrl in extractedUrls.Urls)
            indicators.AddRange(urls.Analyze(embeddedUrl).Indicators);
        if (extractedUrls.ContainsDefanged)
            Add("url.defanged", "Zapis defangowany adresu zostaÅ‚ znormalizowany wyÅ‚Ä…cznie na potrzeby lokalnej analizy.", 1, ThreatCategory.SuspiciousNavigation);
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
            Add("context.urgency", "W tym samym oknie niedawno wystÄ…piÅ‚a presja czasu, a teraz proÅ›ba o logowanie.", 2, ThreatCategory.CredentialPhishing);
        indicators = indicators.DistinctBy(i => i.Id).ToList();
        var riskAssessment = RiskEngine.Evaluate(indicators);
        var risk = riskAssessment.Level;
        var category = indicators.OrderByDescending(i => i.Weight).Select(i => i.Category).FirstOrDefault();
        if (indicators.Any(i => i.Id == "text.payment") && !indicators.Any(i => i.Id == "text.credentials") && !indicators.Any(i => i.Weight >= 4)) category = ThreatCategory.PaymentFraud;
        if (indicators.Any(i => i.Id == "text.credentials") && indicators.Any(i => i.Id.StartsWith("url.", StringComparison.Ordinal) && i.Weight >= 3)) category = ThreatCategory.CredentialPhishing;
        var uncertainty = new List<string> { "ReguÅ‚y nie potwierdzajÄ… intencji nadawcy ani bezpieczeÅ„stwa strony. Brak sygnaÅ‚Ã³w nie oznacza bezpieczeÅ„stwa." };
        if (extractedUrls.Urls.Count > 0)
            uncertainty.Add("Adresy HTTP/HTTPS zapisane w treÅ›ci przeanalizowano lokalnie; faktyczny cel klikniÄ™cia nie zostaÅ‚ potwierdzony.");
        if (extractedUrls.ContainsDefanged)
            uncertainty.Add("Zapis hxxp lub [.] zostaÅ‚ znormalizowany w pamiÄ™ci; adresu nie otwierano.");
        if (extractedUrls.Truncated)
            uncertainty.Add($"Przeanalizowano najwyÅ¼ej {MaximumEmbeddedUrls} rÃ³Å¼nych adresÃ³w z treÅ›ci; pozostaÅ‚e pominiÄ™to.");
        if (context.Navigation is null) uncertainty.Add("Nie ustalono wiarygodnego adresu docelowego ani przekierowaÅ„; UI Automation nie potwierdza nawigacji.");
        else if (!urls.Analyze(context.Navigation.Target).IsValid) uncertainty.Add("Podany adres nie jest poprawnym adresem HTTP/HTTPS.");
        if (context.Navigation?.DisplayedUrl is { } displayed && !urls.Analyze(displayed).IsValid)
            uncertainty.Add("Widoczny tekst linku nie jest poprawnym adresem HTTP/HTTPS; nie moÅ¼na porÃ³wnaÄ‡ adresÃ³w.");
        if (context.Navigation?.VerifiedRedirectTarget is { } redirect && !urls.Analyze(redirect).IsValid)
            uncertainty.Add("Podany cel przekierowania nie jest poprawnym adresem HTTP/HTTPS.");
        if (context.Text.Length > PrivacyFilter.MaximumTextLength) uncertainty.Add("TreÅ›Ä‡ zostaÅ‚a ograniczona do 16 000 znakÃ³w.");
        string[] recommendations = risk == RiskLevel.Information ? ["Zachowaj ostroÅ¼noÅ›Ä‡ i niezaleÅ¼nie zweryfikuj nietypowe proÅ›by."] :
            ["Nie podawaj danych, nie wykonuj przelewu ani polecenia przed weryfikacjÄ….", "OtwÃ³rz usÅ‚ugÄ™ ze znanego adresu i skontaktuj siÄ™ z nadawcÄ… niezaleÅ¼nym kanaÅ‚em."];
        var explanation = indicators.Count == 0 ? "Nie wykryto sygnaÅ‚Ã³w obsÅ‚ugiwanych przez reguÅ‚y. To nie jest potwierdzenie bezpieczeÅ„stwa." :
            string.Join(" ", indicators.Select(i => i.Description)) + " MoÅ¼liwe konsekwencje obejmujÄ… utratÄ™ danych, pieniÄ™dzy lub kontroli nad urzÄ…dzeniem.";
        return new(category, risk, indicators, uncertainty, recommendations, explanation, riskAssessment.Score);
    }

    public static (IReadOnlyList<string> Urls, bool Truncated, bool ContainsDefanged) ExtractEmbeddedUrls(string text)
    {
        var candidates = new List<(string Value, bool Defanged)>();
        foreach (var match in EmbeddedHttpUrl.Matches(text).Cast<Match>()
                     .Concat(EmbeddedDefangedHttpUrl.Matches(text).Cast<Match>()))
        {
            if (NormalizeEmbeddedUrl(TrimUrlBoundaryPunctuation(match.Value)) is { } candidate)
                candidates.Add(candidate);
        }
        var matches = candidates
            .GroupBy(candidate => candidate.Value, StringComparer.OrdinalIgnoreCase)
            .Select(group => (Value: group.First().Value, Defanged: group.Any(candidate => candidate.Defanged)))
            .Take(MaximumEmbeddedUrls + 1)
            .ToArray();
        var included = matches.Take(MaximumEmbeddedUrls).ToArray();
        return (included.Select(candidate => candidate.Value).ToArray(), matches.Length > MaximumEmbeddedUrls,
            included.Any(candidate => candidate.Defanged));
    }
    private static (string Value, bool Defanged)? NormalizeEmbeddedUrl(string candidate)
    {
        if (candidate.Length == 0) return null;
        var defanged = false;
        var scheme = DefangedScheme.Match(candidate);
        if (scheme.Success)
        {
            var normalizedScheme = candidate.StartsWith("hxxps", StringComparison.OrdinalIgnoreCase) ? "https://" : "http://";
            candidate = normalizedScheme + candidate[scheme.Length..];
            defanged = true;
        }

        var authorityStart = candidate.IndexOf("://", StringComparison.Ordinal);
        if (authorityStart < 0) return (candidate, defanged);
        authorityStart += 3;
        var authorityEnd = candidate.IndexOfAny(['/','?','#'], authorityStart);
        if (authorityEnd < 0) authorityEnd = candidate.Length;
        var authority = candidate[authorityStart..authorityEnd];
        var hostStart = authority.LastIndexOf('@') + 1;
        var hostPort = authority[hostStart..];
        // A defang marker only has meaning in a DNS host. Never rewrite userinfo,
        // ports, or IPv6 literals as though they were domain labels.
        if (hostPort.StartsWith("[", StringComparison.Ordinal)) return (candidate, false);
        var portSeparator = hostPort.LastIndexOf(':');
        var hostLength = portSeparator >= 0 && hostPort[(portSeparator + 1)..].All(char.IsAsciiDigit)
            ? portSeparator
            : hostPort.Length;
        var host = hostPort[..hostLength];
        var normalizedHost = DefangedHostSeparator.Replace(host, ".");
        if (!string.Equals(host, normalizedHost, StringComparison.Ordinal))
        {
            var absoluteHostStart = authorityStart + hostStart;
            candidate = candidate[..absoluteHostStart] + normalizedHost + candidate[(absoluteHostStart + hostLength)..];
            defanged = true;
        }

        if (!defanged) return (candidate, false);
        return Uri.TryCreate(candidate, UriKind.Absolute, out var uri) &&
               uri.Scheme is "http" or "https" && !string.IsNullOrWhiteSpace(uri.Host)
            ? (candidate, true)
            : null;
    }
    private static string TrimUrlN÷ÒÚ$z{-®éÜj×¥Ì¹•µ‰•‘‘•µÕÉ°µ±¥µ¥Ğˆ¤°4(€€€€€€€€ ‰9¥”ÕÍÑ…±½¹¼İ¥…Éå½‘¹•¼…‘É•ÍÔˆ°€‰…¹…±åÍ¥Ì¹¹…Ù¥…Ñ¥½¸µÑ…É•ĞµÕ¹Ù•É¥™¥•ˆ¤°4(€€€€€€€€ ‰A½‘…¹ä…‘É•Ì¹¥”©•ÍĞÁ½ÁÉ…İ¹å´ˆ°€‰…¹…±åÍ¥Ì¹¹…Ù¥…Ñ¥½¸µÑ…É•Ğµ¥¹Ù…±¥ˆ¤°4(€€€€€€€€ ‰]¥‘½é¹äÑ•­ÍĞ±¥¹­Ô¹¥”©•ÍĞˆ°€‰…¹…±åÍ¥Ì¹‘¥ÍÁ±…å•µÕÉ°µ¥¹Ù…±¥ˆ¤°4(€€€€€€€€ ‰A½‘…¹ä•°ÁÉé•­¥•É½İ…¹¥„¹¥”©•ÍĞˆ°€‰…¹…±åÍ¥Ì¹É•‘¥É•ĞµÑ…É•Ğµ¥¹Ù…±¥ˆ¤°4(€€€€€€€€ ‰QÉ—oé½ÍÑ‡	„½É…¹¥é½¹„ˆ°€‰…¹…±åÍ¥Ì¹¥¹ÁÕĞµÑÉÕ¹…Ñ•ˆ¤°4(€€€€€€€€ ‰]å¹¥¬±½­…±¹•¼µ½‘•±Ô¹¥”©•ÍĞÍ­…±¥‰É½İ…¹å´ˆ°€‰…¹…±åÍ¥Ì¹…¤µ¹½Ğµ…±¥‰É…Ñ•ˆ¤°4(€€€€€€€€ ‰M•µ…¹Ñåé¹”Á½Éë‘­½İ…¹¥”±½­…±¹å ƒéËÍ‘—‰ç	¼¹¥•‘½ÍÓeÁ¹”ˆ°€‰…¹…±åÍ¥Ì¹Í•µ…¹Ñ¥ŒµÉ…¹­¥¹œµÕ¹…Ù…¥±…‰±”ˆ¤°4(€€€€€€€€ ‰1½­…±¹äµ½‘•°$©•ÍĞ¹¥•‘½ÍÓeÁ¹ä±ÕˆéİËÍ§ˆ°€‰…¹…±åÍ¥Ì¹…¤µÕ¹…Ù…¥±…‰±”µÉÕ±”µ½¹±äˆ¤°4(€€€€€€€€ ‰9¥•ÁÉ…İ¥“	½İä±¥µ¥Ğé…ÍÔµ½‘•±Ôˆ°€‰…¹…±åÍ¥Ì¹…¤µÑ¥µ•½ÕĞµ¥¹Ù…±¥µÉÕ±”µ½¹±äˆ¤4(€€€tì4(4(€€€ÁÕ‰±¥ŒÍÑ…Ñ¥Œ%I•…‘=¹±å1¥ÍĞñÍÑÉ¥¹œøÉ½µU¹•ÉÑ…¥¹Ñ¥•Ì¡%¹Õµ•É…‰±”ñÍÑÉ¥¹œøÕ¹•ÉÑ…¥¹Ñ¥•Ì¤4(€€€ì4(€€€€€€€ÉÕµ•¹Ñ9Õ±±á•ÁÑ¥½¸¹Q¡É½İ%™9Õ±°¡Õ¹•ÉÑ…¥¹Ñ¥•Ì¤ì4(€€€€€€€Ù…È½‘•Ì€ô¹•Ü!…Í¡M•ĞñÍÑÉ¥¹œø¡MÑÉ¥¹½µÁ…É•È¹=É‘¥¹…°¤ì4(€€€€€€€™½É•… €¡Ù…ÈÕ¹•ÉÑ…¥¹Ñä¥¸Õ¹•ÉÑ…¥¹Ñ¥•Ì¤4(€€€€€€€€€€€™½É•… €¡Ù…È€¡ÁÉ•™¥à°½‘”¤¥¸-¹½İ¸¤4(€€€€€€€€€€€€€€€¥˜€¡Õ¹•ÉÑ…¥¹Ñä¹MÑ…ÉÑÍ]¥Ñ ¡ÁÉ•™¥à°MÑÉ¥¹½µÁ…É¥Í½¸¹=É‘¥¹…°¤¤½‘•Ì¹‘¡½‘”¤ì4(€€€€€€€É•ÑÕÉ¸½‘•Ì¹=É‘•È¡MÑÉ¥¹½µÁ…É•È¹=É‘¥¹…°¤¹Q½ÉÉ…ä ¤ì4(€€€ô4)ô4(¼¼‘•ÍÑ¥¹…Ñ¥½¸µÕÍĞ½µ”™É½´…¸•áÁ±¥¥ĞÕÍ•È¥¹ÁÕĞ½È„™ÕÑÕÉ”ÑÉÕÍÑ•¹…Ù¥…Ñ¥½¸ÁÉ½Ù¥‘•È¸4(¼¼Q•áĞ½˜…¸…É‰¥ÑÉ…ÉäU$ÕÑ½µ…Ñ¥½¸±…‰•°¥Ì9=P•Ù¥‘•¹”½˜…¸…ÑÕ…°±¥¹¬Ñ…É•Ğ¸4)ÁÕ‰±¥ŒÍ•…±•É•½É9…Ù¥…Ñ¥½¹M¥¹…°¡ÍÑÉ¥¹œQ…É•Ğ°ÍÑÉ¥¹œü¥ÍÁ±…å•‘UÉ°€ô¹Õ±°°ÍÑÉ¥¹œüY•É¥™¥•‘I•‘¥É•ÑQ…É•Ğ€ô¹Õ±°¤ì4)ÁÕ‰±¥ŒÍ•…±•É•½É¹…±åÍ¥Í½¹Ñ•áĞ¡ÍÑÉ¥¹œÁÁ±¥…Ñ¥½¸°ÍÑÉ¥¹œQ•áĞ°…Ñ•Q¥µ•=™™Í•ĞQ¥µ•ÍÑ…µÀ°4(€€€9…Ù¥…Ñ¥½¹M¥¹…°ü9…Ù¥…Ñ¥½¸€ô¹Õ±°°ÍÑÉ¥¹œü½ÉÉ•±…Ñ¥½¹-•ä€ô¹Õ±°¤ì4)ÁÕ‰±¥ŒÍ•…±•É•½ÉUÉ±¹…±åÍ¥Ì¡‰½½°%ÍY…±¥°ÍÑÉ¥¹œü=É¥¥¸°ÍÑÉ¥¹œü!½ÍĞ°ÍÑÉ¥¹œüI•¥ÍÑÉ…‰±•½µ…¥¸°4(€€€%I•…‘=¹±å1¥ÍĞñQ¡É•…Ñ%¹‘¥…Ñ½Èø%¹‘¥…Ñ½ÉÌ¤ì4(