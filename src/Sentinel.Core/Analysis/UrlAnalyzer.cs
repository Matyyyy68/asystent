using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace Sentinel.Core.Analysis;

/// <summary>Pure offline analysis. Never resolves DNS or visits a target.</summary>
public sealed class UrlAnalyzer(DomainNames domains)
{
    private static readonly Regex AuthenticationPath = new(
        @"(?:^|[/?&=._-])(?:login|log-in|signin|sign-in|verify|verification|account|password|auth|payment|wallet)(?=$|[/?&=._-])",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Dictionary<string, string[]> Brands = new(StringComparer.Ordinal)
    {
        ["paypal"] = ["paypal.com"], ["microsoft"] = ["microsoft.com", "microsoftonline.com", "live.com", "office.com"],
        ["google"] = ["google.com", "google.pl"], ["apple"] = ["apple.com"], ["allegro"] = ["allegro.pl", "allegro.com"]
    };
    // These ICANN Spec 13 brand TLDs are operated by the corresponding brand owners.
    private static readonly HashSet<string> BrandTlds = new(StringComparer.Ordinal) { "apple", "google", "microsoft" };
    public UrlAnalysis Analyze(string value)
    {
        var signals = new List<ThreatIndicator>();
        if (string.IsNullOrWhiteSpace(value) || value.Length > 4096 || !Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("https" or "http") || string.IsNullOrEmpty(uri.Host))
            return new(false, null, null, null, signals);
        string host;
        try { host = uri.HostNameType == UriHostNameType.IPv6 ? uri.IdnHost.Trim('[', ']') : DomainNames.Ascii(uri.IdnHost); }
        catch (ArgumentException) { return new(false, null, null, null, signals); }
        var ip = IPAddress.TryParse(host.Trim('[', ']'), out _);
        var registered = ip ? null : domains.RegistrableDomain(host);
        void Add(string id, string text, int weight) => signals.Add(new(id, text, weight, ThreatCategory.SuspiciousNavigation));
        if (uri.Scheme != "https") Add("url.http", "Połączenie nie używa HTTPS.", 1);
        if (ip) Add("url.ip", "Adres docelowy używa adresu IP zamiast nazwy domeny.", 1);
        if (!uri.IsDefaultPort) Add("url.port", "Adres zawiera niestandardowy port.", 1);
        if (uri.UserInfo.Length > 0) Add("url.userinfo", "Adres zawiera część przed znakiem @, która może mylić co do celu.", 3);
        if (host.Split('.').Any(l => l.StartsWith("xn--", StringComparison.Ordinal))) Add("url.idn", "Nazwa domeny zawiera znaki IDN; sama ta cecha nie dowodzi oszustwa.", 1);
        if (host.Split('.').Any(ContainsMixedLatinGreekOrCyrillic))
            Add("url.idn_mixed_script", "Jedna etykieta domeny miesza alfabet łaciński z greckim lub cyrylicą; może to utrudniać rozpoznanie nazwy.", 1);
        if (new[] { "zip", "mov", "top", "xyz" }.Contains(host.Split('.')[^1])) Add("url.tld", "Sufiks domeny wymaga dodatkowej weryfikacji.", 1);
        var pathAndQuery = uri.PathAndQuery;
        var structurallyComplex = value.Length >= 120 || host.Split('.').Length >= 5 ||
            pathAndQuery.Length >= 60 || pathAndQuery.Count(character => character == '/') >= 4;
        if (structurallyComplex && AuthenticationPath.IsMatch(pathAndQuery))
            Add("url.auth_structure", "Adres łączy ścieżkę logowania, weryfikacji lub płatności z dodatkową złożonością URL.", 3);

        var hostLabels = host.Split('.');
        var queryPairs = uri.Query.Length > 1 ? uri.Query.Count(character => character == '&') + 1 : 0;
        var structuralDimensions = 0;
        if (value.Length >= 75) structuralDimensions++;
        if (host.Length >= 50 || hostLabels.Length >= 5 || host.Count(character => character == '-') >= 3) structuralDimensions++;
        if (queryPairs >= 4 || pathAndQuery.Count(char.IsAsciiDigit) >= 6) structuralDimensions++;
        if (uri.AbsolutePath.Count(character => character == '/') >= 4) structuralDimensions++;
        if (structuralDimensions >= 3)
            Add("url.structure_combination", "Adres łączy kilka cech złożonej konstrukcji hosta, parametrów lub ścieżki; to sygnał ostrzegawczy, nie dowód złośliwości.", 3);
        if (registered is not null)
        {
            var label = registered.Split('.')[0];
            var skeleton = Skeleton(label);
            var brandHostLabels = host.Split('.');
            var registeredLabelCount = registered.Split('.').Length;
            var subdomainLabels = brandHostLabels.Take(Math.Max(0, brandHostLabels.Length - registeredLabelCount));
            foreach (var (brand, legitimate) in Brands)
            {
                if (legitimate.Any(d => DomainNames.Within(host, d)) ||
                    (BrandTlds.Contains(brand) && DomainNames.Within(host, brand))) continue;
                if (subdomainLabels.Contains(brand, StringComparer.Ordinal) ||
                    (!label.Equals(brand, StringComparison.Ordinal) && skeleton.Equals(brand, StringComparison.Ordinal)) ||
                    new[] { "-login", "-secure", "-account", "-sso" }.Any(suffix => label == brand + suffix) ||
                    (label.Length >= 4 && !label.Equals(brand, StringComparison.Ordinal) && Distance(label, brand) == 1))
                {
                    Add("url.brand", "Domena przypomina znaną markę lub umieszcza jej nazwę w mylącej subdomenie.", 4);
                    break;
                }
                if (label.Equals(brand, StringComparison.Ordinal))
                    Add("url.brand_exact", "Domena używa dokładnego słowa znanej marki, ale jej właściciela nie zweryfikowano.", 1);
            }
        }
        // Paths, queries, fragments and userinfo never leave this normalizer.
        var authorityHost = uri.HostNameType == UriHostNameType.IPv6 ? $"[{host}]" : host;
        var origin = $"{uri.Scheme}://{authorityHost}" + (uri.IsDefaultPort ? "" : $":{uri.Port}");
        return new(true, origin, host, registered, signals);
    }
    private static bool ContainsMixedLatinGreekOrCyrillic(string asciiLabel)
    {
        string unicode;
        try { unicode = new System.Globalization.IdnMapping().GetUnicode(asciiLabel); }
        catch (ArgumentException) { return false; }

        bool latin = false, greek = false, cyrillic = false;
        foreach (var rune in unicode.EnumerateRunes())
        {
            if (!Rune.IsLetter(rune)) continue;
            int value = rune.Value;
            if (value is >= 0x0041 and <= 0x024F or >= 0x1E00 and <= 0x1EFF or >= 0x2C60 and <= 0x2C7F or >= 0xA720 and <= 0xA7FF or >= 0xAB30 and <= 0xAB6F) latin = true;
            else if (value is >= 0x0370 and <= 0x03FF or >= 0x1F00 and <= 0x1FFF) greek = true;
            else if (value is >= 0x0400 and <= 0x052F or >= 0x2DE0 and <= 0x2DFF or >= 0xA640 and <= 0xA69F) cyrillic = true;
        }
        return (latin && (greek || cyrillic)) || (greek && cyrillic);
    }
    public IReadOnlyList<ThreatIndicator> Compare(NavigationSignal navigation)
    {
        var target = Analyze(navigation.Target); var signals = target.Indicators.ToList();
        if (navigation.DisplayedUrl is { } displayed)
        {
            var visible = Analyze(displayed);
            if (visible.IsValid && target.IsValid && !SameSite(visible, target))
                signals.Add(new("url.linkMismatch", "Widoczny adres linku różni się od wiarygodnie ustalonego celu.", 3, ThreatCategory.SuspiciousNavigation));
        }
        if (navigation.VerifiedRedirectTarget is { } redirect)
        {
            var final = Analyze(redirect);
            if (final.IsValid && target.IsValid && !SameSite(target, final))
                signals.Add(new("url.redirect", "Zaobserwowane przekierowanie zmienia domenę docelową.", 2, ThreatCategory.SuspiciousNavigation));
            signals.AddRange(final.Indicators);
        }
        return signals.DistinctBy(s => s.Id).ToArray();
    }
    private static bool SameSite(UrlAnalysis a, UrlAnalysis b) =>
        (a.RegistrableDomain ?? a.Host) == (b.RegistrableDomain ?? b.Host);
    private static string Skeleton(string label)
    {
        string unicode;
        try { unicode = new System.Globalization.IdnMapping().GetUnicode(label); }
        catch (ArgumentException) { return label; }
        // Small, explicitly limited confusable set; not a complete Unicode security profile.
        return new string(unicode.Select(c => c switch
        {
            'а' or 'α' => 'a', 'р' or 'ρ' => 'p', 'о' or 'ο' => 'o', 'с' => 'c', 'ѕ' => 's',
            'е' or 'ε' => 'e', 'у' => 'y', 'і' or 'ι' => 'i', 'х' or 'χ' => 'x', _ => c
        }).ToArray());
    }
    private static int Distance(string left, string right)
    {
        if (Math.Abs(left.Length - right.Length) > 1) return 2;
        var previous = Enumerable.Range(0, right.Length + 1).ToArray();
        for (int i = 1; i <= left.Length; i++)
        {
            var next = new int[right.Length + 1]; next[0] = i;
            for (int j = 1; j <= right.Length; j++)
                next[j] = Math.Min(Math.Min(next[j - 1] + 1, previous[j] + 1), previous[j - 1] + (left[i - 1] == right[j - 1] ? 0 : 1));
            previous = next;
        }
        return previous[^1];
    }
}
