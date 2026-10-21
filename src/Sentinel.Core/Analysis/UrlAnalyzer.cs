using System.Net;

namespace Sentinel.Core.Analysis;

/// <summary>Pure offline analysis. Never resolves DNS or visits a target.</summary>
public sealed class UrlAnalyzer(DomainNames domains)
{
    private static readonly Dictionary<string, string[]> Brands = new(StringComparer.Ordinal)
    {
        ["paypal"] = ["paypal.com"], ["microsoft"] = ["microsoft.com", "microsoftonline.com", "live.com", "office.com"],
        ["google"] = ["google.com", "google.pl"], ["apple"] = ["apple.com"], ["allegro"] = ["allegro.pl", "allegro.com"]
    };
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
        if (new[] { "zip", "mov", "top", "xyz" }.Contains(host.Split('.')[^1])) Add("url.tld", "Sufiks domeny wymaga dodatkowej weryfikacji.", 1);
        if (registered is not null)
        {
            var label = registered.Split('.')[0];
            var skeleton = Skeleton(label);
            foreach (var (brand, legitimate) in Brands)
            {
                if (legitimate.Any(d => DomainNames.Within(host, d))) continue;
                if (host.Split('.').Contains(brand) || skeleton.Equals(brand, StringComparison.Ordinal) ||
                    new[] { "-login", "-secure", "-account", "-sso" }.Any(suffix => label == brand + suffix) ||
                    (label.Length >= 4 && Distance(label, brand) == 1))
                {
                    Add("url.brand", "Domena przypomina znaną markę lub umieszcza jej nazwę w mylącej subdomenie.", 4);
                    break;
                }
            }
        }
        // Paths, queries, fragments and userinfo never leave this normalizer.
        var authorityHost = uri.HostNameType == UriHostNameType.IPv6 ? $"[{host}]" : host;
        var origin = $"{uri.Scheme}://{authorityHost}" + (uri.IsDefaultPort ? "" : $":{uri.Port}");
        return new(true, origin, host, registered, signals);
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
            'а' or 'α' => 'a', 'р' or 'ρ' => 'p', 'о' or 'ο' => 'o', 'с' => 'c',
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
