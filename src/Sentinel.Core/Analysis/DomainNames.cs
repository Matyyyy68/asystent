using System.Globalization;
using System.Net;
using System.Reflection;

namespace Sentinel.Core.Analysis;

/// <summary>Offline Public Suffix List matcher including wildcard, exception and private rules.</summary>
public sealed class DomainNames
{
    private readonly HashSet<string> rules = new(StringComparer.Ordinal);
    private readonly HashSet<string> wildcards = new(StringComparer.Ordinal);
    private readonly HashSet<string> exceptions = new(StringComparer.Ordinal);
    private static readonly IdnMapping Idn = new();
    public DomainNames()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Sentinel.Core.Data.public_suffix_list.dat")
            ?? throw new InvalidOperationException("Brak listy publicznych sufiksów.");
        using var reader = new StreamReader(stream);
        while (reader.ReadLine() is { } line)
        {
            line = line.Trim();
            if (line.Length == 0 || line.StartsWith("//", StringComparison.Ordinal)) continue;
            if (line.StartsWith('!')) exceptions.Add(Ascii(line[1..]));
            else if (line.StartsWith("*.", StringComparison.Ordinal)) wildcards.Add(Ascii(line[2..]));
            else rules.Add(Ascii(line));
        }
    }
    public static string Ascii(string host) => Idn.GetAscii(host.TrimEnd('.')).ToLowerInvariant();
    public string? RegistrableDomain(string host)
    {
        if (IPAddress.TryParse(host.Trim('[', ']'), out _)) return null;
        host = Ascii(host);
        var labels = host.Split('.');
        int suffixLength = 1;
        for (int i = 0; i < labels.Length; i++)
        {
            var tail = string.Join('.', labels[i..]);
            if (exceptions.Contains(tail)) return i == 0 ? host : string.Join('.', labels[i..]);
            if (rules.Contains(tail)) suffixLength = Math.Max(suffixLength, labels.Length - i);
            if (i > 0 && wildcards.Contains(tail)) suffixLength = Math.Max(suffixLength, labels.Length - i + 1);
        }
        return labels.Length > suffixLength ? string.Join('.', labels[^(suffixLength + 1)..]) : null;
    }
    public static bool Within(string host, string domain) => host.Equals(domain, StringComparison.Ordinal) || host.EndsWith('.' + domain, StringComparison.Ordinal);
}
