using System.Text.RegularExpressions;

namespace Sentinel.Core.Context;

public static class PrivacyFilter
{
    public const int MaximumTextLength = 16_000;
    private static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(100);
    private static readonly Regex Secrets = new(@"(?i)\b(?:password|hasło|haslo|token|secret|authorization|cookie|session|api[_-]?key)\b\s*[:=]\s*[^\r\n]+", RegexOptions.CultureInvariant, Timeout);
    private static readonly Regex Urls = new(@"(?i)\b(?:https?://|www\.)[^\s<>]+", RegexOptions.CultureInvariant, Timeout);
    private static readonly Regex Email = new(@"\b[^\s@]+@[^\s@]+\.[^\s@]+\b", RegexOptions.CultureInvariant, Timeout);
    private static readonly Regex Numbers = new(@"\b(?:\d[ -]?){6,}\b", RegexOptions.CultureInvariant, Timeout);
    private static readonly Regex Opaque = new(@"\b[A-Za-z0-9_+/=-]{24,}\b", RegexOptions.CultureInvariant, Timeout);
    public static string Redact(string text)
    {
        text = text[..Math.Min(text.Length, MaximumTextLength)];
        try
        {
            text = Secrets.Replace(text, "[dane poufne]");
            text = Urls.Replace(text, "[adres]");
            text = Email.Replace(text, "[email]");
            text = Numbers.Replace(text, "[numer]");
            return Opaque.Replace(text, "[identyfikator]");
        }
        catch (RegexMatchTimeoutException) { return "[tekst pominięty: limit maskowania]"; }
    }
}
