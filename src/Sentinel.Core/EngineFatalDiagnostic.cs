namespace Sentinel.Core;

/// <summary>Extracts only the exception type from the Engine's redacted fatal stderr marker.</summary>
public static class EngineFatalDiagnostic
{
    private const string Prefix = "SENTINEL_ENGINE_FATAL type=";

    public static string? ReadExceptionType(string? line)
    {
        if (line is null || !line.StartsWith(Prefix, StringComparison.Ordinal)) return null;
        var type = line[Prefix.Length..];
        if (type.Length is 0 or > 160 || type.Any(character =>
                !(char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '+' or '`')))
            return "System.Exception";
        return type;
    }
}
