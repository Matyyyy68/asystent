using System.Text;

namespace Sentinel.Core;

/// <summary>Reads the shared data-directory pointer without accepting unbounded or non-local paths.</summary>
public static class DataDirectoryPointer
{
    public const int MaximumPointerBytes = 4096;

    public static async Task<string> ReadAsync(string pointerPath, string fallbackDirectory,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pointerPath);
        FileStream stream;
        try
        {
            stream = new FileStream(pointerPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        }
        catch (FileNotFoundException) { return Validate(fallbackDirectory); }
        catch (DirectoryNotFoundException) { return Validate(fallbackDirectory); }

        await using (stream)
        {
            if (stream.Length is <= 0 or > MaximumPointerBytes)
                throw new InvalidDataException("Plik ścieżki danych ma nieprawidłowy rozmiar.");

            var bytes = new byte[MaximumPointerBytes + 1];
            var length = 0;
            while (length < bytes.Length)
            {
                var read = await stream.ReadAsync(bytes.AsMemory(length), cancellationToken);
                if (read == 0) break;
                length += read;
            }
            if (length is <= 0 or > MaximumPointerBytes)
                throw new InvalidDataException("Plik ścieżki danych przekracza dozwolony limit.");

            string value;
            try { value = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetString(bytes, 0, length).TrimStart('\uFEFF').Trim(); }
            catch (DecoderFallbackException ex) { throw new InvalidDataException("Plik ścieżki danych nie jest poprawnym UTF-8.", ex); }
            return Validate(value);
        }
    }

    public static string Validate(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        if (directory.Length > MaximumPointerBytes || directory.Any(char.IsControl) || !Path.IsPathFullyQualified(directory))
            throw new InvalidDataException("Ścieżka danych musi być poprawną ścieżką lokalną.");

        string fullPath;
        try { fullPath = Path.GetFullPath(directory); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        { throw new InvalidDataException("Ścieżka danych jest nieprawidłowa.", ex); }

        if (fullPath.StartsWith('\\') || (OperatingSystem.IsWindows() && fullPath.StartsWith("//", StringComparison.Ordinal)) ||
            string.Equals(Path.TrimEndingDirectorySeparator(fullPath), Path.GetPathRoot(fullPath), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Ścieżka danych musi wskazywać lokalny katalog, a nie udział sieciowy lub katalog główny dysku.");
        return fullPath;
    }
}
