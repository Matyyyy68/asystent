using Microsoft.Win32;
using System.Text.Json;

internal static class BrowserDiagnostics
{
    public static object Read(string root)
    {
        string Status(string browser, string vendor)
        {
            if (!OperatingSystem.IsWindows()) return "Niedostępne poza Windows";
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey($@"Software\{vendor}\NativeMessagingHosts\com.sentinelai.urlcheck");
                if (key?.GetValue("") is not string manifest) return "Host niezainstalowany";
                if (!File.Exists(manifest)) return "Błąd konfiguracji: brak manifestu";
                using var document = JsonDocument.Parse(File.ReadAllText(manifest));
                if (!File.Exists(document.RootElement.GetProperty("path").GetString())) return "Błąd konfiguracji: brak programu hosta";
                var marker = Path.Combine(root, $"browser-{browser}.json");
                if (!File.Exists(marker)) return "Host zainstalowany; instalacja rozszerzenia niepotwierdzona";
                using var contact = JsonDocument.Parse(File.ReadAllText(marker));
                var last = contact.RootElement.GetProperty("LastContactUtc").GetDateTimeOffset();
                if (contact.RootElement.TryGetProperty("Enabled", out var enabled) && enabled.ValueKind == JsonValueKind.False)
                    return "Rozszerzenie wyłączone przez użytkownika";
                return DateTimeOffset.UtcNow - last < TimeSpan.FromMinutes(2)
                    ? "Zainstalowane; potwierdzony kontakt w ostatnich 2 minutach"
                    : "Zainstalowane; brak niedawnego kontaktu — otwórz popup rozszerzenia";
            }
            catch { return "Błąd konfiguracji integracji"; }
        }
        return new { chrome = Status("chrome", @"Google\Chrome"), edge = Status("edge", @"Microsoft\Edge") };
    }
}
