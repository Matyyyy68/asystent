using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;
using Sentinel.Core.Analysis;

// Versioned JSON-lines protocol on inherited stdio only; no listening TCP port.
var json = new JsonSerializerOptions(JsonSerializerDefaults.Web);
json.Converters.Add(new JsonStringEnumConverter());
var root = Environment.GetEnvironmentVariable("SENTINEL_DATA_ROOT") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelAI");
Directory.CreateDirectory(root);
var pointer = Path.Combine(root, "data-path.txt");
var directory = File.Exists(pointer) ? File.ReadAllText(pointer).Trim() : Path.Combine(root, "data");
var store = new LocalStore(directory);
await store.InitializeAsync();
if (!File.Exists(pointer)) await File.WriteAllTextAsync(pointer, directory);
var settings = await store.LoadSettingsAsync();
await store.ApplyRetentionAsync(settings.RetentionDays);
var rules = new ThreatAnalysisEngine(new UrlAnalyzer(new DomainNames()));
var reputation = new DomainReputation(directory);
var deduplicator = new NotificationDeduplicator();
DateTimeOffset? lastDnsRead = null;
string dnsState = "Jeszcze nie wykonano odczytu cache DNS";
while (await Console.In.ReadLineAsync() is { } line)
{
    string? id = null;
    try
    {
        if (line.Length > 24000) throw new InvalidDataException("Żądanie przekracza limit.");
        using var doc = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 8 });
        var request = doc.RootElement;
        id = request.GetProperty("id").GetString();
        if (request.GetProperty("version").GetInt32() != 1) throw new InvalidDataException("Nieobsługiwana wersja API.");
        object result;
        switch (request.GetProperty("method").GetString())
        {
            case "status":
                result = new { engine = "ready", rules = ThreatAnalysisEngine.RulesVersion, settings,
                    dns = dnsState, lastDnsRead, wfp = "Niewdrożone", ai = "Wyłączone w nowym kliencie",
                    reputation = reputation.Status(DateTimeOffset.UtcNow), browsers = BrowserDiagnostics.Read(root), database = store.DatabasePath };
                break;
            case "updateFeed": await reputation.UpdateAsync(); result = reputation.Status(DateTimeOffset.UtcNow); break;
            case "rollbackFeed": reputation.Rollback(); result = reputation.Status(DateTimeOffset.UtcNow); break;
            case "collect":
                var detections = new List<string>();
                if (!settings.Paused && OperatingSystem.IsWindows())
                {
                    try
                    {
                        using var process = new System.Diagnostics.Process { StartInfo = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
                            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
                        } };
                        process.StartInfo.ArgumentList.Add("-NoProfile"); process.StartInfo.ArgumentList.Add("-NonInteractive");
                        process.StartInfo.ArgumentList.Add("-Command");
                        process.StartInfo.ArgumentList.Add("$ErrorActionPreference='Stop'; Get-DnsClientCache | Select-Object -First 2000 -ExpandProperty Entry | ConvertTo-Json -Compress");
                        process.Start();
                        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                        var output = process.StandardOutput.ReadToEndAsync(timeout.Token);
                        var errors = process.StandardError.ReadToEndAsync(timeout.Token);
                        try { await process.WaitForExitAsync(timeout.Token); }
                        catch { process.Kill(entireProcessTree: true); throw; }
                        var content = await output; await errors;
                        if (process.ExitCode != 0 || content.Length > 600000) throw new InvalidDataException("Odczyt DNS niedostępny.");
                        if (!string.IsNullOrWhiteSpace(content))
                        {
                            using var entries = JsonDocument.Parse(content);
                            var names = entries.RootElement.ValueKind == JsonValueKind.Array
                                ? entries.RootElement.EnumerateArray().Select(e => e.GetString()).ToArray() : [entries.RootElement.GetString()];
                            foreach (var name in reputation.FindMatches(names.OfType<string>(), DateTimeOffset.UtcNow))
                            {
                                if (!deduplicator.TryMark(name, DateTimeOffset.UtcNow)) continue;
                                await store.AddLocalOnlyAsync(new SecurityEvent(0, DateTimeOffset.UtcNow, RiskLevel.High,
                                    "Domena na liście CERT Polska", "Cache DNS Windows", "Zaobserwowano domenę z aktualnej listy: " + name,
                                    "Ostrzeżenie, bez blokowania. Cache nie wskazuje procesu ani czasu nawigacji.", EventStatus.New));
                                detections.Add(name!);
                            }
                        }
                        lastDnsRead = DateTimeOffset.UtcNow; dnsState = "Odczyt cache DNS działa; bez DoH, pełnych URL i PID";
                        await store.ApplyRetentionAsync(settings.RetentionDays);
                    }
                    catch (Exception ex) { dnsState = "Odczyt cache DNS niedostępny: " + ex.GetType().Name; }
                }
                else dnsState = "Obserwacja wstrzymana";
                result = new { detections = detections.Count, notifications = settings.Notifications, dns = dnsState };
                break;
            case "history": result = await store.ReadAsync(); break;
            case "pause":
                var pausedSettings = settings with { Paused = request.GetProperty("paused").GetBoolean() };
                await store.SaveSettingsAsync(pausedSettings);
                settings = pausedSettings;
                result = settings;
                break;
            case "settings":
                var updatedSettings = settings with { RetentionDays = request.GetProperty("retentionDays").GetInt32(),
                    Notifications = request.GetProperty("notifications").GetBoolean(),
                    DnsPollIntervalSeconds = request.TryGetProperty("dnsPollIntervalSeconds", out var interval) ? interval.GetInt32() : settings.DnsPollIntervalSeconds };
                await store.SaveSettingsAsync(updatedSettings);
                settings = updatedSettings;
                await store.ApplyRetentionAsync(settings.RetentionDays);
                result = settings;
                break;
            case "analyze":
                var text = request.GetProperty("text").GetString() ?? "";
                var url = request.GetProperty("url").GetString();
                if (text.Length > 16000 || url?.Length > 4096) throw new InvalidDataException("Zbyt długa treść.");
                var assessment = rules.Analyze(new AnalysisContext("Ręczna analiza", text, DateTimeOffset.UtcNow,
                    string.IsNullOrWhiteSpace(url) ? null : new NavigationSignal(url)));
                if (Uri.TryCreate(url, UriKind.Absolute, out var target) && target.Scheme is "http" or "https" && reputation.Contains(target.IdnHost, DateTimeOffset.UtcNow))
                    assessment = assessment with { Risk = RiskLevel.High, Category = ThreatCategory.SuspiciousNavigation,
                        Indicators = assessment.Indicators.Append(new ThreatIndicator("reputation.cert", "Domena znajduje się na aktualnej liście ostrzeżeń CERT Polska.", 10, ThreatCategory.SuspiciousNavigation)).ToArray(),
                        Explanation = "Domena znajduje się na aktualnej liście ostrzeżeń CERT Polska. " + assessment.Explanation };
                if (assessment.Indicators.Count > 0)
                    await store.AddLocalOnlyAsync(new SecurityEvent(0, DateTimeOffset.UtcNow, assessment.Risk,
                        assessment.Category.ToString(), "Ręczna analiza", assessment.Explanation,
                        string.Join(" ", assessment.Recommendations), EventStatus.New));
                await store.ApplyRetentionAsync(settings.RetentionDays);
                result = assessment;
                break;
            case "connections":
                // Read-only system snapshot; no DNS resolution, packet capture or process attribution.
                result = settings.Paused ? [] : IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections()
                    .Take(1000).Select(c => new { address = c.RemoteEndPoint.Address.ToString(), port = c.RemoteEndPoint.Port,
                        state = c.State.ToString(), action = "Obserwacja; bez blokowania i reputacji" }).ToArray();
                break;
            case "file":
                var path = request.GetProperty("path").GetString() ?? throw new InvalidDataException();
                var info = new FileInfo(path);
                if (!info.Exists || info.Length > 256L * 1024 * 1024) throw new InvalidDataException("Limit pliku: 256 MiB.");
                await using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                    result = new { name = info.Name, size = info.Length, sha256 = Convert.ToHexString(await SHA256.HashDataAsync(stream)),
                        verdict = "Hash obliczony. Brak bazy reputacji plików; wynik nie potwierdza bezpieczeństwa." };
                break;
            case "clearHistory": await store.DeleteHistoryAsync(); result = new { deleted = true }; break;
            default: throw new InvalidDataException("Nieznana metoda.");
        }
        Console.WriteLine(JsonSerializer.Serialize(new { id, ok = true, result }, json));
    }
    catch (Exception ex)
    {
        Console.WriteLine(JsonSerializer.Serialize(new { id, ok = false, error = ex is InvalidDataException or ArgumentException
            ? ex.Message : "Operacja nie powiodła się: " + ex.GetType().Name }, json));
    }
}
