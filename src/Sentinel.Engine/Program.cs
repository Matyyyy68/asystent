using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using Sentinel.Core;
using Sentinel.Contracts;
using Sentinel.Core.Analysis;
using Sentinel.Core.Configuration;
using Sentinel.Core.Enterprise;
using Sentinel.Core.Knowledge;

// Versioned JSON-lines protocol on inherited stdio only; no listening TCP port.
var json = new JsonSerializerOptions(JsonSerializerDefaults.Web);
json.Converters.Add(new JsonStringEnumConverter());
var root = Environment.GetEnvironmentVariable("SENTINEL_DATA_ROOT") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelAI");
Directory.CreateDirectory(root);
var pointer = Path.Combine(root, "data-path.txt");
var directory = File.Exists(pointer) ? File.ReadAllText(pointer).Trim() : Path.Combine(root, "data");
var store = new LocalStore(directory);
await store.InitializeAsync();
var installationProfile = await store.GetInstallationProfileAsync();
var deviceCredentials = new WindowsDpapiCredentialStore(directory);
var malwareBazaarCredentials = new WindowsDpapiCredentialStore(directory, "malwarebazaar-auth-key.bin", 1, 256,
    "Sentinel AI MalwareBazaar API key", "SentinelAI/MalwareBazaarAuthKey/v1");
using var malwareBazaarHttpClient = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(10) };
var malwareBazaar = new MalwareBazaarClient(malwareBazaarHttpClient);
var knowledge = new LocalKnowledgeBase(directory);
await knowledge.InitializeAsync();
if (!File.Exists(pointer)) await File.WriteAllTextAsync(pointer, directory);
var downloadsDirectory = Environment.GetEnvironmentVariable("SENTINEL_DOWNLOADS_PATH") ??
    DownloadedFileMonitor.GetKnownDownloadsDirectory();
using var downloadedFileMonitor = new DownloadedFileMonitor(downloadsDirectory);
var settings = await store.LoadSettingsAsync();
await downloadedFileMonitor.SetEnabledAsync(store, settings.MonitorDownloadedFiles && !settings.Paused);
var defaultExcludedApplications = settings.ExcludedApplications;
await store.ApplyRetentionAsync(settings.RetentionDays);
var domainNames = new DomainNames();
var urlAnalyzer = new UrlAnalyzer(domainNames);
var rules = new ThreatAnalysisEngine(urlAnalyzer);
var reputation = new DomainReputation(directory);
var fileHashReputation = new FileHashReputation(directory);
var processMonitor = new ProcessSnapshotMonitor();
var tcpConnectionMonitor = new TcpConnectionSnapshotMonitor(async cancellationToken =>
    await ReadConnectionSnapshotBatchAsync(cancellationToken),
    wasRecentlyObservedStart: processMonitor.WasRecentlyObservedStart);
using var aiHttpClient = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
var aiProvider = new OllamaLocalProvider(aiHttpClient);
var orchestrator = new AnalysisOrchestrator(rules, aiProvider, knowledge);
var deduplicator = new NotificationDeduplicator();
using var enterpriseHttpClient = CreateEnterpriseHttpClient();
var enterpriseAgent = new EnterpriseAgentClient(enterpriseHttpClient);
var enterpriseCredentialRotator = new EnterpriseCredentialRotator(enterpriseAgent, deviceCredentials);
DateTimeOffset? lastEnterpriseSyncAttempt = null;
DateTimeOffset? lastEnterpriseSync = null;
string? enterpriseError = null;
var enterpriseSyncIntervalSeconds = 60;
HttpClient CreateEnterpriseHttpClient()
{
    var handler = new HttpClientHandler { AllowAutoRedirect = false };
#if DEBUG
    // Test-only exact leaf pin for loopback E2E. Release builds never read this setting.
    var testCertificatePath = Environment.GetEnvironmentVariable("SENTINEL_TEST_TLS_CERT_PATH");
    if (!string.IsNullOrWhiteSpace(testCertificatePath))
    {
        using var testCertificate = X509CertificateLoader.LoadCertificateFromFile(testCertificatePath);
        var expectedHash = testCertificate.GetCertHashString(HashAlgorithmName.SHA256);
        handler.ServerCertificateCustomValidationCallback = (request, presented, _, errors) =>
            request?.RequestUri?.IsLoopback == true && presented is not null &&
            errors is SslPolicyErrors.None or SslPolicyErrors.RemoteCertificateChainErrors &&
            presented.GetCertHashString(HashAlgorithmName.SHA256).Equals(expectedHash, StringComparison.OrdinalIgnoreCase) &&
            presented.NotBefore.ToUniversalTime() <= DateTime.UtcNow && presented.NotAfter.ToUniversalTime() > DateTime.UtcNow;
    }
#endif
    return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
}
async Task<bool> IsMalwareBazaarConfiguredAsync()
{
    try { return await malwareBazaarCredentials.ReadAsync() is not null; }
    catch { return false; }
}
async Task<object> EnterpriseStatusAsync()
{
    string? token = null;
    try
    {
        if (OperatingSystem.IsWindows() && installationProfile.Variant == ProductVariant.EnterpriseClient)
            token = await deviceCredentials.ReadAsync();
    }
    catch { enterpriseError = "credential_unavailable"; }
    return new { variant = installationProfile.Variant.ToString(), server = installationProfile.EnterpriseServerUri,
        paired = !string.IsNullOrEmpty(token), sharingMetadata = installationProfile.ShareSecurityMetadata,
        queuedEvents = installationProfile.Variant == ProductVariant.EnterpriseClient ? await store.CountPendingEnterpriseEventsAsync() : 0,
        lastSync = lastEnterpriseSync, error = enterpriseError };
}
async Task<object> SyncEnterpriseAsync(bool force)
{
    if (installationProfile.Variant != ProductVariant.EnterpriseClient || string.IsNullOrEmpty(installationProfile.EnterpriseServerUri))
        return new { paired = false, synchronized = 0, reason = "enterprise_not_configured" };
    string? token;
    try { token = await deviceCredentials.ReadAsync(); }
    catch { enterpriseError = "credential_unavailable"; return new { paired = false, synchronized = 0, reason = enterpriseError }; }
    if (string.IsNullOrEmpty(token)) return new { paired = false, synchronized = 0, reason = "not_paired" };
    if (!installationProfile.ShareSecurityMetadata)
        return new { paired = true, synchronized = 0, reason = "consent_disabled", lastSync = lastEnterpriseSync };
    if (!force && lastEnterpriseSyncAttempt is { } previous && DateTimeOffset.UtcNow - previous < TimeSpan.FromSeconds(enterpriseSyncIntervalSeconds))
        return new { paired = true, synchronized = 0, reason = "interval_not_elapsed" };
    lastEnterpriseSyncAttempt = DateTimeOffset.UtcNow;
    var server = EnterpriseAgentClient.ValidateServer(installationProfile.EnterpriseServerUri);
    try
    {
        await enterpriseAgent.SendHeartbeatAsync(server, token);
        using var configuration = await enterpriseAgent.ReadConfigurationAsync(server, token);
        var policy = EnterprisePolicy.Parse(configuration);
        if (policy.AnalysisMode != "local" || policy.AnalysisIntervalSeconds is < 10 or > 300)
            throw new InvalidDataException("Polityka wymaga trybu lokalnego i odstępu 10–300 sekund obsługiwanego przez ten klient.");
        var combinedExclusions = defaultExcludedApplications.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Concat(policy.ExcludedApplications).Distinct(StringComparer.OrdinalIgnoreCase);
        var excludedApplications = string.Join(';', combinedExclusions);
        if (excludedApplications.Length > 2000)
            throw new InvalidDataException("Lista wykluczeń polityki Enterprise przekracza limit klienta.");
        settings = settings with { MinimumIntervalSeconds = policy.AnalysisIntervalSeconds,
            ExcludedApplications = excludedApplications,
            Notifications = policy.NotificationLevel != "history" };
        await store.SaveSettingsAsync(settings);
        await store.ApplyRetentionAsync(settings.RetentionDays);
        enterpriseSyncIntervalSeconds = policy.SyncIntervalSeconds;
        var pending = installationProfile.ShareSecurityMetadata
            ? await store.ReadPendingEnterpriseEventsAsync() : Array.Empty<PendingEnterpriseEvent>();
        var accepted = 0;
        if (pending.Count > 0)
        {
            var response = await enterpriseAgent.SendEventsAsync(server, token, pending);
            await store.MarkEnterpriseEventsSentAsync(pending.Select(item => item.EventId));
            accepted = response.Accepted + response.Duplicates;
        }
        lastEnterpriseSync = DateTimeOffset.UtcNow;
        enterpriseError = null;
        return new { paired = true, synchronized = accepted, policyVersion = policy.Version,
            syncIntervalSeconds = policy.SyncIntervalSeconds, lastSync = lastEnterpriseSync, error = (string?)null };
    }
    catch (Exception ex)
    {
        enterpriseError = ex.GetType().Name == nameof(InvalidDataException) ? "configuration_invalid" : "sync_failed";
        try { await enterpriseAgent.SendHeartbeatAsync(server, token, enterpriseError); } catch { }
        return new { paired = true, synchronized = 0, reason = enterpriseError, lastSync = lastEnterpriseSync };
    }
}
async Task RecordDetectionAsync(SecurityEvent item, string category, string ruleCode)
{
    await store.AddLocalOnlyAsync(item);
    if (installationProfile is { Variant: ProductVariant.EnterpriseClient, ShareSecurityMetadata: true } && item.Risk >= RiskLevel.Moderate &&
        !await store.EnqueueEnterpriseEventAsync(new PendingEnterpriseEvent(item.EventId!.Value, item.Timestamp, category, (int)item.Risk, ruleCode,
            EnterpriseEventV1Rules.NormalizeSource(item.Source), EnterpriseEventV1Rules.NormalizeRuleVersion(item.RuleVersion), item.SchemaVersion)))
        enterpriseError = "queue_full";
}
DateTimeOffset? lastDnsRead = null;
DateTimeOffset? lastDnsError = null;
DateTimeOffset? lastDnsAttempt = null;
string dnsState = "Jeszcze nie wykonano odczytu cache DNS";
Task<ConnectionSnapshot[]> ReadConnectionSnapshotAsync(CancellationToken cancellationToken)
{
    cancellationToken.ThrowIfCancellationRequested();
    return Task.FromResult(WindowsConnectionTableReader.Read());
}
Task<ConnectionSnapshotBatch> ReadConnectionSnapshotBatchAsync(CancellationToken cancellationToken)
{
    cancellationToken.ThrowIfCancellationRequested();
    return Task.FromResult(WindowsConnectionTableReader.ReadBatch());
}
object ReadRuntimeMetrics()
{
    using var current = System.Diagnostics.Process.GetCurrentProcess();
    current.Refresh();
    return new { workingSetBytes = current.WorkingSet64, privateMemoryBytes = current.PrivateMemorySize64,
        cpuTimeMilliseconds = current.TotalProcessorTime.TotalMilliseconds, processorCount = Environment.ProcessorCount };
}
async Task<object> ReadAuthenticodeSignatureAsync(string path, CancellationToken cancellationToken)
{
    if (!OperatingSystem.IsWindows()) return new { status = "Unsupported", signer = (string?)null, thumbprint = (string?)null };
    const string script = "$ErrorActionPreference='Stop'; Import-Module Microsoft.PowerShell.Security -ErrorAction Stop; $p=[Environment]::GetEnvironmentVariable('SENTINEL_FILE_TO_VERIFY'); " +
        "$s=Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop; " +
        "$subject=$null; $thumbprint=$null; if($s.SignerCertificate){$subject=$s.SignerCertificate.Subject;$thumbprint=$s.SignerCertificate.Thumbprint}; " +
        "[pscustomobject]@{status=[string]$s.Status;signer=$subject;thumbprint=$thumbprint}|ConvertTo-Json -Compress -Depth 2";
    using var process = new System.Diagnostics.Process { StartInfo = new System.Diagnostics.ProcessStartInfo
    {
        FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
        UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
    } };
    process.StartInfo.ArgumentList.Add("-NoProfile"); process.StartInfo.ArgumentList.Add("-NonInteractive");
    process.StartInfo.ArgumentList.Add("-Command"); process.StartInfo.ArgumentList.Add(script);
    process.StartInfo.Environment["SENTINEL_FILE_TO_VERIFY"] = path;
    process.StartInfo.Environment["PSModulePath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "Modules");
    process.Start();
    // Windows PowerShell can take longer to cold-start on a loaded runner or first-use profile.
    // Keep the signature check bounded without treating a slow host as an unsigned file.
    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); timeout.CancelAfter(TimeSpan.FromSeconds(30));
    var output = process.StandardOutput.ReadToEndAsync(timeout.Token);
    var errors = process.StandardError.ReadToEndAsync(timeout.Token);
    try
    {
        await process.WaitForExitAsync(timeout.Token);
        var jsonText = await output; await errors;
        if (process.ExitCode != 0 || jsonText.Length > 16_384) return new { status = "Unknown", signer = (string?)null, thumbprint = (string?)null };
        using var document = JsonDocument.Parse(jsonText, new JsonDocumentOptions { MaxDepth = 4 });
        var root = document.RootElement;
        var status = root.TryGetProperty("status", out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
        var signer = root.TryGetProperty("signer", out var signerValue) && signerValue.ValueKind == JsonValueKind.String ? signerValue.GetString() : null;
        var thumbprint = root.TryGetProperty("thumbprint", out var thumbprintValue) && thumbprintValue.ValueKind == JsonValueKind.String ? thumbprintValue.GetString() : null;
        return new { status = status is "Valid" or "NotSigned" or "HashMismatch" or "NotTrusted" ? status : "Unknown", signer, thumbprint };
    }
    catch
    {
        try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
        return new { status = "Unknown", signer = (string?)null, thumbprint = (string?)null };
    }
}
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
                    dns = dnsState, lastDnsReadUtc = lastDnsRead, lastDnsErrorUtc = lastDnsError,
                    processes = processMonitor.State, tcpConnections = tcpConnectionMonitor.State,
                    enterprise = await EnterpriseStatusAsync(),
                    malwareBazaar = new { configured = await IsMalwareBazaarConfiguredAsync() },
                    runtime = ReadRuntimeMetrics(),
                    wfp = "Niewdrożone", ai = settings.UseLocalAI ? "Włączone przez użytkownika · Ollama loopback" : "Wyłączone",
                    reputation = reputation.Status(DateTimeOffset.UtcNow), fileHashReputation = fileHashReputation.Status(),
                    downloadedFiles = downloadedFileMonitor.State,
                    browsers = BrowserDiagnostics.Read(root), database = store.DatabasePath,
                    storage = new { history = await store.GetStorageMetricsAsync(), knowledge = await knowledge.GetStorageMetricsAsync() } };
                break;
            case "updateFeed": await reputation.UpdateAsync(); result = reputation.Status(DateTimeOffset.UtcNow); break;
            case "rollbackFeed": reputation.Rollback(); result = reputation.Status(DateTimeOffset.UtcNow); break;
            case "collect":
                var detections = new List<string>();
                var processChanges = await processMonitor.CollectAsync(store, settings.Paused, settings.ExcludedApplications);
                var tcpChanges = await tcpConnectionMonitor.CollectAsync(store, settings.MonitorNetworkConnections, settings.Paused,
                    settings.ExcludedApplications);
                var downloadedFileMatches = await downloadedFileMonitor.CollectAsync(store, fileHashReputation);
                if (settings.Paused) dnsState = "Obserwacja wstrzymana";
                else if (OperatingSystem.IsWindows() && (lastDnsAttempt is not { } previousDnsAttempt || DateTimeOffset.UtcNow - previousDnsAttempt >= TimeSpan.FromSeconds(settings.DnsPollIntervalSeconds)))
                {
                    lastDnsAttempt = DateTimeOffset.UtcNow;
                    try
                    {
                        using var process = new System.Diagnostics.Process { StartInfo = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "ipconfig.exe"),
                            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
                        } };
                        process.StartInfo.ArgumentList.Add("/displaydns");
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
                            var names = WindowsDnsCacheParser.Parse(content);
                            foreach (var name in reputation.FindMatches(names.OfType<string>(), DateTimeOffset.UtcNow))
                            {
                                var dnsObservedAt = DateTimeOffset.UtcNow;
                                if (!deduplicator.TryMark(name, dnsObservedAt)) continue;
                                var correlationDomain = domainNames.RegistrableDomain(name) ?? DomainNames.Ascii(name);
                                var correlationId = await store.GetDomainCorrelationIdAsync(correlationDomain, dnsObservedAt);
                                await RecordDetectionAsync(new SecurityEvent(0, dnsObservedAt, RiskLevel.High,
                                    "Domena na liście CERT Polska", "Cache DNS Windows", "Zaobserwowano domenę z aktualnej listy: " + name,
                                    "Ostrzeżenie, bez blokowania. Cache nie wskazuje procesu ani czasu nawigacji.", EventStatus.New,
                                    EventId: Guid.NewGuid(), Source: "dns-cache", RuleVersion: ThreatAnalysisEngine.RulesVersion,
                                    CorrelationId: correlationId,
                                    EvidenceCodes: ["dns.windows-cache-entry", "reputation.cert.current-feed-match"],
                                    SignalHash: LocalStore.CreateHostSignalHash(name)), "url", "reputation.cert");
                                detections.Add(name!);
                            }
                        }
                        lastDnsRead = DateTimeOffset.UtcNow; dnsState = "Odczyt cache DNS działa; bez DoH, pełnych URL i PID";
                        await store.ApplyRetentionAsync(settings.RetentionDays);
                    }
                    catch (Exception ex) { lastDnsError = DateTimeOffset.UtcNow; dnsState = "Odczyt cache DNS niedostępny: " + ex.GetType().Name; }
                }
                var enterpriseSync = installationProfile.Variant == ProductVariant.EnterpriseClient
                    ? await SyncEnterpriseAsync(force: false) : null;
                result = new { detections = detections.Count, notifications = settings.Notifications, dns = dnsState,
                    processChanges, processes = processMonitor.State, tcpChanges, tcpConnections = tcpConnectionMonitor.State,
                    downloadedFileMatches, downloadedFiles = downloadedFileMonitor.State, enterpriseSync };
                break;
            case "history": result = await store.ReadAsync(); break;
            case "eventStatus":
                if (!Enum.TryParse<EventStatus>(request.GetProperty("status").GetString(), ignoreCase: true, out var eventStatus) || !Enum.IsDefined(eventStatus))
                    throw new InvalidDataException("Nieprawidłowy status zdarzenia.");
                await store.SetStatusAsync(request.GetProperty("eventId").GetInt64(), eventStatus);
                result = new { updated = true };
                break;
            case "knowledgeList": result = await knowledge.ListAsync(); break;
            case "knowledgeImport":
                var documentPath = request.GetProperty("path").GetString() ?? throw new InvalidDataException("Nie wskazano dokumentu.");
                result = await knowledge.ImportAsync(documentPath);
                break;
            case "knowledgeSearch":
                var query = request.GetProperty("query").GetString() ?? "";
                result = await knowledge.SearchAsync(query);
                break;
            case "knowledgeDelete":
                var documentId = request.GetProperty("documentId").GetString() ?? "";
                result = new { deleted = await knowledge.DeleteAsync(documentId) };
                break;
            case "knowledgeBackup":
                var knowledgeBackupPath = request.GetProperty("path").GetString() ?? throw new InvalidDataException("Nie wskazano pliku kopii.");
                await knowledge.BackupAsync(knowledgeBackupPath);
                result = new { backedUp = true };
                break;
            case "knowledgeRestore":
                var knowledgeRestorePath = request.GetProperty("path").GetString() ?? throw new InvalidDataException("Nie wskazano pliku kopii.");
                result = new { restoredDocuments = await knowledge.RestoreAsync(knowledgeRestorePath) };
                break;
            case "historyExport":
                var exportPath = request.GetProperty("path").GetString() ?? throw new InvalidDataException("Nie wskazano pliku eksportu.");
                await store.ExportAsync(exportPath);
                result = new { exported = true };
                break;
            case "historyExportCsv":
                var csvExportPath = request.GetProperty("path").GetString() ?? throw new InvalidDataException("Nie wskazano pliku eksportu.");
                await store.ExportCsvAsync(csvExportPath);
                result = new { exported = true };
                break;
            case "diagnosticsExport":
                var diagnosticsPath = request.GetProperty("path").GetString() ?? throw new InvalidDataException("Nie wskazano pliku diagnostyki.");
                var hostLifecycle = request.TryGetProperty("hostLifecycle", out var hostLifecycleElement) && hostLifecycleElement.ValueKind == JsonValueKind.Object
                    ? hostLifecycleElement
                    : default;
                var requestedHostStatus = hostLifecycle.ValueKind == JsonValueKind.Object && hostLifecycle.TryGetProperty("status", out var hostStatusElement) && hostStatusElement.ValueKind == JsonValueKind.String
                    ? hostStatusElement.GetString()
                    : null;
                var safeHostStatus = requestedHostStatus is "starting" or "ready" or "restarting" or "stopped" ? requestedHostStatus : "unknown";
                var requestedExitCode = hostLifecycle.ValueKind == JsonValueKind.Object && hostLifecycle.TryGetProperty("lastExitCode", out var hostExitElement) && hostExitElement.ValueKind == JsonValueKind.String
                    ? hostExitElement.GetString()
                    : null;
                var safeExitCode = requestedExitCode is null ? null : new string(requestedExitCode.Where(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_').Take(40).ToArray());
                var hostStderrObserved = hostLifecycle.ValueKind == JsonValueKind.Object && hostLifecycle.TryGetProperty("stderrObserved", out var hostStderrElement)
                    && hostStderrElement.ValueKind == JsonValueKind.True;
                var requestedExceptionType = hostLifecycle.ValueKind == JsonValueKind.Object && hostLifecycle.TryGetProperty("stderrExceptionType", out var hostExceptionElement)
                    && hostExceptionElement.ValueKind == JsonValueKind.String ? hostExceptionElement.GetString() : null;
                var safeExceptionType = requestedExceptionType is { Length: > 0 and <= 160 } && requestedExceptionType.EndsWith("Exception", StringComparison.Ordinal)
                    && char.IsAsciiLetter(requestedExceptionType[0])
                    && requestedExceptionType.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '+' or '`')
                    ? requestedExceptionType : null;
                var diagnostics = new
                {
                    exportedAtUtc = DateTimeOffset.UtcNow,
                    applicationVersion = typeof(Program).Assembly.GetName().Version?.ToString(3),
                    operatingSystem = new { version = Environment.OSVersion.Version.ToString(), architecture = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString() },
                    runtime = new { framework = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription, architecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString() },
                    hostLifecycle = new { status = safeHostStatus, lastExitCode = safeExitCode, stderrObserved = hostStderrObserved, stderrExceptionType = safeExceptionType },
                    monitors = new { dns = dnsState, lastDnsReadUtc = lastDnsRead, lastDnsErrorUtc = lastDnsError,
                        processes = processMonitor.State, tcpConnections = tcpConnectionMonitor.State, downloadedFiles = downloadedFileMonitor.State },
                    settings = new { retentionDays = settings.RetentionDays, notifications = settings.Notifications, paused = settings.Paused, useLocalAI = settings.UseLocalAI,
                        monitorForegroundChanges = settings.MonitorForegroundChanges, monitorNetworkConnections = settings.MonitorNetworkConnections,
                        monitorDownloadedFiles = settings.MonitorDownloadedFiles, dnsPollIntervalSeconds = settings.DnsPollIntervalSeconds },
                    storage = new { history = await store.GetStorageMetricsAsync(), knowledge = await knowledge.GetStorageMetricsAsync() }
                };
                await using (var diagnosticsFile = new FileStream(diagnosticsPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    await JsonSerializer.SerializeAsync(diagnosticsFile, diagnostics, json);
                result = new { exported = true };
                break;
            case "databaseBackup":
                var databaseBackupPath = request.GetProperty("path").GetString() ?? throw new InvalidDataException("Nie wskazano pliku kopii.");
                await store.BackupAsync(databaseBackupPath);
                result = new { backedUp = true };
                break;
            case "databaseRestore":
                var databaseRestorePath = request.GetProperty("path").GetString() ?? throw new InvalidDataException("Nie wskazano pliku kopii.");
                await store.RestoreAsync(databaseRestorePath);
                settings = await store.LoadSettingsAsync();
                await store.ApplyRetentionAsync(settings.RetentionDays);
                result = new { restored = true, eventCount = await store.CountEventsAsync(), installationProfilePreserved = true };
                break;
            case "aiModels":
                var endpoint = request.GetProperty("endpoint").GetString() ?? settings.LocalAIEndpoint;
                result = await aiProvider.ListModelsAsync(endpoint);
                break;
            case "aiSettings":
                var aiSettings = settings with { UseLocalAI = request.GetProperty("useLocalAI").GetBoolean(),
                    LocalAIEndpoint = request.GetProperty("endpoint").GetString() ?? "",
                    LocalAIModel = request.GetProperty("model").GetString() ?? "",
                    LocalAITimeoutSeconds = request.TryGetProperty("timeoutSeconds", out var timeoutSeconds) ? timeoutSeconds.GetInt32() : settings.LocalAITimeoutSeconds };
                await store.SaveSettingsAsync(aiSettings);
                settings = aiSettings;
                result = settings;
                break;
            case "enterpriseStatus": result = await EnterpriseStatusAsync(); break;
            case "enterprisePair":
                if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Parowanie Enterprise wymaga Windows DPAPI.");
                if (!request.GetProperty("shareSecurityMetadata").GetBoolean())
                    throw new InvalidDataException("Parowanie wymaga jawnego potwierdzenia synchronizacji metadanych bezpieczeństwa.");
                var enterpriseServer = EnterpriseAgentClient.ValidateServer(request.GetProperty("server").GetString() ?? "");
                var invitationCode = request.GetProperty("invitationCode").GetString() ?? "";
                var enrollment = await enterpriseAgent.EnrollAsync(enterpriseServer, invitationCode, Environment.MachineName,
                    typeof(EnterpriseAgentClient).Assembly.GetName().Version?.ToString(3) ?? "0.0.0");
                await deviceCredentials.WriteAsync(enrollment.DeviceToken);
                try
                {
                    await store.SetEnterpriseProfileAsync(enterpriseServer.ToString(), shareSecurityMetadata: true);
                    installationProfile = await store.GetInstallationProfileAsync();
                }
                catch { await deviceCredentials.DeleteAsync(); throw; }
                lastEnterpriseSyncAttempt = null;
                result = new { paired = true, deviceId = enrollment.DeviceId, group = enrollment.Group };
                break;
            case "enterpriseConsent":
                if (installationProfile.Variant != ProductVariant.EnterpriseClient || installationProfile.EnterpriseServerUri is null)
                    throw new InvalidOperationException("Najpierw sparuj urządzenie z serwerem Enterprise.");
                var shareMetadata = request.GetProperty("enabled").GetBoolean();
                if (shareMetadata && string.IsNullOrEmpty(await deviceCredentials.ReadAsync()))
                    throw new InvalidOperationException("Brak poświadczenia urządzenia; sparuj je ponownie przed włączeniem synchronizacji.");
                await store.SetEnterpriseProfileAsync(installationProfile.EnterpriseServerUri, shareMetadata);
                installationProfile = await store.GetInstallationProfileAsync();
                if (!shareMetadata) await store.ClearEnterpriseEventQueueAsync();
                result = new { sharingMetadata = shareMetadata, queuedEvents = await store.CountPendingEnterpriseEventsAsync() };
                break;
            case "enterpriseSync": result = await SyncEnterpriseAsync(force: true); break;
            case "enterpriseRotateCredential":
                if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Poświadczenia Enterprise wymagają Windows DPAPI.");
                if (installationProfile.Variant != ProductVariant.EnterpriseClient || installationProfile.EnterpriseServerUri is null)
                    throw new InvalidOperationException("Najpierw sparuj urządzenie z serwerem Enterprise.");
                if (!installationProfile.ShareSecurityMetadata)
                    throw new InvalidOperationException("Wznów komunikację Enterprise za zgodą, aby odnowić poświadczenie.");
                await enterpriseCredentialRotator.RotateAsync(EnterpriseAgentClient.ValidateServer(installationProfile.EnterpriseServerUri));
                lastEnterpriseSyncAttempt = null;
                result = new { rotated = true };
                break;
            case "pause":
                var pausedSettings = settings with { Paused = request.GetProperty("paused").GetBoolean() };
                await store.SaveSettingsAsync(pausedSettings);
                settings = pausedSettings;
                await downloadedFileMonitor.SetEnabledAsync(store, settings.MonitorDownloadedFiles && !settings.Paused);
                result = settings;
                break;
            case "settings":
                var updatedSettings = settings with { RetentionDays = request.GetProperty("retentionDays").GetInt32(),
                    Notifications = request.GetProperty("notifications").GetBoolean(),
                    DnsPollIntervalSeconds = request.TryGetProperty("dnsPollIntervalSeconds", out var interval) ? interval.GetInt32() : settings.DnsPollIntervalSeconds,
                    MonitorNetworkConnections = request.TryGetProperty("monitorNetworkConnections", out var monitorNetwork) ? monitorNetwork.GetBoolean() : settings.MonitorNetworkConnections,
                    MonitorDownloadedFiles = request.TryGetProperty("monitorDownloadedFiles", out var monitorDownloads) ? monitorDownloads.GetBoolean() : settings.MonitorDownloadedFiles };
                await store.SaveSettingsAsync(updatedSettings);
                settings = updatedSettings;
                await downloadedFileMonitor.SetEnabledAsync(store, settings.MonitorDownloadedFiles && !settings.Paused);
                await store.ApplyRetentionAsync(settings.RetentionDays);
                result = settings;
                break;
            case "analyze":
                var text = request.GetProperty("text").GetString() ?? "";
                var url = request.GetProperty("url").GetString();
                if (text.Length > 16000 || url?.Length > 4096) throw new InvalidDataException("Zbyt długa treść.");
                var observedAt = DateTimeOffset.UtcNow;
                var urlAnalysis = string.IsNullOrWhiteSpace(url) ? null : urlAnalyzer.Analyze(url);
                var context = new AnalysisContext("Ręczna analiza", text, observedAt,
                    string.IsNullOrWhiteSpace(url) ? null : new NavigationSignal(url));
                var assessment = await orchestrator.AnalyzeAsync(context, settings.UseLocalAI, settings.LocalAIEndpoint,
                    settings.LocalAIModel, settings.LocalAITimeoutSeconds);
                if (Uri.TryCreate(url, UriKind.Absolute, out var target) && target.Scheme is "http" or "https" && reputation.Contains(target.IdnHost, DateTimeOffset.UtcNow))
                    assessment = assessment with { Risk = RiskLevel.High, Category = ThreatCategory.SuspiciousNavigation,
                        Indicators = assessment.Indicators.Append(new ThreatIndicator("reputation.cert", "Domena znajduje się na aktualnej liście ostrzeżeń CERT Polska.", 10, ThreatCategory.SuspiciousNavigation)).ToArray(),
                        Explanation = "Domena znajduje się na aktualnej liście ostrzeżeń CERT Polska. " + assessment.Explanation };
                if (assessment.Indicators.Count > 0)
                {
                    var correlationDomain = urlAnalysis?.RegistrableDomain ?? urlAnalysis?.Host;
                    Guid? correlationId = urlAnalysis is { IsValid: true } && correlationDomain is not null &&
                        Uri.CheckHostName(correlationDomain) == UriHostNameType.Dns &&
                        assessment.Indicators.Any(indicator => indicator.Id.StartsWith("url.", StringComparison.Ordinal) || indicator.Id == "reputation.cert")
                        ? await store.GetDomainCorrelationIdAsync(correlationDomain, observedAt)
                        : null;
                    await RecordDetectionAsync(new SecurityEvent(0, observedAt, assessment.Risk,
                        assessment.Category.ToString(), "Ręczna analiza", assessment.Explanation,
                        string.Join(" ", assessment.Recommendations), EventStatus.New,
                        EventId: Guid.NewGuid(), Source: "manual-analysis", RuleVersion: ThreatAnalysisEngine.RulesVersion,
                        CorrelationId: correlationId,
                        EvidenceCodes: assessment.Indicators.Select(indicator => indicator.Id).Distinct(StringComparer.Ordinal).Take(32).ToArray(),
                        SignalHash: assessment.Indicators.Any(indicator => indicator.Id == "reputation.cert")
                            ? LocalStore.CreateHostSignalHash(urlAnalysis?.Host) : null),
                        assessment.Category == ThreatCategory.SuspiciousNavigation ? "url" : "message",
                        "local." + (assessment.Category == ThreatCategory.SuspiciousNavigation ? "url" : "message"));
                }
                await store.ApplyRetentionAsync(settings.RetentionDays);
                result = assessment;
                break;
            case "connections":
                // Read-only, on-demand Windows snapshot; short-lived flows and payloads are not observed.
                result = settings.Paused ? [] : await ReadConnectionSnapshotAsync(CancellationToken.None);
                break;
            case "file":
                var path = request.GetProperty("path").GetString() ?? throw new InvalidDataException();
                var info = new FileInfo(path);
                if (!info.Exists) throw new FileNotFoundException("Nie znaleziono pliku.");
                await using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (stream.Length > 256L * 1024 * 1024) throw new InvalidDataException("Limit pliku: 256 MiB.");
                    var hash = Convert.ToHexString(await SHA256.HashDataAsync(stream));
                    var signature = await ReadAuthenticodeSignatureAsync(info.FullName, CancellationToken.None);
                    var fileReputation = fileHashReputation.Check(hash);
                    var reputationText = !fileReputation.FeedImported ? "Brak lokalnej listy hashy."
                        : fileReputation.Match ? "Hash znajduje się na ręcznie zaimportowanej lokalnej liście; źródło nie zostało niezależnie zweryfikowane."
                        : "Hash nie znajduje się na ręcznie zaimportowanej lokalnej liście; brak dopasowania nie potwierdza bezpieczeństwa.";
                    if (fileReputation.Match)
                    {
                        await store.AddLocalOnlyAsync(new SecurityEvent(0, DateTimeOffset.UtcNow, RiskLevel.Information,
                            "Plik · dopasowanie lokalnej listy SHA-256", "Ręczna analiza pliku",
                            "SHA-256 pliku pasuje do lokalnej listy użytkownika; źródło listy nie jest niezależnie zweryfikowane.",
                            "Sprawdź pochodzenie pliku i źródło listy. Dopasowanie nie jest automatycznym werdyktem zagrożenia.",
                            EventStatus.New, EventId: Guid.NewGuid(), Source: "manual-file-analysis",
                            RuleVersion: ThreatAnalysisEngine.RulesVersion,
                            EvidenceCodes: ["file.sha256.matches-local-list", "file.local-list-source-unverified"],
                            SignalHash: hash));
                    }
                    result = new { name = info.Name, size = stream.Length, sha256 = hash, signature,
                        reputation = new { feedImported = fileReputation.FeedImported, match = fileReputation.Match, explanation = reputationText },
                        verdict = "Obliczono SHA-256 i sprawdzono stan podpisu Authenticode. " + reputationText + " Żaden z tych wyników sam nie potwierdza bezpieczeństwa pliku." };
                }
                break;
            case "fileHashFeedImport":
                var fileFeedPath = request.GetProperty("path").GetString() ?? throw new InvalidDataException();
                var fileFeedStatus = await fileHashReputation.ImportFileAsync(fileFeedPath);
                result = new { fileFeedStatus.HashCount, fileFeedStatus.ImportedAt,
                    explanation = $"Zaimportowano {fileFeedStatus.HashCount} hashy do lokalnej listy. Sentinel nie weryfikuje niezależnie źródła." };
                break;
            case "malwareBazaarConfigure":
                if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Klucz MalwareBazaar wymaga Windows DPAPI.");
                var malwareBazaarKey = request.GetProperty("apiKey").GetString() ?? "";
                if (string.IsNullOrWhiteSpace(malwareBazaarKey)) await malwareBazaarCredentials.DeleteAsync();
                else
                {
                    if (!request.GetProperty("consent").GetBoolean()) throw new InvalidDataException("Zapis klucza wymaga jawnej zgody na ręczne zapytania hashy.");
                    MalwareBazaarClient.ValidateApiKey(malwareBazaarKey);
                    await malwareBazaarCredentials.WriteAsync(malwareBazaarKey);
                }
                result = new { configured = !string.IsNullOrWhiteSpace(malwareBazaarKey) };
                break;
            case "malwareBazaarLookup":
                if (!request.GetProperty("consent").GetBoolean()) throw new InvalidDataException("Zapytanie wymaga jawnej zgody na wysłanie SHA-256.");
                var configuredMalwareBazaarKey = await malwareBazaarCredentials.ReadAsync()
                    ?? throw new InvalidOperationException("Najpierw skonfiguruj osobisty Auth-Key MalwareBazaar.");
                var malwareHash = request.GetProperty("sha256").GetString() ?? "";
                result = await malwareBazaar.LookupAsync(malwareHash, configuredMalwareBazaarKey);
                break;
            case "clearHistory": await store.DeleteHistoryAsync(); result = new { deleted = true }; break;
            default: throw new InvalidDataException("Nieznana metoda.");
        }
        Console.WriteLine(JsonSerializer.Serialize(new { id, ok = true, result }, json));
    }
    catch (Exception ex)
    {
        var error = ex switch
        {
            SqliteException { SqliteErrorCode: 13 } => "Brak miejsca na dysku lub osiągnięto limit 512 MiB lokalnej historii. Zwolnij miejsce, skróć retencję albo wykonaj kopię i usuń część historii.",
            InvalidDataException or ArgumentException => ex.Message,
            _ => "Operacja nie powiodła się: " + ex.GetType().Name
        };
        Console.WriteLine(JsonSerializer.Serialize(new { id, ok = false, error }, json));
    }
}
