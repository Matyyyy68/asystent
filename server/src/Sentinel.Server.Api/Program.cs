using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.Data.Sqlite;
using Sentinel.Server.Api;
using Sentinel.Server.Core;
using Sentinel.Server.Infrastructure;
using Sentinel.Contracts;
using Sentinel.Core.Knowledge;
using Sentinel.Core.Analysis;

if (args.Length == 1 && args[0] == "--bootstrap-admin")
{
    await BootstrapAdministratorAsync();
    return;
}

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    WebRootPath = Path.Combine(AppContext.BaseDirectory, "wwwroot")
});
builder.Host.UseWindowsService(options => options.ServiceName = "Sentinel AI Server");
var configuredUrls = builder.Configuration["urls"] ?? builder.Configuration["ASPNETCORE_URLS"];
if (string.IsNullOrWhiteSpace(configuredUrls))
    builder.WebHost.UseUrls("http://127.0.0.1:5080");
else
    foreach (var rawUrl in configuredUrls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri)) throw new InvalidOperationException("Nieprawidłowy adres nasłuchiwania.");
        var loopback = uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || IPAddress.TryParse(uri.Host, out var ip) && IPAddress.IsLoopback(ip);
        if (!loopback && uri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("Nasłuchiwanie poza localhost wymaga HTTPS z prawidłowym certyfikatem TLS.");
    }

var defaultDataDirectory = OperatingSystem.IsWindows()
    ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SentinelAI", "Server")
    : Path.Combine("/var/lib", "sentinel-ai", "server");
var dataDirectory = builder.Configuration["Sentinel:DataDirectory"] ?? defaultDataDirectory;
var dataDirectoryConfigured = !string.IsNullOrWhiteSpace(builder.Configuration["Sentinel:DataDirectory"]);
var databasePath = Path.GetFullPath(Path.Combine(dataDirectory, "sentinel-server.db"));
var eventRetentionDays = builder.Configuration.GetValue<int?>("Sentinel:EventRetentionDays") ?? 90;
if (eventRetentionDays is < 30 or > 3650) throw new InvalidOperationException("Sentinel:EventRetentionDays musi wynosić 30–3650.");
var store = new SqliteServerStore(databasePath, eventRetentionDays);
var knowledgeDirectory = Path.Combine(Path.GetFullPath(dataDirectory), "Knowledge");
var knowledge = new LocalKnowledgeBase(knowledgeDirectory);
var aiProvider = new OllamaLocalProvider(OllamaLocalProvider.CreateDirectHttpClient());
var localRules = new ThreatAnalysisEngine(new UrlAnalyzer(new DomainNames()));
var passwordHasher = new AdminPasswordHasher();
var configuredBootstrapUsername = builder.Configuration["Sentinel:BootstrapAdminUsername"];
var configuredBootstrapPassword = builder.Configuration["Sentinel:BootstrapAdminPassword"];
var dummyPasswordHash = passwordHasher.Hash(RandomToken(32));
builder.Services.AddSingleton<IServerStore>(store);
builder.Services.AddSingleton(store);
builder.Services.AddHostedService<EventRetentionService>();
builder.Services.AddSingleton(passwordHasher);
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("enrollment", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown", _ => new FixedWindowRateLimiterOptions
        { PermitLimit = 20, Window = TimeSpan.FromMinutes(1), QueueLimit = 0, AutoReplenishment = true }));
    options.AddPolicy("admin-login", context => RateLimitPartition.GetSlidingWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown", _ => new SlidingWindowRateLimiterOptions
        { PermitLimit = 5, Window = TimeSpan.FromMinutes(15), SegmentsPerWindow = 3, QueueLimit = 0, AutoReplenishment = true }));
});
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = LocalKnowledgeBase.MaximumFileBytes + 64 * 1024);
builder.Services.AddSingleton<IKnowledgeBaseProvider>(knowledge);
builder.Services.AddSingleton<IAIProvider>(aiProvider);
builder.Services.AddSingleton(localRules);
builder.Services.AddSingleton<AnalysisOrchestrator>();

var app = builder.Build();
await store.InitializeAsync();
await knowledge.InitializeAsync();
var processStartedAtUtc = DateTimeOffset.UtcNow;
if (configuredBootstrapUsername is not null || configuredBootstrapPassword is not null)
{
    if (!IsValidUsername(configuredBootstrapUsername) || !AdminPasswordHasher.IsValid(configuredBootstrapPassword ?? ""))
        throw new InvalidOperationException("Pierwszy administrator wymaga nazwy 3–64 znaki i hasła 14–128 znaków.");
    await store.TryBootstrapAdminAsync(NormalizeUsername(configuredBootstrapUsername!), passwordHasher.Hash(configuredBootstrapPassword!), DateTimeOffset.UtcNow);
    builder.Configuration["Sentinel:BootstrapAdminPassword"] = null;
    Environment.SetEnvironmentVariable("Sentinel__BootstrapAdminPassword", null);
}
app.Use(async (context, next) =>
{
    var correlationId = context.Request.Headers.TryGetValue("X-Correlation-ID", out var supplied) &&
                        supplied.Count == 1 && Guid.TryParse(supplied[0], out var parsed)
        ? parsed.ToString("D") : Guid.NewGuid().ToString("D");
    context.Response.Headers["X-Correlation-ID"] = correlationId;
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
    if (context.Request.Path.StartsWithSegments("/api/v1/admin/auth")) context.Response.Headers.CacheControl = "no-store";
    if (context.Request.Path.StartsWithSegments("/admin")) context.Response.Headers.CacheControl = "no-store";
    await next();
});
app.UseRateLimiter();

var publicSiteRoot = Path.Combine(AppContext.BaseDirectory, "wwwroot");
app.MapGet("/", () => Results.File(Path.Combine(publicSiteRoot, "index.html"), "text/html; charset=utf-8"));
app.MapGet("/site.css", () => Results.File(Path.Combine(publicSiteRoot, "site.css"), "text/css; charset=utf-8"));
app.MapGet("/site.js", () => Results.File(Path.Combine(publicSiteRoot, "site.js"), "text/javascript; charset=utf-8"));
app.MapGet("/favicon.svg", () => Results.File(Path.Combine(publicSiteRoot, "favicon.svg"), "image/svg+xml"));
app.MapGet("/healthz", () => Results.Ok(new { status = "healthy" }));
app.MapGet("/readyz", async (IServerStore repository, CancellationToken ct) =>
    await repository.CheckReadyAsync(ct)
        ? Results.Ok(new { status = "ready", apiVersion = "v1", productVersion = System.Reflection.Assembly.GetEntryAssembly()?.GetName().Version?.ToString(3) ?? "unknown" })
        : Results.Problem(title: "Magazyn danych niedostępny", statusCode: StatusCodes.Status503ServiceUnavailable));
var adminUiRoot = Path.Combine(AppContext.BaseDirectory, "wwwroot", "admin");
app.MapGet("/admin", () => Results.File(Path.Combine(adminUiRoot, "index.html"), "text/html; charset=utf-8"));
app.MapGet("/admin/{asset}", (string asset) => asset switch
{
    "app.css" => Results.File(Path.Combine(adminUiRoot, "app.css"), "text/css; charset=utf-8"),
    "app.js" => Results.File(Path.Combine(adminUiRoot, "app.js"), "text/javascript; charset=utf-8"),
    _ => Results.NotFound()
});

var admin = app.MapGroup("/api/v1/admin");
app.MapPost("/api/v1/admin/auth/login", async (AdminLoginBody body, HttpContext http, IServerStore repository, AdminPasswordHasher hasher, CancellationToken ct) =>
{
    if (!IsValidUsername(body.Username) || body.Password is null || body.Password.Length is < 1 or > 128) return Results.Unauthorized();
    var username = NormalizeUsername(body.Username); var account = await repository.FindAdminAsync(username, ct);
    var hash = account?.PasswordHash ?? dummyPasswordHash;
    var passwordValid = hasher.Verify(body.Password, hash);
    if (account is null || account.Disabled || !passwordValid) return Results.Unauthorized();
    var token = RandomToken(32); var now = DateTimeOffset.UtcNow; var expires = now.AddHours(12);
    await repository.CreateAdminSessionAsync(account.Id, HashToken(token), now, expires, ct);
    return Results.Ok(new { accessToken = token, expiresAt = expires, user = new { account.Id, account.Username, role = account.Role.ToString() } });
}).RequireRateLimiting("admin-login");

var allAdmins = app.MapGroup("/api/v1/admin");
allAdmins.AddEndpointFilter(AuthenticateAdmin(store));
var securityAdmins = app.MapGroup("/api/v1/admin");
securityAdmins.AddEndpointFilter(AuthenticateAdmin(store));
securityAdmins.AddEndpointFilter(RequireRoles(AdminRole.SystemAdministrator, AdminRole.SecurityAdministrator));
var systemAdmins = app.MapGroup("/api/v1/admin");
systemAdmins.AddEndpointFilter(AuthenticateAdmin(store));
systemAdmins.AddEndpointFilter(RequireRoles(AdminRole.SystemAdministrator));

systemAdmins.MapGet("/diagnostics/host", () =>
{
    using var process = System.Diagnostics.Process.GetCurrentProcess();
    process.Refresh();
    var storeBytes = GetDatabaseFootprint(databasePath);
    var uptimeSeconds = Math.Max(0, (long)(DateTimeOffset.UtcNow - processStartedAtUtc).TotalSeconds);
    var productVersion = System.Reflection.Assembly.GetEntryAssembly()?.GetName().Version?.ToString(3) ?? "unknown";
    var listenerSummary = (string.IsNullOrWhiteSpace(configuredUrls) ? "http://127.0.0.1:5080" : configuredUrls)
        .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(raw => Uri.TryCreate(raw, UriKind.Absolute, out var uri)
            ? new { scheme = uri.Scheme, port = uri.Port, loopback = uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || IPAddress.TryParse(uri.Host, out var ip) && IPAddress.IsLoopback(ip) }
            : new { scheme = "unknown", port = 0, loopback = false })
        .ToArray();
    return Results.Ok(new
    {
        capturedAtUtc = DateTimeOffset.UtcNow,
        productVersion,
        runtimeVersion = RuntimeInformation.FrameworkDescription,
        operatingSystem = OperatingSystem.IsWindows() ? "Windows" : OperatingSystem.IsLinux() ? "Linux" : "Other",
        processUptimeSeconds = uptimeSeconds,
        processWorkingSetBytes = Math.Max(0, process.WorkingSet64),
        managedMemoryBytes = Math.Max(0, GC.GetTotalMemory(forceFullCollection: false)),
        database = new { state = storeBytes is null ? "unavailable" : "available", totalBytes = storeBytes },
        deployment = new { listeners = listenerSummary, eventRetentionDays, customDataDirectory = dataDirectoryConfigured }
    });
});

systemAdmins.MapPost("/backups", async (HttpContext context, SqliteServerStore repository, IServerStore audit, CancellationToken ct) =>
{
    var actor = (AdminIdentity)context.Items["admin"]!;
    var backupDirectory = Path.Combine(Path.GetFullPath(dataDirectory), "Backups");
    Directory.CreateDirectory(backupDirectory);
    var backupName = $"sentinel-server-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.db";
    var backupPath = Path.Combine(backupDirectory, backupName);
    try
    {
        await audit.RecordAdminActionAsync(actor.Username, "server.backup_requested", backupName, DateTimeOffset.UtcNow, ct);
        await repository.CreateBackupAsync(backupPath, ct);
        return Results.Ok(new { fileName = backupName, downloadUrl = $"/api/v1/admin/backups/{Uri.EscapeDataString(backupName)}" });
    }
    catch
    {
        if (File.Exists(backupPath)) File.Delete(backupPath);
        throw;
    }
});
systemAdmins.MapGet("/backups/{fileName}", (string fileName) =>
{
    if (!System.Text.RegularExpressions.Regex.IsMatch(fileName, "^sentinel-server-[0-9]{8}-[0-9]{6}-[a-f0-9]{32}\\.db$", System.Text.RegularExpressions.RegexOptions.CultureInvariant))
        return Results.NotFound();
    var backupPath = Path.Combine(Path.GetFullPath(dataDirectory), "Backups", fileName);
    return File.Exists(backupPath)
        ? Results.File(backupPath, "application/vnd.sqlite3", fileName, enableRangeProcessing: false)
        : Results.NotFound();
});

allAdmins.MapGet("/ai/configuration", async (IServerStore repository, CancellationToken ct) =>
{
    var config = await repository.ReadServerAIConfigurationAsync(ct);
    return Results.Ok(new { config.Endpoint, config.Model, config.Enabled, config.TimeoutSeconds, config.Version,
        status = config.Enabled ? "configured_not_tested" : "disabled", execution = "loopback_only" });
});
allAdmins.MapGet("/ai/models", async (IServerStore repository, IAIProvider provider, CancellationToken ct) =>
{
    var config = await repository.ReadServerAIConfigurationAsync(ct);
    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(10));
    try { return Results.Ok(await provider.ListModelsAsync(config.Endpoint, timeout.Token)); }
    catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException or InvalidDataException or ArgumentException or System.Text.Json.JsonException)
    { return Results.Problem(title: "Lokalny provider modelu nie odpowiada", detail: "Sprawdź, czy Ollama działa na serwerze i czy endpoint loopback jest prawidłowy.", statusCode: StatusCodes.Status503ServiceUnavailable); }
});
systemAdmins.MapPut("/ai/configuration", async (ServerAIConfigurationBody body, HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    var current = await repository.ReadServerAIConfigurationAsync(ct);
    var actor = (AdminIdentity)context.Items["admin"]!;
    var candidate = new ServerAIConfiguration(body.Endpoint ?? "", body.Model ?? "", body.Enabled, body.TimeoutSeconds, current.Version);
    try
    {
        var saved = await repository.WriteServerAIConfigurationAsync(candidate, body.ExpectedVersion, actor.Username, DateTimeOffset.UtcNow, ct);
        return saved ? Results.Ok(await repository.ReadServerAIConfigurationAsync(ct)) : Results.Conflict(new { error = "Konfiguracja zmieniła się od czasu odczytu." });
    }
    catch (ArgumentException exception) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["configuration"] = [exception.Message] }); }
});
systemAdmins.MapPost("/ai/test", async (ServerAITestBody body, IServerStore repository, IAIProvider provider, CancellationToken ct) =>
{
    var config = await repository.ReadServerAIConfigurationAsync(ct);
    var model = string.IsNullOrWhiteSpace(body.Model) ? config.Model : body.Model;
    if (string.IsNullOrWhiteSpace(model) || model.Length > 160 || model.Any(char.IsControl))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["model"] = ["Wybierz model z listy lokalnie zainstalowanych modeli."] });
    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(config.TimeoutSeconds));
    try
    {
        var response = await provider.AnalyzeAsync(config.Endpoint, model,
            new AnalysisContext("Synthetic server self-test", "Pilnie: blokada konta. Zaloguj się, aby potwierdzić dane.", DateTimeOffset.UtcNow), [], timeout.Token);
        return Results.Ok(new { status = "responded", model, response.Risk, category = response.Category.ToString(), response.Explanation,
            syntheticOnly = true, calibratedProbability = false });
    }
    catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException or InvalidDataException or ArgumentException or System.Text.Json.JsonException)
    { return Results.Problem(title: "Test lokalnego modelu nie powiódł się", detail: "Model nie odpowiedział poprawnym wynikiem w wyznaczonym czasie.", statusCode: StatusCodes.Status503ServiceUnavailable); }
});

allAdmins.MapGet("/auth/me", (HttpContext context) =>
{
    var identity = (AdminIdentity)context.Items["admin"]!;
    return Results.Ok(new { identity.Id, identity.Username, role = identity.Role.ToString() });
});
allAdmins.MapPost("/auth/logout", async (HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    var identity = (AdminIdentity)context.Items["admin"]!;
    await repository.RevokeAdminSessionAsync(identity.SessionId, identity.Id, identity.Username, DateTimeOffset.UtcNow, ct);
    return Results.NoContent();
});
allAdmins.MapPut("/auth/password", async (ChangePasswordBody body, HttpContext context, IServerStore repository, AdminPasswordHasher hasher, CancellationToken ct) =>
{
    var identity = (AdminIdentity)context.Items["admin"]!;
    if (!AdminPasswordHasher.IsValid(body.NewPassword ?? ""))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["newPassword"] = ["Hasło musi mieć od 14 do 128 znaków i nie może zawierać znaków sterujących."] });
    var credential = await repository.FindAdminAsync(identity.Username, ct);
    if (credential is null || !hasher.Verify(body.CurrentPassword ?? "", credential.PasswordHash)) return Results.Unauthorized();
    await repository.ChangeAdminPasswordAsync(identity.Id, hasher.Hash(body.NewPassword!), identity.Username, DateTimeOffset.UtcNow, ct);
    return Results.NoContent();
});
allAdmins.MapGet("/devices", async (IServerStore repository, CancellationToken ct) =>
{
    var now = DateTimeOffset.UtcNow; var items = await repository.ListDevicesAsync(ct);
    var rows = await Task.WhenAll(items.Select(async device => (Device: device, Policy: await repository.GetEffectivePolicyAsync(device.Id, ct))));
    return Results.Ok(rows.Select(row => { var device = row.Device; var policy = row.Policy; var applied = device.AppliedPolicy;
        bool? policyCurrent = policy is null || applied is null ? null : applied.GlobalVersion == policy.GlobalVersion
            && applied.GroupVersion == policy.GroupVersion && applied.DeviceVersion == policy.DeviceVersion;
        return new { device.Id, device.Name, device.Group, device.ClientVersion,
        device.RegisteredAt, device.LastSeenAt, isOnline = device.Approved && !device.Revoked && device.LastSeenAt is { } seen && now - seen <= TimeSpan.FromMinutes(2),
        device.Revoked, device.Approved, device.LastError, appliedPolicy = applied, policyCurrent };
    }));
});
allAdmins.MapGet("/groups", async (IServerStore repository, CancellationToken ct) => Results.Ok(await repository.ListGroupsAsync(ct)));
allAdmins.MapGet("/events", async (int? limit, string? deviceId, IServerStore repository, CancellationToken ct) =>
    Results.Ok(await repository.ListEventsAsync(limit ?? 100, deviceId, ct)));
allAdmins.MapGet("/knowledge/documents", async (IKnowledgeBaseProvider repository, CancellationToken ct) => Results.Ok(await repository.ListAsync(ct)));
allAdmins.MapGet("/knowledge/search", async (string? query, int? limit, IKnowledgeBaseProvider repository, CancellationToken ct) =>
{
    if (query is null || query.Length > 4000 || limit is < 1 or > 20) return Results.BadRequest(new { error = "Podaj zapytanie do 4000 znaków i limit 1–20." });
    return Results.Ok(await repository.SearchAsync(query, limit ?? 5, ct));
});
securityAdmins.MapGet("/knowledge/search-semantic", async (string? query, int? limit, string? model,
    IKnowledgeBaseProvider repository, IServerStore serverStore, IAIProvider provider, CancellationToken ct) =>
{
    if (query is null || query.Length > 4000 || limit is < 1 or > 20 || string.IsNullOrWhiteSpace(model) || model.Length > 160 || model.Any(char.IsControl))
        return Results.BadRequest(new { error = "Podaj zapytanie do 4000 znaków, limit 1–20 i nazwę modelu embeddingowego." });
    if (repository is not ISemanticKnowledgeBaseProvider semanticRepository || provider is not ITextEmbeddingProvider embeddings)
        return Results.Problem(title: "Wyszukiwanie semantyczne jest niedostępne", statusCode: StatusCodes.Status501NotImplemented);
    var config = await serverStore.ReadServerAIConfigurationAsync(ct);
    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
    timeout.CancelAfter(TimeSpan.FromSeconds(config.TimeoutSeconds));
    try
    {
        var hits = await semanticRepository.SearchSemanticAsync(query, config.Endpoint, model, embeddings, limit ?? 5, timeout.Token);
        return Results.Ok(hits);
    }
    catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException or InvalidDataException or ArgumentException or InvalidOperationException or System.Text.Json.JsonException)
    {
        return Results.Problem(title: "Lokalne wyszukiwanie semantyczne nie powiodło się", detail: "Sprawdź dostępność skonfigurowanej usługi Ollama i zgodność wybranego modelu embeddingowego.", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
});
securityAdmins.MapPost("/knowledge/documents", async (HttpContext context, IKnowledgeBaseProvider repository, CancellationToken ct) =>
{
    var actor = (AdminIdentity)context.Items["admin"]!;
    var nameHeader = context.Request.Headers["X-Sentinel-Filename"];
    if (nameHeader.Count != 1 || string.IsNullOrWhiteSpace(nameHeader[0])) return Results.BadRequest(new { error = "Brak nagłówka X-Sentinel-Filename." });
    var fileName = nameHeader[0]!;
    if (fileName.Length > 180 || fileName != Path.GetFileName(fileName) || fileName.Contains('/') || fileName.Contains('\\') || fileName.Any(char.IsControl))
        return Results.BadRequest(new { error = "Nazwa dokumentu jest nieprawidłowa." });
    if (!string.Equals(context.Request.ContentType?.Split(';', 2)[0].Trim(), "application/octet-stream", StringComparison.OrdinalIgnoreCase))
        return Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);
    if (context.Request.ContentLength is > LocalKnowledgeBase.MaximumFileBytes) return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
    var extension = Path.GetExtension(fileName).ToLowerInvariant();
    if (extension is not (".txt" or ".md" or ".docx" or ".pdf")) return Results.BadRequest(new { error = "Obsługiwane są pliki TXT, Markdown, DOCX i tekstowe PDF." });
    var temporaryFile = Path.Combine(Path.GetTempPath(), "sentinel-upload-" + Guid.NewGuid().ToString("N") + extension);
    try
    {
        await using (var output = new FileStream(temporaryFile, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous))
        {
            var buffer = new byte[81920]; long total = 0;
            while (true)
            {
                var read = await context.Request.Body.ReadAsync(buffer, ct);
                if (read == 0) break;
                total += read;
                if (total > LocalKnowledgeBase.MaximumFileBytes) return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
                await output.WriteAsync(buffer.AsMemory(0, read), ct);
            }
            await output.FlushAsync(ct);
        }
        var document = await repository.ImportAsync(temporaryFile, fileName, ct);
        await store.RecordAdminActionAsync(actor.Username, "knowledge.document_imported", document.Id, DateTimeOffset.UtcNow, ct);
        return Results.Created($"/api/v1/admin/knowledge/documents/{document.Id}", document);
    }
    catch (NotSupportedException exception) { return Results.BadRequest(new { error = exception.Message }); }
    catch (InvalidDataException exception) { return Results.BadRequest(new { error = exception.Message }); }
    finally { try { File.Delete(temporaryFile); } catch (IOException) { } }
});
securityAdmins.MapDelete("/knowledge/documents/{id}", async (string id, HttpContext context, IKnowledgeBaseProvider repository, IServerStore serverStore, CancellationToken ct) =>
{
    var deleted = await repository.DeleteAsync(id, ct);
    if (!deleted) return Results.NotFound();
    var actor = (AdminIdentity)context.Items["admin"]!;
    await serverStore.RecordAdminActionAsync(actor.Username, "knowledge.document_deleted", id, DateTimeOffset.UtcNow, ct);
    return Results.NoContent();
});
allAdmins.MapGet("/policies/global", async (IServerStore repository, CancellationToken ct) => Results.Ok(await repository.ReadGlobalPolicyAsync(ct)));
allAdmins.MapGet("/devices/{id}/policy", async (string id, IServerStore repository, CancellationToken ct) =>
{
    var effective = await repository.GetEffectivePolicyAsync(id, ct);
    return effective is null ? Results.NotFound() : Results.Ok(effective);
});
allAdmins.MapGet("/devices/{id}/policy/override", async (string id, IServerStore repository, CancellationToken ct) =>
{
    var policy = await repository.ReadDevicePolicyAsync(id, ct);
    return policy is null ? Results.NotFound() : Results.Ok(policy);
});
allAdmins.MapGet("/groups/{id}/policy", async (string id, IServerStore repository, CancellationToken ct) =>
{
    var policy = await repository.ReadGroupPolicyAsync(id, ct);
    return policy is null ? Results.NotFound() : Results.Ok(policy);
});

securityAdmins.MapPost("/groups", async (CreateGroupBody body, HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(body.Name) || body.Name.Trim().Length > 80 || body.Name.Any(char.IsControl))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["name"] = ["Nazwa grupy jest wymagana i może mieć maksymalnie 80 znaków."] });
    try
    {
        var actor = (AdminIdentity)context.Items["admin"]!;
        var group = await repository.CreateGroupAsync(body.Name.Trim(), actor.Username, DateTimeOffset.UtcNow, ct);
        return Results.Created($"/api/v1/admin/groups/{group.Id}", group);
    }
    catch (SqliteException ex) when (ex.SqliteErrorCode == 19) { return Results.Conflict(new { error = "Grupa o tej nazwie już istnieje." }); }
});
securityAdmins.MapPut("/devices/{id}/group", async (string id, SetDeviceGroupBody body, HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    if (!(await repository.ListGroupsAsync(ct)).Any(g => g.Id == body.GroupId)) return Results.NotFound();
    var actor = (AdminIdentity)context.Items["admin"]!;
    return await repository.SetDeviceGroupAsync(id, body.GroupId, actor.Username, DateTimeOffset.UtcNow, ct) ? Results.NoContent() : Results.NotFound();
});
securityAdmins.MapPut("/policies/global", async (PolicyWriteBody body, HttpContext context, IServerStore repository, CancellationToken ct) =>
    await WritePolicy(body, (AdminIdentity)context.Items["admin"]!, repository, ct,
        (write, actor, now) => repository.WriteGlobalPolicyAsync(write, actor, now, ct)));
securityAdmins.MapPut("/groups/{id}/policy", async (string id, PolicyWriteBody body, HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    if (await repository.ReadGroupPolicyAsync(id, ct) is null) return Results.NotFound();
    return await WritePolicy(body, (AdminIdentity)context.Items["admin"]!, repository, ct,
        (write, actor, now) => repository.WriteGroupPolicyAsync(id, write, actor, now, ct));
});
securityAdmins.MapPut("/devices/{id}/policy", async (string id, PolicyWriteBody body, HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    if (await repository.ReadDevicePolicyAsync(id, ct) is null && (await repository.GetEffectivePolicyAsync(id, ct)) is null) return Results.NotFound();
    return await WritePolicy(body, (AdminIdentity)context.Items["admin"]!, repository, ct,
        (write, actor, now) => repository.WriteDevicePolicyAsync(id, write, actor, now, ct));
});

securityAdmins.MapPost("/invitations", async (CreateInvitationBody body, HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    var now = DateTimeOffset.UtcNow;
    if (string.IsNullOrWhiteSpace(body.Group) || body.Group.Length > 80 || body.Group.Any(char.IsControl) ||
        body.ExpiresAt <= now || body.ExpiresAt > now.AddDays(30) || body.MaximumRegistrations is < 1 or > 1000)
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["invitation"] = ["Podaj grupę, ważność do 30 dni i limit rejestracji 1–1000."] });
    if (await repository.FindGroupByNameAsync(body.Group.Trim(), ct) is null)
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["group"] = ["Wybierz istniejącą grupę urządzeń."] });
    var code = RandomToken(24);
    var administrator = (AdminIdentity)context.Items["admin"]!;
    var invitation = await repository.CreateInvitationAsync(new(body.Group.Trim(), body.ExpiresAt, body.MaximumRegistrations, body.RequiresApproval), HashToken(code), administrator.Username, now, ct);
    return Results.Json(new { invitation.Id, invitation.Group,
        invitation.ExpiresAt, invitation.MaximumRegistrations, invitation.RequiresApproval, registrationCode = code }, statusCode: StatusCodes.Status201Created);
});
securityAdmins.MapDelete("/invitations/{id}", async (string id, HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    var administrator = (AdminIdentity)context.Items["admin"]!;
    return await repository.RevokeInvitationAsync(id, administrator.Username, DateTimeOffset.UtcNow, ct) ? Results.NoContent() : Results.NotFound();
});
securityAdmins.MapDelete("/devices/{id}", async (string id, HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    var administrator = (AdminIdentity)context.Items["admin"]!;
    return await repository.RevokeDeviceAsync(id, administrator.Username, DateTimeOffset.UtcNow, ct) ? Results.NoContent() : Results.NotFound();
});
securityAdmins.MapPut("/devices/{id}/approval", async (string id, SetDeviceApprovalBody body, HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    var administrator = (AdminIdentity)context.Items["admin"]!;
    return await repository.SetDeviceApprovalAsync(id, body.Approved, administrator.Username, DateTimeOffset.UtcNow, ct)
        ? Results.NoContent() : Results.NotFound();
});
securityAdmins.MapGet("/audit", async (int? limit, IServerStore repository, CancellationToken ct) => Results.Ok(await repository.ReadAuditAsync(limit ?? 100, ct)));
securityAdmins.MapPut("/events/{deviceId}/{eventId}/status", async (string deviceId, string eventId, SetEventStatusBody body,
    HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    if (body.Status is not ("open" or "resolved" or "false_positive"))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["status"] = ["Status musi mieć wartość open, resolved lub false_positive."] });
    var actor = (AdminIdentity)context.Items["admin"]!;
    return await repository.SetEventStatusAsync(eventId, deviceId, body.Status, actor.Username, DateTimeOffset.UtcNow, ct)
        ? Results.NoContent() : Results.NotFound();
});

systemAdmins.MapGet("/users", async (IServerStore repository, CancellationToken ct) =>
{
    var users = await repository.ListAdminsAsync(ct);
    return Results.Ok(users.Select(user => new { user.Id, user.Username, role = user.Role.ToString(), user.Disabled }));
});
systemAdmins.MapPost("/users", async (CreateAdminBody body, HttpContext context, IServerStore repository, AdminPasswordHasher hasher, CancellationToken ct) =>
{
    if (!IsValidUsername(body.Username) || !AdminPasswordHasher.IsValid(body.Password ?? "") ||
        !Enum.TryParse<AdminRole>(body.Role, true, out var role) || !Enum.IsDefined(role))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["user"] = ["Podaj nazwę 3–64 znaki, hasło 14–128 znaków i prawidłową rolę."] });
    var actor = (AdminIdentity)context.Items["admin"]!;
    try
    {
        var user = await repository.CreateAdminAsync(NormalizeUsername(body.Username), hasher.Hash(body.Password!), role, actor.Username, DateTimeOffset.UtcNow, ct);
        return Results.Created($"/api/v1/admin/users/{user.Id}", new { user.Id, user.Username, role = user.Role.ToString(), user.Disabled });
    }
    catch (SqliteException ex) when (ex.SqliteErrorCode == 19) { return Results.Conflict(new { error = "Nazwa użytkownika jest już zajęta." }); }
});
systemAdmins.MapPut("/users/{id}/disabled", async (string id, SetDisabledBody body, HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    var actor = (AdminIdentity)context.Items["admin"]!;
    try { return await repository.SetAdminDisabledAsync(id, body.Disabled, actor.Username, DateTimeOffset.UtcNow, ct) ? Results.NoContent() : Results.NotFound(); }
    catch (InvalidOperationException ex) { return Results.Conflict(new { error = ex.Message }); }
});
systemAdmins.MapPut("/users/{id}/role", async (string id, SetRoleBody body, HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    if (!Enum.TryParse<AdminRole>(body.Role, true, out var role) || !Enum.IsDefined(role)) return Results.BadRequest();
    var actor = (AdminIdentity)context.Items["admin"]!;
    try { return await repository.SetAdminRoleAsync(id, role, actor.Username, DateTimeOffset.UtcNow, ct) ? Results.NoContent() : Results.NotFound(); }
    catch (InvalidOperationException ex) { return Results.Conflict(new { error = ex.Message }); }
});

var agents = app.MapGroup("/api/v1/agents");
agents.MapPost("/enroll", async (EnrollmentBody body, IServerStore repository, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(body.InvitationCode) || body.InvitationCode.Length > 100 ||
        string.IsNullOrWhiteSpace(body.DeviceName) || body.DeviceName.Length > 120 || body.DeviceName.Any(char.IsControl) ||
        string.IsNullOrWhiteSpace(body.ClientVersion) || body.ClientVersion.Length > 40 || body.ClientVersion.Any(char.IsControl))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["device"] = ["Nieprawidłowa nazwa urządzenia, wersja klienta lub kod zaproszenia."] });
    var token = RandomToken(32);
    var result = await repository.EnrollAsync(new(body.InvitationCode, body.DeviceName.Trim(), body.ClientVersion.Trim(), token),
        HashToken(body.InvitationCode), HashToken(token), DateTimeOffset.UtcNow, ct);
    if (result is null) return Results.Unauthorized();
    return Results.Json(result, statusCode: StatusCodes.Status201Created);
}).RequireRateLimiting("enrollment");

var authenticatedAgents = app.MapGroup("/api/v1/agents");
authenticatedAgents.AddEndpointFilter(async (context, next) =>
{
    var authorization = context.HttpContext.Request.Headers.Authorization.ToString();
    if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return Results.Unauthorized();
    var rawToken = authorization[7..];
    if (rawToken.Length is < 40 or > 100) return Results.Unauthorized();
    var device = await store.AuthenticateDeviceAsync(HashToken(rawToken), DateTimeOffset.UtcNow, context.HttpContext.RequestAborted);
    if (device is null) return Results.Unauthorized();
    context.HttpContext.Items["device"] = device;
    return await next(context);
});
authenticatedAgents.MapGet("/me", (HttpContext context) =>
{
    var device = (Device)context.Items["device"]!;
    return Results.Ok(new { device.Id, device.Name, device.Group, device.ClientVersion, device.RegisteredAt });
});
authenticatedAgents.MapGet("/configuration", async (HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    var device = (Device)context.Items["device"]!;
    var configuration = await repository.GetEffectivePolicyAsync(device.Id, ct);
    return configuration is null ? Results.NotFound() : Results.Ok(configuration);
});
authenticatedAgents.MapPost("/credentials/rotate", async (RotateDeviceCredentialBody body, HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    if (body.NewDeviceToken is null || body.NewDeviceToken.Length is < 40 or > 100 || body.NewDeviceToken.Any(char.IsControl))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["newDeviceToken"] = ["Nowe poświadczenie urządzenia jest nieprawidłowe."] });
    var device = (Device)context.Items["device"]!;
    var current = context.Request.Headers.Authorization.ToString()[7..];
    var staged = await repository.StageDeviceCredentialRotationAsync(device.Id, HashToken(current), HashToken(body.NewDeviceToken), ct);
    if (!staged) return Results.Conflict(new { error = "Nie można przygotować zmiany poświadczenia urządzenia." });
    await repository.RecordAdminActionAsync($"device:{device.Id}", "device.credential_rotation_staged", device.Id, DateTimeOffset.UtcNow, ct);
    return Results.NoContent();
});
authenticatedAgents.MapPost("/analyze", async (AgentAnalysisBody body, HttpContext context, IServerStore repository, AnalysisOrchestrator analysis, CancellationToken ct) =>
{
    var device = (Device)context.Items["device"]!;
    if (body.Text is null || body.Text.Length > Sentinel.Core.Context.PrivacyFilter.MaximumTextLength ||
        body.Text.Length == 0 && string.IsNullOrWhiteSpace(body.TargetUrl) || body.TargetUrl?.Length > 4096 ||
        body.TargetUrl?.Any(char.IsControl) == true ||
        body.Application is null || body.Application.Length is 0 or > 100 || body.Application.Any(char.IsControl) ||
        !body.ContextSharingConfirmed)
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["analysis"] = ["Wymagany jest tekst do 16 000 znaków lub adres celu, nazwa aplikacji i jawne potwierdzenie przesłania kontekstu."] });
    var policy = await repository.GetEffectivePolicyAsync(device.Id, ct);
    if (policy?.Effective.IncludeContext != true)
        return Results.Problem(title: "Polityka nie zezwala na analizę serwerową", detail: "Administrator musi jawnie włączyć udostępnianie kontekstu dla urządzenia.", statusCode: StatusCodes.Status403Forbidden);
    if (policy.Effective.AiProvider is not ("disabled" or "ollama"))
        return Results.Problem(title: "Provider AI nie jest obsługiwany przez tę politykę.", statusCode: StatusCodes.Status409Conflict);
    var config = await repository.ReadServerAIConfigurationAsync(ct);
    var useModel = config.Enabled && policy.Effective.AiProvider == "ollama";
    var result = await analysis.AnalyzeAsync(new AnalysisContext(body.Application, body.Text, DateTimeOffset.UtcNow,
        string.IsNullOrWhiteSpace(body.TargetUrl) ? null : new NavigationSignal(body.TargetUrl)), useModel, config.Endpoint, config.Model,
        embeddingModel: null, timeoutSeconds: config.TimeoutSeconds, cancellationToken: ct,
        useKnowledge: policy.Effective.RagEnabled == true);
    return Results.Ok(new { result.Category, result.Risk, result.Indicators, result.Uncertainties, result.Recommendations, result.Explanation,
        modelEnabled = useModel, contextPersisted = false });
});
authenticatedAgents.MapPost("/heartbeat", async (HeartbeatBody? body, HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    var device = (Device)context.Items["device"]!;
    var error = body?.LastError;
    if (error is not null && error is not ("local_store" or "sync_failed" or "configuration_invalid" or "client_update"))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["lastError"] = ["Dozwolone są wyłącznie kody: local_store, sync_failed, configuration_invalid, client_update."] });
    var revisions = new[] { body?.GlobalPolicyVersion, body?.GroupPolicyVersion, body?.DevicePolicyVersion };
    AppliedPolicyRevision? appliedPolicy = null;
    if (revisions.Any(value => value.HasValue))
    {
        if (revisions.Any(value => value is null or < 0))
            return Results.ValidationProblem(new Dictionary<string, string[]> { ["policyVersion"] = ["Wszystkie trzy nieujemne wersje polityki muszą być podane razem."] });
        appliedPolicy = new(body!.GlobalPolicyVersion!.Value, body.GroupPolicyVersion!.Value, body.DevicePolicyVersion!.Value);
    }
    await repository.HeartbeatAsync(device.Id, DateTimeOffset.UtcNow, error, ct, appliedPolicy);
    return Results.NoContent();
});
authenticatedAgents.MapPost("/events", async (EnterpriseEventBatchV1? body, HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    if (body?.Events is not { Count: >= 1 and <= 100 } events)
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["events"] = ["Batch musi zawierać 1–100 zdarzeń."] });
    var now = DateTimeOffset.UtcNow;
    foreach (var item in events)
    {
        var error = SecurityEventRules.Validate(item, now);
        if (error is not null) return Results.ValidationProblem(new Dictionary<string, string[]> { ["events"] = [error] });
    }
    var device = (Device)context.Items["device"]!;
    return Results.Ok(await repository.IngestEventsAsync(device.Id, events, now, ct));
});

app.Run();

static string RandomToken(int bytes) => Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
static async Task BootstrapAdministratorAsync()
{
    if (Console.IsInputRedirected)
        throw new InvalidOperationException("Bootstrap wymaga interaktywnego terminala, aby hasło nie trafiło do argumentów ani potoków.");
    var defaultDataDirectory = OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SentinelAI", "Server")
        : Path.Combine("/var/lib", "sentinel-ai", "server");
    var dataDirectory = Environment.GetEnvironmentVariable("Sentinel__DataDirectory") ?? defaultDataDirectory;
    var databasePath = Path.GetFullPath(Path.Combine(dataDirectory, "sentinel-server.db"));
    Console.Write("Nazwa pierwszego administratora: ");
    var username = Console.ReadLine()?.Trim() ?? "";
    if (!IsValidUsername(username)) throw new ArgumentException("Nazwa musi mieć 3–64 znaki: litery ASCII, cyfry, kropka, podkreślenie, @ lub myślnik.");
    var password = ReadHiddenPassword("Hasło (14–128 znaków): ");
    try
    {
        if (!AdminPasswordHasher.IsValid(password)) throw new ArgumentException("Hasło musi mieć 14–128 znaków i nie może zawierać znaków sterujących.");
        var confirmation = ReadHiddenPassword("Powtórz hasło: ");
        if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(confirmation)))
            throw new ArgumentException("Wpisane hasła różnią się.");
        var repository = new SqliteServerStore(databasePath);
        await repository.InitializeAsync();
        var created = await repository.TryBootstrapAdminAsync(NormalizeUsername(username), new AdminPasswordHasher().Hash(password), DateTimeOffset.UtcNow);
        if (!created) throw new InvalidOperationException("Konto administratora już istnieje. Bootstrap nie zmienia istniejących kont.");
        Console.WriteLine("Utworzono pierwsze konto administratora. Hasło nie zostało zapisane w pliku konfiguracyjnym.");
    }
    finally { password = string.Empty; }
}

static string ReadHiddenPassword(string prompt)
{
    Console.Write(prompt);
    var value = new StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter) { Console.WriteLine(); break; }
        if (key.Key == ConsoleKey.Backspace) { if (value.Length > 0) value.Length--; continue; }
        if (!char.IsControl(key.KeyChar) && value.Length < 128) value.Append(key.KeyChar);
    }
    return value.ToString();
}
static string HashToken(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();
static bool IsValidUsername(string? username) => username is { Length: >= 3 and <= 64 } && username.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '@' or '-');
static string NormalizeUsername(string username) => username.Trim().ToLowerInvariant();
static long? GetDatabaseFootprint(string databasePath)
{
    try
    {
        long total = 0;
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            var path = databasePath + suffix;
            if (File.Exists(path)) total = checked(total + new FileInfo(path).Length);
        }
        return total;
    }
    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or OverflowException)
    {
        return null;
    }
}
static async Task<IResult> WritePolicy(PolicyWriteBody body, AdminIdentity identity, IServerStore repository, CancellationToken ct,
    Func<PolicyWrite, string, DateTimeOffset, Task<bool>> write)
{
    if (body.Policy is null || body.ExpectedVersion < 0)
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["policy"] = ["Polityka i nieujemny expectedVersion są wymagane."] });
    var error = PolicyRules.Validate(body.Policy);
    if (error is not null) return Results.ValidationProblem(new Dictionary<string, string[]> { ["policy"] = [error] });
    if (PolicyRules.ExposesContext(body.Policy) &&
        (identity.Role != AdminRole.SystemAdministrator || !body.ConfirmedSensitiveChange))
        return Results.Problem(title: "Zmiana udostępnia kontekst poza urządzeniem.",
            detail: "Wymagane jest konto administratora systemowego oraz jawne potwierdzenie zmiany.", statusCode: StatusCodes.Status403Forbidden);
    var saved = await write(new(body.Policy, body.ExpectedVersion), identity.Username, DateTimeOffset.UtcNow);
    return saved ? Results.NoContent() : Results.Conflict(new { error = "Polityka zmieniła się od czasu odczytu. Pobierz aktualną wersję i ponów zapis." });
}
static Func<EndpointFilterInvocationContext, EndpointFilterDelegate, ValueTask<object?>> AuthenticateAdmin(IServerStore repository) => async (context, next) =>
{
    var header = context.HttpContext.Request.Headers.Authorization.ToString();
    if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return Results.Unauthorized();
    var token = header[7..];
    if (token.Length is < 40 or > 100) return Results.Unauthorized();
    var identity = await repository.AuthenticateAdminSessionAsync(HashToken(token), DateTimeOffset.UtcNow, context.HttpContext.RequestAborted);
    if (identity is null) return Results.Unauthorized();
    context.HttpContext.Items["admin"] = identity;
    return await next(context);
};
static Func<EndpointFilterInvocationContext, EndpointFilterDelegate, ValueTask<object?>> RequireRoles(params AdminRole[] allowed) => async (context, next) =>
{
    if (context.HttpContext.Items["admin"] is not AdminIdentity identity || !allowed.Contains(identity.Role))
        return Results.StatusCode(StatusCodes.Status403Forbidden);
    return await next(context);
};

sealed record CreateInvitationBody(string Group, DateTimeOffset ExpiresAt, int MaximumRegistrations, bool RequiresApproval = false);
sealed record EnrollmentBody(string InvitationCode, string DeviceName, string ClientVersion);
sealed record HeartbeatBody(string? LastError, long? GlobalPolicyVersion = null, long? GroupPolicyVersion = null, long? DevicePolicyVersion = null);
sealed record AdminLoginBody(string Username, string Password);
sealed record CreateAdminBody(string Username, string Password, string Role);
sealed record SetDisabledBody(bool Disabled);
sealed record SetRoleBody(string Role);
sealed record ChangePasswordBody(string CurrentPassword, string NewPassword);
sealed record CreateGroupBody(string Name);
sealed record SetDeviceGroupBody(string GroupId);
sealed record SetDeviceApprovalBody(bool Approved);
sealed record RotateDeviceCredentialBody(string? NewDeviceToken);
sealed record PolicyWriteBody(PolicyDocument? Policy, long ExpectedVersion, bool ConfirmedSensitiveChange = false);
sealed record SetEventStatusBody(string Status);
sealed record ServerAIConfigurationBody(string? Endpoint, string? Model, bool Enabled, int TimeoutSeconds, long ExpectedVersion);
sealed record ServerAITestBody(string? Model);
sealed record AgentAnalysisBody(string? Application, string? Text, string? TargetUrl, bool ContextSharingConfirmed);

public partial class Program;
