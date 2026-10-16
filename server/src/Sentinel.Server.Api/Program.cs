using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Sentinel.Server.Core;
using Sentinel.Server.Infrastructure;

var builder = WebApplication.CreateBuilder(args);
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
var databasePath = Path.GetFullPath(Path.Combine(dataDirectory, "sentinel-server.db"));
var store = new SqliteServerStore(databasePath);
builder.Services.AddSingleton<IServerStore>(store);
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("enrollment", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown", _ => new FixedWindowRateLimiterOptions
        { PermitLimit = 20, Window = TimeSpan.FromMinutes(1), QueueLimit = 0, AutoReplenishment = true }));
});
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 64 * 1024);

var app = builder.Build();
await store.InitializeAsync();
app.Use(async (context, next) =>
{
    var correlationId = context.Request.Headers.TryGetValue("X-Correlation-ID", out var supplied) &&
                        supplied.Count == 1 && Guid.TryParse(supplied[0], out var parsed)
        ? parsed.ToString("D") : Guid.NewGuid().ToString("D");
    context.Response.Headers["X-Correlation-ID"] = correlationId;
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    await next();
});
app.UseRateLimiter();

app.MapGet("/healthz", () => Results.Ok(new { status = "healthy" }));
app.MapGet("/readyz", async (IServerStore repository, CancellationToken ct) =>
    await repository.CheckReadyAsync(ct)
        ? Results.Ok(new { status = "ready", apiVersion = "v1" })
        : Results.Problem(title: "Magazyn danych niedostępny", statusCode: StatusCodes.Status503ServiceUnavailable));

var admin = app.MapGroup("/api/v1/admin");
admin.AddEndpointFilter(async (context, next) =>
{
    var expected = app.Configuration["Sentinel:AdminApiKey"];
    if (string.IsNullOrEmpty(expected) || expected.Length < 32) return Results.Problem(
        title: "Administracja nie została skonfigurowana", statusCode: StatusCodes.Status503ServiceUnavailable);
    var provided = context.HttpContext.Request.Headers.Authorization.ToString();
    if (!provided.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return Results.Unauthorized();
    var actualBytes = SHA256.HashData(Encoding.UTF8.GetBytes(provided[7..]));
    var expectedBytes = SHA256.HashData(Encoding.UTF8.GetBytes(expected));
    return CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes)
        ? await next(context) : Results.Unauthorized();
});
admin.MapPost("/invitations", async (CreateInvitationBody body, IServerStore repository, CancellationToken ct) =>
{
    var now = DateTimeOffset.UtcNow;
    if (string.IsNullOrWhiteSpace(body.Group) || body.Group.Length > 80 || body.Group.Any(char.IsControl) ||
        body.ExpiresAt <= now || body.ExpiresAt > now.AddDays(30) || body.MaximumRegistrations is < 1 or > 1000)
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["invitation"] = ["Podaj grupę, ważność do 30 dni i limit rejestracji 1–1000."] });
    var code = RandomToken(24);
    var invitation = await repository.CreateInvitationAsync(new(body.Group.Trim(), body.ExpiresAt, body.MaximumRegistrations), HashToken(code), ct);
    return Results.Json(new { invitation.Id, invitation.Group,
        invitation.ExpiresAt, invitation.MaximumRegistrations, registrationCode = code }, statusCode: StatusCodes.Status201Created);
});
admin.MapDelete("/invitations/{id}", async (string id, IServerStore repository, CancellationToken ct) =>
    await repository.RevokeInvitationAsync(id, ct) ? Results.NoContent() : Results.NotFound());
admin.MapGet("/devices", async (IServerStore repository, CancellationToken ct) =>
{
    var now = DateTimeOffset.UtcNow; var items = await repository.ListDevicesAsync(ct);
    return Results.Ok(items.Select(device => new { device.Id, device.Name, device.Group, device.ClientVersion,
        device.RegisteredAt, device.LastSeenAt, isOnline = device.LastSeenAt is { } seen && now - seen <= TimeSpan.FromMinutes(2),
        device.Revoked, device.LastError }));
});
admin.MapDelete("/devices/{id}", async (string id, IServerStore repository, CancellationToken ct) =>
    await repository.RevokeDeviceAsync(id, ct) ? Results.NoContent() : Results.NotFound());

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
authenticatedAgents.MapPost("/heartbeat", async (HeartbeatBody? body, HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    var device = (Device)context.Items["device"]!;
    var error = body?.LastError;
    if (error is not null && error is not ("local_store" or "sync_failed" or "configuration_invalid" or "client_update"))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["lastError"] = ["Dozwolone są wyłącznie kody: local_store, sync_failed, configuration_invalid, client_update."] });
    await repository.HeartbeatAsync(device.Id, DateTimeOffset.UtcNow, error, ct);
    return Results.NoContent();
});

app.Run();

static string RandomToken(int bytes) => Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
static string HashToken(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();
sealed record CreateInvitationBody(string Group, DateTimeOffset ExpiresAt, int MaximumRegistrations);
sealed record EnrollmentBody(string InvitationCode, string DeviceName, string ClientVersion);
sealed record HeartbeatBody(string? LastError);

public partial class Program;
