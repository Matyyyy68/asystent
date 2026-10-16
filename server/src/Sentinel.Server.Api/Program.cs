using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.Data.Sqlite;
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
var passwordHasher = new AdminPasswordHasher();
var configuredBootstrapUsername = builder.Configuration["Sentinel:BootstrapAdminUsername"];
var configuredBootstrapPassword = builder.Configuration["Sentinel:BootstrapAdminPassword"];
var dummyPasswordHash = passwordHasher.Hash(RandomToken(32));
builder.Services.AddSingleton<IServerStore>(store);
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
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 64 * 1024);

var app = builder.Build();
await store.InitializeAsync();
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
    if (context.Request.Path.StartsWithSegments("/api/v1/admin/auth")) context.Response.Headers.CacheControl = "no-store";
    await next();
});
app.UseRateLimiter();

app.MapGet("/healthz", () => Results.Ok(new { status = "healthy" }));
app.MapGet("/readyz", async (IServerStore repository, CancellationToken ct) =>
    await repository.CheckReadyAsync(ct)
        ? Results.Ok(new { status = "ready", apiVersion = "v1" })
        : Results.Problem(title: "Magazyn danych niedostępny", statusCode: StatusCodes.Status503ServiceUnavailable));

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
    return Results.Ok(items.Select(device => new { device.Id, device.Name, device.Group, device.ClientVersion,
        device.RegisteredAt, device.LastSeenAt, isOnline = device.LastSeenAt is { } seen && now - seen <= TimeSpan.FromMinutes(2),
        device.Revoked, device.LastError }));
});

securityAdmins.MapPost("/invitations", async (CreateInvitationBody body, HttpContext context, IServerStore repository, CancellationToken ct) =>
{
    var now = DateTimeOffset.UtcNow;
    if (string.IsNullOrWhiteSpace(body.Group) || body.Group.Length > 80 || body.Group.Any(char.IsControl) ||
        body.ExpiresAt <= now || body.ExpiresAt > now.AddDays(30) || body.MaximumRegistrations is < 1 or > 1000)
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["invitation"] = ["Podaj grupę, ważność do 30 dni i limit rejestracji 1–1000."] });
    var code = RandomToken(24);
    var administrator = (AdminIdentity)context.Items["admin"]!;
    var invitation = await repository.CreateInvitationAsync(new(body.Group.Trim(), body.ExpiresAt, body.MaximumRegistrations), HashToken(code), administrator.Username, now, ct);
    return Results.Json(new { invitation.Id, invitation.Group,
        invitation.ExpiresAt, invitation.MaximumRegistrations, registrationCode = code }, statusCode: StatusCodes.Status201Created);
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
securityAdmins.MapGet("/audit", async (int? limit, IServerStore repository, CancellationToken ct) => Results.Ok(await repository.ReadAuditAsync(limit ?? 100, ct)));

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
static bool IsValidUsername(string? username) => username is { Length: >= 3 and <= 64 } && username.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '@' or '-');
static string NormalizeUsername(string username) => username.Trim().ToLowerInvariant();
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

sealed record CreateInvitationBody(string Group, DateTimeOffset ExpiresAt, int MaximumRegistrations);
sealed record EnrollmentBody(string InvitationCode, string DeviceName, string ClientVersion);
sealed record HeartbeatBody(string? LastError);
sealed record AdminLoginBody(string Username, string Password);
sealed record CreateAdminBody(string Username, string Password, string Role);
sealed record SetDisabledBody(bool Disabled);
sealed record SetRoleBody(string Role);
sealed record ChangePasswordBody(string CurrentPassword, string NewPassword);

public partial class Program;
