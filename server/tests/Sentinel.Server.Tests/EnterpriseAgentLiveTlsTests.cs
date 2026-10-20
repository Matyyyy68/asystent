using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Sentinel.Core.Enterprise;
using Xunit;

namespace Sentinel.Server.Tests;

public sealed class EnterpriseAgentLiveTlsTests
{
    [Fact]
    public async Task AgentEnrollsSyncsRotatesAndIsRevokedAgainstLiveTlsServer()
    {
        var repository = FindRepositoryRoot();
        var configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent?.Name ?? "Release";
        var serverDll = Path.Combine(repository, "server", "src", "Sentinel.Server.Api", "bin", configuration, "net10.0", "Sentinel.Server.Api.dll");
        Assert.True(File.Exists(serverDll), $"Server API was not built: {serverDll}");

        var temp = Path.Combine(Path.GetTempPath(), "sentinel-agent-tls-e2e-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        var pfxPath = Path.Combine(temp, "loopback.pfx");
        var databasePath = Path.Combine(temp, "database");
        var pfxPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        using var certificate = CreateLoopbackCertificate();
        await File.WriteAllBytesAsync(pfxPath, certificate.Export(X509ContentType.Pfx, pfxPassword));

        using var portLease = new TcpListener(IPAddress.Loopback, 0);
        portLease.Start();
        var port = ((IPEndPoint)portLease.LocalEndpoint).Port;
        portLease.Stop();
        var server = $"https://127.0.0.1:{port}";
        const string adminUsername = "tls-e2e-admin";
        const string adminPassword = "Tls-e2e-admin-password-42!";
        Task<string> stderrTask = Task.FromResult(string.Empty);
        Task<string> stdoutTask = Task.FromResult(string.Empty);
        Process? process = null;

        Process StartServer()
        {
            var instance = new Process
            {
                StartInfo = new ProcessStartInfo("dotnet")
                {
                    FileName = "dotnet",
                    Arguments = $"\"{serverDll}\"",
                    WorkingDirectory = repository,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                }
            };
            instance.StartInfo.Environment["ASPNETCORE_URLS"] = server;
            instance.StartInfo.Environment["ASPNETCORE_Kestrel__Certificates__Default__Path"] = pfxPath;
            instance.StartInfo.Environment["ASPNETCORE_Kestrel__Certificates__Default__Password"] = pfxPassword;
            instance.StartInfo.Environment["Sentinel__DataDirectory"] = databasePath;
            instance.StartInfo.Environment["Sentinel__BootstrapAdminUsername"] = adminUsername;
            instance.StartInfo.Environment["Sentinel__BootstrapAdminPassword"] = adminPassword;
            Assert.True(instance.Start());
            stdoutTask = instance.StandardOutput.ReadToEndAsync();
            stderrTask = instance.StandardError.ReadToEndAsync();
            return instance;
        }

        try
        {
            process = StartServer();
            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, presented, _, errors) =>
                    presented is not null
                    && presented.GetCertHashString(HashAlgorithmName.SHA256).Equals(certificate.GetCertHashString(HashAlgorithmName.SHA256), StringComparison.OrdinalIgnoreCase)
                    && (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0
                    && presented.NotBefore.ToUniversalTime() <= DateTime.UtcNow
                    && presented.NotAfter.ToUniversalTime() > DateTime.UtcNow,
            };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
            await WaitForReadyAsync(http, server, process, stdoutTask, stderrTask, timeout.Token);

            var adminLogin = await SendJsonAsync(http, server, "/api/v1/admin/auth/login", HttpMethod.Post,
                new { username = adminUsername, password = adminPassword }, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            var adminToken = adminLogin!["accessToken"]!.GetValue<string>();
            var group = await SendJsonAsync(http, server, "/api/v1/admin/groups", HttpMethod.Post,
                new { name = "TLS E2E" }, adminToken, HttpStatusCode.Created, timeout.Token);
            var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);
            var invitation = await SendJsonAsync(http, server, "/api/v1/admin/invitations", HttpMethod.Post,
                new { group = group!["name"]!.GetValue<string>(), expiresAt, maximumRegistrations = 1, requiresApproval = true },
                adminToken, HttpStatusCode.Created, timeout.Token);

            var agent = new EnterpriseAgentClient(http);
            var enrollment = await agent.EnrollAsync(EnterpriseAgentClient.ValidateServer(server),
                invitation!["registrationCode"]!.GetValue<string>(), "TLS-E2E-DEVICE",
                typeof(EnterpriseAgentClient).Assembly.GetName().Version?.ToString(3) ?? "0.0.0", timeout.Token);
            var approval = await SendJsonAsync(http, server, $"/api/v1/admin/devices/{Uri.EscapeDataString(enrollment.DeviceId)}/approval",
                HttpMethod.Put, new { approved = true }, adminToken, HttpStatusCode.NoContent, timeout.Token);
            Assert.Null(approval);

            using (var configurationResponse = await agent.ReadConfigurationAsync(EnterpriseAgentClient.ValidateServer(server), enrollment.DeviceToken, timeout.Token))
                Assert.Equal("local", configurationResponse.RootElement.GetProperty("effective").GetProperty("analysisMode").GetString());
            await agent.SendHeartbeatAsync(EnterpriseAgentClient.ValidateServer(server), enrollment.DeviceToken, cancellationToken: timeout.Token);

            var item = new PendingEnterpriseEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, "url", 3, "url.suspicious_domain",
                "manual-analysis", "2026.10.1");
            // Keep the batch locally through an outage, restart the API on the same TLS identity,
            // then retry. The test client pins only this temporary leaf certificate in memory;
            // Windows certificate stores and system trust are never changed.
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync(timeout.Token);
            process.Dispose();
            var outage = await Assert.ThrowsAsync<HttpRequestException>(() => agent.SendEventsAsync(
                EnterpriseAgentClient.ValidateServer(server), enrollment.DeviceToken, [item], timeout.Token));
            Assert.NotNull(outage);
            process = StartServer();
            await WaitForReadyAsync(http, server, process, stdoutTask, stderrTask, timeout.Token);
            var firstBatch = await agent.SendEventsAsync(EnterpriseAgentClient.ValidateServer(server), enrollment.DeviceToken, [item], timeout.Token);
            var replayedBatch = await agent.SendEventsAsync(EnterpriseAgentClient.ValidateServer(server), enrollment.DeviceToken, [item], timeout.Token);
            Assert.Equal(1, firstBatch.Accepted);
            Assert.Equal(0, firstBatch.Duplicates);
            Assert.Equal(0, replayedBatch.Accepted);
            Assert.Equal(1, replayedBatch.Duplicates);

            var credentialStore = new InMemoryCredentialStore(enrollment.DeviceToken);
            await new EnterpriseCredentialRotator(agent, credentialStore).RotateAsync(EnterpriseAgentClient.ValidateServer(server), timeout.Token);
            var rotatedToken = credentialStore.Value!;
            // The rotator promotes its staged candidate on first use; the previous credential must then fail.
            var retiredCredential = await Assert.ThrowsAsync<HttpRequestException>(() => agent.SendHeartbeatAsync(
                EnterpriseAgentClient.ValidateServer(server), enrollment.DeviceToken, cancellationToken: timeout.Token));
            Assert.Equal(HttpStatusCode.Unauthorized, retiredCredential.StatusCode);

            var revoke = await SendJsonAsync(http, server, $"/api/v1/admin/devices/{Uri.EscapeDataString(enrollment.DeviceId)}",
                HttpMethod.Delete, token: adminToken, expected: HttpStatusCode.NoContent, cancellationToken: timeout.Token);
            Assert.Null(revoke);
            var revoked = await Assert.ThrowsAsync<HttpRequestException>(() => agent.SendHeartbeatAsync(EnterpriseAgentClient.ValidateServer(server), rotatedToken, cancellationToken: timeout.Token));
            Assert.Equal(HttpStatusCode.Unauthorized, revoked.StatusCode);
        }
        finally
        {
            if (process is not null && !process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
            process?.Dispose();
            try { Directory.Delete(temp, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    private static X509Certificate2 CreateLoopbackCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=127.0.0.1", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var usages = new OidCollection { new("1.3.6.1.5.5.7.3.1") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, false));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
    }

    private static async Task WaitForReadyAsync(HttpClient http, string server, Process process, Task<string> stdout, Task<string> stderr, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            if (process.HasExited) throw new InvalidOperationException("Live TLS server exited before readiness. stdout: " + await stdout + " stderr: " + await stderr);
            try
            {
                using var response = await http.GetAsync(server + "/readyz", cancellationToken);
                if (response.IsSuccessStatusCode) return;
            }
            catch (HttpRequestException) { }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested) { }
            await Task.Delay(100, cancellationToken);
        }
        throw new TimeoutException("Live TLS server did not become ready.");
    }

    private static async Task<JsonNode?> SendJsonAsync(HttpClient http, string server, string path, HttpMethod method,
        object? body = null, string? token = null, HttpStatusCode expected = HttpStatusCode.OK, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(method, server + path);
        if (body is not null) request.Content = JsonContent.Create(body);
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await http.SendAsync(request, cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        Assert.True(response.StatusCode == expected,
            $"{method} {path}: expected {(int)expected}, received {(int)response.StatusCode}. {content}");
        return string.IsNullOrWhiteSpace(content) ? null : JsonNode.Parse(content);
    }

    private sealed class InMemoryCredentialStore(string? value) : IDeviceCredentialStore
    {
        public string? Value { get; private set; } = value;
        public Task<string?> ReadAsync(CancellationToken cancellationToken = default) => Task.FromResult(Value);
        public Task WriteAsync(string token, CancellationToken cancellationToken = default) { Value = token; return Task.CompletedTask; }
        public Task DeleteAsync(CancellationToken cancellationToken = default) { Value = null; return Task.CompletedTask; }
    }

    private static string FindRepositoryRoot()
    {
        for (var current = new DirectoryInfo(AppContext.BaseDirectory); current is not null; current = current.Parent)
            if (File.Exists(Path.Combine(current.FullName, "eng", "ProductVersion.props"))) return current.FullName;
        throw new DirectoryNotFoundException("Could not find repository root from the test output directory.");
    }
}
