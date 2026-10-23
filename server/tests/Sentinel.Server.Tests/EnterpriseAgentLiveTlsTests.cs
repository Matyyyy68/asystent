using System.Diagnostics;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sentinel.Core;
using Sentinel.Core.Configuration;
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
        var stderrLines = new ConcurrentQueue<string>();
        var stdoutLines = new ConcurrentQueue<string>();
        Process? process = null;

        Process StartServer()
        {
            EnsureTestCertificateIsLoadable(pfxPath, pfxPassword);
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
            instance.StartInfo.Environment["Logging__EventLog__LogLevel__Default"] = "None";
            instance.OutputDataReceived += (_, args) => { if (args.Data is not null) stdoutLines.Enqueue(args.Data); };
            instance.ErrorDataReceived += (_, args) => { if (args.Data is not null) stderrLines.Enqueue(args.Data); };
            Assert.True(instance.Start());
            instance.BeginOutputReadLine();
            instance.BeginErrorReadLine();
            return instance;
        }

        try
        {
            process = StartServer();
            using var handler = new HttpClientHandler
            {
                UseProxy = false,
                ServerCertificateCustomValidationCallback = (_, presented, _, errors) =>
                    presented is not null
                    && presented.GetCertHashString(HashAlgorithmName.SHA256).Equals(certificate.GetCertHashString(HashAlgorithmName.SHA256), StringComparison.OrdinalIgnoreCase)
                    && (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0
                    && presented.NotBefore.ToUniversalTime() <= DateTime.UtcNow
                    && presented.NotAfter.ToUniversalTime() > DateTime.UtcNow,
            };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
            await WaitForReadyAsync(http, server, process, stdoutLines, stderrLines, timeout.Token);

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
            var stoppedProcess = process ?? throw new InvalidOperationException("Live TLS server was not started.");
            stoppedProcess.Kill(entireProcessTree: true);
            await stoppedProcess.WaitForExitAsync(timeout.Token);
            stoppedProcess.Dispose();
            process = null;
            var outage = await Assert.ThrowsAsync<HttpRequestException>(() => agent.SendEventsAsync(
                EnterpriseAgentClient.ValidateServer(server), enrollment.DeviceToken, [item], timeout.Token));
            Assert.NotNull(outage);
            process = StartServer();
            await WaitForReadyAsync(http, server, process, stdoutLines, stderrLines, timeout.Token);
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

    [WindowsDpapiFact]
    public async Task ActiveEngineRetriesQueuedEventsAfterLiveTlsApiReturns()
    {
        var repository = FindRepositoryRoot();
        var configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent?.Name ?? "Release";
        var serverDll = Path.Combine(repository, "server", "src", "Sentinel.Server.Api", "bin", configuration, "net10.0", "Sentinel.Server.Api.dll");
        var engineDll = Path.Combine(repository, "src", "Sentinel.Engine", "bin", "Debug", "net10.0", "Sentinel.Engine.dll");
        Assert.True(File.Exists(serverDll), $"Server API was not built: {serverDll}");
        Assert.True(File.Exists(engineDll), $"Debug Engine was not built: {engineDll}");

        var temp = Path.Combine(Path.GetTempPath(), "sentinel-engine-live-retry-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        var pfxPath = Path.Combine(temp, "loopback.pfx");
        var certificatePath = Path.Combine(temp, "loopback.cer");
        var databasePath = Path.Combine(temp, "server-database");
        var clientRoot = Path.Combine(temp, "client");
        var downloads = Path.Combine(temp, "Downloads");
        Directory.CreateDirectory(downloads);
        var pfxPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        using var certificate = CreateLoopbackCertificate();
        await File.WriteAllBytesAsync(pfxPath, certificate.Export(X509ContentType.Pfx, pfxPassword));
        await File.WriteAllBytesAsync(certificatePath, certificate.Export(X509ContentType.Cert));

        using var portLease = new TcpListener(IPAddress.Loopback, 0);
        portLease.Start();
        var port = ((IPEndPoint)portLease.LocalEndpoint).Port;
        portLease.Stop();
        var server = $"https://127.0.0.1:{port}";
        const string adminUsername = "engine-retry-admin";
        const string adminPassword = "Engine-retry-admin-password-42!";
        var stderrLines = new ConcurrentQueue<string>();
        var stdoutLines = new ConcurrentQueue<string>();
        Process? apiProcess = null;

        Process StartServer()
        {
            EnsureTestCertificateIsLoadable(pfxPath, pfxPassword);
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
            instance.StartInfo.Environment["Logging__EventLog__LogLevel__Default"] = "None";
            instance.OutputDataReceived += (_, args) => { if (args.Data is not null) stdoutLines.Enqueue(args.Data); };
            instance.ErrorDataReceived += (_, args) => { if (args.Data is not null) stderrLines.Enqueue(args.Data); };
            Assert.True(instance.Start());
            instance.BeginOutputReadLine();
            instance.BeginErrorReadLine();
            return instance;
        }

        try
        {
            apiProcess = StartServer();
            using var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                UseProxy = false,
                ServerCertificateCustomValidationCallback = (_, presented, _, errors) =>
                    presented is not null
                    && presented.GetCertHashString(HashAlgorithmName.SHA256).Equals(certificate.GetCertHashString(HashAlgorithmName.SHA256), StringComparison.OrdinalIgnoreCase)
                    && (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0
                    && presented.NotBefore.ToUniversalTime() <= DateTime.UtcNow
                    && presented.NotAfter.ToUniversalTime() > DateTime.UtcNow,
            };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
            // This scenario deliberately waits for the configured 30-second retry interval after
            // restarting the API. Hosted Windows runners can spend over 30 seconds on the setup
            // and TLS enrollment before reaching that wait, so keep the whole live test budget
            // comfortably above the retry window.
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            await WaitForReadyAsync(http, server, apiProcess, stdoutLines, stderrLines, timeout.Token);

            var adminLogin = await SendJsonAsync(http, server, "/api/v1/admin/auth/login", HttpMethod.Post,
                new { username = adminUsername, password = adminPassword }, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            var adminToken = adminLogin!["accessToken"]!.GetValue<string>();
            var globalPolicy = await SendJsonAsync(http, server, "/api/v1/admin/policies/global", HttpMethod.Get,
                token: adminToken, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            var globalVersion = globalPolicy!["version"]!.GetValue<long>();
            await SendJsonAsync(http, server, "/api/v1/admin/policies/global", HttpMethod.Put,
                new { policy = new { syncIntervalSeconds = 30 }, expectedVersion = globalVersion }, adminToken, HttpStatusCode.NoContent, timeout.Token);
            var group = await SendJsonAsync(http, server, "/api/v1/admin/groups", HttpMethod.Post,
                new { name = "Engine Retry E2E" }, adminToken, HttpStatusCode.Created, timeout.Token);
            var invitation = await SendJsonAsync(http, server, "/api/v1/admin/invitations", HttpMethod.Post,
                new { group = group!["name"]!.GetValue<string>(), expiresAt = DateTimeOffset.UtcNow.AddMinutes(5), maximumRegistrations = 1, requiresApproval = true },
                adminToken, HttpStatusCode.Created, timeout.Token);
            var agent = new EnterpriseAgentClient(http);
            var enrollment = await agent.EnrollAsync(EnterpriseAgentClient.ValidateServer(server),
                invitation!["registrationCode"]!.GetValue<string>(), "ENGINE-RETRY-DEVICE",
                typeof(EnterpriseAgentClient).Assembly.GetName().Version?.ToString(3) ?? "0.0.0", timeout.Token);
            await SendJsonAsync(http, server, $"/api/v1/admin/devices/{Uri.EscapeDataString(enrollment.DeviceId)}/approval",
                HttpMethod.Put, new { approved = true }, adminToken, HttpStatusCode.NoContent, timeout.Token);

            var clientDatabase = Path.Combine(clientRoot, "data");
            var localStore = new LocalStore(clientDatabase);
            await localStore.InitializeAsync(new InstalledProductProfile(ProductVariant.EnterpriseClient, server, ShareSecurityMetadata: true));
            var eventId = Guid.NewGuid();
            var occurredAt = DateTimeOffset.UtcNow;
            await localStore.AddLocalOnlyAsync(new SecurityEvent(0, occurredAt, RiskLevel.High, "Syntetyczne wykrycie", "Active Engine retry",
                "sekret-treści-do-zachowania-lokalnie", "wyjaśnienie nie może trafić do serwera", EventStatus.New,
                EventId: eventId, Source: "manual-analysis", RuleVersion: "2026.10.1"));
            await new WindowsDpapiCredentialStore(clientDatabase).WriteAsync(enrollment.DeviceToken);

            await using var engine = await EngineProcess.StartAsync(engineDll, repository, clientRoot, downloads, certificatePath);
            using var initialSync = await engine.CallAsync("enterpriseSync");
            Assert.Equal(0, initialSync.RootElement.GetProperty("result").GetProperty("synchronized").GetInt32());
            Assert.Equal(30, initialSync.RootElement.GetProperty("result").GetProperty("syncIntervalSeconds").GetInt32());
            Assert.True(await localStore.EnqueueEnterpriseEventAsync(new PendingEnterpriseEvent(eventId, occurredAt, "url", 3,
                "url.suspicious_domain", "manual-analysis", "2026.10.1")));
            apiProcess.Kill(entireProcessTree: true);
            await apiProcess.WaitForExitAsync(timeout.Token);
            apiProcess.Dispose();
            apiProcess = null;

            using var offlineSync = await engine.CallAsync("enterpriseSync");
            Assert.Equal("sync_failed", offlineSync.RootElement.GetProperty("result").GetProperty("reason").GetString());
            using var offlineStatus = await engine.CallAsync("status");
            Assert.Equal(1, offlineStatus.RootElement.GetProperty("result").GetProperty("enterprise").GetProperty("queuedEvents").GetInt32());

            apiProcess = StartServer();
            await WaitForReadyAsync(http, server, apiProcess, stdoutLines, stderrLines, timeout.Token);
            await Task.Delay(TimeSpan.FromSeconds(31), timeout.Token);
            using var automaticRetry = await engine.CallAsync("collect");
            Assert.Equal(1, automaticRetry.RootElement.GetProperty("result").GetProperty("enterpriseSync").GetProperty("synchronized").GetInt32());
            using var syncedStatus = await engine.CallAsync("status");
            Assert.Equal(0, syncedStatus.RootElement.GetProperty("result").GetProperty("enterprise").GetProperty("queuedEvents").GetInt32());

            var refreshedLogin = await SendJsonAsync(http, server, "/api/v1/admin/auth/login", HttpMethod.Post,
                new { username = adminUsername, password = adminPassword }, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            var events = await SendJsonAsync(http, server, $"/api/v1/admin/events?deviceId={Uri.EscapeDataString(enrollment.DeviceId)}",
                HttpMethod.Get, token: refreshedLogin!["accessToken"]!.GetValue<string>(), expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            Assert.NotNull(events);
            Assert.Contains(eventId.ToString(), events!.ToJsonString(), StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("sekret-treści-do-zachowania-lokalnie", events.ToJsonString());
            Assert.DoesNotContain("wyjaśnienie nie może trafić do serwera", events.ToJsonString());
        }
        finally
        {
            if (apiProcess is not null && !apiProcess.HasExited)
            {
                apiProcess.Kill(entireProcessTree: true);
                await apiProcess.WaitForExitAsync();
            }
            apiProcess?.Dispose();
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

    private static void EnsureTestCertificateIsLoadable(string path, string password)
    {
        if (!File.Exists(path))
            throw new InvalidOperationException("The temporary TLS certificate file does not exist; the API child process was not started.");

        try
        {
            using var imported = X509CertificateLoader.LoadPkcs12FromFile(path, password, X509KeyStorageFlags.DefaultKeySet);
            if (!imported.HasPrivateKey)
                throw new InvalidOperationException("The temporary TLS certificate has no private key; the API child process was not started.");
        }
        catch (CryptographicException exception)
        {
            throw new InvalidOperationException("The temporary TLS certificate cannot be imported in the test process; the API child process was not started.", exception);
        }
    }

    private static async Task WaitForReadyAsync(HttpClient http, string server, Process process,
        ConcurrentQueue<string> stdout, ConcurrentQueue<string> stderr, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            if (process.HasExited) throw new InvalidOperationException("Live TLS server exited before readiness. stdout: " + string.Join(Environment.NewLine, stdout) + " stderr: " + string.Join(Environment.NewLine, stderr));
            try
            {
                using var response = await http.GetAsync(server + "/readyz", cancellationToken);
                if (response.IsSuccessStatusCode) return;
            }
            catch (TaskCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException("Live TLS server did not become ready. stdout: " + string.Join(Environment.NewLine, stdout) + " stderr: " + string.Join(Environment.NewLine, stderr));
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

    private sealed class WindowsDpapiFactAttribute : FactAttribute
    {
        public WindowsDpapiFactAttribute()
        {
            if (!OperatingSystem.IsWindows()) Skip = "Active Engine retry requires Windows DPAPI.";
            else
            {
                try
                {
                    var directory = Path.Combine(Path.GetTempPath(), "sentinel-enterprise-dpapi-probe-" + Guid.NewGuid().ToString("N"));
                    try { new WindowsDpapiCredentialStore(directory).WriteAsync("dpapi-probe-0123456789012345678901234567890123456789").GetAwaiter().GetResult(); }
                    finally { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }
                }
                catch (CryptographicException) { Skip = "Active Engine retry requires an available current-user DPAPI profile."; }
            }
        }
    }

    private sealed class EngineProcess(Process process, Task<string> stderr) : IAsyncDisposable
    {
        private readonly StreamWriter input = process.StandardInput;
        private readonly StreamReader output = process.StandardOutput;
        private int requestId;

        public static Task<EngineProcess> StartAsync(string engineDll, string repository, string root, string downloads, string testCertificatePath)
        {
            var start = new ProcessStartInfo("dotnet")
            {
                Arguments = $"\"{engineDll}\"", WorkingDirectory = repository, UseShellExecute = false,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true
            };
            start.Environment["SENTINEL_DATA_ROOT"] = root;
            start.Environment["SENTINEL_DOWNLOADS_PATH"] = downloads;
            start.Environment["SENTINEL_TEST_TLS_CERT_PATH"] = testCertificatePath;
            var child = Process.Start(start) ?? throw new IOException("Could not start Sentinel Engine test process.");
            return Task.FromResult(new EngineProcess(child, child.StandardError.ReadToEndAsync()));
        }

        public async Task<JsonDocument> CallAsync(string method)
        {
            var id = Interlocked.Increment(ref requestId).ToString(System.Globalization.CultureInfo.InvariantCulture);
            await input.WriteLineAsync(JsonSerializer.Serialize(new { id, version = 1, method }));
            await input.FlushAsync();
            var line = await output.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20));
            if (line is null) throw new InvalidOperationException("Engine exited before replying: " + await stderr);
            var response = JsonDocument.Parse(line);
            Assert.Equal(id, response.RootElement.GetProperty("id").GetString());
            Assert.True(response.RootElement.GetProperty("ok").GetBoolean(), response.RootElement.TryGetProperty("error", out var error) ? error.GetString() : line);
            return response;
        }

        public async ValueTask DisposeAsync()
        {
            input.Close();
            try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (TimeoutException) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); }
            if (process.ExitCode != 0) throw new InvalidOperationException("Engine test process failed: " + await stderr);
            process.Dispose();
        }
    }

    private static string FindRepositoryRoot()
    {
        for (var current = new DirectoryInfo(AppContext.BaseDirectory); current is not null; current = current.Parent)
            if (File.Exists(Path.Combine(current.FullName, "eng", "ProductVersion.props"))) return current.FullName;
        throw new DirectoryNotFoundException("Could not find repository root from the test output directory.");
    }
}
