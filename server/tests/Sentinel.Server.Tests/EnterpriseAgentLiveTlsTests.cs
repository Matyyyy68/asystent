using System.Diagnostics;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using UglyToad.PdfPig.Content;
using UglyToad.PdfPig.Core;
using UglyToad.PdfPig.Fonts.Standard14Fonts;
using UglyToad.PdfPig.Writer;
using Sentinel.Core;
using Sentinel.Core.Configuration;
using Sentinel.Core.Enterprise;
using Xunit;

namespace Sentinel.Server.Tests;

public sealed class EnterpriseAgentLiveTlsTests
{
    [Fact]
    public async Task AdminCanImportAndSearchTextFromPdfOverLoopback()
    {
        await using var embedding = new OllamaEmbeddingFixture();
        var repository = FindRepositoryRoot();
        var configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent?.Name ?? "Release";
        var serverDll = Path.Combine(repository, "server", "src", "Sentinel.Server.Api", "bin", configuration, "net10.0", "Sentinel.Server.Api.dll");
        Assert.True(File.Exists(serverDll), $"Server API was not built: {serverDll}");

        var temp = Path.Combine(Path.GetTempPath(), "sentinel-pdf-upload-e2e-" + Guid.NewGuid().ToString("N"));
        var databasePath = Path.Combine(temp, "database");
        Directory.CreateDirectory(temp);
        using var portLease = new TcpListener(IPAddress.Loopback, 0);
        portLease.Start();
        var port = ((IPEndPoint)portLease.LocalEndpoint).Port;
        portLease.Stop();
        var server = $"http://127.0.0.1:{port}";
        const string adminUsername = "pdf-e2e-admin";
        const string adminPassword = "Pdf-e2e-admin-password-42!";
        var stdoutLines = new ConcurrentQueue<string>();
        var stderrLines = new ConcurrentQueue<string>();
        Process? process = null;

        try
        {
            var startInfo = new ProcessStartInfo("dotnet")
            {
                FileName = "dotnet",
                Arguments = $"\"{serverDll}\"",
                WorkingDirectory = repository,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            startInfo.Environment["ASPNETCORE_URLS"] = server;
            startInfo.Environment["Sentinel__DataDirectory"] = databasePath;
            startInfo.Environment["Sentinel__BootstrapAdminUsername"] = adminUsername;
            startInfo.Environment["Sentinel__BootstrapAdminPassword"] = adminPassword;
            startInfo.Environment["Logging__EventLog__LogLevel__Default"] = "None";
            process = new Process { StartInfo = startInfo };
            process.OutputDataReceived += (_, args) => { if (args.Data is not null) stdoutLines.Enqueue(args.Data); };
            process.ErrorDataReceived += (_, args) => { if (args.Data is not null) stderrLines.Enqueue(args.Data); };
            Assert.True(process.Start());
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            using var http = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(15) };
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
            await WaitForReadyAsync(http, server, process, stdoutLines, stderrLines, timeout.Token);
            var login = await SendJsonAsync(http, server, "/api/v1/admin/auth/login", HttpMethod.Post,
                new { username = adminUsername, password = adminPassword }, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            var adminToken = login!["accessToken"]!.GetValue<string>();
            await SendJsonAsync(http, server, "/api/v1/admin/users", HttpMethod.Post,
                new { username = "readonly-e2e", password = "Read-only-e2e-password-42!", role = "ReadOnly" },
                adminToken, HttpStatusCode.Created, timeout.Token);
            var readOnlyLogin = await SendJsonAsync(http, server, "/api/v1/admin/auth/login", HttpMethod.Post,
                new { username = "readonly-e2e", password = "Read-only-e2e-password-42!" }, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            var readOnlyToken = readOnlyLogin!["accessToken"]!.GetValue<string>();

            var hostDiagnostics = await SendJsonAsync(http, server, "/api/v1/admin/diagnostics/host", HttpMethod.Get,
                token: adminToken, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            Assert.NotNull(hostDiagnostics!["capturedAtUtc"]);
            Assert.False(string.IsNullOrWhiteSpace(hostDiagnostics["productVersion"]!.GetValue<string>()));
            Assert.True(hostDiagnostics["processUptimeSeconds"]!.GetValue<long>() >= 0);
            Assert.True(hostDiagnostics["processWorkingSetBytes"]!.GetValue<long>() > 0);
            Assert.Equal("available", hostDiagnostics["database"]!["state"]!.GetValue<string>());
            Assert.True(hostDiagnostics["database"]!["totalBytes"]!.GetValue<long>() > 0);
            Assert.Equal(90, hostDiagnostics["deployment"]!["eventRetentionDays"]!.GetValue<int>());
            Assert.True(hostDiagnostics["deployment"]!["customDataDirectory"]!.GetValue<bool>());
            Assert.Equal("http", hostDiagnostics["deployment"]!["listeners"]![0]!["scheme"]!.GetValue<string>());
            Assert.True(hostDiagnostics["deployment"]!["listeners"]![0]!["loopback"]!.GetValue<bool>());
            Assert.DoesNotContain(databasePath, hostDiagnostics.ToJsonString(), StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(adminUsername, hostDiagnostics.ToJsonString(), StringComparison.OrdinalIgnoreCase);
            await SendJsonAsync(http, server, "/api/v1/admin/diagnostics/host", HttpMethod.Get,
                token: readOnlyToken, expected: HttpStatusCode.Forbidden, cancellationToken: timeout.Token);

            var builder = new PdfDocumentBuilder();
            var page = builder.AddPage(PageSize.A4);
            var font = builder.AddStandard14Font(Standard14Font.Helvetica);
            page.AddText("Enterprise payment security, company policy insists checking details", 12, new PdfPoint(25, 700), font);
            using (var upload = new HttpRequestMessage(HttpMethod.Post, new Uri(new Uri(server), "/api/v1/admin/knowledge/documents")))
            {
                upload.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
                upload.Headers.Add("X-Sentinel-Filename", "enterprise-e2e.pdf");
                upload.Content = new ByteArrayContent(builder.Build());
                upload.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                using var response = await http.SendAsync(upload, timeout.Token);
                Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            }

            var hits = await SendJsonAsync(http, server,
                "/api/v1/admin/knowledge/search?query=payment&limit=5",
                HttpMethod.Get, token: adminToken, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            Assert.Equal("enterprise-e2e.pdf", hits![0]!["sourceName"]!.GetValue<string>());
            Assert.Contains("payment", hits.ToJsonString(), StringComparison.OrdinalIgnoreCase);

            var aiConfiguration = await SendJsonAsync(http, server, "/api/v1/admin/ai/configuration", HttpMethod.Get,
                token: adminToken, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            await SendJsonAsync(http, server, "/api/v1/admin/ai/configuration", HttpMethod.Put,
                new { endpoint = embedding.Endpoint, model = "e2e-embedding", enabled = false, timeoutSeconds = 30,
                    expectedVersion = aiConfiguration!["version"]!.GetValue<long>() },
                adminToken, HttpStatusCode.OK, timeout.Token);
            Assert.Null(await SendJsonAsync(http, server,
                "/api/v1/admin/knowledge/search-semantic?query=payment&limit=5&model=e2e-embedding",
                HttpMethod.Get, token: readOnlyToken, expected: HttpStatusCode.Forbidden, cancellationToken: timeout.Token));
            Assert.Equal(0, embedding.RequestCount); // A read-only user cannot trigger indexing or send KB text to Ollama.
            var semanticHits = await SendJsonAsync(http, server,
                "/api/v1/admin/knowledge/search-semantic?query=payment&limit=5&model=e2e-embedding",
                HttpMethod.Get, token: adminToken, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            Assert.Equal("enterprise-e2e.pdf", semanticHits![0]!["sourceName"]!.GetValue<string>());
            Assert.Equal(2, embedding.RequestCount); // document chunk and query; the vector cache avoids a second document request.
            Assert.Contains(embedding.ReceivedInputs, input => input.Contains("company policy insists", StringComparison.Ordinal));

            var currentAiConfiguration = await SendJsonAsync(http, server, "/api/v1/admin/ai/configuration", HttpMethod.Get,
                token: adminToken, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            await SendJsonAsync(http, server, "/api/v1/admin/ai/configuration", HttpMethod.Put,
                new { endpoint = embedding.Endpoint, model = "e2e-chat", enabled = true, timeoutSeconds = 30,
                    expectedVersion = currentAiConfiguration!["version"]!.GetValue<long>() },
                adminToken, HttpStatusCode.OK, timeout.Token);

            var group = await SendJsonAsync(http, server, "/api/v1/admin/groups", HttpMethod.Post,
                new { name = "Policy E2E" }, adminToken, HttpStatusCode.Created, timeout.Token);
            var invitation = await SendJsonAsync(http, server, "/api/v1/admin/invitations", HttpMethod.Post,
                new { group = group!["name"]!.GetValue<string>(), expiresAt = DateTimeOffset.UtcNow.AddMinutes(5), maximumRegistrations = 1 },
                adminToken, HttpStatusCode.Created, timeout.Token);
            var enrolled = await SendJsonAsync(http, server, "/api/v1/agents/enroll", HttpMethod.Post,
                new { invitationCode = invitation!["registrationCode"]!.GetValue<string>(), deviceName = "POLICY-E2E", clientVersion = "1.2.3" },
                expected: HttpStatusCode.Created, cancellationToken: timeout.Token);
            var deviceToken = enrolled!["deviceToken"]!.GetValue<string>();
            var deviceId = enrolled["deviceId"]!.GetValue<string>();
            await SendJsonAsync(http, server, $"/api/v1/admin/devices/{deviceId}/policy", HttpMethod.Put,
                new { policy = new { analysisMode = "server", includeContext = true, aiProvider = "ollama", ragEnabled = false }, expectedVersion = 0, confirmedSensitiveChange = true },
                adminToken, HttpStatusCode.NoContent, timeout.Token);
            var configurationResponse = await SendJsonAsync(http, server, "/api/v1/agents/configuration", HttpMethod.Get,
                token: deviceToken, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            Assert.Equal("server", configurationResponse!["effective"]!["analysisMode"]!.GetValue<string>());
            Assert.True(configurationResponse["effective"]!["includeContext"]!.GetValue<bool>());
            Assert.False(configurationResponse["effective"]!["ragEnabled"]!.GetValue<bool>());
            const string remoteContext = "SentinelEnterpriseContextMustNotPersist-9F6A13 Please verify payment details.";
            var unconfirmedAnalysis = await SendJsonAsync(http, server, "/api/v1/agents/analyze", HttpMethod.Post,
                new { application = "Synthetic", text = remoteContext, targetUrl = "https://example.test/login", contextSharingConfirmed = false },
                token: deviceToken, expected: HttpStatusCode.BadRequest, cancellationToken: timeout.Token);
            Assert.NotNull(unconfirmedAnalysis);
            var remoteAnalysis = await SendJsonAsync(http, server, "/api/v1/agents/analyze", HttpMethod.Post,
                new { application = "Synthetic", text = remoteContext, targetUrl = "https://example.test/login", contextSharingConfirmed = true },
                token: deviceToken, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            Assert.False(remoteAnalysis!["contextPersisted"]!.GetValue<bool>());
            Assert.True(remoteAnalysis["modelEnabled"]!.GetValue<bool>());
            Assert.DoesNotContain(embedding.ReceivedChatMessages, prompt => prompt.Contains("company policy insists", StringComparison.Ordinal));
            Assert.Equal(1, embedding.ChatRequestCount);
            var urlOnlyAnalysis = await SendJsonAsync(http, server, "/api/v1/agents/analyze", HttpMethod.Post,
                new { application = "Synthetic", text = "", targetUrl = "https://example.test/login", contextSharingConfirmed = true },
                token: deviceToken, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            Assert.False(urlOnlyAnalysis!["contextPersisted"]!.GetValue<bool>());
            Assert.Equal(2, embedding.ChatRequestCount);
            Assert.DoesNotContain(embedding.ReceivedChatMessages, prompt => prompt.Contains("company policy insists", StringComparison.Ordinal));
            var databaseText = string.Concat(Directory.GetFiles(databasePath, "sentinel-server.db*")
                .Select(path => Encoding.UTF8.GetString(File.ReadAllBytes(path))));
            Assert.DoesNotContain(remoteContext, databaseText, StringComparison.Ordinal);
            Assert.DoesNotContain("https://example.test/login", databaseText, StringComparison.Ordinal);
            var globalVersion = configurationResponse!["globalVersion"]!.GetValue<long>();
            var groupVersion = configurationResponse["groupVersion"]!.GetValue<long>();
            var deviceVersion = configurationResponse["deviceVersion"]!.GetValue<long>();
            var heartbeat = new { globalPolicyVersion = globalVersion, groupPolicyVersion = groupVersion, devicePolicyVersion = deviceVersion };
            Assert.Null(await SendJsonAsync(http, server, "/api/v1/agents/heartbeat", HttpMethod.Post, heartbeat,
                token: deviceToken, expected: HttpStatusCode.NoContent, cancellationToken: timeout.Token));
            var devices = await SendJsonAsync(http, server, "/api/v1/admin/devices", HttpMethod.Get,
                token: adminToken, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            var deviceView = devices!.AsArray().Single(item => item!["id"]!.GetValue<string>() == deviceId);
            Assert.True(deviceView!["policyCurrent"]!.GetValue<bool>());
            Assert.Equal(groupVersion, deviceView["appliedPolicy"]!["groupVersion"]!.GetValue<long>());
            var incompleteHeartbeat = await SendJsonAsync(http, server, "/api/v1/agents/heartbeat", HttpMethod.Post,
                new { globalPolicyVersion = globalVersion }, token: deviceToken,
                expected: HttpStatusCode.BadRequest, cancellationToken: timeout.Token);
            Assert.NotNull(incompleteHeartbeat);
            var negativeHeartbeat = await SendJsonAsync(http, server, "/api/v1/agents/heartbeat", HttpMethod.Post,
                new { globalPolicyVersion = -1, groupPolicyVersion = groupVersion, devicePolicyVersion = deviceVersion },
                token: deviceToken, expected: HttpStatusCode.BadRequest, cancellationToken: timeout.Token);
            Assert.NotNull(negativeHeartbeat);
            Assert.Null(await SendJsonAsync(http, server, "/api/v1/agents/heartbeat", HttpMethod.Post,
                heartbeat with { globalPolicyVersion = globalVersion + 1 }, token: deviceToken,
                expected: HttpStatusCode.NoContent, cancellationToken: timeout.Token));
            devices = await SendJsonAsync(http, server, "/api/v1/admin/devices", HttpMethod.Get,
                token: adminToken, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            deviceView = devices!.AsArray().Single(item => item!["id"]!.GetValue<string>() == deviceId);
            Assert.False(deviceView!["policyCurrent"]!.GetValue<bool>());

            await SendJsonAsync(http, server, $"/api/v1/admin/devices/{deviceId}/policy", HttpMethod.Put,
                new { policy = new { analysisMode = "server", includeContext = true, aiProvider = "ollama", ragEnabled = true },
                    expectedVersion = deviceVersion, confirmedSensitiveChange = true },
                adminToken, HttpStatusCode.NoContent, timeout.Token);
            configurationResponse = await SendJsonAsync(http, server, "/api/v1/agents/configuration", HttpMethod.Get,
                token: deviceToken, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            Assert.True(configurationResponse!["effective"]!["ragEnabled"]!.GetValue<bool>());
            var enabledRagAnalysis = await SendJsonAsync(http, server, "/api/v1/agents/analyze", HttpMethod.Post,
                new { application = "Synthetic", text = "Please verify payment details.", targetUrl = "", contextSharingConfirmed = true },
                token: deviceToken, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            Assert.True(enabledRagAnalysis!["modelEnabled"]!.GetValue<bool>());
            Assert.False(enabledRagAnalysis["contextPersisted"]!.GetValue<bool>());
            Assert.Equal(3, embedding.ChatRequestCount);
            Assert.True(embedding.ReceivedChatMessages.Any(
                prompt => prompt.Contains("company policy insists", StringComparison.Ordinal)),
                string.Join("\n---\n", embedding.ReceivedChatMessages));
        }
        finally
        {
            if (process is { HasExited: false })
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
            process?.Dispose();
            try { Directory.Delete(temp, recursive: true); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task AgentEnrollsSyncsRotatesAndIsRevokedAgainstLiveTlsServer()
    {
        var repository = FindRepositoryRoot();
        var configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent?.Name ?? "Release";
        var serverDll = Path.Combine(repository, "server", "src", "Sentinel.Server.Api", "bin", configuration, "net10.0", "Sentinel.Server.Api.dll");
        Assert.True(File.Exists(serverDll), $"Server API was not built: {serverDll}");

        var temp = Path.Combine(Path.GetTempPath(), "sentinel-agent-tls-e2e-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
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
            EnsureTemporaryCertificateFileExists(pfxPath);
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

            var pdfBuilder = new PdfDocumentBuilder();
            var pdfPage = pdfBuilder.AddPage(PageSize.A4);
            var pdfFont = pdfBuilder.AddStandard14Font(Standard14Font.Helvetica);
            pdfPage.AddText("SentinelEnterprisePdfSearchToken", 12, new PdfPoint(25, 700), pdfFont);
            using (var upload = new HttpRequestMessage(HttpMethod.Post, new Uri(new Uri(server), "/api/v1/admin/knowledge/documents")))
            {
                upload.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
                upload.Headers.Add("X-Sentinel-Filename", "enterprise-e2e.pdf");
                upload.Content = new ByteArrayContent(pdfBuilder.Build());
                upload.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                using var uploaded = await http.SendAsync(upload, timeout.Token);
                Assert.Equal(HttpStatusCode.Created, uploaded.StatusCode);
            }
            var pdfHits = await SendJsonAsync(http, server,
                "/api/v1/admin/knowledge/search?query=SentinelEnterprisePdfSearchToken&limit=5",
                HttpMethod.Get, token: adminToken, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            Assert.Contains("enterprise-e2e.pdf", pdfHits!.ToJsonString(), StringComparison.Ordinal);
            Assert.Contains("SentinelEnterprisePdfSearchToken", pdfHits.ToJsonString(), StringComparison.Ordinal);

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

            EnterprisePolicy appliedPolicy;
            using (var configurationResponse = await agent.ReadConfigurationAsync(EnterpriseAgentClient.ValidateServer(server), enrollment.DeviceToken, timeout.Token))
            {
                Assert.Equal("local", configurationResponse.RootElement.GetProperty("effective").GetProperty("analysisMode").GetString());
                appliedPolicy = EnterprisePolicy.Parse(configurationResponse);
            }
            await agent.SendHeartbeatAsync(EnterpriseAgentClient.ValidateServer(server), enrollment.DeviceToken,
                cancellationToken: timeout.Token, appliedPolicy: new EnterprisePolicyRevision(appliedPolicy.GlobalVersion,
                    appliedPolicy.GroupVersion!.Value, appliedPolicy.DeviceVersion!.Value));
            var devices = await SendJsonAsync(http, server, "/api/v1/admin/devices", HttpMethod.Get,
                token: adminToken, expected: HttpStatusCode.OK, cancellationToken: timeout.Token);
            var deviceView = devices!.AsArray().Single(item => item!["id"]!.GetValue<string>() == enrollment.DeviceId);
            Assert.True(deviceView!["policyCurrent"]!.GetValue<bool>());
            Assert.Equal(appliedPolicy.Version, deviceView["appliedPolicy"]!["globalVersion"]!.GetValue<long>());

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
            EnsureTemporaryCertificateFileExists(pfxPath);
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

    private static void EnsureTemporaryCertificateFileExists(string certificatePath)
    {
        if (!File.Exists(certificatePath) || new FileInfo(certificatePath).Length == 0)
            throw new InvalidOperationException("The temporary TLS certificate file is missing or empty; the API child process was not started.");
    }

    private static async Task WaitForReadyAsync(HttpClient http, string server, Process process,
        ConcurrentQueue<string> stdout, ConcurrentQueue<string> stderr, CancellationToken cancellationToken)
    {
        string? lastTransportFailure = null;
        while (!cancellationToken.IsCancellationRequested)
        {
            var startupFailure = stdout.Concat(stderr).FirstOrDefault(line =>
                line.Contains("Hosting failed to start", StringComparison.OrdinalIgnoreCase)
                || line.Contains("Unhandled exception", StringComparison.OrdinalIgnoreCase));
            if (startupFailure is not null)
                throw new InvalidOperationException("Live TLS server failed during startup. stdout: "
                    + string.Join(Environment.NewLine, stdout) + " stderr: " + string.Join(Environment.NewLine, stderr));
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
            catch (HttpRequestException exception)
            {
                var rootCause = exception.GetBaseException();
                lastTransportFailure = $"{rootCause.GetType().Name}: {rootCause.Message}";
            }
            catch (TaskCanceledException exception) when (!cancellationToken.IsCancellationRequested)
            { lastTransportFailure = $"{exception.GetType().Name}: {exception.Message}"; }
            await Task.Delay(100);
        }
        throw new TimeoutException("Live TLS server did not become ready. Last transport failure: "
            + (lastTransportFailure ?? "none") + " stdout: " + string.Join(Environment.NewLine, stdout)
            + " stderr: " + string.Join(Environment.NewLine, stderr));
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

    private sealed class OllamaEmbeddingFixture : IAsyncDisposable
    {
        private readonly TcpListener listener;
        private readonly CancellationTokenSource shutdown = new();
        private readonly Task worker;
        private int requestCount;
        private int chatRequestCount;
        public string Endpoint { get; }
        public int RequestCount => Volatile.Read(ref requestCount);
        public int ChatRequestCount => Volatile.Read(ref chatRequestCount);
        public ConcurrentBag<string> ReceivedInputs { get; } = new();
        public ConcurrentBag<string> ReceivedChatMessages { get; } = new();

        public OllamaEmbeddingFixture()
        {
            listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            Endpoint = $"http://127.0.0.1:{port}";
            worker = ServeAsync(shutdown.Token);
        }

        private async Task ServeAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                using var client = await listener.AcceptTcpClientAsync(cancellationToken);
                var stream = client.GetStream();
                using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
                var requestLine = await reader.ReadLineAsync(cancellationToken)
                    ?? throw new EndOfStreamException("Missing HTTP request line.");
                var requestPath = requestLine.Split(' ', 3)[1];
                var contentLength = 0;
                var isChunked = false;
                while (await reader.ReadLineAsync(cancellationToken) is { Length: > 0 } header)
                {
                    if (header.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)
                        && int.TryParse(header.AsSpan("Content-Length:".Length).Trim(), out var parsedLength)) contentLength = parsedLength;
                    if (header.StartsWith("Transfer-Encoding:", StringComparison.OrdinalIgnoreCase)
                        && header.Contains("chunked", StringComparison.OrdinalIgnoreCase)) isChunked = true;
                }
                string requestJson;
                if (isChunked)
                {
                    var chunkedBody = new StringBuilder();
                    while (true)
                    {
                        var chunkHeader = await reader.ReadLineAsync(cancellationToken) ?? throw new EndOfStreamException("Missing chunk header.");
                        var chunkLengthText = chunkHeader.Split(';', 2)[0];
                        if (!int.TryParse(chunkLengthText, System.Globalization.NumberStyles.HexNumber,
                                System.Globalization.CultureInfo.InvariantCulture, out var chunkLength) || chunkLength < 0 || chunkLength > 1_000_000)
                            throw new InvalidDataException("Embedding fixture received an invalid chunk size.");
                        if (chunkLength == 0) { _ = await reader.ReadLineAsync(cancellationToken); break; }
                        var chunk = new char[chunkLength];
                        var read = 0;
                        while (read < chunk.Length)
                        {
                            var countRead = await reader.ReadBlockAsync(chunk.AsMemory(read), cancellationToken);
                            if (countRead == 0) throw new EndOfStreamException("Embedding fixture received an incomplete chunk.");
                            read += countRead;
                        }
                        chunkedBody.Append(chunk);
                        _ = await reader.ReadLineAsync(cancellationToken); // CRLF after each chunk.
                    }
                    requestJson = chunkedBody.ToString();
                }
                else
                {
                    if (contentLength is < 1 or > 1_000_000) throw new InvalidDataException("Embedding fixture received an invalid request size.");
                    var requestBody = new char[contentLength];
                    var read = 0;
                    while (read < requestBody.Length)
                    {
                        var countRead = await reader.ReadBlockAsync(requestBody.AsMemory(read), cancellationToken);
                        if (countRead == 0) throw new EndOfStreamException("Embedding fixture received an incomplete request.");
                        read += countRead;
                    }
                    requestJson = new string(requestBody);
                }
                using var document = JsonDocument.Parse(requestJson);
                string responseBody;
                if (requestPath == "/api/chat")
                {
                    var messages = document.RootElement.GetProperty("messages");
                    ReceivedChatMessages.Add(messages[1].GetProperty("content").GetString()!);
                    Interlocked.Increment(ref chatRequestCount);
                    responseBody = "{\"message\":{\"content\":\"{\\\"category\\\":\\\"None\\\",\\\"risk\\\":\\\"Low\\\",\\\"indicators\\\":[],\\\"uncertainties\\\":[],\\\"recommendations\\\":[],\\\"explanation\\\":\\\"Synthetic loopback model.\\\"}\"}}";
                }
                else if (requestPath == "/api/embed")
                {
                    var inputs = document.RootElement.GetProperty("input");
                    var count = inputs.ValueKind == JsonValueKind.Array ? inputs.GetArrayLength() : 1;
                    if (inputs.ValueKind == JsonValueKind.Array)
                        foreach (var item in inputs.EnumerateArray()) if (item.ValueKind == JsonValueKind.String) ReceivedInputs.Add(item.GetString()!);
                    Interlocked.Increment(ref requestCount);
                    responseBody = "{\"embeddings\":[" + string.Join(',', Enumerable.Repeat("[1,0]", count)) + "]}";
                }
                else throw new InvalidDataException($"Unexpected local AI request path: {requestPath}");
                var bytes = Encoding.UTF8.GetBytes(responseBody);
                var headers = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(headers, cancellationToken);
                await stream.WriteAsync(bytes, cancellationToken);
            }
        }

        public async ValueTask DisposeAsync()
        {
            shutdown.Cancel();
            listener.Stop();
            try { await worker.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (OperationCanceledException) { }
            shutdown.Dispose();
        }
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
