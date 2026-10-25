using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Sentinel.Core;
using Sentinel.Core.Configuration;
using Sentinel.Core.Enterprise;
using Xunit;

namespace Sentinel.Tests;

public sealed class EnterpriseEngineOfflineRestartTests
{
    [Fact]
    public async Task StartupExceptionExitsCleanlyAndReportsOnlyItsType()
    {
        var repository = FindRepositoryRoot();
        var configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent?.Name ?? "Release";
        var engineDll = Path.Combine(repository, "src", "Sentinel.Engine", "bin", configuration, "net10.0", "Sentinel.Engine.dll");
        Assert.True(File.Exists(engineDll), $"Engine was not built: {engineDll}");

        var temp = Path.Combine(Path.GetTempPath(), "sentinel-engine-startup-failure-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        var invalidDataRoot = Path.Combine(temp, "not-a-directory");
        await File.WriteAllTextAsync(invalidDataRoot, "force Directory.CreateDirectory to fail");
        try
        {
            var start = new ProcessStartInfo("dotnet")
            {
                Arguments = $"\"{engineDll}\"",
                WorkingDirectory = repository,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            start.Environment["SENTINEL_DATA_ROOT"] = invalidDataRoot;
            using var process = Process.Start(start) ?? throw new IOException("Could not start Sentinel Engine startup-failure test process.");
            var stderrTask = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            var stderr = await stderrTask;

            Assert.Equal(1, process.ExitCode);
            Assert.Contains("SENTINEL_ENGINE_FATAL type=System.IO.IOException", stderr, StringComparison.Ordinal);
            Assert.DoesNotContain("Unhandled exception", stderr, StringComparison.Ordinal);
            Assert.DoesNotContain(invalidDataRoot, stderr, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { Directory.Delete(temp, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    [WindowsDpapiFact]
    public async Task EnterpriseQueueSurvivesEngineRestartWhileOfflineAndConsentStopsRetry()
    {
        var repository = FindRepositoryRoot();
        var configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent?.Name ?? "Release";
        var engineDll = Path.Combine(repository, "src", "Sentinel.Engine", "bin", configuration, "net10.0", "Sentinel.Engine.dll");
        Assert.True(File.Exists(engineDll), $"Engine was not built: {engineDll}");

        var root = Path.Combine(Path.GetTempPath(), "sentinel-enterprise-offline-" + Guid.NewGuid().ToString("N"));
        var database = Path.Combine(root, "data");
        var downloads = Path.Combine(root, "Downloads");
        Directory.CreateDirectory(downloads);
        using var portLease = new TcpListener(IPAddress.Loopback, 0);
        portLease.Start();
        var port = ((IPEndPoint)portLease.LocalEndpoint).Port;
        portLease.Stop();
        var server = $"https://127.0.0.1:{port}";
        var eventId = Guid.NewGuid();
        const string token = "offline-restart-token-1234567890123456789012345678901234567890";

        try
        {
            var store = new LocalStore(database);
            await store.InitializeAsync(new InstalledProductProfile(ProductVariant.EnterpriseClient, server, ShareSecurityMetadata: true));
            var occurredAt = DateTimeOffset.UtcNow;
            await store.AddLocalOnlyAsync(new SecurityEvent(0, occurredAt, RiskLevel.High, "Syntetyczne wykrycie", "Engine restart E2E",
                "Treść lokalna, nie należy do kolejki Enterprise", "Pozostaje wyłącznie w historii lokalnej", EventStatus.New,
                EventId: eventId, Source: "manual-analysis", RuleVersion: "2026.10.1"));
            Assert.True(await store.EnqueueEnterpriseEventAsync(new PendingEnterpriseEvent(eventId, occurredAt, "url", 3,
                "url.suspicious_domain", "manual-analysis", "2026.10.1")));
            await new WindowsDpapiCredentialStore(database).WriteAsync(token);

            await using (var first = await EngineProcess.StartAsync(engineDll, repository, root, downloads))
            {
                using var status = await first.CallAsync("status");
                var enterprise = status.RootElement.GetProperty("result").GetProperty("enterprise");
                Assert.True(enterprise.GetProperty("paired").GetBoolean());
                Assert.True(enterprise.GetProperty("sharingMetadata").GetBoolean());
                Assert.Equal(1, enterprise.GetProperty("queuedEvents").GetInt32());

                using var sync = await first.CallAsync("enterpriseSync");
                Assert.Equal("sync_failed", sync.RootElement.GetProperty("result").GetProperty("reason").GetString());
                using var afterOfflineAttempt = await first.CallAsync("status");
                Assert.Equal(1, afterOfflineAttempt.RootElement.GetProperty("result").GetProperty("enterprise").GetProperty("queuedEvents").GetInt32());
            }

            await using (var restarted = await EngineProcess.StartAsync(engineDll, repository, root, downloads))
            {
                using var statusAfterRestart = await restarted.CallAsync("status");
                var enterprise = statusAfterRestart.RootElement.GetProperty("result").GetProperty("enterprise");
                Assert.True(enterprise.GetProperty("paired").GetBoolean());
                Assert.Equal(1, enterprise.GetProperty("queuedEvents").GetInt32());

                using var retry = await restarted.CallAsync("enterpriseSync");
                Assert.Equal("sync_failed", retry.RootElement.GetProperty("result").GetProperty("reason").GetString());
                using var stopSharing = await restarted.CallAsync("enterpriseConsent", new { enabled = false });
                Assert.Equal(0, stopSharing.RootElement.GetProperty("result").GetProperty("queuedEvents").GetInt32());
                using var stoppedSync = await restarted.CallAsync("enterpriseSync");
                Assert.Equal("consent_disabled", stoppedSync.RootElement.GetProperty("result").GetProperty("reason").GetString());
                using var localHistory = await restarted.CallAsync("history");
                Assert.Single(localHistory.RootElement.GetProperty("result").EnumerateArray());
                using var finalStatus = await restarted.CallAsync("status");
                var finalEnterprise = finalStatus.RootElement.GetProperty("result").GetProperty("enterprise");
                Assert.False(finalEnterprise.GetProperty("sharingMetadata").GetBoolean());
                Assert.Equal(0, finalEnterprise.GetProperty("queuedEvents").GetInt32());
            }
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static string FindRepositoryRoot()
    {
        for (var current = new DirectoryInfo(AppContext.BaseDirectory); current is not null; current = current.Parent)
            if (File.Exists(Path.Combine(current.FullName, "eng", "ProductVersion.props"))) return current.FullName;
        throw new DirectoryNotFoundException("Could not find repository root from test output directory.");
    }

    private sealed class EngineProcess(Process process, Task<string> stderr) : IAsyncDisposable
    {
        private readonly StreamWriter input = process.StandardInput;
        private readonly StreamReader output = process.StandardOutput;
        private readonly Process process = process;
        private int requestId;

        public static Task<EngineProcess> StartAsync(string engineDll, string repository, string root, string downloads)
        {
            var start = new ProcessStartInfo("dotnet")
            {
                Arguments = $"\"{engineDll}\"",
                WorkingDirectory = repository,
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            start.Environment["SENTINEL_DATA_ROOT"] = root;
            start.Environment["SENTINEL_DOWNLOADS_PATH"] = downloads;
            var child = Process.Start(start) ?? throw new IOException("Could not start Sentinel Engine test process.");
            return Task.FromResult(new EngineProcess(child, child.StandardError.ReadToEndAsync()));
        }

        public async Task<JsonDocument> CallAsync(string method, object? data = null)
        {
            var id = Interlocked.Increment(ref requestId).ToString(System.Globalization.CultureInfo.InvariantCulture);
            var request = new Dictionary<string, object?>
            {
                ["id"] = id,
                ["version"] = 1,
                ["method"] = method,
            };
            if (data is not null)
                foreach (var property in JsonSerializer.SerializeToElement(data).EnumerateObject()) request[property.Name] = property.Value.Clone();
            var json = JsonSerializer.Serialize(request);
            await input.WriteLineAsync(json);
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
}
