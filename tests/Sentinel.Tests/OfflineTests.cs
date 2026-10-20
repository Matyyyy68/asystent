using System.Collections.Concurrent;
using System.Diagnostics.Tracing;
using Sentinel.Core.Analysis;
using Xunit;

namespace Sentinel.Tests;

[CollectionDefinition("NetworkAudit", DisableParallelization = true)]
public sealed class NetworkAuditCollection { }

[Collection("NetworkAudit")]
public sealed class OfflineTests
{
    private sealed class NetworkAudit : EventListener
    {
        public ConcurrentQueue<string> Requests { get; } = new();
        protected override void OnEventSourceCreated(EventSource source)
        {
            if (source.Name is "System.Net.Http" or "System.Net.Sockets" or "System.Net.NameResolution") EnableEvents(source,EventLevel.Informational);
        }
        protected override void OnEventWritten(EventWrittenEventArgs e)
        { if (e.EventName is "RequestStart" or "ConnectStart" or "ResolutionStart") Requests?.Enqueue(e.EventName); }
    }
    [Fact] public async Task LocalAnalysisDoesNotAttemptManagedHttpDnsOrSocketAccess()
    {
        using var audit=new NetworkAudit();
        // First prove that the auditor observes real requests. Loopback contains no user context.
        using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        var server = Task.Run(async () =>
        {
            using var peer = await listener.AcceptTcpClientAsync();
            await using var stream = peer.GetStream();
            using var reader = new StreamReader(stream, leaveOpen: true);
            while (await reader.ReadLineAsync() is { Length: > 0 }) { }
            await stream.WriteAsync(System.Text.Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"));
        });
        using var handler = new System.Net.Http.SocketsHttpHandler { UseProxy = false };
        using var client = new System.Net.Http.HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };
        Assert.Equal("OK", await client.GetStringAsync($"http://127.0.0.1:{port}/audit-self-test"));
        await server.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Contains("RequestStart", audit.Requests);
        audit.Requests.Clear();
        var engine=new ThreatAnalysisEngine(new UrlAnalyzer(new DomainNames()));
        foreach (var url in new[] { "https://paypal.com.evil.test", "https://192.0.2.1", "http://example.test/?token=SyntheticOnly" })
        {
            var result=engine.Analyze(new("Synthetic","Pilnie: blokada konta, zaloguj się",DateTimeOffset.UtcNow,new(url)));
            Assert.NotEmpty(result.Indicators);
        }
        Assert.Empty(audit.Requests);
    }
}
