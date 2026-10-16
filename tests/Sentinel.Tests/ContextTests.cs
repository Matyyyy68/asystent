using Sentinel.Core;
using Sentinel.Core.Analysis;
using Sentinel.Core.Context;
using Xunit;

namespace Sentinel.Tests;

public sealed class ContextTests
{
    private sealed class Clock : TimeProvider
    {
        public long Ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Ticks;
    }
    private sealed class Provider : IContextProvider
    {
        public int Reads;
        public int Captures;
        public WindowDescriptor Window = new(1, 1, "example", "Sample window");
        public Task<WindowDescriptor?> GetForegroundAsync(CancellationToken ct) { ct.ThrowIfCancellationRequested(); Reads++; return Task.FromResult<WindowDescriptor?>(Window); }
        public Task<ContextCapture> CaptureAsync(WindowDescriptor window, bool includeStaticText, CancellationToken ct)
        {
            Captures++; ct.ThrowIfCancellationRequested();
            return Task.FromResult(new ContextCapture(CaptureStatus.Captured,new AnalysisContext(window.Application,includeStaticText ? "token: SyntheticSecret" : "",DateTimeOffset.UtcNow)));
        }
    }
    [Fact] public async Task PauseDoesNotReadEvenMetadata()
    {
        var provider=new Provider(); var c=new ContextCollector(provider,new Clock());
        Assert.Equal(CaptureStatus.Paused,(await c.CaptureAsync(new())).Status); Assert.Equal(0,provider.Reads); Assert.Equal(0,provider.Captures);
    }
    [Theory]
    [InlineData("bitwarden", "title", false, false, "")]
    [InlineData("chrome", "title", true, false, "")]
    [InlineData("outlook", "title", false, true, "")]
    [InlineData("example", "Private document", false, false, "private")]
    public async Task ExclusionsRunBeforeUia(string app,string title,bool browsers,bool messaging,string titles)
    {
        var provider=new Provider { Window=new(1,1,app,title) }; var c=new ContextCollector(provider,new Clock());
        var result=await c.CaptureAsync(new(Paused:false,ExcludeBrowsers:browsers,ExcludeMessaging:messaging,ExcludedWindowTitles:titles));
        Assert.Equal(CaptureStatus.Excluded,result.Status); Assert.Equal(0,provider.Captures);
    }
    [Fact] public async Task RateLimitUsesMonotonicClock()
    {
        var provider=new Provider(); var clock=new Clock(); var c=new ContextCollector(provider,clock); var settings=new AppSettings(Paused:false);
        Assert.Equal(CaptureStatus.Captured,(await c.CaptureAsync(settings)).Status);
        Assert.Equal(CaptureStatus.RateLimited,(await c.CaptureAsync(settings)).Status);
        clock.Ticks+=TimeSpan.FromSeconds(10).Ticks;
        Assert.Equal(CaptureStatus.Captured,(await c.CaptureAsync(settings)).Status); Assert.Equal(2,provider.Captures);
    }
    [Fact] public async Task TextIsMaskedBeforeLeavingCollector()
    {
        var provider=new Provider(); var c=new ContextCollector(provider,new Clock());
        var context=(await c.CaptureAsync(new(Paused:false))).Context!; Assert.DoesNotContain("SyntheticSecret",context.Text);
    }
    [Fact] public async Task MetadataOnlyDoesNotAskProviderForText()
    {
        var provider=new Provider(); var c=new ContextCollector(provider,new Clock());
        Assert.Equal("",(await c.CaptureAsync(new(Paused:false,CollectStaticText:false))).Context!.Text);
    }
    [Fact] public async Task CancellationIsNotIgnored()
    {
        var provider=new Provider(); var c=new ContextCollector(provider,new Clock()); using var cancel=new CancellationTokenSource(); cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>c.CaptureAsync(new(Paused:false),cancel.Token)); Assert.Equal(0,provider.Captures);
    }
    [Fact] public void ExclusionsMatchProcessesNotSubstrings()
    {
        var settings=new AppSettings(ExcludedApplications:"chrome.exe;example");
        Assert.True(ContextPolicy.IsExcluded(new(1,1,"CHROME",""),settings));
        Assert.False(ContextPolicy.IsExcluded(new(1,1,"chromehelper",""),settings));
    }
    private sealed class BlockingProvider : IContextProvider
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<ContextCapture> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<WindowDescriptor?> GetForegroundAsync(CancellationToken ct) => Task.FromResult<WindowDescriptor?>(new(1,1,"example",""));
        public Task<ContextCapture> CaptureAsync(WindowDescriptor window, bool includeStaticText, CancellationToken ct)
        { Started.SetResult(); return Completion.Task.WaitAsync(ct); }
    }
    [Fact] public async Task ConcurrentCaptureDoesNotStartAnotherProviderRead()
    {
        var provider = new BlockingProvider(); var collector = new ContextCollector(provider,new Clock());
        using var cancellation = new CancellationTokenSource();
        var first = collector.CaptureAsync(new(Paused:false),cancellation.Token);
        await provider.Started.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal(CaptureStatus.Busy,(await collector.CaptureAsync(new(Paused:false))).Status);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>first);
    }
}
