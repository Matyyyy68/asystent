using Sentinel.Core.Analysis;

namespace Sentinel.Core.Context;

public enum CaptureStatus { Captured, Paused, Excluded, RateLimited, Busy, Unavailable }
public sealed record WindowDescriptor(nint Handle, int ProcessId, string Application, string Title);
public sealed record ContextCapture(CaptureStatus Status, AnalysisContext? Context, bool Truncated = false);
public interface IContextProvider
{
    Task<WindowDescriptor?> GetForegroundAsync(CancellationToken cancellationToken);
    Task<ContextCapture> CaptureAsync(WindowDescriptor window, bool includeStaticText, CancellationToken cancellationToken);
}
public interface IForegroundEventSource : IDisposable
{
    event EventHandler? ForegroundChanged;
    void Start();
    void Stop();
}

public static class ContextPolicy
{
    private static readonly string[] Browsers = ["chrome", "msedge", "firefox", "brave", "opera", "vivaldi"];
    private static readonly string[] Messaging = ["outlook", "thunderbird", "teams", "ms-teams", "slack", "discord", "signal", "telegram", "whatsapp"];
    public static bool IsExcluded(WindowDescriptor window, AppSettings settings)
    {
        var app = Path.GetFileNameWithoutExtension(window.Application);
        static string[] Split(string value) => value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return Split(settings.ExcludedApplications).Any(a => string.Equals(Path.GetFileNameWithoutExtension(a), app, StringComparison.OrdinalIgnoreCase)) ||
            Split(settings.ExcludedWindowTitles).Any(t => window.Title.Contains(t, StringComparison.OrdinalIgnoreCase)) ||
            (settings.ExcludeBrowsers && Browsers.Contains(app, StringComparer.OrdinalIgnoreCase)) ||
            (settings.ExcludeMessaging && Messaging.Contains(app, StringComparer.OrdinalIgnoreCase));
    }
}

/// <summary>Privacy and rate limits are enforced before UI Automation is requested.</summary>
public sealed class ContextCollector(IContextProvider provider, TimeProvider clock)
{
    private int busy;
    private long? lastCapture;
    public async Task<ContextCapture> CaptureAsync(AppSettings settings, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        if (settings.Paused) return new(CaptureStatus.Paused, null);
        if (Interlocked.CompareExchange(ref busy, 1, 0) != 0) return new(CaptureStatus.Busy, null);
        try
        {
            if (lastCapture is { } previous && clock.GetElapsedTime(previous) < TimeSpan.FromSeconds(Math.Clamp(settings.MinimumIntervalSeconds, 3, 300)))
                return new(CaptureStatus.RateLimited, null);
            var window = await provider.GetForegroundAsync(ct);
            if (window is null) return new(CaptureStatus.Unavailable, null);
            if (ContextPolicy.IsExcluded(window, settings)) return new(CaptureStatus.Excluded, null);
            lastCapture = clock.GetTimestamp();
            var capture = await provider.CaptureAsync(window, settings.CollectStaticText, ct);
            ct.ThrowIfCancellationRequested();
            if (capture.Context is not { } context) return capture;
            var safeApp = new string(window.Application.Where(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-').Take(64).ToArray());
            return capture with { Context = context with { Application = safeApp.Length > 0 ? safeApp : "unknown", Text = PrivacyFilter.Redact(context.Text) } };
        }
        finally { Volatile.Write(ref busy, 0); }
    }
}
