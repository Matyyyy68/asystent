using System.IO.Pipes;

namespace Sentinel.UrlHost;

internal static class BrowserDesktopNotifier
{
    public static async Task NotifyAsync(byte signal, CancellationToken cancellationToken)
    {
        try
        {
            await using var pipe = new NamedPipeClientStream(".", "SentinelAI.Desktop.Activation", PipeDirection.Out, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(250, cancellationToken);
            await pipe.WriteAsync(new byte[] { signal }, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or OperationCanceledException)
        {
            // The warning remains visible in the browser; the desktop app may be closed.
        }
    }
}
