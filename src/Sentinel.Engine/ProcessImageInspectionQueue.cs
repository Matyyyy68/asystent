using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading.Channels;
using Sentinel.Core;
using Sentinel.Core.Analysis;

public sealed record AuthenticodeSignatureInfo(string Status, string? Signer, string? Thumbprint);

public sealed class ProcessImageInspectionQueue : IAsyncDisposable
{
    // Include the one in-flight inspection so shutdown/restart can requeue every Pending event.
    private const int Capacity = 33;
    private const long MaximumImageBytes = 256L * 1024 * 1024;
    private readonly LocalStore store;
    private readonly FileHashReputation reputation;
    private readonly Func<string, CancellationToken, Task<AuthenticodeSignatureInfo>> readSignature;
    private readonly Channel<(Guid EventId, string Path)> channel = Channel.CreateBounded<(Guid, string)>(new BoundedChannelOptions(Capacity)
    {
        SingleReader = true,
        SingleWriter = false,
        FullMode = BoundedChannelFullMode.Wait
    });
    private readonly CancellationTokenSource cancellation = new();
    private readonly Task worker;
    private long completed;
    private long dropped;

    public ProcessImageInspectionQueue(LocalStore store, FileHashReputation reputation,
        Func<string, CancellationToken, Task<AuthenticodeSignatureInfo>> readSignature)
    {
        this.store = store;
        this.reputation = reputation;
        this.readSignature = readSignature;
        worker = Task.Run(WorkAsync);
    }

    public long Completed => Interlocked.Read(ref completed);
    public long Dropped => Interlocked.Read(ref dropped);

    public bool TryEnqueue(Guid eventId, string path)
    {
        if (eventId == Guid.Empty || !IsSafeLocalPath(path) || !channel.Writer.TryWrite((eventId, path)))
        {
            Interlocked.Increment(ref dropped);
            return false;
        }
        return true;
    }

    public static string? ResolveExecutablePath(int processId, string expectedName)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            if (!string.Equals(process.ProcessName, expectedName, StringComparison.OrdinalIgnoreCase)) return null;
            var path = process.MainModule?.FileName;
            return path is not null && IsSafeLocalPath(path) ? path : null;
        }
        catch { return null; }
    }

    private static bool IsSafeLocalPath(string? path) => path is { Length: > 0 and <= 4096 } &&
        Path.IsPathFullyQualified(path) && !path.StartsWith(@"\\", StringComparison.Ordinal) && !path.Any(char.IsControl);

    private async Task WorkAsync()
    {
        try
        {
            await foreach (var request in channel.Reader.ReadAllAsync(cancellation.Token))
            {
                string? hash = null;
                string signatureStatus;
                bool? localHashMatch = null;
                try
                {
                    var info = new FileInfo(request.Path);
                    if (!info.Exists) signatureStatus = "Unavailable";
                    else if (info.Length > MaximumImageBytes) signatureStatus = "TooLarge";
                    else
                    {
                        var length = info.Length;
                        var lastWrite = info.LastWriteTimeUtc;
                        await using var stream = new FileStream(request.Path, FileMode.Open, FileAccess.Read,
                            FileShare.ReadWrite | FileShare.Delete, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                        hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellation.Token));
                        info.Refresh();
                        if (!info.Exists || info.Length != length || info.LastWriteTimeUtc != lastWrite)
                        {
                            hash = null;
                            signatureStatus = "Unknown";
                        }
                        else
                        {
                            var lookup = reputation.Check(hash);
                            localHashMatch = lookup.FeedImported ? lookup.Match : null;
                            var signature = await readSignature(request.Path, cancellation.Token);
                            signatureStatus = signature.Status is "Valid" or "NotSigned" or "HashMismatch" or "NotTrusted"
                                ? signature.Status : "Unknown";
                        }
                    }
                }
                catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { break; }
                catch { signatureStatus = "Unknown"; hash = null; localHashMatch = null; }

                try
                {
                    await store.UpdateProcessImageInspectionAsync(request.EventId, hash, signatureStatus, localHashMatch, cancellation.Token);
                    Interlocked.Increment(ref completed);
                }
                catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { break; }
                catch { Interlocked.Increment(ref dropped); }
            }
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
    }

    public async ValueTask DisposeAsync()
    {
        channel.Writer.TryComplete();
        cancellation.Cancel();
        try { await worker; } catch (OperationCanceledException) { }
        cancellation.Dispose();
    }
}
