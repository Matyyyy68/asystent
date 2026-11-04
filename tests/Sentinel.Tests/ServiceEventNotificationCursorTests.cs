using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests;

public sealed class ServiceEventNotificationCursorTests
{
    [Fact]
    public void PersistsMonotonicCursorAcrossAgentRestarts()
    {
        var directory = Path.Combine(Path.GetTempPath(), "SentinelCursorTests", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "cursor");
        try
        {
            var first = new ServiceEventNotificationCursor(path);
            Assert.Equal(0, first.LastEventId);
            Assert.True(first.TryAdvance(12));
            Assert.Equal(12, first.LastEventId);

            var restarted = new ServiceEventNotificationCursor(path);
            Assert.Equal(12, restarted.LastEventId);
            Assert.True(restarted.TryAdvance(11));
            Assert.Equal(12, restarted.LastEventId);
            Assert.True(restarted.TryAdvance(24));

            Assert.Equal(24, new ServiceEventNotificationCursor(path).LastEventId);
            Assert.Throws<ArgumentOutOfRangeException>(() => restarted.TryAdvance(-1));
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch { }
        }
    }

    [Fact]
    public void CorruptCursorFailsOpenWithoutReadingUnboundedContents()
    {
        var directory = Path.Combine(Path.GetTempPath(), "SentinelCursorTests", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "cursor");
        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(path, new string('9', 10_000));
            Assert.Equal(0, new ServiceEventNotificationCursor(path).LastEventId);
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch { }
        }
    }
}
