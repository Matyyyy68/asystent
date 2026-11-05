using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests;

public sealed class ServiceEventTransferCursorTests
{
    [Fact]
    public void CursorAdvancesOnlyForwardAndSurvivesReopen()
    {
        var directory = Path.Combine(Path.GetTempPath(), "sentinel-transfer-cursor-" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "state", "cursor");
        try
        {
            var cursor = new ServiceEventTransferCursor(path);
            Assert.Equal(0, cursor.Read());
            Assert.True(cursor.TryAdvance(12));
            Assert.False(cursor.TryAdvance(11));
            Assert.Equal(12, new ServiceEventTransferCursor(path).Read());
            Assert.True(cursor.TryReset(0));
            Assert.Equal(0, new ServiceEventTransferCursor(path).Read());
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch { }
        }
    }
}
