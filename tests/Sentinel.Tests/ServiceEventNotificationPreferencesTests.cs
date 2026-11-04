using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests;

public sealed class ServiceEventNotificationPreferencesTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void PreservesPreferenceAcrossAgentRestarts(bool enabled)
    {
        var directory = Path.Combine(Path.GetTempPath(), "SentinelNotificationPreferenceTests", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "enabled");
        try
        {
            var first = new ServiceEventNotificationPreferences(path);
            Assert.Null(first.Read());
            Assert.True(first.TryWrite(enabled));

            Assert.Equal(enabled, new ServiceEventNotificationPreferences(path).Read());
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch { }
        }
    }

    [Fact]
    public void CorruptOrUnboundedPreferenceIsUnknown()
    {
        var directory = Path.Combine(Path.GetTempPath(), "SentinelNotificationPreferenceTests", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "enabled");
        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(path, new string('1', 10_000));
            Assert.Null(new ServiceEventNotificationPreferences(path).Read());
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch { }
        }
    }
}

