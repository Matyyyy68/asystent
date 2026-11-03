using Sentinel.Core.Analysis;
using System.Buffers.Binary;
using Xunit;

namespace Sentinel.Tests;

public sealed class NotificationToneTests
{
    [Theory]
    [InlineData(NotificationToneKind.Information)]
    [InlineData(NotificationToneKind.Warning)]
    [InlineData(NotificationToneKind.Critical)]
    [InlineData(NotificationToneKind.AnalysisComplete)]
    public void CreatesValidShortMonoPcmWave(NotificationToneKind kind)
    {
        var wave = NotificationTone.CreateWave(kind);

        Assert.Equal("RIFF", System.Text.Encoding.ASCII.GetString(wave, 0, 4));
        Assert.Equal(wave.Length - 8, BitConverter.ToInt32(wave, 4));
        Assert.Equal("WAVE", System.Text.Encoding.ASCII.GetString(wave, 8, 4));
        Assert.Equal(1, BitConverter.ToInt16(wave, 22));
        Assert.Equal(22_050, BitConverter.ToInt32(wave, 24));
        Assert.Equal(16, BitConverter.ToInt16(wave, 34));
        Assert.Equal(wave.Length - 44, BitConverter.ToInt32(wave, 40));
        Assert.InRange(wave.Length, 44 + 2_000, 44 + 20_000);
        var samples = Enumerable.Range(0, (wave.Length - 44) / 2)
            .Select(index => BinaryPrimitives.ReadInt16LittleEndian(wave.AsSpan(44 + index * 2, 2))).ToArray();
        Assert.Contains(samples, sample => sample != 0);
        Assert.InRange(samples.Max(Math.Abs), 1, (int)(short.MaxValue * 0.15));
    }

    [Fact]
    public void TonesAreDistinctAndInvalidKindsAreRejected()
    {
        Assert.NotEqual(NotificationTone.CreateWave(NotificationToneKind.Information), NotificationTone.CreateWave(NotificationToneKind.Warning));
        Assert.NotEqual(NotificationTone.CreateWave(NotificationToneKind.Warning), NotificationTone.CreateWave(NotificationToneKind.Critical));
        Assert.NotEqual(NotificationTone.CreateWave(NotificationToneKind.Critical), NotificationTone.CreateWave(NotificationToneKind.AnalysisComplete));
        Assert.Throws<ArgumentOutOfRangeException>(() => NotificationTone.CreateWave((NotificationToneKind)99));
    }

    [Fact]
    public void BatchToneUsesTheHighestSeverityWithoutElevatingInformationOnlySignals()
    {
        Assert.Equal(NotificationToneKind.Information,
            NotificationTonePolicy.Select([NotificationToneKind.Information, (NotificationToneKind)99]));
        Assert.Equal(NotificationToneKind.Warning,
            NotificationTonePolicy.Select([NotificationToneKind.Information, NotificationToneKind.Warning]));
        Assert.Equal(NotificationToneKind.Critical,
            NotificationTonePolicy.Select([NotificationToneKind.Warning, NotificationToneKind.Critical]));
        Assert.Equal(NotificationToneKind.Information,
            NotificationTonePolicy.Select([NotificationToneKind.AnalysisComplete, NotificationToneKind.Information]));
    }
}
