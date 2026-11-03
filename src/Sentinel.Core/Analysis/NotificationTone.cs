using System.Buffers.Binary;

namespace Sentinel.Core.Analysis;

public enum NotificationToneKind
{
    Information,
    Warning,
    Critical,
    AnalysisComplete
}

public static class NotificationTonePolicy
{
    public static NotificationToneKind Select(IEnumerable<NotificationToneKind> tones)
    {
        ArgumentNullException.ThrowIfNull(tones);
        var selected = NotificationToneKind.Information;
        foreach (var tone in tones)
        {
            var severity = tone switch
            {
                NotificationToneKind.Information => 0,
                NotificationToneKind.Warning => 1,
                NotificationToneKind.Critical => 2,
                _ => -1
            };
            if (severity > (int)selected) selected = tone;
        }
        return selected;
    }
}

/// <summary>Creates short, quiet Sentinel notification tones as mono 16-bit PCM WAV data.</summary>
public static class NotificationTone
{
    private const int SampleRate = 22_050;
    private const int BytesPerSample = 2;
    private const double Amplitude = 0.14;
    private static readonly (int Frequency, int DurationMs)[][] Patterns =
    [
        [(660, 75), (880, 90)],
        [(740, 110), (587, 125)],
        [(880, 100), (740, 110), (587, 140)],
        [(523, 65), (659, 65), (784, 105)]
    ];

    public static byte[] CreateWave(NotificationToneKind kind)
    {
        if (!Enum.IsDefined(kind)) throw new ArgumentOutOfRangeException(nameof(kind));
        var pattern = Patterns[(int)kind];
        const int gapMs = 38;
        var sampleCount = pattern.Sum(note => Samples(note.DurationMs)) + Samples(gapMs) * (pattern.Length - 1);
        var dataLength = checked(sampleCount * BytesPerSample);
        var wave = new byte[44 + dataLength];
        "RIFF"u8.CopyTo(wave);
        BinaryPrimitives.WriteInt32LittleEndian(wave.AsSpan(4, 4), wave.Length - 8);
        "WAVEfmt "u8.CopyTo(wave.AsSpan(8));
        BinaryPrimitives.WriteInt32LittleEndian(wave.AsSpan(16, 4), 16);
        BinaryPrimitives.WriteInt16LittleEndian(wave.AsSpan(20, 2), 1);
        BinaryPrimitives.WriteInt16LittleEndian(wave.AsSpan(22, 2), 1);
        BinaryPrimitives.WriteInt32LittleEndian(wave.AsSpan(24, 4), SampleRate);
        BinaryPrimitives.WriteInt32LittleEndian(wave.AsSpan(28, 4), SampleRate * BytesPerSample);
        BinaryPrimitives.WriteInt16LittleEndian(wave.AsSpan(32, 2), BytesPerSample);
        BinaryPrimitives.WriteInt16LittleEndian(wave.AsSpan(34, 2), BytesPerSample * 8);
        "data"u8.CopyTo(wave.AsSpan(36));
        BinaryPrimitives.WriteInt32LittleEndian(wave.AsSpan(40, 4), dataLength);

        var sampleIndex = 0;
        foreach (var (frequency, durationMs) in pattern)
        {
            var count = Samples(durationMs);
            var fadeSamples = Math.Min(Samples(12), count / 2);
            for (var i = 0; i < count; i++, sampleIndex++)
            {
                var envelope = Math.Min(1d, Math.Min((double)i / fadeSamples, (double)(count - 1 - i) / fadeSamples));
                var sample = (short)Math.Round(Math.Sin(2 * Math.PI * frequency * i / SampleRate) * short.MaxValue * Amplitude * envelope);
                BinaryPrimitives.WriteInt16LittleEndian(wave.AsSpan(44 + sampleIndex * BytesPerSample, BytesPerSample), sample);
            }
            sampleIndex += Samples(gapMs);
        }

        return wave;
    }

    private static int Samples(int milliseconds) => checked((int)((long)SampleRate * milliseconds / 1000));
}
