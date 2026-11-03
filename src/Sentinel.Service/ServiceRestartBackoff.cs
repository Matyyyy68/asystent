namespace Sentinel.Service;

internal sealed class ServiceRestartBackoff
{
    private int delaySeconds = 1;

    public int CurrentDelaySeconds => delaySeconds;

    public int DelayForFailure(TimeSpan engineUptime)
    {
        if (engineUptime >= TimeSpan.FromSeconds(60))
        {
            delaySeconds = 1;
            return 1;
        }
        var delay = delaySeconds;
        delaySeconds = Math.Min(delaySeconds * 2, 30);
        return delay;
    }

    public bool SelfTest()
    {
        if (CurrentDelaySeconds != 1) return false;
        if (DelayForFailure(TimeSpan.FromSeconds(59)) != 1 || CurrentDelaySeconds != 2) return false;
        if (DelayForFailure(TimeSpan.FromSeconds(59)) != 2 || CurrentDelaySeconds != 4) return false;
        for (var index = 0; index < 10; index++) DelayForFailure(TimeSpan.FromSeconds(59));
        if (CurrentDelaySeconds != 30) return false;
        return DelayForFailure(TimeSpan.FromSeconds(60)) == 1 && CurrentDelaySeconds == 1;
    }
}
