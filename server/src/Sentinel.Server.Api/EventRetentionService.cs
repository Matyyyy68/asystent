using Sentinel.Server.Core;

namespace Sentinel.Server.Api;

public sealed class EventRetentionService(IServerStore store, ILogger<EventRetentionService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var removed = await store.PurgeExpiredEventsAsync(DateTimeOffset.UtcNow, stoppingToken);
                if (removed > 0) logger.LogInformation("Usunięto {Count} zdarzeń po okresie retencji.", removed);
                await Task.Delay(TimeSpan.FromHours(24), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            {
                logger.LogWarning(exception, "Nie udało się wykonać czyszczenia retencji zdarzeń; ponowienie za godzinę.");
                try { await Task.Delay(TimeSpan.FromHours(1), stoppingToken); }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            }
        }
    }
}
