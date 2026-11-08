using Sentinel.Core;
using Sentinel.Engine;
using Xunit;
using System.Globalization;

namespace Sentinel.Tests;

public sealed class WindowsDefenderOperationalCollectorTests
{
    [Fact]
    public async Task SeedsCursorPersistsNewEventsAndOnlyReturnsAlertableIds()
    {
        var directory = Path.Combine(Path.GetTempPath(), "sentinel-defender-collector-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new LocalStore(directory);
            await store.InitializeAsync();
            var oldDetection = Event(20, 1116, "Severe");
            var source = new FakeDefenderLog { LatestRecordId = 20, Records = [oldDetection] };
            var collector = new WindowsDefenderOperationalCollector(store, source);

            var initial = await collector.CollectAsync();
            Assert.Equal(0, initial.EventsRead);
            Assert.Empty(initial.AlertEventIds);
            Assert.Contains("początkowy", initial.Status);

            var high = Event(21, 1116, "High");
            var action = Event(22, 1117, null);
            source.LatestRecordId = 22;
            source.Records = [oldDetection, high, action];

            var collected = await collector.CollectAsync();
            Assert.Equal(2, collected.EventsRead);
            Assert.Collection(collected.AlertEventIds, id => Assert.Equal(WindowsDefenderOperationalEventParser.CreateEventId(high), id));
            Assert.Contains("działa", collected.Status);

            var events = await store.ReadAsync();
            Assert.Equal(2, events.Count);
            var detection = events.Single(item => item.Source == "windows-defender-operational" &&
                item.EvidenceCodes!.Contains("windows.defender.detection"));
            Assert.Equal(RiskLevel.High, detection.Risk);
            Assert.Equal(80, detection.RiskScore);
            Assert.DoesNotContain("C:\\Users\\", detection.Explanation);
            Assert.DoesNotContain("Alice", detection.Explanation);
            var actionEvent = events.Single(item => item.EvidenceCodes!.Contains("windows.defender.action-reported"));
            Assert.Equal(RiskLevel.Information, actionEvent.Risk);

            var reopened = new LocalStore(directory);
            await reopened.InitializeAsync();
            Assert.Equal(22, await reopened.GetWindowsDefenderOperationalRecordCursorAsync());
            var repeated = await new WindowsDefenderOperationalCollector(reopened, source).CollectAsync();
            Assert.Equal(0, repeated.EventsRead);
            Assert.Empty(repeated.AlertEventIds);
            Assert.Equal(2, (await reopened.ReadAsync()).Count);
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task RewindsCursorAfterLogResetAndReportsDisabledChannel()
    {
        var directory = Path.Combine(Path.GetTempPath(), "sentinel-defender-reset-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new LocalStore(directory);
            await store.InitializeAsync();
            var source = new FakeDefenderLog { LatestRecordId = 50 };
            var collector = new WindowsDefenderOperationalCollector(store, source);
            _ = await collector.CollectAsync();

            var afterReset = Event(2, 5008, null);
            source.LatestRecordId = 2;
            source.Records = [afterReset];
            var result = await collector.CollectAsync();

            Assert.Equal(1, result.EventsRead);
            Assert.Contains("resetu dziennika", result.Status);
            Assert.Single(await store.ReadAsync());
            Assert.Equal(2, await store.GetWindowsDefenderOperationalRecordCursorAsync());

            source.Enabled = false;
            var disabled = await collector.CollectAsync();
            Assert.Equal(0, disabled.EventsRead);
            Assert.Contains("wyłączony", disabled.Status);
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private static WindowsDefenderOperationalEvent Event(long recordId, int eventId, string? severity) =>
        new(recordId, DateTimeOffset.Parse("2026-11-08T12:34:56Z", CultureInfo.InvariantCulture), eventId,
            eventId == 1116 ? "Trojan:Example" : null, severity, "Trojan",
            eventId == 1117 ? "Quarantine" : null, eventId is 1118 or 1119 ? "Failed" : null);

    private sealed class FakeDefenderLog : IWindowsDefenderOperationalLogSource
    {
        public bool Enabled { get; set; } = true;
        public long? LatestRecordId { get; set; }
        public IReadOnlyList<WindowsDefenderOperationalEvent> Records { get; set; } = [];

        public Task<bool> IsEnabledAsync(CancellationToken cancellationToken = default) => Task.FromResult(Enabled);
        public Task<long?> ReadLatestRecordIdAsync(CancellationToken cancellationToken = default) => Task.FromResult(LatestRecordId);
        public Task<IReadOnlyList<WindowsDefenderOperationalEvent>> ReadAfterAsync(long recordId,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<WindowsDefenderOperationalEvent>>(Records.Where(item => item.RecordId > recordId)
                .OrderBy(item => item.RecordId).Take(WindowsDefenderOperationalLogSource.MaximumBatchSize).ToArray());
    }
}
