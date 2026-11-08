using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests;

public sealed class ServiceEventPipeProtocolTests
{
    [Fact]
    public void ParsesBoundedTypedServiceEventBatch()
    {
        var parsed = ServiceEventPipeProtocol.ParseResponse(
            """{"id":"agent-events","version":1,"ok":true,"result":{"latestEventId":42,"events":[{"id":41,"risk":"Information","status":"New"},{"id":42,"risk":"Critical","status":"Reviewed"}]}}""");

        Assert.Equal(42, parsed.LatestEventId);
        Assert.Collection(parsed.Events,
            item => Assert.Equal(new SystemServiceEvent(41, "Information", "New"), item),
            item => Assert.Equal(new SystemServiceEvent(42, "Critical", "Reviewed"), item));
    }

    [Fact]
    public void ParsesStableEventIdentityAndSourceForCrossProcessNotificationDeduplication()
    {
        var eventId = Guid.Parse("ca8ca7a2-c708-43b2-9c35-619f541dd54d");
        var parsed = ServiceEventPipeProtocol.ParseResponse(
            """{"id":"agent-events","version":1,"ok":true,"result":{"latestEventId":8,"events":[{"id":8,"risk":"High","status":"New","eventId":"ca8ca7a2-c708-43b2-9c35-619f541dd54d","source":"windows-defender-operational"}]}}""");

        Assert.Equal(new SystemServiceEvent(8, "High", "New", eventId, "windows-defender-operational"), Assert.Single(parsed.Events));
    }

    [Theory]
    [InlineData("{\"id\":7,\"version\":1,\"ok\":true,\"result\":{\"latestEventId\":0,\"events\":[]}}")]
    [InlineData("{\"id\":\"agent-events\",\"version\":\"1\",\"ok\":true,\"result\":{\"latestEventId\":0,\"events\":[]}}")]
    [InlineData("{\"id\":\"agent-events\",\"version\":1,\"ok\":true,\"result\":{\"latestEventId\":0,\"events\":[{}]}}")]
    [InlineData("{\"id\":\"agent-events\",\"version\":1,\"ok\":true,\"result\":{\"latestEventId\":0,\"events\":[{\"id\":1,\"risk\":\"Unknown\",\"status\":\"New\"}]}}")]
    [InlineData("{\"id\":\"agent-events\",\"version\":1,\"ok\":true,\"result\":{\"latestEventId\":0,\"events\":[{\"id\":1,\"risk\":\"Low\",\"status\":\"Unknown\"}]}}")]
    [InlineData("{\"id\":\"agent-events\",\"version\":1,\"ok\":true,\"result\":{\"latestEventId\":0,\"events\":[{\"id\":1,\"risk\":null,\"status\":\"New\"}]}}")]
    [InlineData("{\"id\":\"agent-events\",\"version\":1,\"ok\":true,\"result\":{\"latestEventId\":0,\"events\":[{\"id\":1,\"risk\":\"Low\",\"status\":\"New\",\"eventId\":\"not-a-guid\"}]}}")]
    [InlineData("{\"id\":\"agent-events\",\"version\":1,\"ok\":true,\"result\":{\"latestEventId\":0,\"events\":[{\"id\":1,\"risk\":\"Low\",\"status\":\"New\",\"source\":\"bad\\nsource\"}]}}")]
    [InlineData("[]")]
    public void RejectsMalformedOrUnknownResponses(string json)
        => Assert.Throws<InvalidDataException>(() => ServiceEventPipeProtocol.ParseResponse(json));

    [Fact]
    public void RejectsResponseAboveProtocolLimit()
    {
        var oversized = new string(' ', ServiceEventPipeProtocol.MaximumResponseChars + 1);
        Assert.Throws<InvalidDataException>(() => ServiceEventPipeProtocol.ParseResponse(oversized));
    }

    [Fact]
    public void RejectsMoreThanOnePageOfEvents()
    {
        var events = string.Join(",", Enumerable.Range(1, ServiceEventPipeProtocol.MaximumEvents + 1)
            .Select(id => $"{{\"id\":{id},\"risk\":\"Low\",\"status\":\"New\"}}"));
        var json = $"{{\"id\":\"agent-events\",\"version\":1,\"ok\":true,\"result\":{{\"latestEventId\":13,\"events\":[{events}]}}}}";

        Assert.Throws<InvalidDataException>(() => ServiceEventPipeProtocol.ParseResponse(json));
    }
}
