using Xunit;
using Sentinel.Core.Analysis;

namespace Sentinel.Tests;

public sealed class WindowsDefenderOperationalEventParserTests
{
    private static string Event(int id = 1116, long record = 42, string provider = "Microsoft-Windows-Windows Defender",
        string channel = "Microsoft-Windows-Windows Defender/Operational", string data = """
            <Data Name="Threat Name">Trojan:Example</Data>
            <Data Name="Severity Name">Severe</Data>
            <Data Name="Category Name">Trojan</Data>
            <Data Name="Path">C:\Users\Alice\Downloads\sample.exe</Data>
            <Data Name="User">Alice</Data>
            <Data Name="Action Name">Quarantine</Data>
            <Data Name="Action Status">Succeeded</Data>
            """) => $"""
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="{provider}" /><EventID>{id}</EventID><EventRecordID>{record}</EventRecordID>
            <Channel>{channel}</Channel><TimeCreated SystemTime="2026-11-08T12:34:56.000Z" /></System>
          <EventData>{data}</EventData>
        </Event>
        """;

    [Fact]
    public void ParsesOnlyAllowlistedFieldsAndDropsPathAndUser()
    {
        var parsed = WindowsDefenderOperationalEventParser.Parse(Event());

        var item = Assert.Single(parsed);
        Assert.Equal(42, item.RecordId);
        Assert.Equal(1116, item.EventId);
        Assert.Equal("Trojan:Example", item.ThreatName);
        Assert.Equal("Severe", item.SeverityName);
        Assert.Equal("Quarantine", item.ActionName);
        Assert.Equal("Succeeded", item.ActionStatus);
        Assert.DoesNotContain("Alice", System.Text.Json.JsonSerializer.Serialize(item));
        Assert.DoesNotContain("sample.exe", System.Text.Json.JsonSerializer.Serialize(item));
    }

    [Fact]
    public void RejectsWrongProviderChannelUnsupportedEventsAndOldRecords()
    {
        var xml = "<Events>" + Event(provider: "Other") +
            Event(channel: "Other/Operational", record: 43) + Event(id: 1, record: 44) +
            Event(record: 45) + "</Events>";

        var item = Assert.Single(WindowsDefenderOperationalEventParser.Parse(xml, afterRecordId: 44));
        Assert.Equal(45, item.RecordId);
    }

    [Fact]
    public void RejectsUnsafeFieldValuesAndInvalidXml()
    {
        var xml = Event(data: """
            <Data Name="Threat Name">bad&#xA;path</Data>
            <Data Name="Severity Name">Severe</Data>
            """);
        Assert.Null(Assert.Single(WindowsDefenderOperationalEventParser.Parse(xml)).ThreatName);
        Assert.Throws<System.Xml.XmlException>(() =>
            WindowsDefenderOperationalEventParser.Parse("<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///secret'>]><x>&e;</x>"));
        Assert.Throws<InvalidDataException>(() => WindowsDefenderOperationalEventParser.Parse(new string('x', 2 * 1024 * 1024 + 1)));
    }

    [Fact]
    public void EventIdentityIsStableAndLogResetRestartsCursor()
    {
        var item = Assert.Single(WindowsDefenderOperationalEventParser.Parse(Event()));
        Assert.Equal(WindowsDefenderOperationalEventParser.CreateEventId(item), WindowsDefenderOperationalEventParser.CreateEventId(item));
        Assert.Equal(0, WindowsDefenderOperationalEventParser.ResolveCursorAfterLogReset(80, 3));
        Assert.Equal(80, WindowsDefenderOperationalEventParser.ResolveCursorAfterLogReset(80, 90));
    }
}
