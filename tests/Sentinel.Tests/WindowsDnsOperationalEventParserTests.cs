using Sentinel.Core.Analysis;
using Xunit;

namespace Sentinel.Tests;

public sealed class WindowsDnsOperationalEventParserTests
{
    [Fact]
    public void ParsesOnlyNewDnsClientQueryEventsAndDropsQueryResults()
    {
        const string xml = """
            <Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <Event><System><Provider Name="Microsoft-Windows-DNS-Client"/><EventID>3008</EventID><Channel>Microsoft-Windows-DNS-Client/Operational</Channel><EventRecordID>41</EventRecordID><TimeCreated SystemTime="2026-10-22T12:34:56.000Z"/></System><EventData><Data Name="QueryName">Phishing.Example.</Data><Data Name="QueryType">1</Data><Data Name="QueryOptions">0</Data><Data Name="QueryStatus">0</Data><Data Name="QueryResults">203.0.113.8</Data></EventData></Event>
              <Event><System><Provider Name="Other-Provider"/><EventID>3008</EventID><Channel>Microsoft-Windows-DNS-Client/Operational</Channel><EventRecordID>42</EventRecordID><TimeCreated SystemTime="2026-10-22T12:34:57.000Z"/></System><EventData><Data Name="QueryName">ignored.example</Data><Data Name="QueryType">1</Data><Data Name="QueryStatus">0</Data></EventData></Event>
              <Event><System><Provider Name="Microsoft-Windows-DNS-Client"/><EventID>3008</EventID><Channel>Microsoft-Windows-DNS-Client/Operational</Channel><EventRecordID>43</EventRecordID><TimeCreated SystemTime="2026-10-22T12:34:58.000Z"/></System><EventData><Data Name="QueryName">192.0.2.1</Data><Data Name="QueryType">1</Data><Data Name="QueryStatus">0</Data></EventData></Event>
            </Events>
            """;

        var result = WindowsDnsOperationalEventParser.Parse(xml, afterRecordId: 40);

        Assert.Equal(2, result.Count);
        Assert.Equal(41, result[0].RecordId);
        Assert.Equal("phishing.example", result[0].QueryName);
        Assert.Equal(1u, result[0].QueryType);
        Assert.Equal(0u, result[0].QueryStatus);
        Assert.Equal(new DateTimeOffset(2026, 10, 22, 12, 34, 56, TimeSpan.Zero), result[0].Timestamp);
        Assert.Equal(43, result[1].RecordId);
        Assert.Null(result[1].QueryName);
    }

    [Fact]
    public void RejectsXmlEntitiesAndInvalidLimits()
    {
        const string xml = "<!DOCTYPE Events [<!ENTITY host 'evil.example'>]><Events/>";

        Assert.ThrowsAny<System.Xml.XmlException>(() => WindowsDnsOperationalEventParser.Parse(xml));
        Assert.Throws<ArgumentOutOfRangeException>(() => WindowsDnsOperationalEventParser.Parse("<Events/>", maximumEvents: 2001));
    }
}
