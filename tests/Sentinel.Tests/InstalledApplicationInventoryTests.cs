using Sentinel.Core.Analysis;
using Xunit;

namespace Sentinel.Tests;

public sealed class InstalledApplicationInventoryTests
{
    [Fact]
    public void NormalizesAndDeduplicatesDisplayMetadataWithoutRetainingPaths()
    {
        var result = InstalledApplicationInventoryReader.Normalize([
            new InstalledApplication("Example App", "1.2.3", "Example Publisher"),
            new InstalledApplication("example app", "1.2.3", "example publisher"),
            new InstalledApplication("Browser", null, "Vendor")
        ]);

        Assert.Equal(2, result.Count);
        Assert.Equal(new InstalledApplication("Example App", "1.2.3", "Example Publisher"), result[0]);
        Assert.DoesNotContain(result, item => item.Name.Contains("C:\\", StringComparison.Ordinal));
    }

    [Fact]
    public void DropsBlankNamesAndBoundsRegistryStrings()
    {
        var longValue = new string('x', 500);
        var result = InstalledApplicationInventoryReader.Normalize([
            new InstalledApplication(" \t ", "1", "Vendor"),
            new InstalledApplication("  Sample\u0001App  ", longValue, null)
        ]);

        var application = Assert.Single(result);
        Assert.Equal("SampleApp", application.Name);
        Assert.Equal(200, application.Version!.Length);
        Assert.Null(application.Publisher);
    }

    [Fact]
    public void RejectsNullInput()
    {
        Assert.Throws<ArgumentNullException>(() => InstalledApplicationInventoryReader.Normalize(null!));
    }
}
