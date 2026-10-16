using System.Globalization;
using System.Windows.Data;
using Sentinel.Core;
using Sentinel.Core.Analysis;

namespace Sentinel.Desktop;

public sealed class EnumLabelConverter : IValueConverter
{
    public static string Label(object? value) => value switch
    {
        RiskLevel.Information => "Informacja", RiskLevel.Low => "Niskie", RiskLevel.Moderate => "Umiarkowane", RiskLevel.High => "Wysokie", RiskLevel.Critical => "Krytyczne",
        EventStatus.New => "Nowe", EventStatus.Reviewed => "Sprawdzone", EventStatus.FalsePositive => "Fałszywy alarm",
        ThreatCategory.SocialEngineering => "Presja i socjotechnika",
        ThreatCategory.None => "Brak sklasyfikowanych sygnałów", ThreatCategory.CredentialPhishing => "Możliwy phishing",
        ThreatCategory.PaymentFraud => "Ryzykowna prośba finansowa", ThreatCategory.UnsafeExecution => "Ryzykowne polecenie lub plik",
        ThreatCategory.SecurityTampering => "Wyłączanie zabezpieczeń", ThreatCategory.SuspiciousNavigation => "Podejrzany adres",
        string text when Enum.TryParse<ThreatCategory>(text, out var category) => Label(category),
        _ => value?.ToString() ?? ""
    };
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => Label(value);
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
