using System.Windows;
namespace Sentinel.Desktop;
public partial class MainWindow : Window
{
    public MainWindow(MainViewModel model) { InitializeComponent(); DataContext = model; }
}
