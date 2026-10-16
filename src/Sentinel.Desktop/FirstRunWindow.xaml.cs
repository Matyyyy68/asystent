using System.Windows;

namespace Sentinel.Desktop;

public partial class FirstRunWindow : Window
{
    public string SelectedDirectory { get; private set; }
    public FirstRunWindow(string recommendedDirectory)
    {
        InitializeComponent();
        SelectedDirectory = recommendedDirectory;
        DirectoryLabel.Text = SelectedDirectory;
    }
    private void ChooseDirectory(object sender, RoutedEventArgs e)
    {
        var picker = new Microsoft.Win32.OpenFolderDialog { Title = "Wybierz folder na ustawienia i historię Sentinel AI" };
        if (picker.ShowDialog(this) != true) return;
        SelectedDirectory = picker.FolderName;
        DirectoryLabel.Text = SelectedDirectory;
    }
    private void Continue(object sender, RoutedEventArgs e) => DialogResult = true;
}
