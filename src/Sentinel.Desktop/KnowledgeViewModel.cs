using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using Microsoft.Win32;
using Sentinel.Core.Knowledge;

namespace Sentinel.Desktop;

public sealed class KnowledgeViewModel : INotifyPropertyChanged
{
    private readonly IKnowledgeBaseProvider knowledge;
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Changed([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new(name));
    public ObservableCollection<KnowledgeDocument> Documents { get; } = [];
    public ObservableCollection<KnowledgeHit> Results { get; } = [];
    private string query = "";
    public string Query { get => query; set { query = value; Changed(); } }
    private string message = "Dokumenty i indeks pełnotekstowy pozostają lokalnie. Importowane treści są traktowane jako niezaufane.";
    public string Message { get => message; private set { message = value; Changed(); } }
    private KnowledgeDocument? selectedDocument;
    public KnowledgeDocument? SelectedDocument { get => selectedDocument; set { selectedDocument = value; Changed(); } }
    public ICommand Import { get; }
    public ICommand Delete { get; }
    public ICommand Search { get; }
    public ICommand Refresh { get; }
    public ICommand Backup { get; }

    public KnowledgeViewModel(IKnowledgeBaseProvider knowledge)
    {
        this.knowledge = knowledge;
        Import = new AsyncCommand(ImportAsync, ReportError);
        Delete = new AsyncCommand(DeleteAsync, ReportError);
        Search = new AsyncCommand(SearchAsync, ReportError);
        Refresh = new AsyncCommand(RefreshAsync, ReportError);
        Backup = new AsyncCommand(BackupAsync, ReportError);
    }

    public async Task InitializeAsync() => await RefreshAsync();

    private async Task ImportAsync()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog { Filter = "Dokumenty tekstowe (*.txt;*.md;*.docx)|*.txt;*.md;*.docx|Wszystkie pliki (*.*)|*.*", CheckFileExists = true, Multiselect = false };
        if (dialog.ShowDialog() != true) return;
        var item = await knowledge.ImportAsync(dialog.FileName);
        await RefreshAsync();
        SelectedDocument = Documents.FirstOrDefault(x => x.Id == item.Id);
        Message = $"Zaindeksowano {item.Name}: {item.ChunkCount} fragmentów. Wyszukiwanie używa słów kluczowych FTS5, nie embeddingów semantycznych.";
    }

    private async Task DeleteAsync()
    {
        if (SelectedDocument is not { } item) { Message = "Wybierz dokument z listy."; return; }
        if (System.Windows.MessageBox.Show($"Usunąć lokalny dokument „{item.Name}” i jego fragmenty z indeksu?", "Baza wiedzy", System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Question) != System.Windows.MessageBoxResult.Yes) return;
        var deleted = await knowledge.DeleteAsync(item.Id);
        await RefreshAsync();
        Results.Clear();
        Message = deleted ? "Dokument i jego fragmenty usunięto z lokalnej bazy wiedzy." : "Dokumentu już nie ma w bazie.";
    }

    private async Task SearchAsync()
    {
        var found = await knowledge.SearchAsync(Query, 10);
        Results.Clear();
        foreach (var hit in found) Results.Add(hit);
        Message = found.Count == 0 ? "Brak pasujących fragmentów. To nie oznacza, że sytuacja jest bezpieczna." : $"Znaleziono {found.Count} fragmentów w lokalnym indeksie FTS5.";
    }

    private async Task RefreshAsync()
    {
        var items = await knowledge.ListAsync();
        Documents.Clear();
        foreach (var item in items) Documents.Add(item);
        Message = $"Lokalna baza wiedzy: {Documents.Count} dokumentów. Treść nie jest wysyłana do sieci.";
    }

    private async Task BackupAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog { Filter = "SQLite|*.db", FileName = "sentinel-knowledge-backup.db", OverwritePrompt = false };
        if (dialog.ShowDialog() != true) return;
        await knowledge.BackupAsync(dialog.FileName);
        Message = "Spójna kopia lokalnej bazy wiedzy utworzona.";
    }

    private void ReportError(Exception exception)
    {
        Message = exception switch
        {
            NotSupportedException => exception.Message,
            InvalidDataException => exception.Message,
            IOException => "Nie można odczytać lub zapisać dokumentu. Sprawdź plik i uprawnienia katalogu danych.",
            _ => $"Operacja bazy wiedzy nie powiodła się ({exception.GetType().Name}). Dokument pozostaje lokalny."
        };
    }
}
