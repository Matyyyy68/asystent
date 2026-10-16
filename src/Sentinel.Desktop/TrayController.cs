using System.ComponentModel;
using System.Windows;
using System.Windows.Input;
using System.Windows.Forms;

namespace Sentinel.Desktop;

public sealed class TrayController : IDisposable
{
    private readonly MainWindow window;
    private readonly MainViewModel model;
    private readonly NotifyIcon icon;
    private bool allowClose;

    public TrayController(MainWindow window, MainViewModel model)
    {
        this.window = window; this.model = model;
        var menu = new ContextMenuStrip();
        menu.Items.Add("Otwórz Sentinel AI", null, (_, _) => ShowWindow());
        var status = new ToolStripMenuItem(model.Monitoring.ProtectionStatus) { Enabled = false };
        menu.Items.Add(status);
        menu.Items.Add("Ostatnia aktywność", null, (_, _) => { ShowWindow(); model.OpenHistory.Execute(null); });
        menu.Items.Add("Ustawienia", null, (_, _) => { ShowWindow(); model.OpenSettings.Execute(null); });
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Zakończ", null, (_, _) => Exit());
        icon = new NotifyIcon { Icon = System.Drawing.SystemIcons.Application, Text = "Sentinel AI · analiza lokalna", ContextMenuStrip = menu, Visible = true };
        icon.DoubleClick += (_, _) => ShowWindow();
        model.Monitoring.PropertyChanged += OnProtectionChanged;
        window.Closing += OnWindowClosing;
        UpdateStatus(status);
    }

    private void OnProtectionChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is not (nameof(MonitoringViewModel.ProtectionStatus) or null)) return;
        if (window.Dispatcher.CheckAccess()) UpdateStatus(); else window.Dispatcher.BeginInvoke(new Action(() => UpdateStatus()));
    }

    private void UpdateStatus(ToolStripMenuItem? item = null)
    {
        var status = model.Monitoring.ProtectionStatus;
        var tooltip = status.Length > 55 ? status[..55] : status;
        if (tooltip.Length > 44) tooltip = tooltip[..44];
        icon.Text = $"Sentinel AI · {tooltip}";
        if (item is not null) item.Text = status;
        else if (icon.ContextMenuStrip?.Items.Count > 1 && icon.ContextMenuStrip.Items[1] is ToolStripMenuItem menuItem) menuItem.Text = status;
    }

    public void ShowWindow()
    {
        if (!window.Dispatcher.CheckAccess()) { window.Dispatcher.BeginInvoke((Action)ShowWindow); return; }
        if (!window.IsVisible) window.Show();
        if (window.WindowState == WindowState.Minimized) window.WindowState = WindowState.Normal;
        window.ShowInTaskbar = true; window.Activate();
    }

    public void StartMinimized() { window.ShowInTaskbar = false; window.Hide(); }

    private void OnWindowClosing(object? sender, CancelEventArgs e)
    {
        if (allowClose) return;
        e.Cancel = true; window.ShowInTaskbar = false; window.Hide();
    }

    private void Exit()
    {
        allowClose = true;
        window.Close();
        System.Windows.Application.Current.Shutdown();
    }

    public void Dispose()
    {
        model.Monitoring.PropertyChanged -= OnProtectionChanged;
        icon.Visible = false; icon.Dispose();
    }
}
