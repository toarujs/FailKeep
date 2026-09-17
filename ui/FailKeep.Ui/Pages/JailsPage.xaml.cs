using FailKeep.Ui.Ipc;
using Microsoft.UI.Xaml.Controls;
using System.Collections.ObjectModel;

namespace FailKeep.Ui.Pages;

public sealed record WatchRow(string Ip, int Fails);

public sealed partial class JailsPage : Page
{
    public ObservableCollection<WatchRow> Items { get; } = new();

    public JailsPage()
    {
        InitializeComponent();
        WatchList.ItemsSource = Items;
    }

    private async void Query_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        var name = JailNameBox.Text.Trim();
        if (name.Length == 0) return;
        try
        {
            var data = await IpcClient.CallAsync("jail", new Dictionary<string, object?> { ["name"] = name });
            Items.Clear();
            if (data.TryGetProperty("watching", out var w))
            {
                foreach (var it in w.EnumerateArray())
                {
                    Items.Add(new WatchRow(
                        it.GetProperty("ip").GetString() ?? "",
                        it.GetProperty("fails").GetInt32()));
                }
            }
        }
        catch (Exception ex)
        {
            var dlg = new ContentDialog
            {
                XamlRoot = XamlRoot,
                Title = "错误",
                Content = ex.Message,
                CloseButtonText = "确定"
            };
            _ = dlg.ShowAsync();
        }
    }
}
