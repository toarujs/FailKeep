using FailKeep.Ui.Ipc;
using Microsoft.UI.Xaml.Controls;
using System.Collections.ObjectModel;

namespace FailKeep.Ui.Pages;

public sealed record ListRow(string Ip, string Tier, string Detail);

public sealed partial class ListsPage : Page
{
    public ObservableCollection<ListRow> Items { get; } = new();

    public ListsPage()
    {
        InitializeComponent();
        List.ItemsSource = Items;
        Loaded += async (_, _) => await RefreshAsync();
    }

    private string SelectedTier()
    {
        if (TierBox.SelectedItem is ComboBoxItem { Tag: string t }) return t;
        return "";
    }

    private async void Refresh_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => await RefreshAsync();

    private async Task RefreshAsync()
    {
        try
        {
            var data = await IpcClient.CallAsync("list", new Dictionary<string, object?>
            {
                ["tier"] = string.IsNullOrEmpty(SelectedTier()) ? null : SelectedTier()
            });
            Items.Clear();
            if (data.ValueKind == System.Text.Json.JsonValueKind.Object &&
                data.TryGetProperty("items", out var items))
            {
                foreach (var it in items.EnumerateArray())
                {
                    var ip = it.GetProperty("ip").GetString() ?? "";
                    var tier = it.GetProperty("tier").GetString() ?? "";
                    var detail = "";
                    if (it.TryGetProperty("permanent", out var p) && p.GetBoolean()) detail = "永久";
                    else if (it.TryGetProperty("deadline", out var d) && d.ValueKind == System.Text.Json.JsonValueKind.Number)
                    {
                        var dt = DateTimeOffset.FromUnixTimeSeconds(d.GetInt64()).LocalDateTime;
                        detail = dt.ToString("yyyy-MM-dd HH:mm:ss");
                    }
                    Items.Add(new ListRow(ip, tier, detail));
                }
            }
        }
        catch (Exception ex)
        {
            InfoBar($"加载失败: {ex.Message}", true);
        }
    }

    private async void Unban_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (List.SelectedItem is not ListRow row) return;
        try
        {
            await IpcClient.CallAsync("unban", new Dictionary<string, object?> { ["ip"] = row.Ip });
            await RefreshAsync();
        }
        catch (Exception ex) { InfoBar(ex.Message, true); }
    }

    private async void WhitelistAdd_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        var ip = IpBox.Text.Trim();
        if (ip.Length == 0) return;
        try
        {
            await IpcClient.CallAsync("whitelist_add", new Dictionary<string, object?> { ["ip"] = ip });
            await RefreshAsync();
        }
        catch (Exception ex) { InfoBar(ex.Message, true); }
    }

    private async void BanTemp_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        var ip = IpBox.Text.Trim();
        if (ip.Length == 0) return;
        try
        {
            await IpcClient.CallAsync("ban", new Dictionary<string, object?>
            {
                ["ip"] = ip,
                ["black"] = false,
                ["permanent"] = false
            });
            await RefreshAsync();
        }
        catch (Exception ex) { InfoBar(ex.Message, true); }
    }

    private async void BanBlack_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        var ip = IpBox.Text.Trim();
        if (ip.Length == 0) return;
        try
        {
            await IpcClient.CallAsync("ban", new Dictionary<string, object?>
            {
                ["ip"] = ip,
                ["black"] = true,
                ["permanent"] = false
            });
            await RefreshAsync();
        }
        catch (Exception ex) { InfoBar(ex.Message, true); }
    }

    private void InfoBar(string msg, bool error)
    {
        var dlg = new ContentDialog
        {
            XamlRoot = this.XamlRoot,
            Title = error ? "错误" : "提示",
            Content = msg,
            CloseButtonText = "确定"
        };
        _ = dlg.ShowAsync();
    }
}
