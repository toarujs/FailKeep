using FailKeep.Ui.Ipc;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using System.Collections.ObjectModel;

namespace FailKeep.Ui.Pages;

public sealed record RecentRow(string Ip, string Geo, string Tier, string Meta);

public sealed partial class OverviewPage : Page
{
    public ObservableCollection<RecentRow> Recent { get; } = new();
    private DispatcherTimer? _timer;

    public OverviewPage()
    {
        InitializeComponent();
        RecentList.ItemsSource = Recent;
        Loaded += async (_, _) =>
        {
            await RefreshAsync();
            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _timer.Tick += async (_, _) => await RefreshAsync();
            _timer.Start();
        };
        Unloaded += (_, _) => _timer?.Stop();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        _timer?.Stop();
        base.OnNavigatedFrom(e);
    }

    private async void Refresh_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => await RefreshAsync();

    private async Task RefreshAsync()
    {
        try
        {
            var stats = await IpcClient.CallAsync("stats");
            var win = stats.GetProperty("windows");
            C24.Text = win.GetProperty("24h").GetProperty("total").GetRawText();
            C3.Text = win.GetProperty("3d").GetProperty("total").GetRawText();
            C7.Text = win.GetProperty("7d").GetProperty("total").GetRawText();
            Call.Text = win.GetProperty("all").GetProperty("total").GetRawText();

            var status = await IpcClient.CallAsync("status");
            CurrentText.Text =
                $"当前在封：临时 {status.GetProperty("temp").GetInt32()} · 黑名单 {status.GetProperty("black").GetInt32()} · 白名单 {status.GetProperty("whitelist").GetInt32()}";

            Recent.Clear();
            if (stats.TryGetProperty("recent", out var recent))
            {
                foreach (var item in recent.EnumerateArray())
                {
                    var ip = item.GetProperty("ip").GetString() ?? "";
                    var tier = item.GetProperty("tier").GetString() ?? "";
                    var jail = item.TryGetProperty("jail", out var j) && j.ValueKind == System.Text.Json.JsonValueKind.String
                        ? j.GetString() : "";
                    var manual = item.TryGetProperty("manual", out var m) && m.GetBoolean();
                    var geo = "—";
                    if (item.TryGetProperty("geo", out var g) && g.ValueKind == System.Text.Json.JsonValueKind.Object)
                    {
                        var cc = g.TryGetProperty("country_code", out var c) ? c.GetString() : null;
                        var name = g.TryGetProperty("country_name", out var n) ? n.GetString() : null;
                        if (!string.IsNullOrEmpty(cc)) geo = $"{cc} · {name}";
                    }
                    var at = item.TryGetProperty("at", out var ts)
                        ? DateTimeOffset.FromUnixTimeSeconds(ts.GetInt64()).LocalDateTime.ToString("MM-dd HH:mm")
                        : "";
                    var meta = $"{jail} {(manual ? "手动" : "")} {at}".Trim();
                    Recent.Add(new RecentRow(ip, geo, tier, meta));
                }
            }
            ConnText.Text = "已连接 FailKeep 服务";
        }
        catch (Exception ex)
        {
            ConnText.Text = $"未连接：{ex.Message}";
        }
    }
}
