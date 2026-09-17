using FailKeep.Ui.Ipc;
using Microsoft.UI.Xaml.Controls;

namespace FailKeep.Ui.Pages;

public sealed partial class SettingsPage : Page
{
    public SettingsPage()
    {
        InitializeComponent();
        IpcPathText.Text = $"IPC 端点文件：{IpcClient.EndpointPath}";
        Loaded += async (_, _) => await Ping_Click(this, new Microsoft.UI.Xaml.RoutedEventArgs());
    }

    private async void Ping_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        try
        {
            var st = await IpcClient.CallAsync("status");
            StatusText.Text =
                $"服务在线。临时 {st.GetProperty("temp")} 黑 {st.GetProperty("black")} 白 {st.GetProperty("whitelist")}；24h 封禁 {st.GetProperty("bans_24h")}";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"服务不可用：{ex.Message}";
        }
    }
}
