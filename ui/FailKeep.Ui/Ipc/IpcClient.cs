using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace FailKeep.Ui.Ipc;

public sealed class IpcEndpoint
{
    public int Port { get; set; }
    public string Token { get; set; } = "";
}

public static class IpcClient
{
    public static string EndpointPath { get; set; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FailKeep", "ipc.json");

    public static IpcEndpoint? TryLoadEndpoint()
    {
        try
        {
            if (!File.Exists(EndpointPath)) return null;
            var json = File.ReadAllText(EndpointPath);
            return JsonSerializer.Deserialize<IpcEndpoint>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
        }
        catch
        {
            return null;
        }
    }

    public static async Task<JsonElement> CallAsync(string cmd, object? extra = null, CancellationToken ct = default)
    {
        var ep = TryLoadEndpoint() ?? throw new InvalidOperationException("ipc.json 不存在：请先启动 FailKeep 服务或 run");
        var payload = new Dictionary<string, object?> { ["token"] = ep.Token };
        var req = new Dictionary<string, object?> { ["cmd"] = cmd };
        if (extra is Dictionary<string, object?> d)
        {
            foreach (var (k, v) in d) req[k] = v;
        }
        payload["req"] = req;

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, ep.Port, ct);
        await using var stream = client.GetStream();
        var line = JsonSerializer.Serialize(payload) + "\n";
        var bytes = Encoding.UTF8.GetBytes(line);
        await stream.WriteAsync(bytes, ct);
        await stream.FlushAsync(ct);

        using var reader = new StreamReader(stream, Encoding.UTF8);
        var resp = await reader.ReadLineAsync(ct) ?? throw new InvalidOperationException("IPC 空响应");
        using var doc = JsonDocument.Parse(resp);
        var root = doc.RootElement;
        if (root.TryGetProperty("ok", out var ok) && ok.GetBoolean())
        {
            return root.TryGetProperty("data", out var data) ? data.Clone() : default;
        }
        var err = root.TryGetProperty("error", out var e) ? e.GetString() : "unknown";
        throw new InvalidOperationException(err);
    }
}
