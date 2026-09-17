# FailKeep-ui (WinUI 3, unpackaged)

Optional management UI for the FailKeep service. **Not required** on servers (use CLI / slim package).

## Requirements

- Windows 10 1809+ / Windows Server 2019+
- .NET 8 SDK
- Windows App SDK (pulled by NuGet)

## Build

```powershell
cd ui/FailKeep.Ui
dotnet build -c Release
dotnet publish -c Release -r win-x64 --self-contained false -o publish
```

Self-contained (larger, no shared runtime):

```powershell
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish-sc
```

## Run

1. Start FailKeep service or `FailKeep run` (IPC listens on 127.0.0.1, endpoint file `C:\ProgramData\FailKeep\ipc.json`).
2. Run `publish\FailKeep.Ui.exe` **as Administrator** (needed for ban/unban via service IPC token check is file-based; admin recommended).

## Pages

- **概览**: 24h / 3d / 7d / all ban counts + recent attacking IPs (geo when available)
- **名单**: whitelist / temp / black lists, unban
- **监控**: per-jail watching fail counts
- **设置**: IPC status, config path, about

UI never touches Windows Firewall directly; all mutations go through the service IPC.
