# FailKeep

**English** | [简体中文](README.zh-CN.md)

Lightweight fail2ban-style IP ban service for Windows Server (Rust).

- **Slim package**: `failkeep.exe` (Windows service + CLI) — no UI dependencies
- **Full package**: slim + optional WinUI 3 management app (`ui/FailKeep.Ui`)

## Features

| Area | Support |
|------|---------|
| Sources | Security Event Log (RDP 4625), OpenSSH/sshd file, IIS W3C, custom regex logs, firewall DROP log |
| Lists | Whitelist → Temp blacklist → Blacklist (escalation memory) |
| Firewall | Windows Firewall via netsh; `ban_ports` all or specific |
| Stats | Ban counts for 24h / 3d / 7d / all + recent attack IPs |
| Geo | Optional local MaxMind mmdb (`--features geo`) |
| Ops | CLI, dry-run, IPC for UI, PowerShell hooks, log rotation |
| Service | Install/uninstall as SCM service (admin) |

## Build

```powershell
cargo build --release
# optional GeoIP:
cargo build --release --features geo
```

Binary: `target\release\failkeep.exe`

## Quick start

```powershell
# Admin PowerShell
New-Item -ItemType Directory -Force C:\ProgramData\FailKeep
Copy-Item config.example.toml C:\ProgramData\FailKeep\config.toml
# edit whitelist / jails

.\target\release\failkeep.exe check-config
.\target\release\failkeep.exe install          # registers service FailKeep
sc start FailKeep
.\target\release\failkeep.exe status

# Foreground debug
.\target\release\failkeep.exe run
.\target\release\failkeep.exe run --dry-run    # no firewall changes
```

Enable audit policy for RDP (Security 4625/4624):

```powershell
auditpol /set /subcategory:"登录" /success:enable /failure:enable
# English: auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

## CLI

```
failkeep run [--dry-run]     # foreground + IPC server
failkeep check-config
failkeep status
failkeep list [--whitelist|--temp|--black]
failkeep stats
failkeep jail <name>
failkeep ban <ip> [--black] [--permanent] [--time s]
failkeep unban <ip> | --all
failkeep unblack <ip>
failkeep whitelist add|remove <ip>
failkeep purge-rules
failkeep install | uninstall [--purge-rules]
```

Default config: `C:\ProgramData\FailKeep\config.toml` (`--config` to override).

## Ban model

1. Failures counted in `find_time` per jail.
2. `max_retry` → **temp blacklist** (`temp_bantime`).
3. Temp expires → remembered (`escalation_memory`, 0 = forever).
4. Fail `max_retry` again → **blacklist** (`blacklist_mode` permanent/timed).
5. Whitelist always wins; private IPs skipped unless `ban_private = true`.
6. Optional success events (4624 / sshd Accepted) clear fail counters.

Rules: `FailKeep:temp:<ip>` / `FailKeep:black:<ip>`.

## IPC (for UI / remote CLI)

When `run` or service is active:

- TCP `127.0.0.1:<port>` (loopback only)
- Endpoint: `C:\ProgramData\FailKeep\ipc.json` (`port` + `token`)
- Envelope: `{"token":"...","req":{"cmd":"status"}}`

CLI automatically uses IPC if the endpoint file is present.

## WinUI (optional)

See `ui/FailKeep.Ui/README.md`. Requires .NET 8 + Windows App SDK. Servers can ship slim only.

## Layout

```
src/
  main.rs service.rs config.rs engine.rs
  lists.rs jail.rs filter.rs stats.rs geo.rs ipc.rs applog.rs
  ban/     netsh + state JSON
  source/  file, eventlog, fwlog
ui/FailKeep.Ui/   WinUI 3 management app
```

## Installer (Inno Setup)

```powershell
# requires Inno Setup 6 (ISCC.exe)
.\installer\build-installer.ps1
# output: dist\FailKeep-setup-<version>.exe
```

Uninstall behavior:

- Stops and removes service `FailKeep`, deletes `FailKeep:*` firewall rules
- Asks whether to keep **lists** (`state.json`) and **logs** (`FailKeep.log*`)
- Always removes stale `ipc.json`
- Silent uninstall (`/SILENT`) keeps lists and logs by default

## License

MIT
