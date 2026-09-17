# FailKeep

[English](README.md) | **简体中文**

面向 Windows Server 的轻量级类 fail2ban IP 封禁服务（Rust 实现）。

- **精简包**：`failkeep.exe`（Windows 服务 + CLI）— 无 UI 依赖，适合无人值守服务器
- **完整包**：精简包 + 可选 WinUI 3 管理界面（`ui/FailKeep.Ui`）

## 功能特性

| 类别 | 说明 |
|------|------|
| 日志源 | Security 事件日志（RDP 4625）、OpenSSH/sshd 日志文件、IIS W3C、自定义正则日志、防火墙 DROP 日志 |
| 名单模型 | 白名单 → 临时黑名单 → 黑名单（支持升级记忆） |
| 防火墙 | 通过 netsh 操作 Windows 防火墙；`ban_ports` 可封全部端口或指定端口 |
| 统计 | 24 小时 / 3 天 / 7 天 / 全部封禁次数 + 最近攻击 IP |
| 地理位置 | 可选本地 MaxMind mmdb（编译时 `--features geo`） |
| 运维 | CLI、dry-run 试运行、供 UI 使用的 IPC、PowerShell 钩子、日志轮转 |
| 服务 | 可安装/卸载为 Windows SCM 服务（需管理员） |

## 编译

```powershell
cargo build --release

# 可选：启用本地 GeoIP（需自行准备 mmdb 库文件）
cargo build --release --features geo
```

生成二进制：`target\release\failkeep.exe`

## 快速开始

```powershell
# 管理员 PowerShell
New-Item -ItemType Directory -Force C:\ProgramData\FailKeep
Copy-Item config.example.toml C:\ProgramData\FailKeep\config.toml
# 按需修改白名单、Jail 等

.\target\release\failkeep.exe check-config
.\target\release\failkeep.exe install          # 注册服务 FailKeep（开机自启）
sc start FailKeep
.\target\release\failkeep.exe status

# 前台调试
.\target\release\failkeep.exe run
.\target\release\failkeep.exe run --dry-run    # 只决策，不改防火墙
```

若要防护 RDP，需开启登录审核（Security 4625/4624）：

```powershell
# 中文系统
auditpol /set /subcategory:"登录" /success:enable /failure:enable
# 英文系统
# auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

未安装 OpenSSH 时，可将配置中的 `ssh` Jail 设为 `enabled = false`。

## 命令行（CLI）

```
failkeep run [--dry-run]     # 前台运行 + 启动 IPC
failkeep check-config        # 校验配置
failkeep status              # 总览
failkeep list [--whitelist|--temp|--black]
failkeep stats               # 24h/3d/7d/全部 封禁统计
failkeep jail <名称>         # 查看某 Jail 中正在计数的 IP
failkeep ban <ip> [--black] [--permanent] [--time 秒]
failkeep unban <ip> | --all
failkeep unblack <ip>
failkeep whitelist add|remove <ip>
failkeep purge-rules         # 清除 FailKeep:* 防火墙规则
failkeep install
failkeep uninstall [--purge-rules]
```

默认配置路径：`C:\ProgramData\FailKeep\config.toml`（可用 `--config` 覆盖）。

## 封禁模型

1. 在 `find_time` 时间窗内累计失败次数（按 Jail 独立计数）。
2. 达到 `max_retry` → 进入 **临时黑名单**（时长 `temp_bantime`）。
3. 临时黑到期后释放，但保留「曾临时封禁」记忆（`escalation_memory`，`0` 表示永久记住）。
4. 再次达到 `max_retry` → 升级为 **黑名单**（`blacklist_mode`：`permanent` 永久 或 `timed` 定时清理）。
5. **白名单始终优先**，永不自动封禁；默认不封私网地址（`ban_private = false`）。
6. 可配置成功登录事件（如 4624、sshd Accepted）清空该 IP 的失败计数。

防火墙规则命名：

```
FailKeep:temp:<ip>    # 临时黑名单
FailKeep:black:<ip>   # 黑名单
```

## 三档名单说明

| 档位 | 含义 |
|------|------|
| 白名单 | 信任 IP/CIDR，永不自动封禁 |
| 临时黑名单 | 首次「多次失败」后的短期封禁 |
| 黑名单 | 临时黑释放后再次「多次失败」升级；可永久或到期自动清出 |

## IPC（供 UI / 本机 CLI）

当服务或 `run` 在运行时：

- 仅监听 `127.0.0.1:<端口>`（回环，不对外网开放）
- 端点文件：`C:\ProgramData\FailKeep\ipc.json`（含 `port` 与随机 `token`）
- 请求信封：`{"token":"...","req":{"cmd":"status"}}`

CLI 在检测到端点文件时会自动走 IPC，与正在运行的服务通信。

## WinUI 管理界面（可选）

详见 [`ui/FailKeep.Ui/README.md`](ui/FailKeep.Ui/README.md)。

- 需要 .NET 8 + Windows App SDK
- 服务器生产环境可只部署精简包，无需 UI
- UI 不直接改防火墙，全部操作经 IPC 由服务执行

页面：**概览**（24h/3d/7d/全部 + 攻击 IP）、**名单**、**监控 Jail**、**设置**。

## 目录结构

```
src/
  main.rs service.rs config.rs engine.rs
  lists.rs jail.rs filter.rs stats.rs geo.rs ipc.rs applog.rs
  ban/     netsh 封禁 + 状态 JSON
  source/  file、eventlog、fwlog
ui/FailKeep.Ui/   WinUI 3 管理界面
installer/        Inno Setup 安装脚本
```

## 安装包（Inno Setup）

```powershell
# 需安装 Inno Setup 6（ISCC.exe）
.\installer\build-installer.ps1
# 产物：dist\FailKeep-setup-<版本>.exe
```

卸载行为：

- 停止并删除服务 `FailKeep`，删除 `FailKeep:*` 防火墙规则
- **询问**是否保留黑白名单（`state.json`）与日志（`FailKeep.log*`）
- 始终删除过期的 `ipc.json`
- 静默卸载（`/SILENT`）默认保留名单和日志

## 配置要点

完整示例见 [`config.example.toml`](config.example.toml)。

```toml
[service]
whitelist = ["127.0.0.1", "10.0.0.0/8", "192.168.0.0/16"]
ban_private = false

[lists]
temp_bantime = 600
blacklist_mode = "timed"    # 或 "permanent"
black_bantime = 86400
escalation_memory = 0

[firewall]
rule_prefix = "FailKeep"
ban_ports = "all"           # 或 "3389,22"

[[jail]]
name = "rdp"
max_retry = 5
find_time = 600
```

## 许可证

MIT
