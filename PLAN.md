# FailKeep — Windows Server 轻量 IP 封禁服务规划

类 fail2ban 的 Windows Server 常驻防护：从多种日志源识别失败/攻击行为，按 Jail 规则计数；采用 **白名单 / 临时黑名单 / 黑名单** 三档名单模型，首次超阈进入临时黑名单，再次超阈升级为黑名单（可永久或定时清理），到期后调用 Windows 防火墙自动解封。

**分发形态**：**精简版（仅服务 + CLI）** 与 **完整版（+ 可选 WinUI 管理界面）** 分开打包；UI 按需启动，不进入常驻进程。

---

## 1. 目标与约束

| 维度 | 目标 |
|------|------|
| 平台 | Windows Server 2016+（x64）；UI 完整版建议 Server 2019/2022+ |
| 语言 | 核心 Rust；UI：C# + WinUI 3（独立进程） |
| 形态 | Windows 服务（可控制台调试运行）+ 可选 GUI |
| 封禁手段 | Windows 防火墙入站 Block 规则 |
| 日志源 | **默认内置 RDP、SSH**；另支持 IIS、自定义日志、防火墙丢弃日志 |
| 名单模型 | 白名单 → 临时黑名单 → 黑名单（可升级、可定时/永久） |
| 轻量 | **精简版**空闲 RSS ≤ 25MB、CPU ≤ 0.5%；UI 仅打开时占用，关闭即 0 |
| 可运维 | 开机自启、崩溃可恢复、CLI 名单管理、可选 GUI、紧急解封 |

**非目标（首版不做）**

- 出站过滤 / 应用层代理
- 分布式联动、远程 Web 控制台（本机 GUI / CLI 即可）
- 内核驱动级拦截
- UI 常驻托盘（阶段 E 可选；默认「用完即关」）
- IPv6 完整策略（结构预留，规则生成首版以 IPv4 为主，配置层兼容 IPv6 字面量）

---

## 2. 总体架构

```
                    ┌──────────────────────────────┐
                    │     Windows Service Host     │
                    │  start / stop / shutdown     │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │         Core Engine          │
                    │                              │
   ┌────────────┐   │  ┌──────────┐  ┌──────────┐  │
   │ Event Log  ├───┼─►│          │  │          │  │
   │ Watcher    │   │  │  Fail    │  │  Jail    │  │
   ├────────────┤   │  │ Detector │─►│ Manager  │  │
   │ IIS / File ├───┼─►│ (regex / │  │ (计数/   │  │
   │ Tailer     │   │  │  fields) │  │  时间窗) │  │
   ├────────────┤   │  │          │  │          │  │
   │ FW Drop    ├───┼─►│          │  └────┬─────┘  │
   │ Log Tail   │   │  └──────────┘       │        │
   └────────────┘   │                     ▼        │
                    │         ┌────────────────┐   │
                    │         │  List Manager  │   │
                    │         │ 白/临时黑/黑    │   │
                    │         └───────┬────────┘   │
                    │                 ▼            │
                    │         ┌────────────────┐   │
                    │         │  Ban Executor  │   │
                    │         │  (防火墙规则)   │   │
                    │         └───────┬────────┘   │
                    └─────────────────┼────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              ▼                       ▼                       ▼
     Windows Firewall          Named Pipe IPC            状态 JSON
     (netsh / 可选 WFP)    (CLI / 可选 UI 共用)         (ProgramData)
                                      ▲
                                      │
                    ┌─────────────────┴─────────────────┐
                    │  FailKeep.exe CLI（精简版必备）        │
                    │  FailKeep-ui.exe（完整版可选，WinUI3）│
                    └───────────────────────────────────┘
```

### 打包分发

| 包 | 内容 | 适用 |
|----|------|------|
| **FailKeep-slim**（服务器默认） | `FailKeep.exe`（服务 + CLI）+ 示例配置 | 无人值守、脚本运维 |
| **FailKeep-full** | slim + `FailKeep-ui`（WinUI 3） | 需要可视化名单/状态管理 |

- 精简版 **不包含** Windows App SDK / WebView2 / 任何 UI 依赖。
- 完整版 UI **不注册为服务**、默认不自启；手动打开，关闭即释放内存。
- 共用 `%ProgramData%\FailKeep\`；未装 UI 时 CLI 功能完整。

### 核心数据流

1. 各 **Source Watcher** 周期读取「增量」内容（事件书签 / 文件 offset）。
2. **Fail Detector** 用规则提取失败记录中的源 IP。
3. 先查 **白名单**：命中则丢弃，永不封禁。
4. **Jail Manager** 在滑动时间窗内累加失败次数；达到 `max_retry` 交给 **List Manager** 决策。
5. **List Manager** 按当前档位与历史决定：进入 **临时黑名单**，或从临时黑升级为 **黑名单**。
6. **Ban Executor** 创建/删除防火墙规则；到期自动解封。
7. **State Store** 持久化三档名单与「曾临时封禁」标记，重启后恢复。
8. **CLI / UI** 走同一 IPC；服务是唯一权威，UI 不直连防火墙。

---

## 3. 模块划分

```
FailKeep/
├── Cargo.toml
├── PLAN.md
├── README.md
├── config.example.toml
├── src/
│   ├── main.rs              # CLI 入口
│   ├── service.rs           # Windows 服务包装
│   ├── config.rs            # TOML 配置加载与校验
│   ├── engine.rs            # 主循环
│   ├── filter.rs            # 失败判定与 IP 提取
│   ├── jail.rs              # 失败计数、时间窗、超阈上报
│   ├── lists.rs             # 三档名单与升级
│   ├── stats.rs             # 封禁事件历史与 24h/3d/7d/全部 聚合
│   ├── geo.rs               # 本地 GeoIP（mmdb）+ LRU 缓存
│   ├── ipc.rs               # 命名管道（CLI/UI 共用协议）
│   ├── ban/
│   │   ├── mod.rs
│   │   ├── firewall.rs      # netsh 封禁/解封/列出规则
│   │   └── state.rs         # 三档名单与打击历史持久化
│   └── source/
│       ├── mod.rs
│       ├── eventlog.rs      # Security 事件日志（4625 等）
│       ├── file.rs          # 通用日志 tail（含 IIS、自定义）
│       └── fwlog.rs         # 防火墙丢弃日志
├── ui/                      # 可选，仅完整版
│   └── FailKeep.Ui/            # WinUI 3 (C#) unpackaged
│       ├── App.xaml(.cs)
│       ├── MainWindow.xaml
│       ├── Ipc/NamedPipeClient.cs
│       └── ViewModels/
└── tests/
    └── lists_jail.rs        # 名单升级、时间窗、CIDR 单测
```

| 模块 | 职责 |
|------|------|
| `service` | 注册/卸载服务，控制信号 → 引擎关停 |
| `config` | 读配置、默认值、CIDR/时长解析、启动校验 |
| `source::*` | 只产出「原始日志行 / 事件字段」，不理解封禁语义 |
| `filter` | 判定是否失败、抽出 `IpAddr` |
| `jail` | 每个 Jail 独立计数；超阈上报，不直接封禁 |
| `lists` | 三档名单、升级决策、到期清理、手动名单操作 |
| `stats` | `BanEvent` 环形缓冲、时段封禁次数聚合 |
| `geo` | mmdb 国家查询 + 缓存；库缺失时静默降级 |
| `ipc` | 命名管道服务端：状态查询、名单命令、统计、简单鉴权 |
| `ban::firewall` | 与系统防火墙交互（规则前缀隔离、幂等） |
| `ban::state` | JSON 持久化，支持重启恢复 |
| `engine` | 调度轮询、汇聚事件、驱动到期处理 |
| `ui`（可选） | 管理界面；只调 IPC，不直连防火墙/日志 |

---

## 4. 关键设计决策

### 4.1 轻量运行时：std 线程，不引入 tokio

工作负载本质是「阻塞读 + 定时器 + 少量 IPC」，不需要完整 async 运行时。

- 每个 Source 一个 worker 线程，`mpsc` 把失败 IP 事件送给 Engine。
- Engine 单线程：处理事件、维护 Jail、扫描到期封禁、写状态。
- 理由：更小 RSS、更少运行时调度，适合长期空闲驻留。

### 4.2 增量读取，禁止全量重扫

| 源 | 增量策略 |
|----|----------|
| Event Log | `EvtQuery` + Bookmark，只取新事件 |
| 文件 / IIS | 记录 `(path, offset)`；文件变小/消失视为轮转，从新文件开头读 |
| IIS 新文件 | 监视目录，发现新的 `u_ex*.log` 自动接入 |
| 防火墙日志 | 同文件 tail |

空闲时仅：检查 mtime/size 或事件计数，不做正则全文件扫描。

### 4.3 封禁后端：首版 netsh，结构预留 WFP

```
netsh advfirewall firewall add rule name="FailKeep:rdp-bruteforce:1.2.3.4" ^
    dir=in action=block remoteip=1.2.3.4
netsh advfirewall firewall delete rule name="FailKeep:..."
```

| 方案 | 优点 | 缺点 |
|------|------|------|
| **netsh（首版）** | 实现简单、规则持久、易人工检查 | 每次 ban/unban 起子进程；规则极多时略慢 |
| WFP（后续） | 原生 API、批量高效 | 绑定复杂、权限/生命周期要求高 |

规则统一前缀 `FailKeep:`，便于批量识别与紧急清理。首版规模假设：同时封禁数百 IP，netsh 足够。

### 4.4 三档名单模型（核心业务语义）

每个受保护 IP 在任一时刻属于且仅属于一档之一（互斥）：

| 档位 | 含义 | 防火墙 | 来源 |
|------|------|--------|------|
| **Whitelist 白名单** | 信任 IP，永不自动封禁 | 无 Block 规则 | 配置 + CLI 动态添加 |
| **Unlisted 无名单** | 正常业务 IP，可计失败 | 无 | 默认 |
| **TempBlacklist 临时黑名单** | 首次「多次失败」后的短期封禁 | Block | 超 `max_retry` 自动进入 |
| **Blacklist 黑名单** | 再次「多次失败」后的严厉封禁 | Block | 临时黑释放后再超阈自动升级；或 CLI 手动拉黑 |

#### 升级状态机

```
                    ┌─────────────┐
        配置/CLI    │  Whitelist  │  永不自动封禁
        ─────────►  └──────┬──────┘
                           │ 移出白名单
                           ▼
                    ┌─────────────┐  max_retry 次失败/ find_time
                    │  Unlisted   │ ──────────────────────────┐
                    └──────▲──────┘                           │
                           │                                  ▼
         临时黑到期释放    │                           ┌──────────────┐
         （记住「曾临时封」）◄──────────────────────── │ TempBlacklist│
                           │                           │  bantime_tmp │
                           │ 再次 max_retry 次失败     └──────┬───────┘
                           │ （find_time 内）                 │
                           │                                  │ 有曾临时封标记
                           │                                  ▼
                    ┌──────┴──────┐                   ┌──────────────┐
                    │  Unlisted   │                   │  Blacklist   │
                    │ （黑名单到期）◄──────────────── │ permanent 或 │
                    └─────────────┘                   │ bantime_black│
                                                      └──────────────┘
```

规则细则：

1. **白名单优先**：配置项与运行时名单均先于 Jail 判定；白名单 IP 的失败只计日志/指标，不进入计数封禁路径。
2. **首次超阈** → 进入 **临时黑名单**，时长 `temp_bantime`；期间忽略该 IP 的新失败（可刷新临时到期时间，配置 `temp_ban_refresh`）。
3. **临时黑到期** → 回到 Unlisted，但保留 `temp_banned_at`（升级记忆）。默认永久记住；可选 `escalation_memory`（秒），超过后清零重新当首次。
4. **再次超阈**（已有升级记忆）→ 进入 **黑名单**：
   - `blacklist_mode = "permanent"`：永封，直到手动解封/移出；
   - `blacklist_mode = "timed"`：`black_bantime` 秒后自动清出黑名单并删防火墙规则。
5. **手动名单**：`ban --temp` / `ban --black` / `ban --permanent` / `unban` / `whitelist add|remove`；手动结果与自动路径共用同一状态机，避免双套规则。
6. **同一 IP 多 Jail**：名单与升级记忆全局一份（按 IP），任一 Jail 超阈都可推进状态机；Jail 只贡献失败计数。

#### Jail 配置项（计数触发）

- `max_retry`：时间窗内触发一次「多次失败」判定的次数
- `find_time`：滑动窗口（秒）
- `ignore_ip`：Jail 级额外忽略（在全局白名单之外）
- 超阈后不再由 Jail 决定时长，时长由名单档位配置决定

### 4.5 状态与恢复

- 内存结构（示意）：

```rust
enum ListTier { Whitelist, Unlisted, TempBlacklist, Blacklist }

struct IpRecord {
    tier: ListTier,
    temp_banned_at: Option<SystemTime>,   // 升级记忆
    ban_deadline: Option<SystemTime>,     // 临时黑到期 / 黑名单 timed 清理；None=永久或未封禁
    blacklist_permanent: bool,
    source_jail: Option<String>,          // 最近触发的 Jail
    reason: String,
}

// fails 仅内存：HashMap<IpAddr, VecDeque<SystemTime>> per jail
// records: HashMap<IpAddr, IpRecord>  — 持久化

/// 封禁历史事件（供概览 24h/3d/7d/全部 统计）
struct BanEvent {
    ip: IpAddr,
    tier: BanEventTier,      // Temp | Black
    at: SystemTime,
    jail: Option<String>,
    manual: bool,
}

// events: VecDeque<BanEvent> — 持久化；环形缓冲，超过 max_events 或 age 时裁剪
// 默认 max_events = 20_000；默认保留 90 天（「全部」= 仍在环内的全量）
```

- 落盘：**Whitelist / TempBlacklist / Blacklist / 升级记忆 / 封禁事件历史**；失败计数不持久。
- 启动：加载 state → 删除已过期封禁的防火墙规则 → 对仍有效封禁核对/补规则 → 重算到期队列。
- 配置变更：首版改配置后重启服务生效（热加载列入可选阶段）。

**统计口径（概览页）**

| 指标 | 算法 |
|------|------|
| 24h / 3d / 7d 封禁次数 | `BanEvent.at` 落在窗口内的条数（temp + black 分计 + 合计） |
| 全部 | 环形缓冲内仍保留的事件总数（非「安装以来」绝对值，文案标明） |
| 攻击 IP 属地 | 对「当前在封 + 窗口内出现过的 IP」做本地 GeoIP，结果缓存 |

**GeoIP 属地**

- **离线本地库**（服务器无外网也可用）：可选放置 `GeoLite2-Country.mmdb`（或兼容 DB-IP 库）到 `%ProgramData%\FailKeep\geo\`。
- 配置：`[geo] database = "..."`，`enabled = true`；库文件缺失时不显示属地、不报错阻断。
- 查询：`maxminddb`（或等价）只读打开；内存 LRU 缓存 IP → `country_code` / `country_name`（建议 4k 条）。
- **不调用在线 IP API**（避免隐私、延迟与外网依赖）。
- 私网/回环：直接标「内网 / 本机」，不查库。
- 属地字段：`country_code`（如 CN）、`country_name`（如 China）；UI 可显示旗帜 emoji 或纯文本。
- 许可：GeoLite2 需遵守 MaxMind 许可（归属声明）；文档说明用户自行下载放入，**发行包不内置 mmdb**。

### 4.6 安全与防误伤

- 全局 whitelist 默认：`127.0.0.0/8`、本机网卡 IP、用户管理网段
- `ban_private = false`：默认不把 RFC1918 写入临时黑/黑名单（白名单仍可手工包含）
- 提供 `unban` / `unban --all` / `whitelist add` 紧急放行
- 服务账户：Local System（读 Security 日志 + 改防火墙）

---

## 4b. UI 技术选型（美观 × 低占用）

### 约束前提

- 防护核心必须可 **无 UI 精简部署**（仅 `FailKeep.exe`）。
- UI 是 **按需管理工具**，不是常驻组件：关闭窗口 → 进程退出 → 内存归零。
- 「低占用」主要考核 **服务空闲**；UI 打开时的占用可接受但应克制（目标 < 80MB）。

### 方案对比

| 方案 | 美观 | 打开时内存 | 关闭后 | Server 兼容 | 与精简版拆分 | 结论 |
|------|------|------------|--------|-------------|--------------|------|
| **WinUI 3（C#）unpackaged** | 最佳（Fluent / Mica） | 中 40–80MB | 0 | 2019/2022 好；2016 差 | 独立 exe，天然可选 | **完整版推荐** |
| WPF + 现代主题 | 好（可仿 Fluent） | 中 30–70MB | 0 | 2016+ 最好 | 独立 exe | 兼容更宽时的备选 |
| 原生 Win32/D2D 自绘 | 中高（取决于投入） | **低 10–25MB** | 0 | 最好 | 独立 exe | 若强需求「常驻托盘」再考虑 |
| egui / iced（Rust） | 中（偏工具风） | 中低 20–40MB | 0 | 好 | 可同仓库、可 feature 门控 | 想全 Rust 单语言时可选 |
| WebView2 壳（HTML） | 高 | **高 80–150MB+** | 0 | 需 WV2 运行时 | 独立 | **不推荐**（违背轻量） |
| Electron / Tauri+Web | 高 | 很高 / 中高 | 0 | 一般 | 独立 | 服务器场景过重 |

### 决策

1. **服务 + CLI（Rust）**：精简版唯一内容；常驻占用预算只算这一层。
2. **UI（完整版）**：**WinUI 3 + C# + unpackaged**，独立进程 `FailKeep-ui.exe`。
   - 最强 Fluent 观感（NavigationView、DataGrid、主题色、圆角、暗色）。
   - 不打包进 slim；不注册服务、不默认开机自启。
   - 仅本机命名管道 IPC；不监听 TCP 端口。
3. **若未来需要托盘常驻**（阶段 E）：再评估 Win32 轻量托盘或 egui，不把 WinUI 常驻。

### WinUI 3 实现要点

| 项 | 选择 |
|----|------|
| 工程 | `ui/FailKeep.Ui`，.NET 8，Windows App SDK |
| 打包 | **Unpackaged**（xcopy 可跑），避免 Server 上 MSIX/证书负担 |
| 自包含 | 可选 `PublishSingleFile` + 自带运行时，方便离线服务器 |
| 视觉 | 系统暗/亮色、`NavigationView` 左侧栏、`DataGrid` 三档名单、状态卡片 |
| 交互 | 手动封禁/解封、白名单增删、Jail 开关（写配置需重启服务时明确提示） |
| 刷新 | 打开时拉全量；可见时 2s 轮询；隐藏/最小化暂停轮询 |
| 权限 | 管理员运行才能改名单（管道服务端校验客户端令牌） |
| 失败降级 | 服务未运行 → 空状态 +「启动服务」引导；管道拒绝 → 权限提示 |

### UI 信息架构（四页）

```
┌─────────────┬──────────────────────────────────────────────────────┐
│  FailKeep      │  概览：                                              │
│  ├ 概览      │  · 服务状态 / 当前在封（临时·黑）                     │
│  ├ 名单      │  · 封禁次数卡片：24h · 3天 · 7天 · 全部               │
│  ├ 监控      │  · 攻击 IP 表：IP / 属地 / 档位 / 来源Jail / 时间     │
│  └ 设置      │    （默认近 24h，可切 3d/7d/全部）                    │
│             ├──────────────────────────────────────────────────────┤
│             │  名单：白 / 临时黑 / 黑 DataGrid + 手动操作            │
│             ├──────────────────────────────────────────────────────┤
│             │  监控：Jail 启用与阈值                                 │
│             ├──────────────────────────────────────────────────────┤
│             │  设置：GeoIP 库路径状态、路径、关于                    │
└─────────────┴──────────────────────────────────────────────────────┘
```

#### 概览页规格

| 区块 | 内容 | 数据来源 |
|------|------|----------|
| 时段卡片 ×4 | **24h / 3天 / 7天 / 全部** 封禁次数（可拆 temp/black） | `stats` 聚合 |
| 当前在封 | 临时黑 n · 黑名单 m · 永久 k | `status` / `list` |
| 攻击 IP 列表 | IP、**属地**、档位、Jail、时间、剩余时长 | `stats.recent` |
| 属地展示 | `CN · China`；无库/私网 → `—` / `内网` | **服务端**解析后下发 |

- 「全部」受事件环形缓冲保留策略限制，页脚说明「保留最近 N 天 / M 条」。
- UI 不读 mmdb、不访问外网；属地字段由服务写入 IPC 响应。

### IPC 协议（CLI 与 UI 共用）

- **传输**：TCP `127.0.0.1:<ephemeral>`（仅回环；不监听局域网/公网）
- **端点文件**：`%ProgramData%\FailKeep\ipc.json` 或 `$env:FailKeep_HOME\ipc.json`（含 `port` + 随机 `token`）
- **帧**：一行 JSON 请求 → 一行 JSON 响应
- **信封**：`{"token":"...","req":{"cmd":"..."}}`；token 不匹配返回 `access_denied`

示例：

```json
{"token":"...","req":{"cmd":"list","tier":"temp"}}
{"token":"...","req":{"cmd":"ban","ip":"1.2.3.4","black":true,"permanent":true}}
{"token":"...","req":{"cmd":"unban","ip":"1.2.3.4"}}
{"token":"...","req":{"cmd":"whitelist_add","ip":"10.1.0.5"}}
{"token":"...","req":{"cmd":"status"}}
{"token":"...","req":{"cmd":"stats"}}
{"token":"...","req":{"cmd":"geo_lookup","ip":"1.2.3.4"}}
{"token":"...","req":{"cmd":"jail","name":"rdp"}}
```

- 服务停止时删除端点文件；客户端连接失败即视为服务未运行。
- CLI 在服务运行时优先走 IPC；否则本地直接操作引擎（`run` 模式）。
- WinUI 读同一端点文件，不直连防火墙。

`stats` 响应示例：

```json
{"ok":true,
 "bans":{"24h":{"temp":3,"black":1,"total":4},
         "3d":{"temp":8,"black":2,"total":10},
         "7d":{...},"all":{"total":120,"retained_events":120}},
 "current":{"temp":2,"black":5,"black_permanent":2},
 "recent":[
   {"ip":"1.2.3.4","geo":{"cc":"CN","name":"China"},
    "tier":"black","jail":"rdp","at":"2026-01-01T12:00:00Z","manual":false}
 ]}
```

- 服务端校验：客户端具备管理员 SID；否则 `{"ok":false,"error":"access_denied"}`。
- CLI 在服务运行时优先走 IPC；服务停止时对 state 文件只读展示或提示先启动服务。

---

---

## 5. 配置设计（TOML）

```toml
[service]
poll_interval_ms = 1000
state_file = "C:\\ProgramData\\FailKeep\\state.json"
log_level = "info"

# 白名单：永不自动封禁；支持单 IP 或 CIDR
whitelist = ["127.0.0.1", "10.0.0.0/8", "192.168.0.0/16"]
ban_private = false

# —— 名单策略（全局，可被 jail 覆盖见下）——
[lists]
# 临时黑名单时长（秒）：首次超阈封这么久
temp_bantime = 600
# 临时黑到期前再失败是否刷新到期时间
temp_ban_refresh = false
# 黑名单清理策略： "permanent" | "timed"
blacklist_mode = "timed"
# blacklist_mode = "timed" 时生效；到期自动清出黑名单
black_bantime = 86400
# 升级记忆（秒）：0 或省略 = 永久记住「曾临时封」；>0 则超时后重置为首次
escalation_memory = 0

[firewall]
rule_prefix = "FailKeep"
backend = "netsh"          # 预留 wfp

# 属地（可选；库文件需用户自行下载放置）
[geo]
enabled = true
database = "C:\\ProgramData\\FailKeep\\geo\\GeoLite2-Country.mmdb"
# 事件历史（供概览 24h/3d/7d/全部 统计）
[stats]
max_events = 20000
retain_days = 90

# —— 默认内置：远程桌面（Security 4625）——
[[jail]]
name = "rdp"
enabled = true
max_retry = 5
find_time = 600

[jail.source]
type = "eventlog"
channel = "Security"
event_ids = [4625]
ip_field = "IpAddress"

# —— 默认内置：Windows OpenSSH ——
# 优先 tail sshd 日志（跨版本最稳）；也可改为 eventlog 通道
[[jail]]
name = "ssh"
enabled = true
max_retry = 5
find_time = 600

[jail.source]
type = "file"
path = "C:\\ProgramData\\ssh\\logs\\sshd.log"
# 失败登录（密码/无效用户等）；可按实际日志格式调整
[jail.filter]
pattern = '(?i)failed (?:password|publickey|none) for (?:invalid user )?\S+ from (?P<ip>\d+\.\d+\.\d+\.\d+)'
# 备用：事件通道（OpenSSH 安装版本事件 ID 不同，需按环境填写）
# [jail.source]
# type = "eventlog"
# channel = "OpenSSH/Operational"
# event_ids = []            # 填入本机实际失败事件 ID
# ip_field = "IpAddress"
# 或 ip_field_regex = 'from (?P<ip>[0-9a-fA-F:.]+)'

# —— 可选：IIS 认证失败 ——
[[jail]]
name = "iis-auth"
enabled = false
max_retry = 10
find_time = 300

[jail.source]
type = "iis"
path = "C:\\inetpub\\logs\\LogFiles\\W3SVC*\\u_ex*.log"
status_codes = [401, 403]

# —— 自定义监控（用户按需开启）——
[[jail]]
name = "custom-app"
enabled = false
max_retry = 3
find_time = 60

[jail.source]
type = "file"
path = "C:\\app\\logs\\auth.log"

[jail.filter]
pattern = 'Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)'

# —— 可选：防火墙丢弃（扫描类）——
[[jail]]
name = "fw-drop-scan"
enabled = false
max_retry = 50
find_time = 60

[jail.source]
type = "fwlog"
path = "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log"
```

### 内置监控一览

| Jail | 默认 | 依赖 | 典型场景 |
|------|------|------|----------|
| `rdp` | 开 | 审核登录失败（Security 4625） | RDP / 交互登录爆破 |
| `ssh` | 开 | Windows OpenSSH + `sshd.log`（或自配事件通道） | sshd 认证失败 |
| `iis-auth` | 关 | IIS 日志 | HTTP 401/403 爆破 |
| `custom-app` | 关 | 用户路径与正则 | 任意应用日志 |
| `fw-drop-scan` | 关 | 防火墙日志开启 | 端口扫描/探测 |

自定义监控：复制 `custom-app` 或新增 `[[jail]]`，指定 `type = "file"` + `pattern`（或 eventlog/iis/fwlog）即可，无需改代码。

### 防火墙规则命名（区分档位）

```
FailKeep:temp:<ip>        # 临时黑名单
FailKeep:black:<ip>       # 黑名单
```

便于运维按前缀排查；解封时按 IP 精确删除，不依赖档位前缀匹配唯一性。

### 源类型与提取方式

| type | 输入 | 默认失败判定 | IP 来源 |
|------|------|--------------|---------|
| `eventlog` | 指定 channel + event_ids | 命中 event id 即失败 | EventData 中 `ip_field` |
| `iis` | W3C 日志 glob | status ∈ status_codes | c-ip 列 |
| `file` | 单文件/通配 | 自定义 `filter.pattern` | 命名捕获 `ip` 或组 1 |
| `fwlog` | 防火墙日志 | DROP 动作行 | 源 IP 列 |

---

## 6. 资源与性能预算

### 精简版（服务 + CLI）— 服务器 7×24

| 指标 | 预算 | 实现要点 |
|------|------|----------|
| 二进制体积 | ≤ 10 MB | release + strip + LTO；**零 UI 依赖** |
| 空闲 RSS | ≤ 25 MB | 无 tokio、有界队列、失败表与过期名单定期修剪；BanEvent 环形缓冲默认 2 万条（约 1–2MB） |
| 空闲 CPU | ≤ 0.5% | 默认 1s 轮询；文件无变化时跳过读与正则；GeoIP 仅变更/查询时触发 |
| 封禁延迟 | ≤ poll_interval + 2s | 阈值命中后立刻执行 netsh |
| 到期清理精度 | ≤ 2s | 临时黑到期、黑名单 timed 清理同一扫描 |
| 同时封禁 | 数百～千级 | netsh 串行；规则名含档位便于批量管理 |
| IPC | 空闲可忽略 | 无连接时不处理；不监听 TCP |

### 完整版 UI（`FailKeep-ui.exe`）— 仅打开时

| 指标 | 预算 | 实现要点 |
|------|------|----------|
| 安装体积 | 30–80MB（视自包含） | slim 用户可不安装 |
| 打开时 RSS | ≤ 80MB 目标 | 避免超大 DataGrid 一次加载；分页 |
| 空闲轮询 | 可见时 2s；隐藏暂停 | 不后台跑动画/不透明常驻 |
| 关闭后 | 0 | 进程退出，无托盘残留（默认） |
| 服务额外开销 | ≈0 | UI 不在服务进程内 |

**修剪策略**：

- 失败时间戳：`find_time` 外出队，空条目删除
- 临时黑/黑名单：到期即删规则并改档
- 升级记忆：`escalation_memory > 0` 时超时清除 `temp_banned_at`
- 白名单：不过期，仅手动或配置变更移除

---

## 7. CLI 与运维接口

```
FailKeep run [--config path]
FailKeep install [--config path]
FailKeep uninstall
FailKeep start | stop | status

# 名单查看
FailKeep list                      # 概览：白/临时黑/黑 计数
FailKeep list --whitelist
FailKeep list --temp
FailKeep list --black
FailKeep stats                     # 24h/3d/7d/全部 封禁次数（文本）

# 名单操作
FailKeep whitelist add <ip|cidr>
FailKeep whitelist remove <ip|cidr>
FailKeep ban <ip> [--temp|--black|--permanent] [--time seconds] [--jail manual]
FailKeep unban <ip> | --all        # 紧急解封（移出临时黑/黑，保留白名单不动）
FailKeep unblack <ip>              # 仅移出黑名单

FailKeep check-config
```

服务名：`FailKeep`；显示名：`FailKeep Lightweight Ban Service`。

日志：Windows 事件日志（Application）+ 可选滚动文件（`%ProgramData%\FailKeep\FailKeep.log`）。

GUI（完整版）：运行 `FailKeep-ui.exe`；与 CLI 共用命名管道，命令语义一致。精简版无此文件。

---

## 8. 实现阶段

### 阶段 A — 核心骨架（可跑通文件源 + 名单状态机）

1. `cargo` 工程、配置结构、`config.example.toml`（含默认 rdp/ssh/custom）
2. 通用文件 tailer（offset + 轮转）
3. 正则 Fail Detector + Jail 计数
4. **List Manager**：白名单 / 临时黑 / 黑名单升级与到期
5. netsh 封禁/解封 + 规则前缀（区分 temp/black）
6. 控制台 `run` / `list` / `ban` / `unban` / `whitelist`
7. 状态 JSON 持久化（含升级记忆）

**验收**：伪造失败日志 → 进临时黑并出现防火墙规则 → 到期释放且保留记忆 → 再次超阈进黑名单 → 定时/永久策略生效。

### 阶段 B — Windows 系统集成（RDP / SSH 默认可用）

1. Windows 服务 install/run/uninstall
2. Security 事件日志 watcher（**RDP 4625**）
3. **OpenSSH** 事件通道 / sshd 日志文件 watcher
4. IIS 日志：glob 新文件、c-ip 与状态码
5. `ban_private`、Jail 级 ignore、启动恢复三档名单
6. 文档：审核策略、OpenSSH 安装前提

**验收**：真实 RDP 连续失败进临时黑，再犯进黑；SSH 同理；重启服务后名单与防火墙规则一致。

### 阶段 C — 生产硬化

1. 防火墙丢弃日志源
2. `status` / `list` / `check-config` / 更完整错误信息
3. 单测：名单升级、时间窗、CIDR、状态恢复、过滤器
4. 集成测试脚本（临时日志文件驱动）
5. README：安装、权限、排障、紧急解封、自定义 Jail 示例

### 阶段 D — 可选增强

1. 配置热加载（文件监视 + 安全替换 Jail）
2. WFP 后端（大量 IP 时替换 netsh）
3. 简单指标导出（当前失败速率、三档名单规模）
4. ban 通知（写事件日志供 SIEM 采集）

### 阶段 E — WinUI 管理界面（完整版，可选交付）

前置：阶段 A/B 的 IPC 与名单命令已稳定。

1. `ui/FailKeep.Ui` WinUI 3 unpackaged 工程骨架 + 管道客户端
2. **概览页**：服务状态、当前在封、**24h / 3天 / 7天 / 全部** 封禁卡片、攻击 IP 表（含**属地**、档位、Jail、时间）
3. 名单页：白/临时黑/黑 DataGrid，手动 ban/unban/whitelist
4. 监控页：Jail 启用状态与关键参数只读/可写（写配置后提示重启）
5. 设置页：GeoIP 库是否就绪、数据目录、关于
6. 发布脚本：`FailKeep-full` zip = slim + ui 自包含目录（**不含** mmdb）
7. 权限与错误态：非管理员、服务未运行、无 GeoIP 库时属地列显示 `—`

**验收**：完整版 zip 部署后可点选解封；精简版 zip 在无 UI 依赖机器上安装服务正常；两版 CLI 命令一致。

---

## 9. 依赖选型（保持精简）

### 核心（Rust，精简版）

| Crate | 用途 | 备注 |
|-------|------|------|
| `windows` / `windows-service` | 服务、事件日志、命名管道 | 精简 feature |
| `serde` + `toml` | 配置与状态 | |
| `regex` | 日志过滤 | 启动时编译一次 |
| `ipnet` | CIDR 白名单 | |
| `time` | 时间戳 | 比 chrono 更轻 |
| `maxminddb` | 本地 GeoIP mmdb | 可选 feature `geo`；无库可编译 |
| `tracing` + `tracing-subscriber` | 结构化日志 | |
| `anyhow` / `thiserror` | 错误 | |
| `clap` | CLI | 可选 derive |

**不引入**：tokio、WebView2、任何 GUI 框架、HTTP 服务端。

### UI（C#，仅完整版）

| 组件 | 用途 |
|------|------|
| .NET 8 + Windows App SDK (WinUI 3) | 界面 |
| `System.IO.Pipes` | 命名管道客户端 |
| 可选 CommunityToolkit.WinUI | DataGrid / 控件 |

---

## 10. 风险与对策

| 风险 | 对策 |
|------|------|
| 误封管理员 / 监控探针 | 白名单优先 + `ban_private=false` + `unban --all` |
| Security 日志字段因策略/语言差异 | 配置化 `ip_field` / `ip_field_regex`；文档说明开启审核 |
| OpenSSH 事件 ID / 字段因版本而异 | 默认给常见组合 + 文件源备用；启动时源不可用仅告警不崩溃 |
| IIS 日志轮转导致丢行 | 新文件发现 + 旧文件读到 EOF 再切换 |
| 升级误伤（临时黑后仍被业务探测） | 可配 `escalation_memory`；黑名单 timed 可自动清理 |
| netsh 失败 | 失败重试一次并记错误事件；名单变更与防火墙尽量事务式回滚 |
| 状态文件损坏 | 解析失败则空状态启动并告警 |
| CPU 被高频日志打满 | 有界 channel；默认 1024，满则丢弃并计数告警 |
| UI 被误当成常驻组件 | 默认不自启、无托盘；文档强调 slim 为生产标配 |
| IPC 被本机恶意进程调用 | 管道 ACL + 管理员令牌校验；不监听网络端口 |
| WinUI 在旧 Server 上不可用 | 完整版标明系统要求；旧系统只发 slim + CLI |

---

## 11. 里程碑建议

| 里程碑 | 内容 | 预估 |
|--------|------|------|
| M1 | 阶段 A：文件源 + 三档名单 + 防火墙闭环 + IPC 骨架 | 1–2 天 |
| M2 | 阶段 B：服务化 + **RDP/SSH 默认** + IIS | 2–3 天 |
| M3 | 阶段 C：fwlog、测试、文档、**slim 打包** | 1–2 天 |
| M4 | 阶段 E：WinUI 完整版 + full 打包 | 2–4 天 |
| M5 | 阶段 D 按需（热加载 / WFP / 托盘） | 另计 |

---

## 12. 成功标准

1. 开箱默认保护 **RDP 与 SSH**：连续失败达阈值进入临时黑名单，再次超阈进入黑名单。
2. 临时黑到期自动解封并保留升级记忆；黑名单按 `permanent` / `timed` 策略清理。
3. 白名单 IP 在任何 Jail 下都不会被自动封禁。
4. **精简版**空闲 24h 平均内存 < 25MB，CPU < 0.5%；安装包不含 UI 依赖。
5. **完整版**可可视化管理三档名单；概览页可查看 **24h/3天/7天/全部** 封禁次数与攻击 IP **属地**（有 GeoIP 库时）；UI 关闭后无残留进程；卸载 UI 不影响服务。
6. 手动 `unban` / `whitelist add`（CLI 或 UI）立即生效；服务重启不丢失有效名单。
7. 自定义 `[[jail]]` 仅改配置即可接入新日志，无需改代码。
8. 配置错误启动失败并给出明确原因，不半开运行。

---

## 13. 功能缺口对照（相对 fail2ban / 生产实践）

审查后仍欠缺的能力。标注：**A=首版应有**，B=建议尽快，C=可延后。

### A — 首版应有（缺了会影响正确性或可运维性）

| 缺口 | 问题 | 计划 |
|------|------|------|
| **日志时间戳** | 文件/IIS 若只用「读到时刻」，延迟落盘或回放会导致 `find_time` 失真 | 解析行内时间（IIS date/time 列；自定义可配 `date_pattern`）；失败退回接收时刻 |
| **成功登录清零失败计数** | 合法用户从同 IP 登录，失败窗仍可能误封 | 可配成功事件（4624 / sshd `Accepted`）→ 清零该 Jail 下该 IP 的 fails；默认**不**自动解封，可开 `unban_on_success` |
| **4625 过滤维度** | 仅 EventID 会把服务类失败等算进来 | `logon_types = [3, 10]`、`ignore_users` |
| **封禁端口范围** | 现等价于阻断该 IP **全部入站** | `ban_ports = "all"` 或 `"3389,22"`，写入 `localport` |
| **孤儿防火墙规则对账** | state 与规则可能不一致 | 启动/周期 diff `FailKeep:` 规则 ↔ 名单，补建或删除孤儿 |
| **Jail 观察中明细** | 排障需要「未达阈值」的失败 IP | `FailKeep jail <name>` / IPC：当前 fails Top N |
| **试运行 dry-run** | 生产不敢直接改正则 | `FailKeep run --dry-run`：只决策不改防火墙 |
| **卸载与紧急清理** | uninstall 可能残留大量 Block 规则 | uninstall 默认清 `FailKeep:`；`purge-rules` 仅清规则 |

### B — 建议尽快

| 缺口 | 说明 |
|------|------|
| 黑名单二次加重 | 定时黑到期后再犯：时长 ×N 或转 permanent（fail2ban recidive） |
| 封禁/解封钩子 | 可选 PowerShell/webhook，便于 SIEM；失败不阻断 |
| 本进程日志轮转 | `FailKeep.log` 按大小滚动 |
| IPv6 实质支持 | 事件/sshd 已有 v6；规则与 CIDR 打通 |
| 导出 | `FailKeep export --csv` |
| 服务恢复策略 | install 时配置 SCM 自动重启 |

### C — 可延后

whois/反查、外部黑名单订阅、出站策略、多机同步、远程 Web 控制台。

### 并入各阶段

| 阶段 | 增量 |
|------|------|
| A | dry-run、`purge-rules`、`ban_ports` 配置骨架、对账接口预留 |
| B | logon_types/ignore_users、成功登录清零、行内时间戳、启动对账 |
| C | jail 观察明细、卸载清规则、日志轮转、SCM 恢复、钩子简版 |
| D | bantime increment、IPv6 完整、export、whois/订阅源 |

### 配置与 CLI 增补

```toml
[firewall]
ban_ports = "3389,22"          # 或 "all"

[[jail]]
name = "rdp"
max_retry = 5
find_time = 600
[jail.source]
type = "eventlog"
channel = "Security"
event_ids = [4625]
logon_types = [3, 10]
ignore_users = ["svc-health"]
success_event_ids = [4624]
success_logon_types = [3, 10]
unban_on_success = false

[[jail]]
name = "custom-app"
[jail.source]
type = "file"
date_pattern = '^(?P<ts>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})'
date_format = '%Y-%m-%d %H:%M:%S'
```

```
FailKeep jail <name>
FailKeep purge-rules
FailKeep export --csv <path>
FailKeep run --dry-run
```

