use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

fn default_poll_ms() -> u64 {
    1000
}
fn default_true() -> bool {
    true
}
fn default_temp_bantime() -> u64 {
    600
}
fn default_black_bantime() -> u64 {
    86400
}
fn default_max_events() -> usize {
    20_000
}
fn default_retain_days() -> u32 {
    90
}
fn default_rule_prefix() -> String {
    "FailKeep".into()
}
fn default_backend() -> String {
    "netsh".into()
}
fn default_state_file() -> String {
    r"C:\ProgramData\FailKeep\state.json".into()
}
fn default_channel() -> String {
    "Security".into()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub service: ServiceConfig,
    #[serde(default)]
    pub lists: ListsConfig,
    #[serde(default)]
    pub firewall: FirewallConfig,
    #[serde(default)]
    pub geo: GeoConfig,
    #[serde(default)]
    pub stats: StatsConfig,
    #[serde(default, rename = "jail")]
    pub jails: Vec<JailConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServiceConfig {
    #[serde(default = "default_poll_ms")]
    pub poll_interval_ms: u64,
    #[serde(default = "default_state_file")]
    pub state_file: String,
    #[serde(default = "default_true")]
    pub whitelist_loopback: bool,
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default)]
    pub ban_private: bool,
    #[serde(default)]
    pub log_level: String,
    /// Optional PowerShell invoked on ban (env: FailKeep_IP, FailKeep_KIND, FailKeep_TIER)
    #[serde(default)]
    pub hook_on_ban: Option<String>,
    #[serde(default)]
    pub hook_on_unban: Option<String>,
    #[serde(default = "default_log_file")]
    pub log_file: String,
}

fn default_log_file() -> String {
    r"C:\ProgramData\FailKeep\FailKeep.log".into()
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: default_poll_ms(),
            state_file: default_state_file(),
            whitelist_loopback: true,
            whitelist: vec!["127.0.0.1".into()],
            ban_private: false,
            log_level: "info".into(),
            hook_on_ban: None,
            hook_on_unban: None,
            log_file: default_log_file(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListsConfig {
    #[serde(default = "default_temp_bantime")]
    pub temp_bantime: u64,
    #[serde(default)]
    pub temp_ban_refresh: bool,
    /// "timed" | "permanent"
    #[serde(default = "default_blacklist_mode")]
    pub blacklist_mode: String,
    #[serde(default = "default_black_bantime")]
    pub black_bantime: u64,
    /// 0 = remember forever
    #[serde(default)]
    pub escalation_memory: u64,
}

fn default_blacklist_mode() -> String {
    "timed".into()
}

impl Default for ListsConfig {
    fn default() -> Self {
        Self {
            temp_bantime: default_temp_bantime(),
            temp_ban_refresh: false,
            blacklist_mode: default_blacklist_mode(),
            black_bantime: default_black_bantime(),
            escalation_memory: 0,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FirewallConfig {
    #[serde(default = "default_rule_prefix")]
    pub rule_prefix: String,
    #[serde(default = "default_backend")]
    pub backend: String,
    /// "all" or comma-separated ports
    #[serde(default = "default_ban_ports")]
    pub ban_ports: String,
}

fn default_ban_ports() -> String {
    "all".into()
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            rule_prefix: default_rule_prefix(),
            backend: default_backend(),
            ban_ports: default_ban_ports(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct GeoConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub database: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StatsConfig {
    #[serde(default = "default_max_events")]
    pub max_events: usize,
    #[serde(default = "default_retain_days")]
    pub retain_days: u32,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            max_events: default_max_events(),
            retain_days: default_retain_days(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JailConfig {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_retry")]
    pub max_retry: u32,
    #[serde(default = "default_find_time")]
    pub find_time: u64,
    #[serde(default)]
    pub ignore_ip: Vec<String>,
    pub source: SourceConfig,
    #[serde(default)]
    pub filter: Option<FilterConfig>,
}

fn default_max_retry() -> u32 {
    5
}
fn default_find_time() -> u64 {
    600
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SourceConfig {
    File {
        path: String,
        #[serde(default)]
        date_pattern: Option<String>,
        #[serde(default)]
        date_format: Option<String>,
    },
    Iis {
        path: String,
        #[serde(default = "default_iis_codes")]
        status_codes: Vec<u16>,
    },
    Eventlog {
        #[serde(default = "default_channel")]
        channel: String,
        #[serde(default)]
        event_ids: Vec<u32>,
        #[serde(default)]
        ip_field: Option<String>,
        #[serde(default)]
        logon_types: Vec<u32>,
        #[serde(default)]
        ignore_users: Vec<String>,
        #[serde(default)]
        success_event_ids: Vec<u32>,
        #[serde(default)]
        success_logon_types: Vec<u32>,
        #[serde(default)]
        unban_on_success: bool,
    },
    Fwlog {
        path: String,
    },
}

fn default_iis_codes() -> Vec<u16> {
    vec![401, 403]
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FilterConfig {
    pub pattern: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let cfg: Config = toml::from_str(&raw).context("parse config TOML")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.jails.is_empty() {
            bail!("config has no [[jail]] entries");
        }
        let mut names = std::collections::HashSet::new();
        for j in &self.jails {
            if !names.insert(j.name.clone()) {
                bail!("duplicate jail name: {}", j.name);
            }
            if j.max_retry == 0 {
                bail!("jail {}: max_retry must be > 0", j.name);
            }
            if j.find_time == 0 {
                bail!("jail {}: find_time must be > 0", j.name);
            }
            match &j.source {
                SourceConfig::File { path, date_pattern, .. } => {
                    if path.is_empty() {
                        bail!("jail {}: file path empty", j.name);
                    }
                    if let Some(p) = date_pattern {
                        regex::Regex::new(p)
                            .with_context(|| format!("jail {}: bad date_pattern", j.name))?;
                    }
                }
                SourceConfig::Iis { path, .. } | SourceConfig::Fwlog { path } => {
                    if path.is_empty() {
                        bail!("jail {}: path empty", j.name);
                    }
                }
                SourceConfig::Eventlog { event_ids, .. } => {
                    if event_ids.is_empty() {
                        bail!("jail {}: eventlog event_ids empty", j.name);
                    }
                }
            }
            if let Some(f) = &j.filter {
                regex::Regex::new(&f.pattern)
                    .with_context(|| format!("jail {}: bad filter.pattern", j.name))?;
            } else if matches!(j.source, SourceConfig::File { .. }) {
                bail!("jail {}: file source requires [jail.filter].pattern", j.name);
            }
        }
        let mode = self.lists.blacklist_mode.as_str();
        if mode != "timed" && mode != "permanent" {
            bail!("lists.blacklist_mode must be timed|permanent, got {mode}");
        }
        let ports = self.firewall.ban_ports.trim();
        if ports != "all" && !ports.is_empty() {
            for p in ports.split(',') {
                let p = p.trim();
                if p.is_empty() {
                    continue;
                }
                p.parse::<u16>()
                    .with_context(|| format!("firewall.ban_ports invalid port {p}"))?;
            }
        }
        for w in &self.service.whitelist {
            parse_ip_or_cidr(w).with_context(|| format!("bad whitelist entry {w}"))?;
        }
        Ok(())
    }

    pub fn whitelist_nets(&self) -> Vec<IpNet> {
        self.service
            .whitelist
            .iter()
            .filter_map(|s| parse_ip_or_cidr(s).ok())
            .collect()
    }

    pub fn state_path(&self) -> PathBuf {
        PathBuf::from(&self.service.state_file)
    }
}

pub fn parse_ip_or_cidr(s: &str) -> Result<IpNet> {
    let s = s.trim();
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(IpNet::from(ip));
    }
    s.parse::<IpNet>().with_context(|| format!("parse {s}"))
}

pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

pub fn is_loopback_ip(ip: IpAddr) -> bool {
    ip.is_loopback()
}

/// Jail-specific list overrides (optional nested table kept simple for stage A).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct JailListsOverride {
    pub temp_bantime: Option<u64>,
    pub black_bantime: Option<u64>,
    pub blacklist_mode: Option<String>,
}

pub type JailMap = BTreeMap<String, JailConfig>;
