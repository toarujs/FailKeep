use crate::lists::{IpRecord, Tier};
use crate::stats::BanEvent;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use time::OffsetDateTime;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PersistedState {
    #[serde(default)]
    pub records: HashMap<IpAddr, IpRecord>,
    #[serde(default)]
    pub events: Vec<BanEvent>,
    /// file tail offsets
    #[serde(default)]
    pub offsets: Vec<(PathBuf, u64)>,
    /// channel -> last EventRecordID
    #[serde(default)]
    pub eventlog_records: HashMap<String, u64>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub saved_at: Option<OffsetDateTime>,
}

pub fn load(path: &Path) -> Result<PersistedState> {
    if !path.exists() {
        return Ok(PersistedState::default());
    }
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let st: PersistedState = serde_json::from_str(&raw)
        .with_context(|| format!("parse state JSON {}", path.display()))?;
    Ok(st)
}

pub fn save(path: &Path, state: &mut PersistedState) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    state.saved_at = Some(OffsetDateTime::now_utc());
    let json = serde_json::to_string_pretty(state)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
    Ok(())
}

pub fn system_time_to_odt(t: SystemTime) -> OffsetDateTime {
    let d: std::time::Duration = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    OffsetDateTime::from_unix_timestamp(d.as_secs() as i64).unwrap_or_else(|_| OffsetDateTime::now_utc())
}

#[allow(dead_code)]
pub fn tier_label(t: Tier) -> &'static str {
    match t {
        Tier::Whitelist => "whitelist",
        Tier::Unlisted => "unlisted",
        Tier::Temp => "temp",
        Tier::Black => "black",
    }
}
