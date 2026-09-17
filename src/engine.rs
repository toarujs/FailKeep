use crate::ban::firewall::{apply_ban, reconcile, Firewall};
use crate::ban::state::{load as load_state, save as save_state, PersistedState};
use crate::config::Config;
use crate::jail::Jail;
use crate::lists::{BanAction, ListManager, Tier};
use crate::stats::{BanEvent, BanEventTier, Stats};
use anyhow::Result;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;
use tracing::{info, warn};

pub type EngineHandle = Arc<Mutex<EngineInner>>;

pub struct Engine {
    inner: EngineHandle,
    stop: Arc<AtomicBool>,
}

pub struct EngineInner {
    cfg: Config,
    jails: Vec<Jail>,
    lists: ListManager,
    stats: Stats,
    fw: Firewall,
    state_path: PathBuf,
    dry_run: bool,
    dirty: bool,
    eventlog_records: HashMap<String, u64>,
}

impl Engine {
    pub fn new(cfg: Config, dry_run: bool) -> Result<Self> {
        let mut jails = Vec::new();
        for j in cfg.jails.clone() {
            if !j.enabled {
                continue;
            }
            match Jail::new(j) {
                Ok(jail) => jails.push(jail),
                Err(e) => warn!("skip jail: {e:#}"),
            }
        }
        let lists = ListManager::new(
            cfg.lists.clone(),
            cfg.whitelist_nets(),
            cfg.service.ban_private,
        );
        let stats = Stats::new(cfg.stats.max_events, cfg.stats.retain_days);
        let fw = Firewall::new(&cfg.firewall, dry_run);
        let state_path = cfg.state_path();
        let mut inner = EngineInner {
            cfg,
            jails,
            lists,
            stats,
            fw,
            state_path,
            dry_run,
            dirty: false,
            eventlog_records: HashMap::new(),
        };
        inner.restore()?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn handle(&self) -> EngineHandle {
        Arc::clone(&self.inner)
    }

    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    pub fn run_loop(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        let interval = {
            let g = self.inner.lock().unwrap();
            Duration::from_millis(g.cfg.service.poll_interval_ms.max(100))
        };
        {
            let g = self.inner.lock().unwrap();
            info!(
                "engine start: jails={:?} poll={}ms dry_run={}",
                g.jails.iter().map(|j| j.cfg.name.clone()).collect::<Vec<_>>(),
                interval.as_millis(),
                g.dry_run
            );
        }
        loop {
            if shutdown.load(Ordering::Relaxed) || self.stop.load(Ordering::Relaxed) {
                break;
            }
            {
                let mut g = self.inner.lock().unwrap();
                if let Err(e) = g.tick() {
                    warn!("tick error: {e:#}");
                }
            }
            let mut left = interval;
            while left > Duration::ZERO
                && !shutdown.load(Ordering::Relaxed)
                && !self.stop.load(Ordering::Relaxed)
            {
                let step = left.min(Duration::from_millis(100));
                std::thread::sleep(step);
                left = left.saturating_sub(step);
            }
        }
        info!("engine stopping; persisting");
        self.inner.lock().unwrap().persist()?;
        Ok(())
    }
}

impl EngineInner {
    fn restore(&mut self) -> Result<()> {
        let st = load_state(&self.state_path)?;
        self.lists.set_from_persisted(st.records);
        self.stats = Stats::from_events(
            st.events,
            self.cfg.stats.max_events,
            self.cfg.stats.retain_days,
        );
        for (path, off) in &st.offsets {
            for jail in &mut self.jails {
                if let Some(t) = jail.tailer.as_mut() {
                    t.restore_offset(path.clone(), *off);
                }
            }
        }
        for (ch, rid) in st.eventlog_records {
            for jail in &mut self.jails {
                if let Some(el) = jail.eventlog.as_mut() {
                    if el.channel() == ch {
                        el.restore_record_id(rid);
                    }
                }
            }
        }
        if !self.dry_run {
            let desired: Vec<(IpAddr, Tier)> = self
                .lists
                .banned_ips()
                .into_iter()
                .map(|(ip, tier, _, _)| (ip, tier))
                .collect();
            match reconcile(&self.fw, &desired) {
                Ok((to_ban, to_unban)) => {
                    for (ip, tier) in to_ban {
                        info!("restore ban {ip} ({tier:?})");
                        let _ = apply_ban(&self.fw, ip, tier);
                    }
                    for ip in to_unban {
                        info!("remove orphan firewall ban {ip}");
                        let _ = self.fw.unban(ip);
                    }
                }
                Err(e) => warn!("firewall reconcile skipped: {e:#}"),
            }
        }
        Ok(())
    }

    pub fn persist(&mut self) -> Result<()> {
        if self.dry_run {
            return Ok(());
        }
        let mut map: HashMap<PathBuf, u64> = HashMap::new();
        for j in &self.jails {
            if let Some(t) = j.tailer.as_ref() {
                for (p, o) in t.offsets_snapshot() {
                    map.insert(p, o);
                }
            }
        }
        let mut eventlog_records = HashMap::new();
        for j in &self.jails {
            if let Some(el) = j.eventlog.as_ref() {
                eventlog_records.insert(el.channel().to_string(), el.last_record_id());
            }
        }
        let mut st = PersistedState {
            records: self.lists.export_records(),
            events: self.stats.export_events(),
            offsets: map.into_iter().collect(),
            eventlog_records,
            saved_at: None,
        };
        save_state(&self.state_path, &mut st)?;
        self.dirty = false;
        Ok(())
    }

    pub fn lists(&self) -> &ListManager {
        &self.lists
    }
    pub fn lists_mut(&mut self) -> &mut ListManager {
        &mut self.lists
    }
    pub fn stats(&self) -> &Stats {
        &self.stats
    }
    pub fn fw(&self) -> &Firewall {
        &self.fw
    }
    pub fn dry_run(&self) -> bool {
        self.dry_run
    }
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn jail_status(&mut self, name: &str) -> Option<JailStatus> {
        let now = OffsetDateTime::now_utc();
        let jail = self.jails.iter().find(|j| j.cfg.name == name)?;
        let top = jail.fails.top(now, jail.cfg.find_time, 20);
        Some(JailStatus {
            name: jail.cfg.name.clone(),
            max_retry: jail.cfg.max_retry,
            find_time: jail.cfg.find_time,
            watching: top,
        })
    }

    pub fn tick(&mut self) -> Result<()> {
        let now = OffsetDateTime::now_utc();
        let mut new_bans = Vec::new();
        let mut successes: Vec<(String, IpAddr)> = Vec::new();

        for jail in &mut self.jails {
            // file / iis / fwlog
            let mut hits = match jail.poll_file(now) {
                Ok(h) => h,
                Err(e) => {
                    warn!("jail {} file poll: {e:#}", jail.cfg.name);
                    Vec::new()
                }
            };
            // event log
            if let Some(el) = jail.eventlog.as_mut() {
                match el.poll() {
                    Ok((f, s, _rid)) => {
                        for mut h in f {
                            h.jail = jail.cfg.name.clone();
                            hits.push(h);
                        }
                        for ip in s {
                            successes.push((jail.cfg.name.clone(), ip));
                        }
                    }
                    Err(e) => warn!("jail {} eventlog: {e:#}", jail.cfg.name),
                }
            }

            for hit in hits {
                if jail.ignored_ip(hit.ip) {
                    continue;
                }
                if self.lists.is_whitelisted(hit.ip) {
                    continue;
                }
                if !matches!(
                    self.lists.tier_of(hit.ip),
                    Tier::Unlisted | Tier::Whitelist
                ) {
                    continue;
                }
                let count = jail.record_fail(hit.ip, hit.at);
                if count >= jail.cfg.max_retry && self.lists.can_auto_ban(hit.ip) {
                    let d = self.lists.on_threshold(hit.ip, &jail.cfg.name, now);
                    if !matches!(d.action, BanAction::None) {
                        new_bans.push(d);
                    }
                }
            }
        }

        // successes clear fail counters (and optionally unban)
        for (jail_name, ip) in successes {
            for jail in &mut self.jails {
                if jail.cfg.name == jail_name {
                    jail.on_success(ip);
                }
            }
            // unban_on_success from eventlog policy
            let unban = self.jails.iter().find_map(|j| {
                if j.cfg.name == jail_name {
                    j.eventlog
                        .as_ref()
                        .map(|e| e.policy().unban_on_success)
                } else {
                    None
                }
            });
            if unban == Some(true)
                && matches!(self.lists.tier_of(ip), Tier::Temp | Tier::Black)
            {
                let d = self.lists.unban(ip, now);
                info!("unban {ip} on success ({jail_name})");
                if let Err(e) = self.fw.unban(d.ip) {
                    warn!("unban fw {ip}: {e:#}");
                }
                self.dirty = true;
            }
        }

        for d in new_bans {
            match &d.action {
                BanAction::BanTemp { .. } | BanAction::BanBlack { .. } => {
                    info!("BAN {} tier={:?} note={}", d.ip, d.tier, d.note);
                    if let Err(e) = apply_ban(&self.fw, d.ip, d.tier) {
                        warn!("firewall ban {} failed: {e:#}", d.ip);
                    }
                    let (tier_ev, jail) = {
                        let r = self.lists.record(d.ip);
                        (
                            match d.tier {
                                Tier::Black => BanEventTier::Black,
                                _ => BanEventTier::Temp,
                            },
                            r.and_then(|r| r.source_jail.clone()),
                        )
                    };
                    self.stats.push(BanEvent {
                        ip: d.ip,
                        tier: tier_ev,
                        at: now,
                        jail,
                        manual: false,
                    });
                    self.run_hooks("ban", d.ip, d.tier);
                    self.dirty = true;
                }
                BanAction::Unban => {
                    if let Err(e) = self.fw.unban(d.ip) {
                        warn!("firewall unban {} failed: {e:#}", d.ip);
                    }
                    self.dirty = true;
                }
                BanAction::None => {}
            }
        }

        let expired = self.lists.tick_expiry(now);
        for d in expired {
            info!("UNBAN {} ({})", d.ip, d.note);
            if let Err(e) = self.fw.unban(d.ip) {
                warn!("unban {} failed: {e:#}", d.ip);
            }
            self.run_hooks("unban", d.ip, d.tier);
            self.dirty = true;
        }

        if now.second() == 0 {
            for jail in &mut self.jails {
                let ft = jail.cfg.find_time;
                jail.fails.prune_all(now, ft);
            }
            self.dirty = true;
        }

        if self.dirty {
            if let Err(e) = self.persist() {
                warn!("persist state: {e:#}");
            }
        }
        Ok(())
    }

    fn run_hooks(&self, kind: &str, ip: IpAddr, tier: Tier) {
        let script = match kind {
            "ban" => self.cfg.service.hook_on_ban.as_deref(),
            _ => self.cfg.service.hook_on_unban.as_deref(),
        };
        let Some(script) = script else { return };
        if script.is_empty() {
            return;
        }
        let mut cmd = std::process::Command::new("powershell.exe");
        cmd.arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-Command")
            .arg(script)
            .env("FAILKEEP_IP", ip.to_string())
            .env("FAILKEEP_KIND", kind)
            .env("FAILKEEP_TIER", format!("{tier:?}").to_lowercase());
        match cmd.output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => warn!(
                "hook {kind} exit={:?} stderr={}",
                o.status.code(),
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => warn!("hook {kind} spawn: {e}"),
        }
    }

    pub fn apply_decision(&mut self, d: crate::lists::Decision, manual: bool) -> Result<()> {
        let now = OffsetDateTime::now_utc();
        match &d.action {
            BanAction::BanTemp { .. } | BanAction::BanBlack { .. } => {
                apply_ban(&self.fw, d.ip, d.tier)?;
                let tier_ev = match d.tier {
                    Tier::Black => BanEventTier::Black,
                    _ => BanEventTier::Temp,
                };
                self.stats.push(BanEvent {
                    ip: d.ip,
                    tier: tier_ev,
                    at: now,
                    jail: self.lists.record(d.ip).and_then(|r| r.source_jail.clone()),
                    manual,
                });
                self.run_hooks("ban", d.ip, d.tier);
            }
            BanAction::Unban => {
                self.fw.unban(d.ip)?;
                self.run_hooks("unban", d.ip, Tier::Unlisted);
            }
            BanAction::None => {}
        }
        self.persist()?;
        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct JailStatus {
    pub name: String,
    pub max_retry: u32,
    pub find_time: u64,
    pub watching: Vec<(IpAddr, u32)>,
}
