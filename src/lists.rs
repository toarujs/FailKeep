use crate::config::{is_loopback_ip, is_private_ip, ListsConfig};
use anyhow::Result;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Whitelist,
    Unlisted,
    Temp,
    Black,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRecord {
    pub tier: Tier,
    /// Upgrade memory: last time this IP left a temp ban
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub temp_banned_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub ban_deadline: Option<OffsetDateTime>,
    pub blacklist_permanent: bool,
    #[serde(default)]
    pub source_jail: Option<String>,
    #[serde(default)]
    pub reason: String,
}

impl Default for IpRecord {
    fn default() -> Self {
        Self {
            tier: Tier::Unlisted,
            temp_banned_at: None,
            ban_deadline: None,
            blacklist_permanent: false,
            source_jail: None,
            reason: String::new(),
        }
    }
}

/// What the executor should do after a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanAction {
    /// Enter or refresh temp ban
    BanTemp { deadline: Option<OffsetDateTime> },
    /// Enter blacklist
    BanBlack {
        permanent: bool,
        deadline: Option<OffsetDateTime>,
    },
    /// Remove ban rules
    Unban,
    /// No firewall change
    None,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub ip: IpAddr,
    pub action: BanAction,
    pub tier: Tier,
    pub note: String,
}

pub struct ListManager {
    cfg: ListsConfig,
    whitelist_nets: Vec<IpNet>,
    whitelist_exact: HashSet<IpAddr>,
    ban_private: bool,
    records: HashMap<IpAddr, IpRecord>,
}

impl ListManager {
    pub fn new(lists: ListsConfig, whitelist_nets: Vec<IpNet>, ban_private: bool) -> Self {
        let mut whitelist_exact = HashSet::new();
        let mut nets = Vec::new();
        for n in whitelist_nets {
            match n {
                IpNet::V4(v4) if v4.prefix_len() == 32 => {
                    whitelist_exact.insert(IpAddr::V4(v4.addr()));
                }
                IpNet::V6(v6) if v6.prefix_len() == 128 => {
                    whitelist_exact.insert(IpAddr::V6(v6.addr()));
                }
                other => nets.push(other),
            }
        }
        Self {
            cfg: lists,
            whitelist_nets: nets,
            whitelist_exact,
            ban_private,
            records: HashMap::new(),
        }
    }

    pub fn config(&self) -> &ListsConfig {
        &self.cfg
    }

    pub fn is_whitelisted(&self, ip: IpAddr) -> bool {
        if self.whitelist_exact.contains(&ip) {
            return true;
        }
        for n in &self.whitelist_nets {
            if n.contains(&ip) {
                return true;
            }
        }
        false
    }

    pub fn add_whitelist_ip(&mut self, ip: IpAddr) {
        self.whitelist_exact.insert(ip);
        if let Some(r) = self.records.get_mut(&ip) {
            if r.tier != Tier::Whitelist {
                r.tier = Tier::Whitelist;
                r.ban_deadline = None;
                r.blacklist_permanent = false;
            }
        } else {
            self.records.insert(
                ip,
                IpRecord {
                    tier: Tier::Whitelist,
                    ..Default::default()
                },
            );
        }
    }

    pub fn add_whitelist_net(&mut self, net: IpNet) {
        match net {
            IpNet::V4(v4) if v4.prefix_len() == 32 => self.add_whitelist_ip(IpAddr::V4(v4.addr())),
            IpNet::V6(v6) if v6.prefix_len() == 128 => self.add_whitelist_ip(IpAddr::V6(v6.addr())),
            other => self.whitelist_nets.push(other),
        }
    }

    pub fn remove_whitelist_ip(&mut self, ip: IpAddr) {
        self.whitelist_exact.remove(&ip);
        self.whitelist_nets.retain(|n| !matches!(n, IpNet::V4(v) if v.prefix_len()==32 && IpAddr::V4(v.addr())==ip));
        self.whitelist_nets.retain(|n| !matches!(n, IpNet::V6(v) if v.prefix_len()==128 && IpAddr::V6(v.addr())==ip));
        if let Some(r) = self.records.get_mut(&ip) {
            if r.tier == Tier::Whitelist {
                r.tier = Tier::Unlisted;
            }
        }
    }

    pub fn whitelist_ips(&self) -> Vec<IpAddr> {
        let mut v: Vec<_> = self.whitelist_exact.iter().copied().collect();
        v.sort();
        v
    }

    pub fn whitelist_nets(&self) -> &[IpNet] {
        &self.whitelist_nets
    }

    pub fn record(&self, ip: IpAddr) -> Option<&IpRecord> {
        self.records.get(&ip)
    }

    pub fn tier_of(&self, ip: IpAddr) -> Tier {
        if self.is_whitelisted(ip) {
            return Tier::Whitelist;
        }
        self.records.get(&ip).map(|r| r.tier).unwrap_or(Tier::Unlisted)
    }

    pub fn iter_records(&self) -> impl Iterator<Item = (IpAddr, &IpRecord)> {
        self.records.iter().map(|(k, v)| (*k, v))
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let mut w2 = 0usize;
        let mut t2 = 0usize;
        let mut b2 = 0usize;
        for (ip, r) in &self.records {
            if r.tier == Tier::Whitelist || self.is_whitelisted(*ip) {
                w2 += 1;
                continue;
            }
            match r.tier {
                Tier::Temp => t2 += 1,
                Tier::Black => b2 += 1,
                _ => {}
            }
        }
        for ip in &self.whitelist_exact {
            if !self.records.contains_key(ip) {
                w2 += 1;
            }
        }
        for _ in &self.whitelist_nets {
            w2 += 1;
        }
        (w2, t2, b2)
    }

    pub fn can_auto_ban(&self, ip: IpAddr) -> bool {
        if self.is_whitelisted(ip) || is_loopback_ip(ip) {
            return false;
        }
        if !self.ban_private && is_private_ip(ip) {
            return false;
        }
        matches!(self.tier_of(ip), Tier::Unlisted)
    }

    /// Threshold reached in a jail.
    pub fn on_threshold(&mut self, ip: IpAddr, jail: &str, now: OffsetDateTime) -> Decision {
        if self.is_whitelisted(ip) || is_loopback_ip(ip) {
            return Decision {
                ip,
                action: BanAction::None,
                tier: Tier::Whitelist,
                note: "whitelist".into(),
            };
        }
        if !self.ban_private && is_private_ip(ip) {
            return Decision {
                ip,
                action: BanAction::None,
                tier: Tier::Unlisted,
                note: "private ip skipped".into(),
            };
        }
        let rec = self.records.entry(ip).or_default();
        let has_memory = rec.temp_banned_at.map(|t| {
            if self.cfg.escalation_memory == 0 {
                true
            } else {
                (now - t).whole_seconds() as u64 <= self.cfg.escalation_memory
            }
        }) == Some(true);

        match rec.tier {
            Tier::Whitelist => Decision {
                ip,
                action: BanAction::None,
                tier: Tier::Whitelist,
                note: "whitelist".into(),
            },
            Tier::Temp => {
                if self.cfg.temp_ban_refresh {
                    let deadline = now + time::Duration::seconds(self.cfg.temp_bantime as i64);
                    rec.ban_deadline = Some(deadline);
                    rec.source_jail = Some(jail.into());
                    Decision {
                        ip,
                        action: BanAction::BanTemp {
                            deadline: Some(deadline),
                        },
                        tier: Tier::Temp,
                        note: "refresh temp ban".into(),
                    }
                } else {
                    Decision {
                        ip,
                        action: BanAction::None,
                        tier: Tier::Temp,
                        note: "already temp banned".into(),
                    }
                }
            }
            Tier::Black => Decision {
                ip,
                action: BanAction::None,
                tier: Tier::Black,
                note: "already blacklisted".into(),
            },
            Tier::Unlisted => {
                if has_memory {
                    // escalate to blacklist
                    let permanent = self.cfg.blacklist_mode == "permanent";
                    let deadline = if permanent {
                        None
                    } else {
                        Some(now + time::Duration::seconds(self.cfg.black_bantime as i64))
                    };
                    rec.tier = Tier::Black;
                    rec.blacklist_permanent = permanent;
                    rec.ban_deadline = deadline;
                    rec.source_jail = Some(jail.into());
                    rec.reason = format!("escalated from temp via {jail}");
                    Decision {
                        ip,
                        action: BanAction::BanBlack {
                            permanent,
                            deadline,
                        },
                        tier: Tier::Black,
                        note: "escalate to blacklist".into(),
                    }
                } else {
                    let deadline = now + time::Duration::seconds(self.cfg.temp_bantime as i64);
                    rec.tier = Tier::Temp;
                    rec.ban_deadline = Some(deadline);
                    rec.blacklist_permanent = false;
                    rec.source_jail = Some(jail.into());
                    rec.reason = format!("threshold in {jail}");
                    Decision {
                        ip,
                        action: BanAction::BanTemp {
                            deadline: Some(deadline),
                        },
                        tier: Tier::Temp,
                        note: "enter temp blacklist".into(),
                    }
                }
            }
        }
    }

    /// Manual ban by operator.
    pub fn manual_ban(
        &mut self,
        ip: IpAddr,
        black: bool,
        permanent: bool,
        duration_secs: Option<u64>,
        now: OffsetDateTime,
    ) -> Decision {
        let rec = self.records.entry(ip).or_default();
        if black {
            // permanent if --permanent or explicit no duration with permanent mode intent
            let is_perm = permanent || (duration_secs.is_none() && self.cfg.blacklist_mode == "permanent");
            let deadline = if is_perm {
                None
            } else {
                let d = duration_secs.unwrap_or(self.cfg.black_bantime);
                Some(now + time::Duration::seconds(d as i64))
            };
            rec.tier = Tier::Black;
            rec.blacklist_permanent = deadline.is_none();
            rec.ban_deadline = deadline;
            rec.source_jail = Some("manual".into());
            rec.reason = "manual blacklist".into();
            Decision {
                ip,
                action: BanAction::BanBlack {
                    permanent: deadline.is_none(),
                    deadline,
                },
                tier: Tier::Black,
                note: "manual black".into(),
            }
        } else {
            let d = duration_secs.unwrap_or(self.cfg.temp_bantime);
            let deadline = now + time::Duration::seconds(d as i64);
            rec.tier = Tier::Temp;
            rec.ban_deadline = Some(deadline);
            rec.blacklist_permanent = false;
            rec.source_jail = Some("manual".into());
            rec.reason = "manual temp".into();
            Decision {
                ip,
                action: BanAction::BanTemp {
                    deadline: Some(deadline),
                },
                tier: Tier::Temp,
                note: "manual temp".into(),
            }
        }
    }

    pub fn unban(&mut self, ip: IpAddr, now: OffsetDateTime) -> Decision {
        let rec = self.records.entry(ip).or_default();
        let was_black = rec.tier == Tier::Black || rec.tier == Tier::Temp;
        if rec.tier == Tier::Temp {
            rec.temp_banned_at = Some(now);
        }
        rec.tier = Tier::Unlisted;
        rec.ban_deadline = None;
        rec.blacklist_permanent = false;
        Decision {
            ip,
            action: if was_black { BanAction::Unban } else { BanAction::None },
            tier: Tier::Unlisted,
            note: "unban".into(),
        }
    }

    /// Clear only blacklist (keep temp memory).
    pub fn unblack(&mut self, ip: IpAddr, now: OffsetDateTime) -> Decision {
        let rec = self.records.entry(ip).or_default();
        let was = rec.tier == Tier::Black;
        if rec.tier == Tier::Black {
            // keep upgrade memory — already had temp before
            rec.tier = Tier::Unlisted;
            rec.ban_deadline = None;
            rec.blacklist_permanent = false;
        }
        let _ = now;
        Decision {
            ip,
            action: if was { BanAction::Unban } else { BanAction::None },
            tier: Tier::Unlisted,
            note: "unblack".into(),
        }
    }

    /// Remove expired bans; return decisions to unban in firewall.
    pub fn tick_expiry(&mut self, now: OffsetDateTime) -> Vec<Decision> {
        let mut out = Vec::new();
        for (ip, rec) in self.records.iter_mut() {
            if rec.tier == Tier::Temp || rec.tier == Tier::Black {
                if let Some(dl) = rec.ban_deadline {
                    if now >= dl {
                        let from_temp = rec.tier == Tier::Temp;
                        if from_temp {
                            rec.temp_banned_at = Some(now);
                        }
                        rec.tier = Tier::Unlisted;
                        rec.ban_deadline = None;
                        rec.blacklist_permanent = false;
                        out.push(Decision {
                            ip: *ip,
                            action: BanAction::Unban,
                            tier: Tier::Unlisted,
                            note: if from_temp {
                                "temp expired".into()
                            } else {
                                "black expired".into()
                            },
                        });
                    }
                }
            }
        }
        out
    }

    pub fn set_from_persisted(&mut self, records: HashMap<IpAddr, IpRecord>) {
        self.records = records;
    }

    pub fn export_records(&self) -> HashMap<IpAddr, IpRecord> {
        self.records.clone()
    }

    /// IPs currently in temp or black.
    pub fn banned_ips(&self) -> Vec<(IpAddr, Tier, Option<OffsetDateTime>, bool)> {
        let mut v = Vec::new();
        for (ip, r) in &self.records {
            if matches!(r.tier, Tier::Temp | Tier::Black) {
                v.push((*ip, r.tier, r.ban_deadline, r.blacklist_permanent));
            }
        }
        v.sort_by_key(|x| x.0);
        v
    }
}

/// Rolling failure counters per jail.
#[derive(Debug, Default)]
pub struct FailTracker {
    // ip -> fail timestamps
    fails: HashMap<IpAddr, VecDeque<OffsetDateTime>>,
}

impl FailTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a fail; returns count in window after insert.
    pub fn record(&mut self, ip: IpAddr, at: OffsetDateTime, find_time: u64) -> u32 {
        let cutoff = at - time::Duration::seconds(find_time as i64);
        let q = self.fails.entry(ip).or_default();
        q.push_back(at);
        while let Some(front) = q.front() {
            if *front < cutoff {
                q.pop_front();
            } else {
                break;
            }
        }
        q.len() as u32
    }

    pub fn clear(&mut self, ip: IpAddr) {
        self.fails.remove(&ip);
    }

    pub fn count(&self, ip: IpAddr, now: OffsetDateTime, find_time: u64) -> u32 {
        match self.fails.get(&ip) {
            Some(q) => {
                let cutoff = now - time::Duration::seconds(find_time as i64);
                q.iter().filter(|t| **t >= cutoff).count() as u32
            }
            None => 0,
        }
    }

    pub fn top(&self, now: OffsetDateTime, find_time: u64, n: usize) -> Vec<(IpAddr, u32)> {
        let cutoff = now - time::Duration::seconds(find_time as i64);
        let mut v: Vec<_> = self
            .fails
            .iter()
            .map(|(ip, q)| {
                let c = q.iter().filter(|t| **t >= cutoff).count() as u32;
                (*ip, c)
            })
            .filter(|(_, c)| *c > 0)
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    pub fn prune_all(&mut self, now: OffsetDateTime, find_time: u64) {
        let cutoff = now - time::Duration::seconds(find_time as i64);
        self.fails.retain(|_, q| {
            while let Some(front) = q.front() {
                if *front < cutoff {
                    q.pop_front();
                } else {
                    break;
                }
            }
            !q.is_empty()
        });
    }
}

pub fn default_lists_cfg() -> ListsConfig {
    ListsConfig::default()
}

#[allow(dead_code)]
fn _r() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn escalate_temp_then_black() {
        let mut lm = ListManager::new(ListsConfig::default(), vec![], false);
        let now = OffsetDateTime::now_utc();
        let d1 = lm.on_threshold(ip("203.0.113.10"), "rdp", now);
        assert_eq!(d1.tier, Tier::Temp);
        assert!(matches!(d1.action, BanAction::BanTemp { .. }));
        // expire temp
        let later = now + time::Duration::seconds(700);
        let expired = lm.tick_expiry(later);
        assert_eq!(expired.len(), 1);
        assert_eq!(lm.tier_of(ip("203.0.113.10")), Tier::Unlisted);
        // second threshold -> black
        let d2 = lm.on_threshold(ip("203.0.113.10"), "rdp", later + time::Duration::seconds(10));
        assert_eq!(d2.tier, Tier::Black);
    }

    #[test]
    fn whitelist_never_bans() {
        let nets = vec![ipnet::IpNet::from(ip("198.51.100.1"))];
        let mut lm = ListManager::new(ListsConfig::default(), nets, false);
        let now = OffsetDateTime::now_utc();
        let d = lm.on_threshold(ip("198.51.100.1"), "rdp", now);
        assert_eq!(d.action, BanAction::None);
    }

    #[test]
    fn private_skipped_when_disabled() {
        let mut lm = ListManager::new(ListsConfig::default(), vec![], false);
        let now = OffsetDateTime::now_utc();
        let d = lm.on_threshold(ip("10.1.2.3"), "rdp", now);
        assert_eq!(d.action, BanAction::None);
    }
}
