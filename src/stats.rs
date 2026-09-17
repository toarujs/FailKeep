use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::IpAddr;
use time::{Duration, OffsetDateTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BanEventTier {
    Temp,
    Black,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanEvent {
    pub ip: IpAddr,
    pub tier: BanEventTier,
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    #[serde(default)]
    pub jail: Option<String>,
    #[serde(default)]
    pub manual: bool,
}

#[derive(Debug)]
pub struct Stats {
    events: VecDeque<BanEvent>,
    max_events: usize,
    retain_days: i64,
}

impl Stats {
    pub fn new(max_events: usize, retain_days: u32) -> Self {
        Self {
            events: VecDeque::new(),
            max_events: max_events.max(1),
            retain_days: retain_days as i64,
        }
    }

    pub fn from_events(events: Vec<BanEvent>, max_events: usize, retain_days: u32) -> Self {
        let mut s = Self::new(max_events, retain_days);
        for e in events {
            s.events.push_back(e);
        }
        s.trim(OffsetDateTime::now_utc());
        s
    }

    pub fn push(&mut self, ev: BanEvent) {
        self.events.push_back(ev);
        self.trim(OffsetDateTime::now_utc());
    }

    fn trim(&mut self, now: OffsetDateTime) {
        let cutoff = now - Duration::days(self.retain_days);
        while let Some(front) = self.events.front() {
            if front.at < cutoff {
                self.events.pop_front();
            } else {
                break;
            }
        }
        while self.events.len() > self.max_events {
            self.events.pop_front();
        }
    }

    pub fn export_events(&self) -> Vec<BanEvent> {
        self.events.iter().cloned().collect()
    }

    pub fn count_in(&self, window: Duration, now: OffsetDateTime) -> WindowCount {
        let cutoff = now - window;
        let mut wc = WindowCount::default();
        for e in &self.events {
            if e.at >= cutoff {
                wc.total += 1;
                match e.tier {
                    BanEventTier::Temp => wc.temp += 1,
                    BanEventTier::Black => wc.black += 1,
                }
            }
        }
        wc
    }

    pub fn all_counts(&self) -> WindowCount {
        let mut wc = WindowCount::default();
        for e in &self.events {
            wc.total += 1;
            match e.tier {
                BanEventTier::Temp => wc.temp += 1,
                BanEventTier::Black => wc.black += 1,
            }
        }
        wc
    }

    /// Recent unique events (newest first), limited.
    pub fn recent(&self, window: Option<Duration>, now: OffsetDateTime, limit: usize) -> Vec<BanEvent> {
        let cutoff = window.map(|w| now - w);
        let mut v: Vec<_> = self
            .events
            .iter()
            .rev()
            .filter(|e| cutoff.map(|c| e.at >= c).unwrap_or(true))
            .cloned()
            .collect();
        v.truncate(limit);
        v
    }

    pub fn retained_len(&self) -> usize {
        self.events.len()
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct WindowCount {
    pub temp: u32,
    pub black: u32,
    pub total: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows() {
        let mut s = Stats::new(100, 90);
        let now = OffsetDateTime::now_utc();
        s.push(BanEvent {
            ip: "1.2.3.4".parse().unwrap(),
            tier: BanEventTier::Temp,
            at: now,
            jail: Some("rdp".into()),
            manual: false,
        });
        s.push(BanEvent {
            ip: "5.6.7.8".parse().unwrap(),
            tier: BanEventTier::Black,
            at: now - Duration::days(2),
            jail: Some("rdp".into()),
            manual: false,
        });
        let h24 = s.count_in(Duration::hours(24), now);
        assert_eq!(h24.total, 1);
        let d3 = s.count_in(Duration::days(3), now);
        assert_eq!(d3.total, 2);
        assert_eq!(s.all_counts().total, 2);
    }
}
