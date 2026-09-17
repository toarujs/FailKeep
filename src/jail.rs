use crate::config::JailConfig;
use crate::filter::FileFilter;
use crate::lists::FailTracker;
use crate::source::eventlog::EventLogSource;
use crate::source::fwlog::parse_fw_line;
use crate::source::FileTailer;
use crate::config::SourceConfig;
use anyhow::Result;
use std::net::IpAddr;
use time::OffsetDateTime;

pub struct Jail {
    pub cfg: JailConfig,
    pub filter: FileFilter,
    pub tailer: Option<FileTailer>,
    pub eventlog: Option<EventLogSource>,
    pub fails: FailTracker,
    is_fwlog: bool,
}

impl Jail {
    pub fn new(cfg: JailConfig) -> Result<Self> {
        let filter = FileFilter::for_source(&cfg.name, &cfg.source, cfg.filter.as_ref())?;
        let tailer = FileTailer::from_source(&cfg.source);
        let eventlog = EventLogSource::from_source(&cfg.source);
        let is_fwlog = matches!(cfg.source, SourceConfig::Fwlog { .. });
        Ok(Self {
            cfg,
            filter,
            tailer,
            eventlog,
            fails: FailTracker::new(),
            is_fwlog,
        })
    }

    pub fn poll_file(&mut self, now: OffsetDateTime) -> Result<Vec<crate::filter::FailHit>> {
        let mut hits = Vec::new();
        if let Some(t) = self.tailer.as_mut() {
            let lines = t.read_new_lines()?;
            for (path, line) in lines {
                let path_s = path.to_string_lossy().to_string();
                if self.is_fwlog {
                    if let Some(mut h) = parse_fw_line(&line, now) {
                        h.jail = self.cfg.name.clone();
                        hits.push(h);
                    }
                    continue;
                }
                for mut h in self.filter.match_line(&path_s, &line, now) {
                    h.jail = self.cfg.name.clone();
                    hits.push(h);
                }
            }
        }
        Ok(hits)
    }

    pub fn record_fail(&mut self, ip: IpAddr, at: OffsetDateTime) -> u32 {
        self.fails.record(ip, at, self.cfg.find_time)
    }

    pub fn on_success(&mut self, ip: IpAddr) {
        self.fails.clear(ip);
    }

    pub fn ignored_ip(&self, ip: IpAddr) -> bool {
        use crate::config::parse_ip_or_cidr;
        for s in &self.cfg.ignore_ip {
            if let Ok(net) = parse_ip_or_cidr(s) {
                if net.contains(&ip) {
                    return true;
                }
            }
        }
        false
    }
}
