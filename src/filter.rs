use crate::config::{FilterConfig, SourceConfig};
use crate::source::file::{parse_iis_fields, parse_iis_fields_header, parse_line_time};
use anyhow::Result;
use once_cell::sync::OnceCell;
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use time::OffsetDateTime;

/// A detected auth/service failure from a log line or event.
#[derive(Debug, Clone)]
pub struct FailHit {
    pub ip: IpAddr,
    /// Event/log time if available, else receive time
    pub at: OffsetDateTime,
    pub jail: String,
}

/// A detected success (clears fail counters).
#[derive(Debug, Clone)]
pub struct SuccessHit {
    pub ip: IpAddr,
    pub at: OffsetDateTime,
    pub jail: String,
}

#[derive(Debug)]
pub struct FileFilter {
    re: Regex,
    date_re: Option<Regex>,
    date_fmt: Option<String>,
    is_iis: bool,
    iis_codes: Vec<u16>,
    /// path -> IIS field header
    iis_headers: Mutex<HashMap<String, Vec<String>>>,
}

static IP_CAPTURE: OnceCell<Regex> = OnceCell::new();

fn ip_capture_re() -> &'static Regex {
    IP_CAPTURE.get_or_init(|| {
        Regex::new(r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+)")
            .expect("ip regex")
    })
}

impl FileFilter {
    pub fn for_file(_jail: &str, filter: Option<&FilterConfig>, date_pattern: Option<&str>, date_format: Option<&str>) -> Result<Self> {
        let re = match filter {
            Some(f) => Regex::new(&f.pattern)?,
            None => ip_capture_re().clone(),
        };
        Ok(Self {
            re,
            date_re: date_pattern.map(Regex::new).transpose()?,
            date_fmt: date_format.map(|s| s.to_string()),
            is_iis: false,
            iis_codes: vec![],
            iis_headers: Mutex::new(HashMap::new()),
        })
    }

    pub fn for_iis(status_codes: &[u16]) -> Self {
        Self {
            re: ip_capture_re().clone(),
            date_re: None,
            date_fmt: None,
            is_iis: true,
            iis_codes: status_codes.to_vec(),
            iis_headers: Mutex::new(HashMap::new()),
        }
    }

    pub fn for_source(jail_name: &str, source: &SourceConfig, filter: Option<&FilterConfig>) -> Result<Self> {
        match source {
            SourceConfig::File {
                date_pattern,
                date_format,
                ..
            } => Self::for_file(
                jail_name,
                filter,
                date_pattern.as_deref(),
                date_format.as_deref(),
            ),
            SourceConfig::Iis { status_codes, .. } => Ok(Self::for_iis(status_codes)),
            SourceConfig::Fwlog { .. } => Ok(Self {
                re: ip_capture_re().clone(),
                date_re: None,
                date_fmt: None,
                is_iis: false,
                iis_codes: vec![],
                iis_headers: Mutex::new(HashMap::new()),
            }),
            SourceConfig::Eventlog { .. } => Ok(Self {
                re: ip_capture_re().clone(),
                date_re: None,
                date_fmt: None,
                is_iis: false,
                iis_codes: vec![],
                iis_headers: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Returns failure IPs found in a raw log line (0..n; usually 0 or 1).
    pub fn match_line(&self, path: &str, line: &str, now: OffsetDateTime) -> Vec<FailHit> {
        let mut hits = Vec::new();
        if line.starts_with('#') {
            if self.is_iis {
                if let Some(fields) = parse_iis_fields_header(line) {
                    self.iis_headers
                        .lock()
                        .unwrap()
                        .insert(path.to_string(), fields);
                }
            }
            return hits;
        }
        if self.is_iis {
            let headers = self.iis_headers.lock().unwrap();
            if let Some(fields) = headers.get(path) {
                let refs: Vec<&str> = fields.iter().map(|s| s.as_str()).collect();
                if let Some((ip_s, status)) = parse_iis_fields(&refs, line) {
                    if self.iis_codes.contains(&status) {
                        if let Ok(ip) = ip_s.parse::<IpAddr>() {
                            hits.push(FailHit {
                                ip,
                                at: now,
                                jail: String::new(),
                            });
                        }
                    }
                }
            }
            return hits;
        }
        let at = parse_line_time(line, self.date_re.as_ref(), self.date_fmt.as_deref())
            .unwrap_or(now);
        if let Some(caps) = self.re.captures(line) {
            let ip_s = caps
                .name("ip")
                .map(|m| m.as_str())
                .or_else(|| caps.get(1).map(|m| m.as_str()));
            if let Some(ip_s) = ip_s {
                // strip IPv6-mapped prefixes if any
                let ip_s = ip_s.trim_start_matches("::ffff:");
                if let Ok(ip) = ip_s.parse::<IpAddr>() {
                    hits.push(FailHit {
                        ip,
                        at,
                        jail: String::new(),
                    });
                }
            }
        }
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FilterConfig;

    #[test]
    fn custom_regex_extract() {
        let f = FileFilter::for_file(
            "t",
            Some(&FilterConfig {
                pattern: r"(?i)failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)".into(),
            }),
            None,
            None,
        )
        .unwrap();
        let now = OffsetDateTime::now_utc();
        let hits = f.match_line(
            "x.log",
            "Failed password for root from 203.0.113.9 port 22 ssh2",
            now,
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].ip.to_string(), "203.0.113.9");
    }

    #[test]
    fn iis_status_filter() {
        let mut f = FileFilter::for_iis(&[401, 403]);
        let now = OffsetDateTime::now_utc();
        f.match_line(
            "u.log",
            "#Fields: date time c-ip cs-method sc-status",
            now,
        );
        let hits = f.match_line("u.log", "2026-01-01 00:00:01 198.51.100.7 GET 401", now);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].ip.to_string(), "198.51.100.7");
        let hits2 = f.match_line("u.log", "2026-01-01 00:00:02 198.51.100.7 GET 200", now);
        assert!(hits2.is_empty());
    }
}
