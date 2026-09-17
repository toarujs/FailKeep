//! Windows Event Log incremental reader (windows 0.58 API).

use crate::config::SourceConfig;
use crate::filter::FailHit;
use anyhow::{anyhow, Result};
use std::net::IpAddr;
use time::OffsetDateTime;
use tracing::debug;

pub fn extract_record_id(xml: &str) -> Option<u64> {
    let start = xml.find("<EventRecordID>")? + "<EventRecordID>".len();
    let end = xml[start..].find("</EventRecordID>")? + start;
    xml[start..end].trim().parse().ok()
}

pub fn extract_event_id(xml: &str) -> Option<u32> {
    let start = xml.find("<EventID")?;
    let gt = xml[start..].find('>')? + start + 1;
    let end = xml[gt..].find("</EventID>")? + gt;
    xml[gt..end].trim().parse().ok()
}

pub fn extract_event_time(xml: &str) -> Option<OffsetDateTime> {
    let key = "SystemTime=\"";
    let i = xml.find(key)? + key.len();
    let j = xml[i..].find('"')? + i;
    let raw = &xml[i..j];
    let cleaned = raw.trim_end_matches('Z');
    let sec = cleaned.split('.').next().unwrap_or(cleaned);
    let s = format!("{sec}Z");
    OffsetDateTime::parse(&s, &time::format_description::well_known::Rfc3339).ok()
}

pub fn extract_event_data(xml: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for quote in ['\'', '"'] {
        let pat = format!("Name={quote}");
        let mut rest = xml;
        while let Some(i) = rest.find(&pat) {
            let nstart = i + pat.len();
            let Some(nend_rel) = rest[nstart..].find(quote) else {
                break;
            };
            let nend = nstart + nend_rel;
            let name = rest[nstart..nend].to_string();
            let after = &rest[nend + 1..];
            let Some(gt_rel) = after.find('>') else {
                break;
            };
            let vstart = gt_rel + 1;
            let value = match after[vstart..].find("</Data>") {
                Some(ve) => after[vstart..vstart + ve].to_string(),
                None => String::new(),
            };
            out.push((name, value));
            rest = &rest[nend + 1..];
        }
        if !out.is_empty() {
            break;
        }
    }
    out
}

pub fn data_get<'a>(data: &'a [(String, String)], key: &str) -> Option<&'a str> {
    data.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

fn parse_ip_loose(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    if s.is_empty() || s == "-" {
        return None;
    }
    let s = s.strip_prefix("::ffff:").unwrap_or(s);
    s.parse().ok()
}

#[derive(Debug, Clone)]
pub struct EventlogPolicy {
    pub ip_field: String,
    pub logon_types: Vec<u32>,
    pub ignore_users: Vec<String>,
    pub fail_event_ids: Vec<u32>,
    pub success_event_ids: Vec<u32>,
    pub success_logon_types: Vec<u32>,
    pub unban_on_success: bool,
}

pub struct EventLogSource {
    channel: String,
    policy: EventlogPolicy,
    last_record_id: u64,
    first_poll: bool,
}

impl EventLogSource {
    pub fn from_source(src: &SourceConfig) -> Option<Self> {
        match src {
            SourceConfig::Eventlog {
                channel,
                event_ids,
                ip_field,
                logon_types,
                ignore_users,
                success_event_ids,
                success_logon_types,
                unban_on_success,
            } => Some(Self {
                channel: channel.clone(),
                policy: EventlogPolicy {
                    ip_field: ip_field.clone().unwrap_or_else(|| "IpAddress".into()),
                    logon_types: logon_types.clone(),
                    ignore_users: ignore_users.clone(),
                    fail_event_ids: event_ids.clone(),
                    success_event_ids: success_event_ids.clone(),
                    success_logon_types: success_logon_types.clone(),
                    unban_on_success: *unban_on_success,
                },
                last_record_id: 0,
                first_poll: true,
            }),
            _ => None,
        }
    }

    pub fn policy(&self) -> &EventlogPolicy {
        &self.policy
    }

    pub fn channel(&self) -> &str {
        &self.channel
    }

    pub fn restore_record_id(&mut self, id: u64) {
        self.last_record_id = id;
        self.first_poll = false;
    }

    pub fn last_record_id(&self) -> u64 {
        self.last_record_id
    }

    pub fn poll(&mut self) -> Result<(Vec<FailHit>, Vec<IpAddr>, u64)> {
        #[cfg(windows)]
        {
            self.poll_windows()
        }
        #[cfg(not(windows))]
        {
            Ok((Vec::new(), Vec::new(), self.last_record_id))
        }
    }

    #[cfg(windows)]
    fn poll_windows(&mut self) -> Result<(Vec<FailHit>, Vec<IpAddr>, u64)> {
        use windows::core::PCWSTR;
        use windows::Win32::System::EventLog::{
            EvtClose, EvtCreateBookmark, EvtNext, EvtQuery, EvtSeek, EvtUpdateBookmark,
            EvtQueryChannelPath, EvtQueryReverseDirection, EVT_HANDLE, EVT_SEEK_FLAGS,
        };

        let mut ids: Vec<u32> = self.policy.fail_event_ids.clone();
        for s in &self.policy.success_event_ids {
            if !ids.contains(s) {
                ids.push(*s);
            }
        }
        let select = if ids.is_empty() {
            "*".to_string()
        } else {
            let parts: Vec<String> = ids.iter().map(|i| format!("EventID={i}")).collect();
            format!("*[System[({})]]", parts.join(" or "))
        };
        let qfilter = format!(
            "<QueryList><Query Id=\"0\" Path=\"{ch}\"><Select Path=\"{ch}\">{select}</Select></Query></QueryList>",
            ch = self.channel
        );
        let qbuf: Vec<u16> = qfilter.encode_utf16().chain(std::iter::once(0)).collect();
        let qpc = PCWSTR(qbuf.as_ptr());

        let flags = EvtQueryChannelPath.0 | EvtQueryReverseDirection.0;
        let h = unsafe { EvtQuery(None, qpc, None, flags) }
            .map_err(|e| anyhow!("EvtQuery({}): {e}", self.channel))?;

        let mut bookmark: Option<EVT_HANDLE> = None;
        if self.last_record_id > 0 {
            let bm_xml = format!(
                "<BookmarkList><Bookmark Channel='{}' RecordId='{}' IsCurrent='true'/></BookmarkList>",
                self.channel, self.last_record_id
            );
            let bbuf: Vec<u16> = bm_xml.encode_utf16().chain(std::iter::once(0)).collect();
            let bpc = PCWSTR(bbuf.as_ptr());
            if let Ok(bh) = unsafe { EvtCreateBookmark(bpc) } {
                let _ = unsafe { EvtSeek(h, 0, bh, 0, EVT_SEEK_FLAGS(0).0) };
                bookmark = Some(bh);
            }
        }

        let mut fails = Vec::new();
        let mut successes = Vec::new();
        let mut max_rid = self.last_record_id;
        let mut seen = 0u32;

        loop {
            let mut batch: [isize; 32] = [0isize; 32];
            let mut returned = 0u32;
            let ok = unsafe { EvtNext(h, &mut batch, 1000u32, 0u32, &mut returned) };
            if returned == 0 {
                let _ = ok;
                break;
            }
            for i in 0..returned as usize {
                let ev = EVT_HANDLE(batch[i]);
                let xml = render_event_xml(ev);
                let _ = unsafe { EvtClose(ev) };
                seen += 1;
                let Some(xml) = xml else { continue };
                let rid = extract_record_id(&xml).unwrap_or(0);
                if rid > max_rid {
                    max_rid = rid;
                }
                if self.last_record_id > 0 && rid <= self.last_record_id {
                    continue;
                }
                if self.first_poll {
                    continue;
                }
                let Some(eid) = extract_event_id(&xml) else {
                    continue;
                };
                let data = extract_event_data(&xml);
                let at = extract_event_time(&xml).unwrap_or_else(OffsetDateTime::now_utc);
                let lt = data_get(&data, "LogonType").and_then(|s| s.trim().parse::<u32>().ok());
                let user = data_get(&data, "TargetUserName").unwrap_or("");

                if self.policy.success_event_ids.contains(&eid) {
                    if !self.policy.success_logon_types.is_empty() {
                        if let Some(lt) = lt {
                            if !self.policy.success_logon_types.contains(&lt) {
                                continue;
                            }
                        }
                    }
                    let ip_s = data_get(&data, &self.policy.ip_field)
                        .or_else(|| data_get(&data, "IpAddress"));
                    if let Some(ip) = ip_s.and_then(parse_ip_loose) {
                        successes.push(ip);
                    }
                    continue;
                }

                if !self.policy.fail_event_ids.contains(&eid) {
                    continue;
                }
                if !self.policy.logon_types.is_empty() {
                    if let Some(lt) = lt {
                        if !self.policy.logon_types.contains(&lt) {
                            continue;
                        }
                    }
                }
                if self
                    .policy
                    .ignore_users
                    .iter()
                    .any(|u| u.eq_ignore_ascii_case(user))
                {
                    continue;
                }
                let ip_s = data_get(&data, &self.policy.ip_field)
                    .or_else(|| data_get(&data, "IpAddress"));
                if let Some(ip) = ip_s.and_then(parse_ip_loose) {
                    fails.push(FailHit {
                        ip,
                        at,
                        jail: String::new(),
                    });
                }
            }
            if returned < 32 {
                break;
            }
            if seen > 10_000 {
                debug!("eventlog poll cap reached");
                break;
            }
        }

        if self.first_poll && max_rid > 0 {
            self.last_record_id = max_rid;
            self.first_poll = false;
        } else if max_rid > self.last_record_id {
            self.last_record_id = max_rid;
        }

        if let Some(bh) = bookmark {
            let _ = unsafe { EvtUpdateBookmark(bh, EVT_HANDLE(0)) };
            let _ = unsafe { EvtClose(bh) };
        }
        let _ = unsafe { EvtClose(h) };
        drop(qbuf);
        Ok((fails, successes, self.last_record_id))
    }
}

#[cfg(windows)]
fn render_event_xml(h: windows::Win32::System::EventLog::EVT_HANDLE) -> Option<String> {
    use std::ffi::c_void;
    use windows::Win32::System::EventLog::{EvtRender, EvtRenderEventXml};

    let mut buf: Vec<u16> = vec![0u16; 4096];
    loop {
        let mut used = 0u32;
        let mut count = 0u32;
        let ok = unsafe {
            EvtRender(
                None,
                h,
                EvtRenderEventXml.0 as u32,
                buf.len() as u32,
                Some(buf.as_mut_ptr() as *mut c_void),
                &mut used,
                &mut count,
            )
        };
        if ok.is_ok() {
            let nchars = if used as usize <= buf.len() {
                used as usize
            } else {
                (used / 2) as usize
            };
            let nchars = nchars.min(buf.len());
            let s = String::from_utf16_lossy(&buf[..nchars]);
            if s.contains("<Event") {
                return Some(s);
            }
            let alt = (used / 2) as usize;
            if alt > 0 && alt <= buf.len() {
                return Some(String::from_utf16_lossy(&buf[..alt]));
            }
            return Some(s);
        }
        if buf.len() >= 512 * 1024 {
            return None;
        }
        buf.resize(buf.len() * 2, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_xml_bits() {
        let xml = r#"<Event><System><EventID>4625</EventID><TimeCreated SystemTime="2026-01-02T03:04:05.000000000Z"/><EventRecordID>99</EventRecordID></System>
<EventData><Data Name='TargetUserName'>bob</Data><Data Name='IpAddress'>203.0.113.9</Data><Data Name='LogonType'>3</Data></EventData></Event>"#;
        assert_eq!(extract_event_id(xml), Some(4625));
        assert_eq!(extract_record_id(xml), Some(99));
        let data = extract_event_data(xml);
        assert_eq!(data_get(&data, "IpAddress"), Some("203.0.113.9"));
        assert_eq!(data_get(&data, "LogonType"), Some("3"));
        assert!(extract_event_time(xml).is_some());
    }
}
