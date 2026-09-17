//! Firewall W3C log tail (DROP lines).

use crate::filter::FailHit;
use std::net::IpAddr;
use time::OffsetDateTime;

/// Parse a pfirewall.log data line.
/// Typical: `2026-01-01 12:00:00 DROP TCP 1.2.3.4 5.6.7.8 12345 80 ...`
/// Field order can vary; we look for DROP and take first public-looking IP as source.
pub fn parse_fw_line(line: &str, now: OffsetDateTime) -> Option<FailHit> {
    if line.starts_with('#') || line.trim().is_empty() {
        return None;
    }
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 5 {
        return None;
    }
    // Find DROP/DROP-all token
    let action_idx = cols
        .iter()
        .position(|c| c.eq_ignore_ascii_case("drop") || c.eq_ignore_ascii_case("drop-all"))?;
    // After date time action proto src dst sport dport ...
    // date=0 time=1 action=2 → src often index 4
    let src_s = cols.get(action_idx + 2)?;
    let ip: IpAddr = src_s.parse().ok()?;
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    // parse date time if present
    let at = parse_fw_time(cols.get(0)?, cols.get(1)?).unwrap_or(now);
    Some(FailHit {
        ip,
        at,
        jail: String::new(),
    })
}

fn parse_fw_time(d: &str, t: &str) -> Option<OffsetDateTime> {
    crate::source::file::parse_datetime_str(
        &format!("{d} {t}"),
        "[year]-[month]-[day] [hour]:[minute]:[second]",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_line() {
        let now = OffsetDateTime::now_utc();
        let h = parse_fw_line("2026-01-01 12:00:00 DROP TCP 203.0.113.8 10.0.0.5 4444 3389", now);
        assert!(h.is_some());
        let h = h.unwrap();
        assert_eq!(h.ip.to_string(), "203.0.113.8");
        assert!(parse_fw_line("#Software: Windows Firewall", now).is_none());
    }
}
