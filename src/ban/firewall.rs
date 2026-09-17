use crate::config::FirewallConfig;
use crate::lists::Tier;
use anyhow::{bail, Context, Result};
use std::net::IpAddr;
use std::process::Command;
use tracing::{debug, warn};

pub struct Firewall {
    prefix: String,
    /// "all" or list of ports
    ban_ports: String,
    dry_run: bool,
}

impl Firewall {
    pub fn new(cfg: &FirewallConfig, dry_run: bool) -> Self {
        Self {
            prefix: cfg.rule_prefix.clone(),
            ban_ports: cfg.ban_ports.clone(),
            dry_run,
        }
    }

    pub fn rule_name(&self, tier: Tier, ip: IpAddr) -> String {
        let t = match tier {
            Tier::Temp => "temp",
            Tier::Black => "black",
            _ => "temp",
        };
        format!("{}:{}:{}", self.prefix, t, ip)
    }

    /// Name used when deleting — we may have either tier prefix.
    pub fn rule_name_temp(&self, ip: IpAddr) -> String {
        format!("{}:temp:{}", self.prefix, ip)
    }
    pub fn rule_name_black(&self, ip: IpAddr) -> String {
        format!("{}:black:{}", self.prefix, ip)
    }

    pub fn ban(&self, ip: IpAddr, tier: Tier) -> Result<()> {
        let name = self.rule_name(tier, ip);
        // Remove opposite-tier leftover first for idempotency
        let _ = self.delete_rule(&self.rule_name_temp(ip));
        let _ = self.delete_rule(&self.rule_name_black(ip));
        self.add_rule(&name, ip)
    }

    pub fn unban(&self, ip: IpAddr) -> Result<()> {
        let mut last = Ok(());
        for name in [self.rule_name_temp(ip), self.rule_name_black(ip)] {
            match self.delete_rule(&name) {
                Ok(()) => {}
                Err(e) => last = Err(e),
            }
        }
        last
    }

    fn add_rule(&self, name: &str, ip: IpAddr) -> Result<()> {
        if self.dry_run {
            debug!(target: "FailKeep::fw", "DRY-RUN ban {ip} name={name} ports={}", self.ban_ports);
            return Ok(());
        }
        let mut args = vec![
            "advfirewall".to_string(),
            "firewall".to_string(),
            "add".to_string(),
            "rule".to_string(),
            format!("name={name}"),
            "dir=in".into(),
            "action=block".into(),
            format!("remoteip={ip}"),
            "enable=yes".into(),
            "profile=any".into(),
        ];
        if self.ban_ports != "all" && !self.ban_ports.is_empty() {
            args.push(format!("localport={}", self.ban_ports.replace(' ', "")));
        }
        run_netsh(&args).with_context(|| format!("netsh add rule {name}"))
    }

    fn delete_rule(&self, name: &str) -> Result<()> {
        if self.dry_run {
            debug!(target: "FailKeep::fw", "DRY-RUN delete rule {name}");
            return Ok(());
        }
        let args = [
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={name}"),
        ];
        // delete returns error if missing — treat as ok
        match run_netsh_str(&args) {
            Ok(_) => Ok(()),
            Err(e) => {
                let msg = format!("{e:#}");
                if msg.contains("No rules") || msg.contains("找不到") {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    /// List remote IPs for rules with our prefix.
    pub fn list_banned_ips(&self) -> Result<Vec<(String, IpAddr)>> {
        if self.dry_run {
            return Ok(vec![]);
        }
        let args = [
            "advfirewall",
            "firewall",
            "show",
            "rule",
            "name=all",
            // netsh doesn't filter by prefix well; parse all and filter
        ];
        let out = run_netsh_str(&args)?;
        Ok(parse_rule_ips(&out, &self.prefix))
    }

    pub fn purge_prefix_rules(&self) -> Result<usize> {
        let rules = self.list_banned_ips()?;
        let mut n = 0;
        for (name, _ip) in rules {
            if self.delete_rule(&name).is_ok() {
                n += 1;
            }
        }
        Ok(n)
    }
}

fn run_netsh(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("empty netsh args");
    }
    let out = Command::new("netsh")
        .args(args)
        .output()
        .context("spawn netsh")?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        bail!("netsh failed: {stderr}{stdout}");
    }
}

fn run_netsh_str(args: &[&str]) -> Result<String> {
    let out = Command::new("netsh")
        .args(args)
        .output()
        .context("spawn netsh")?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if out.status.success() {
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("netsh failed: {stderr}{stdout}");
    }
}

/// Parse `netsh advfirewall firewall show rule name=all` output for our prefix rules.
/// Windows localization: match Rule Name: / 规则名: lines containing prefix.
fn parse_rule_ips(out: &str, prefix: &str) -> Vec<(String, IpAddr)> {
    let mut result = Vec::new();
    let mut current_name: Option<String> = None;
    for line in out.lines() {
        let t = line.trim();
        let name = if let Some(rest) = t.strip_prefix("Rule Name:") {
            Some(rest.trim().to_string())
        } else if let Some(rest) = t.strip_prefix("规则名:") {
            Some(rest.trim().to_string())
        } else {
            None
        };
        if let Some(n) = name {
            current_name = Some(n);
            continue;
        }
        // Remote IP lines — we stored IP in rule name as prefix:tier:ip
        if let Some(n) = &current_name {
            if n.starts_with(prefix) {
                if let Some(ip_s) = n.rsplit(':').next() {
                    // last component may be IPv4
                    if let Ok(ip) = ip_s.parse::<IpAddr>() {
                        result.push((n.clone(), ip));
                        current_name = None;
                    }
                }
            }
        }
    }
    // Fallback: scan all lines for prefix:...:ip pattern (more robust)
    if result.is_empty() {
        for line in out.lines() {
            let t = line.trim();
            for part in t.split_whitespace() {
                if part.starts_with(prefix) {
                    if let Some(ip_s) = part.rsplit(':').next() {
                        if let Ok(ip) = ip_s.parse::<IpAddr>() {
                            result.push((part.to_string(), ip));
                        }
                    }
                }
            }
            // also whole-line name after colon
            if t.contains(prefix) {
                if let Some(idx) = t.find(prefix) {
                    let rest = &t[idx..];
                    let token = rest.split_whitespace().next().unwrap_or(rest);
                    if let Some(ip_s) = token.rsplit(':').next() {
                        if let Ok(ip) = ip_s.parse::<IpAddr>() {
                            let name = token.to_string();
                            if !result.iter().any(|(n, _)| n == &name) {
                                result.push((name, ip));
                            }
                        }
                    }
                }
            }
        }
    }
    result
}

/// Reconcile: return (to_ban, to_unban) based on desired set vs actual rules.
pub fn reconcile(
    fw: &Firewall,
    desired: &[(IpAddr, Tier)],
) -> Result<(Vec<(IpAddr, Tier)>, Vec<IpAddr>)> {
    let actual = fw.list_banned_ips()?;
    let actual_ips: Vec<IpAddr> = actual.iter().map(|(_, ip)| *ip).collect();
    let desired_ips: Vec<IpAddr> = desired.iter().map(|(ip, _)| *ip).collect();

    let mut to_ban = Vec::new();
    for (ip, tier) in desired {
        if !actual_ips.contains(ip) {
            to_ban.push((*ip, *tier));
        }
    }
    let mut to_unban = Vec::new();
    for ip in actual_ips {
        if !desired_ips.contains(&ip) {
            to_unban.push(ip);
        }
    }
    Ok((to_ban, to_unban))
}

pub fn apply_ban(fw: &Firewall, ip: IpAddr, tier: Tier) -> Result<()> {
    match fw.ban(ip, tier) {
        Ok(()) => Ok(()),
        Err(e) => {
            warn!("ban {ip} failed, retry once: {e:#}");
            std::thread::sleep(std::time::Duration::from_millis(200));
            fw.ban(ip, tier)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_names() {
        let sample = "\n\
Rule Name:                            FailKeep:temp:203.0.113.5\n\
----------------------------------------------------------------------\n\
Enabled:                              Yes\n\
";
        let ips = parse_rule_ips(sample, "FailKeep");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].1.to_string(), "203.0.113.5");
    }
}
