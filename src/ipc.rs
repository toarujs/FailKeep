//! Local IPC: TCP on 127.0.0.1, port+token file for clients (CLI / WinUI).
//! Not exposed on LAN; bind is loopback-only.

use crate::engine::EngineHandle;
use crate::lists::Tier;
use crate::stats::BanEventTier;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use time::{Duration as TimeDuration, OffsetDateTime};
use tracing::{info, warn};

pub fn ipc_file_path() -> PathBuf {
    // Prefer config-adjacent location
    if let Ok(p) = std::env::var("FailKeep_HOME") {
        return PathBuf::from(p).join("ipc.json");
    }
    PathBuf::from(r"C:\ProgramData\FailKeep\ipc.json")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcEndpoint {
    pub port: u16,
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    List {
        #[serde(default)]
        tier: Option<String>,
    },
    Stats,
    Ban {
        ip: String,
        #[serde(default)]
        black: bool,
        #[serde(default)]
        permanent: bool,
        #[serde(default)]
        time: Option<u64>,
    },
    Unban {
        #[serde(default)]
        ip: Option<String>,
        #[serde(default)]
        all: bool,
    },
    Unblack {
        ip: String,
    },
    WhitelistAdd {
        ip: String,
    },
    WhitelistRemove {
        ip: String,
    },
    Jail {
        name: String,
    },
    Ping,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Wire {
    pub token: String,
    pub req: Request,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl Response {
    pub fn ok_data(v: serde_json::Value) -> Self {
        Self {
            ok: true,
            error: None,
            data: Some(v),
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            data: None,
        }
    }
}

pub fn handle_request(eng: &EngineHandle, req: Request) -> Response {
    let mut g = match eng.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    match req {
        Request::Ping => Response::ok_data(serde_json::json!({"pong": true})),
        Request::Status => {
            let (w, t, b) = g.lists().counts();
            let now = OffsetDateTime::now_utc();
            Response::ok_data(serde_json::json!({
                "whitelist": w,
                "temp": t,
                "black": b,
                "dry_run": g.dry_run(),
                "bans_24h": g.stats().count_in(TimeDuration::hours(24), now).total,
                "bans_3d": g.stats().count_in(TimeDuration::days(3), now).total,
                "bans_7d": g.stats().count_in(TimeDuration::days(7), now).total,
                "bans_all": g.stats().all_counts().total,
            }))
        }
        Request::List { tier } => {
            let mut items = Vec::new();
            let tier = tier.unwrap_or_default();
            if tier.is_empty() || tier == "whitelist" {
                for ip in g.lists().whitelist_ips() {
                    items.push(serde_json::json!({"ip": ip.to_string(), "tier": "whitelist"}));
                }
                for n in g.lists().whitelist_nets() {
                    items.push(serde_json::json!({"ip": n.to_string(), "tier": "whitelist"}));
                }
            }
            if tier.is_empty() || tier == "temp" || tier == "black" {
                for (ip, t, deadline, perm) in g.lists().banned_ips() {
                    let name = match t {
                        Tier::Temp => "temp",
                        Tier::Black => "black",
                        _ => continue,
                    };
                    if !tier.is_empty() && tier != name {
                        continue;
                    }
                    items.push(serde_json::json!({
                        "ip": ip.to_string(),
                        "tier": name,
                        "deadline": deadline.map(|d| d.unix_timestamp()),
                        "permanent": perm,
                    }));
                }
            }
            Response::ok_data(serde_json::json!({ "items": items }))
        }
        Request::Stats => {
            let now = OffsetDateTime::now_utc();
            let h24 = g.stats().count_in(TimeDuration::hours(24), now);
            let d3 = g.stats().count_in(TimeDuration::days(3), now);
            let d7 = g.stats().count_in(TimeDuration::days(7), now);
            let all = g.stats().all_counts();
            let recent = g.stats().recent(None, now, 50);
            let mut recent_json = Vec::new();
            for e in recent {
                let geo = crate::geo::lookup_ip(e.ip);
                recent_json.push(serde_json::json!({
                    "ip": e.ip.to_string(),
                    "tier": match e.tier { BanEventTier::Temp => "temp", BanEventTier::Black => "black" },
                    "at": e.at.unix_timestamp(),
                    "jail": e.jail,
                    "manual": e.manual,
                    "geo": geo,
                }));
            }
            Response::ok_data(serde_json::json!({
                "windows": {
                    "24h": h24, "3d": d3, "7d": d7, "all": all,
                },
                "retained_events": g.stats().retained_len(),
                "recent": recent_json,
            }))
        }
        Request::Ban {
            ip,
            black,
            permanent,
            time,
        } => {
            let addr: IpAddr = match ip.parse() {
                Ok(a) => a,
                Err(e) => return Response::err(format!("bad ip: {e}")),
            };
            let now = OffsetDateTime::now_utc();
            let d = g.lists_mut().manual_ban(addr, black, permanent, time, now);
            match g.apply_decision(d, true) {
                Ok(()) => Response::ok_data(serde_json::json!({"ip": ip, "banned": true})),
                Err(e) => Response::err(format!("{e:#}")),
            }
        }
        Request::Unban { ip, all } => {
            if all {
                let ips: Vec<IpAddr> = g.lists().banned_ips().into_iter().map(|x| x.0).collect();
                for addr in ips {
                    let d = g.lists_mut().unban(addr, OffsetDateTime::now_utc());
                    if let Err(e) = g.apply_decision(d, true) {
                        return Response::err(format!("{e:#}"));
                    }
                }
                Response::ok_data(serde_json::json!({"unbanned": "all"}))
            } else {
                let Some(ip) = ip else {
                    return Response::err("ip required");
                };
                let addr: IpAddr = match ip.parse() {
                    Ok(a) => a,
                    Err(e) => return Response::err(format!("bad ip: {e}")),
                };
                let d = g.lists_mut().unban(addr, OffsetDateTime::now_utc());
                match g.apply_decision(d, true) {
                    Ok(()) => Response::ok_data(serde_json::json!({"ip": ip})),
                    Err(e) => Response::err(format!("{e:#}")),
                }
            }
        }
        Request::Unblack { ip } => {
            let addr: IpAddr = match ip.parse() {
                Ok(a) => a,
                Err(e) => return Response::err(format!("bad ip: {e}")),
            };
            let d = g.lists_mut().unblack(addr, OffsetDateTime::now_utc());
            match g.apply_decision(d, true) {
                Ok(()) => Response::ok_data(serde_json::json!({"ip": ip})),
                Err(e) => Response::err(format!("{e:#}")),
            }
        }
        Request::WhitelistAdd { ip } => {
            match crate::config::parse_ip_or_cidr(&ip) {
                Ok(net) => g.lists_mut().add_whitelist_net(net),
                Err(e) => return Response::err(format!("{e:#}")),
            }
            if let Ok(addr) = ip.parse::<IpAddr>() {
                g.lists_mut().add_whitelist_ip(addr);
                if matches!(g.lists().tier_of(addr), Tier::Temp | Tier::Black) {
                    let d = g.lists_mut().unban(addr, OffsetDateTime::now_utc());
                    let _ = g.fw().unban(d.ip);
                }
            }
            match g.persist() {
                Ok(()) => Response::ok_data(serde_json::json!({"whitelisted": ip})),
                Err(e) => Response::err(format!("{e:#}")),
            }
        }
        Request::WhitelistRemove { ip } => {
            let addr: IpAddr = match ip.parse() {
                Ok(a) => a,
                Err(e) => return Response::err(format!("bad ip: {e}")),
            };
            g.lists_mut().remove_whitelist_ip(addr);
            match g.persist() {
                Ok(()) => Response::ok_data(serde_json::json!({"removed": ip})),
                Err(e) => Response::err(format!("{e:#}")),
            }
        }
        Request::Jail { name } => match g.jail_status(&name) {
            Some(st) => {
                let watching: Vec<_> = st
                    .watching
                    .iter()
                    .map(|(ip, c)| serde_json::json!({"ip": ip.to_string(), "fails": c}))
                    .collect();
                Response::ok_data(serde_json::json!({
                    "name": st.name,
                    "max_retry": st.max_retry,
                    "find_time": st.find_time,
                    "watching": watching,
                }))
            }
            None => Response::err(format!("jail not found: {name}")),
        },
    }
}

fn random_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    format!("{pid:x}-{t:x}")
}

pub fn spawn_ipc_server(eng: EngineHandle, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        if let Err(e) = ipc_server_loop(eng, stop) {
            warn!("ipc server ended: {e:#}");
        }
    })
}

fn ipc_server_loop(eng: EngineHandle, stop: Arc<AtomicBool>) -> Result<()> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let port = listener.local_addr()?.port();
    let token = random_token();
    let ep = IpcEndpoint {
        port,
        token: token.clone(),
    };
    let path = ipc_file_path();
    if let Some(p) = path.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    std::fs::write(&path, serde_json::to_string_pretty(&ep)?)?;
    info!(port, path=%path.display(), "ipc listening on 127.0.0.1");
    listener.set_nonblocking(true)?;

    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let eng = Arc::clone(&eng);
                let token = token.clone();
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let _ = serve_client(stream, peer, eng, token, stop);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                warn!("ipc accept: {e}");
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}

fn serve_client(
    stream: TcpStream,
    peer: SocketAddr,
    eng: EngineHandle,
    token: String,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut line = String::new();
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        let raw = line.trim();
        if raw.is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Wire>(raw) {
            Ok(w) => {
                if w.token != token {
                    Response::err("access_denied")
                } else {
                    handle_request(&eng, w.req)
                }
            }
            Err(e) => Response::err(format!("bad request: {e}")),
        };
        let mut out = serde_json::to_string(&resp)?;
        out.push('\n');
        writer.write_all(out.as_bytes())?;
        writer.flush()?;
    }
    let _ = peer;
    Ok(())
}

fn load_endpoint() -> Result<IpcEndpoint> {
    let path = ipc_file_path();
    let raw = std::fs::read_to_string(&path)
        .map_err(|_| anyhow::anyhow!("ipc endpoint file missing (is the service running?)"))?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn call(req: &Request) -> Result<Response> {
    let ep = load_endpoint()?;
    let mut stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, ep.port)))?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    let wire = Wire {
        token: ep.token,
        req: serde_json::from_value(serde_json::to_value(req)?)?,
    };
    let mut payload = serde_json::to_string(&wire)?;
    payload.push('\n');
    stream.write_all(payload.as_bytes())?;
    stream.flush()?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let resp: Response = serde_json::from_str(line.trim())
        .map_err(|e| anyhow::anyhow!("parse response: {e}; raw={line}"))?;
    Ok(resp)
}

pub fn server_available() -> bool {
    call(&Request::Ping).map(|r| r.ok).unwrap_or(false)
}
