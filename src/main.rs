mod applog;
mod ban;
mod config;
mod engine;
mod filter;
mod geo;
mod ipc;
mod jail;
mod lists;
mod service;
mod source;
mod stats;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use config::Config;
use engine::{Engine, EngineHandle};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "FailKeep", version, about = "Lightweight IP ban service for Windows Server")]
struct Cli {
    #[arg(long, global = true, default_value = r"C:\ProgramData\FailKeep\config.toml")]
    config: PathBuf,

    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run engine in foreground (also serves named-pipe IPC)
    Run {
        #[arg(long)]
        dry_run: bool,
    },
    /// Internal: SCM service entry (used by installed service)
    ServiceRun,
    CheckConfig,
    Status,
    List {
        #[arg(long)]
        whitelist: bool,
        #[arg(long)]
        temp: bool,
        #[arg(long)]
        black: bool,
    },
    Stats,
    Jail { name: String },
    Ban {
        ip: String,
        #[arg(long)]
        black: bool,
        #[arg(long)]
        permanent: bool,
        #[arg(long)]
        time: Option<u64>,
    },
    Unban {
        ip: Option<String>,
        #[arg(long)]
        all: bool,
    },
    Unblack { ip: String },
    Whitelist {
        #[command(subcommand)]
        action: WhitelistCmd,
    },
    PurgeRules,
    /// Install Windows service (admin)
    Install {
        /// Also copy example config if missing
        #[arg(long)]
        force_config: bool,
    },
    /// Uninstall service; --purge-rules deletes FailKeep firewall rules
    Uninstall {
        #[arg(long)]
        purge_rules: bool,
    },
}

#[derive(Subcommand, Debug)]
enum WhitelistCmd {
    Add { ip: String },
    Remove { ip: String },
}

fn init_logging(level: &str, file: &str) {
    use std::io::Write;
    use tracing_subscriber::EnvFilter;

    struct DualWriter;
    impl Write for DualWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = std::io::stderr().write(buf)?;
            applog::log_line(&String::from_utf8_lossy(buf));
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            std::io::stderr().flush()
        }
    }

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("FailKeep={level},info")));
    applog::init_file(file, 5 * 1024 * 1024);
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(|| DualWriter)
        .init();
}

fn load_cfg(path: &PathBuf) -> Result<Config> {
    if !path.exists() {
        bail!(
            "config not found: {}\nCopy config.example.toml to that path and edit.",
            path.display()
        );
    }
    Config::load(path)
}

fn print_ipc(resp: ipc::Response) -> Result<()> {
    if resp.ok {
        if let Some(data) = resp.data {
            println!("{}", serde_json::to_string_pretty(&data)?);
        } else {
            println!("ok");
        }
        Ok(())
    } else {
        bail!(resp.error.unwrap_or_else(|| "unknown error".into()))
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.cmd {
        Commands::CheckConfig => {
            let cfg = load_cfg(&cli.config)?;
            println!(
                "OK: {} jail(s), state={}, ban_ports={}",
                cfg.jails.len(),
                cfg.service.state_file,
                cfg.firewall.ban_ports
            );
            for j in &cfg.jails {
                println!(
                    "  - {} enabled={} max_retry={} find_time={}s",
                    j.name, j.enabled, j.max_retry, j.find_time
                );
            }
            return Ok(());
        }
        Commands::Install { force_config } => {
            ensure_config(&cli.config, *force_config)?;
            let exe = std::env::current_exe()?;
            service::install_service(&cli.config, &exe)?;
            return Ok(());
        }
        Commands::Uninstall { purge_rules } => {
            service::uninstall_service(*purge_rules)?;
            return Ok(());
        }
        Commands::PurgeRules => {
            let cfg = if cli.config.exists() {
                load_cfg(&cli.config)?
            } else {
                Config {
                    service: Default::default(),
                    lists: Default::default(),
                    firewall: Default::default(),
                    geo: Default::default(),
                    stats: Default::default(),
                    jails: vec![],
                }
            };
            let fw = ban::firewall::Firewall::new(&cfg.firewall, false);
            let n = fw.purge_prefix_rules()?;
            println!("removed {n} FailKeep firewall rule(s)");
            return Ok(());
        }
        Commands::ServiceRun => {
            return service::run_service(cli.config.clone());
        }
        _ => {}
    }

    let cfg = load_cfg(&cli.config)?;
    init_logging(&cfg.service.log_level, &cfg.service.log_file);
    geo::init(cfg.geo.enabled, &cfg.geo.database);

    // Prefer IPC when a live engine is already running (except Run/ServiceRun)
    let prefer_ipc = !matches!(cli.cmd, Commands::Run { .. } | Commands::ServiceRun);
    if prefer_ipc && ipc::server_available() {
        return run_via_ipc(&cli.cmd);
    }

    let dry_run = matches!(&cli.cmd, Commands::Run { dry_run: true });
    let mut eng = Engine::new(cfg, dry_run)?;

    match &cli.cmd {
        Commands::Run { .. } => {
            let stop = eng.stop_flag();
            let handle = eng.handle();
            let _ipc = ipc::spawn_ipc_server(handle, stop.clone());
            let sd = stop.clone();
            ctrlc(sd);
            eng.run_loop(Arc::new(AtomicBool::new(false)))?;
        }
        Commands::Status => print_status(&eng.handle())?,
        Commands::List {
            whitelist,
            temp,
            black,
        } => print_list(&eng.handle(), *whitelist, *temp, *black)?,
        Commands::Stats => print_stats(&eng.handle())?,
        Commands::Jail { name } => print_jail(&eng.handle(), name)?,
        Commands::Ban {
            ip,
            black,
            permanent,
            time,
        } => {
            let req = ipc::Request::Ban {
                ip: ip.clone(),
                black: *black,
                permanent: *permanent,
                time: *time,
            };
            let resp = ipc::handle_request(&eng.handle(), req);
            print_ipc(resp)?;
        }
        Commands::Unban { ip, all } => {
            let req = ipc::Request::Unban {
                ip: ip.clone(),
                all: *all,
            };
            let resp = ipc::handle_request(&eng.handle(), req);
            print_ipc(resp)?;
        }
        Commands::Unblack { ip } => {
            let resp = ipc::handle_request(
                &eng.handle(),
                ipc::Request::Unblack { ip: ip.clone() },
            );
            print_ipc(resp)?;
        }
        Commands::Whitelist { action } => {
            let req = match action {
                WhitelistCmd::Add { ip } => ipc::Request::WhitelistAdd { ip: ip.clone() },
                WhitelistCmd::Remove { ip } => ipc::Request::WhitelistRemove { ip: ip.clone() },
            };
            let resp = ipc::handle_request(&eng.handle(), req);
            print_ipc(resp)?;
        }
        Commands::CheckConfig
        | Commands::Install { .. }
        | Commands::Uninstall { .. }
        | Commands::PurgeRules
        | Commands::ServiceRun => {}
    }
    Ok(())
}

fn ensure_config(path: &PathBuf, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Ok(());
    }
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let example = include_str!("../config.example.toml");
    std::fs::write(path, example)?;
    println!("wrote {}", path.display());
    Ok(())
}

fn run_via_ipc(cmd: &Commands) -> Result<()> {
    let req = match cmd {
        Commands::Status => ipc::Request::Status,
        Commands::List {
            whitelist,
            temp,
            black,
        } => {
            let tier = if *whitelist {
                Some("whitelist".into())
            } else if *temp {
                Some("temp".into())
            } else if *black {
                Some("black".into())
            } else {
                None
            };
            ipc::Request::List { tier }
        }
        Commands::Stats => ipc::Request::Stats,
        Commands::Jail { name } => ipc::Request::Jail { name: name.clone() },
        Commands::Ban {
            ip,
            black,
            permanent,
            time,
        } => ipc::Request::Ban {
            ip: ip.clone(),
            black: *black,
            permanent: *permanent,
            time: *time,
        },
        Commands::Unban { ip, all } => ipc::Request::Unban {
            ip: ip.clone(),
            all: *all,
        },
        Commands::Unblack { ip } => ipc::Request::Unblack { ip: ip.clone() },
        Commands::Whitelist { action } => match action {
            WhitelistCmd::Add { ip } => ipc::Request::WhitelistAdd { ip: ip.clone() },
            WhitelistCmd::Remove { ip } => ipc::Request::WhitelistRemove { ip: ip.clone() },
        },
        _ => bail!("command not supported via IPC"),
    };
    let resp = ipc::call(&req)?;
    print_ipc(resp)
}

fn print_status(handle: &EngineHandle) -> Result<()> {
    print_ipc(ipc::handle_request(handle, ipc::Request::Status))
}
fn print_list(handle: &EngineHandle, w: bool, t: bool, b: bool) -> Result<()> {
    let tier = if w {
        Some("whitelist".into())
    } else if t {
        Some("temp".into())
    } else if b {
        Some("black".into())
    } else {
        None
    };
    print_ipc(ipc::handle_request(handle, ipc::Request::List { tier }))
}
fn print_stats(handle: &EngineHandle) -> Result<()> {
    print_ipc(ipc::handle_request(handle, ipc::Request::Stats))
}
fn print_jail(handle: &EngineHandle, name: &str) -> Result<()> {
    print_ipc(ipc::handle_request(
        handle,
        ipc::Request::Jail {
            name: name.to_string(),
        },
    ))
}

fn ctrlc(flag: Arc<AtomicBool>) {
    #[cfg(windows)]
    {
        use std::sync::OnceLock;
        static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
        let _ = FLAG.set(flag);
        unsafe {
            extern "system" {
                fn SetConsoleCtrlHandler(
                    handler: Option<unsafe extern "system" fn(u32) -> i32>,
                    add: i32,
                ) -> i32;
            }
            unsafe extern "system" fn handler(ctrl: u32) -> i32 {
                if ctrl == 0 || ctrl == 1 {
                    if let Some(f) = FLAG.get() {
                        f.store(true, Ordering::SeqCst);
                    }
                    return 1;
                }
                0
            }
            SetConsoleCtrlHandler(Some(handler), 1);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = flag;
    }
}
