//! Windows service host (SCM).

use crate::config::Config;
use crate::engine::Engine;
use anyhow::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

pub const SERVICE_NAME: &str = "FailKeep";
pub const SERVICE_DISPLAY: &str = "FailKeep Lightweight Ban Service";
pub const SERVICE_DESC: &str =
    "Monitors auth failures and bans attacking IPs via Windows Firewall.";

#[cfg(windows)]
pub fn run_service(config_path: std::path::PathBuf) -> Result<()> {
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
        ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let stop = Arc::new(AtomicBool::new(false));
    let stop_handler = Arc::clone(&stop);

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
                stop_handler.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP
            | ServiceControlAccept::SHUTDOWN
            | ServiceControlAccept::PRESHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let cfg = Config::load(&config_path)?;
    let mut eng = Engine::new(cfg, false)?;
    let ipc_stop = stop.clone();
    let _ipc = crate::ipc::spawn_ipc_server(eng.handle(), ipc_stop);

    let run_res = eng.run_loop(stop.clone());

    let exit = match run_res {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(e) => {
            error!("service engine error: {e:#}");
            ServiceExitCode::Win32(1)
        }
    };
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: exit,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    Ok(())
}

#[cfg(not(windows))]
pub fn run_service(_config_path: std::path::PathBuf) -> Result<()> {
    anyhow::bail!("Windows service only supported on Windows")
}

#[cfg(windows)]
pub fn install_service(config_path: &std::path::Path, exe: &std::path::Path) -> Result<()> {
    use windows_service::service::{ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
    let bin = format!("\"{}\" --config \"{}\" service-run", exe.display(), config_path.display());
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: SERVICE_DISPLAY.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.into(),
        launch_arguments: vec![
            "--config".into(),
            config_path.display().to_string().into(),
            "service-run".into(),
        ],
        dependencies: vec![],
        account_name: None, // Local System
        account_password: None,
    };
    // Prefer launch_arguments over manual bin string
    let _ = bin;
    let service = mgr.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
    let _ = service.set_description(SERVICE_DESC);
    // Recovery: restart after 5s, twice
    // (windows-service may not expose recovery API in all versions — optional)
    info!(path=%config_path.display(), "service installed");
    println!("Installed {SERVICE_NAME}");
    println!("Start: sc start {SERVICE_NAME}");
    Ok(())
}

#[cfg(not(windows))]
pub fn install_service(_config_path: &std::path::Path, _exe: &std::path::Path) -> Result<()> {
    anyhow::bail!("Windows only")
}

#[cfg(windows)]
pub fn uninstall_service(remove_rules: bool) -> Result<()> {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = mgr.open_service(SERVICE_NAME, ServiceAccess::ALL_ACCESS)?;
    let _ = service.stop();
    // wait briefly
    for _ in 0..20 {
        if let Ok(st) = service.query_status() {
            if st.current_state == ServiceState::Stopped {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    service.delete()?;
    info!("service uninstalled");
    println!("Uninstalled {SERVICE_NAME}");
    if remove_rules {
        // Caller passes config or we use default prefix
        let fw = crate::ban::firewall::Firewall::new(
            &crate::config::FirewallConfig::default(),
            false,
        );
        match fw.purge_prefix_rules() {
            Ok(n) => println!("purged {n} firewall rules"),
            Err(e) => eprintln!("purge rules: {e:#}"),
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn uninstall_service(_remove_rules: bool) -> Result<()> {
    anyhow::bail!("Windows only")
}

/// Shared engine handle for IPC + main loop.
pub fn install_hint() -> String {
    format!(
        "Install (admin):\n  FailKeep install --config C:\\ProgramData\\FailKeep\\config.toml\nService: {SERVICE_NAME}"
    )
}
