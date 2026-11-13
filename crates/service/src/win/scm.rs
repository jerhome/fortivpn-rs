//! Service Windows : installation, démarrage/arrêt, boucle du service (SCM).

use std::ffi::OsString;
use std::io;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::watch;
use windows_service::service::{
    Service, ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl,
    ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use super::pipe;
use crate::controller::{Controller, SessionRunner};

/// Nom du service.
pub const SERVICE_NAME: &str = "fortivpn-rs";
const DISPLAY_NAME: &str = "FortiVPN-rs";
const DESCRIPTION: &str = "Client Fortinet SSL VPN : établit le tunnel pour le compte des \
     utilisateurs (pilotage par le named pipe \\\\.\\pipe\\fortivpn-rs).";
/// Arguments de ligne de commande avec lesquels le SCM relance l'exécutable.
const LAUNCH_ARGS: [&str; 2] = ["service", "run"];
/// Délai annoncé au SCM pour l'arrêt (nettoyage réseau compris).
const STOP_WAIT_HINT: Duration = Duration::from_secs(35);
/// Attente maximale d'un changement d'état du service.
const STATE_TIMEOUT: Duration = Duration::from_secs(30);
/// `ERROR_SERVICE_ALREADY_RUNNING` / `ERROR_SERVICE_NOT_ACTIVE`.
const ERROR_ALREADY_RUNNING: i32 = 1056;
const ERROR_NOT_ACTIVE: i32 = 1062;

/// Message lisible, chaîne de causes comprise (l'erreur de la crate seule se
/// résume à « Windows API call failed »).
fn describe(e: &windows_service::Error) -> String {
    let mut out = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        out.push_str(" : ");
        out.push_str(&s.to_string());
        source = s.source();
    }
    out
}

fn to_io(e: &windows_service::Error) -> io::Error {
    let text = describe(e);
    match raw_code(e) {
        Some(c) => io::Error::new(io::Error::from_raw_os_error(c).kind(), text),
        None => io::Error::other(text),
    }
}

fn raw_code(e: &windows_service::Error) -> Option<i32> {
    match e {
        windows_service::Error::Winapi(inner) => inner.raw_os_error(),
        _ => None,
    }
}

fn manager(access: ServiceManagerAccess) -> io::Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access).map_err(|e| to_io(&e))
}

fn open(access: ServiceAccess, manager_access: ServiceManagerAccess) -> io::Result<Service> {
    manager(manager_access)?
        .open_service(SERVICE_NAME, access)
        .map_err(|e| to_io(&e))
}

/// Installe le service (démarrage automatique, compte `LocalSystem`) pour `exe` ;
/// l'appelant a vérifié que `exe` est dans un dossier réservé aux administrateurs.
pub fn install(exe: &Path) -> io::Result<()> {
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.to_path_buf(),
        launch_arguments: LAUNCH_ARGS.iter().map(OsString::from).collect(),
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager(ServiceManagerAccess::CREATE_SERVICE)?
        .create_service(&info, ServiceAccess::CHANGE_CONFIG)
        .map_err(|e| to_io(&e))?;
    service.set_description(DESCRIPTION).map_err(|e| to_io(&e))
}

/// Attend que le service atteigne `wanted`.
fn wait_state(service: &Service, wanted: ServiceState) -> io::Result<()> {
    let deadline = Instant::now() + STATE_TIMEOUT;
    loop {
        let status = service.query_status().map_err(|e| to_io(&e))?;
        if status.current_state == wanted {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "le service n'a pas changé d'état à temps",
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Démarre le service (sans erreur s'il tourne déjà) et attend `Running`.
pub fn start() -> io::Result<()> {
    let service = open(
        ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        ServiceManagerAccess::CONNECT,
    )?;
    match service.start::<&str>(&[]) {
        Ok(()) => {}
        Err(e) if raw_code(&e) == Some(ERROR_ALREADY_RUNNING) => {}
        Err(e) => return Err(to_io(&e)),
    }
    wait_state(&service, ServiceState::Running)
}

/// Arrête le service (sans erreur s'il est arrêté) et attend `Stopped`.
pub fn stop() -> io::Result<()> {
    let service = open(
        ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
        ServiceManagerAccess::CONNECT,
    )?;
    stop_service(&service)
}

fn stop_service(service: &Service) -> io::Result<()> {
    match service.stop() {
        Ok(_) => {}
        Err(e) if raw_code(&e) == Some(ERROR_NOT_ACTIVE) => return Ok(()),
        Err(e) => return Err(to_io(&e)),
    }
    wait_state(service, ServiceState::Stopped)
}

/// Arrête puis supprime le service.
pub fn uninstall() -> io::Result<()> {
    let service = open(
        ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
        ServiceManagerAccess::CONNECT,
    )?;
    stop_service(&service)?;
    service.delete().map_err(|e| to_io(&e))
}

/// PID du processus du service en cours d'exécution (lecture seule, ouverte aux
/// utilisateurs standard).
pub(super) fn service_process_id() -> io::Result<u32> {
    let service = open(ServiceAccess::QUERY_STATUS, ServiceManagerAccess::CONNECT)?;
    let status = service.query_status().map_err(|e| to_io(&e))?;
    match status.process_id {
        Some(pid) if pid != 0 && status.current_state == ServiceState::Running => Ok(pid),
        _ => Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "le service fortivpn-rs n'est pas démarré (`fortivpn service start`, en administrateur)",
        )),
    }
}

/// Corps du service, fourni à `service_main` : reçoit le signal d'arrêt et un
/// rappel « arrêt en cours ».
type Entry = Box<dyn FnOnce(watch::Receiver<bool>, &dyn Fn()) -> io::Result<()> + Send>;

static ENTRY: Mutex<Option<Entry>> = Mutex::new(None);

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    let entry = ENTRY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let Some(entry) = entry else {
        tracing::error!("point d'entrée du service absent");
        return;
    };
    if let Err(e) = run(entry) {
        tracing::error!(error = %e, "service terminé en erreur");
    }
}

fn status(
    state: ServiceState,
    accepted: ServiceControlAccept,
    exit: u32,
    checkpoint: u32,
    wait_hint: Duration,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepted,
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint,
        wait_hint,
        process_id: None,
    }
}

fn run(entry: Entry) -> io::Result<()> {
    let (stop_tx, stop_rx) = watch::channel(false);
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let handle = service_control_handler::register(SERVICE_NAME, handler).map_err(|e| to_io(&e))?;
    let set = |s: ServiceStatus| {
        if let Err(e) = handle.set_service_status(s) {
            tracing::warn!(error = %describe(&e), "statut du service non transmis au SCM");
        }
    };
    set(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        0,
        0,
        Duration::ZERO,
    ));
    let stopping = || {
        set(status(
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            0,
            1,
            STOP_WAIT_HINT,
        ));
    };
    let result = entry(stop_rx, &stopping);
    let exit = u32::from(result.is_err());
    set(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit,
        0,
        Duration::ZERO,
    ));
    result
}

/// Exécute le processus comme service (appelé quand le SCM lance
/// `fortivpn service run`) : sert le pipe jusqu'à l'ordre d'arrêt du SCM, puis
/// coupe la session éventuelle (nettoyage réseau) avant de s'arrêter. Bloquant.
pub fn run_service<R: SessionRunner>(runner: R) -> io::Result<()> {
    let entry: Entry = Box::new(move |stop, stopping| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        runtime.block_on(async move {
            let controller = std::sync::Arc::new(Controller::new(runner));
            let served = pipe::serve(std::sync::Arc::clone(&controller), stop).await;
            stopping();
            controller.shutdown().await;
            served
        })
    });
    *ENTRY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(entry);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|e| to_io(&e))
}
