//! Mode service Windows (story 4.3).
//!
//! - **Service** (`fortivpn service run`, lancé par le gestionnaire de services,
//!   compte SYSTEM) : [`ServiceRunner`] exécute la [`Session`](fortivpn_core::Session)
//!   avec `WinNetBackend` et le transport de [`crate::transport::build_transport`].
//!   Hôte, utilisateur, realm, empreinte et interface viennent **uniquement** de
//!   `%ProgramData%\fortivpn-rs\config.toml`, vérifié réservé aux administrateurs ;
//!   le client du pipe ne fournit que le mot de passe (revue 5.3, M4).
//! - **Administration** (`fortivpn service install|uninstall|start|stop`) : droits
//!   administrateur.
//! - **Client** (`connect --service`, `disconnect`, `status`) : sans privilèges, parle
//!   au service par le named pipe `\\.\pipe\fortivpn-rs`.
//!
//! La logique du protocole et de la machine d'états est dans `fortivpn-service`
//! (testée sous Linux) ; ici, la colle (conversion des événements de session, rendu
//! de l'état, vérification de la configuration protégée) l'est aussi. Les appels
//! système (pipe, SCM) sont `cfg(windows)` et seulement compilés depuis WSL.

use std::path::Path;

use fortivpn_core::{Credentials, DisconnectReason, SessionOptions, SessionState};
use fortivpn_service::{
    ErrorCode, EventSink, Outcome, Request, Response, SessionRunner, Stage, State, StatusReport,
};
use secrecy::SecretString;
use tokio::sync::oneshot;

use crate::cli::ServiceAction;
use crate::config::{self, Config};
use crate::exit::{self, Exit};
use crate::{run, transport};

// ---------------------------------------------------------------------------
// Conversions pures
// ---------------------------------------------------------------------------

/// Étape du protocole correspondant à un état de session (`None` : pas d'étape).
pub(crate) fn stage_of(state: &SessionState) -> Option<Stage> {
    match state {
        SessionState::Connecting => Some(Stage::Connecting),
        SessionState::Authenticated => Some(Stage::Authenticated),
        SessionState::ConfigReceived => Some(Stage::ConfigReceived),
        SessionState::TunnelUp { config, interface } => Some(Stage::TunnelUp(format!(
            "{} {}",
            interface.name, config.ipv4.address
        ))),
        // `Disconnected` : l'issue est rendue par `run_session` (voir `outcome_of`).
        _ => None,
    }
}

/// Code d'erreur du protocole pour un code de sortie (`None` : succès).
fn error_code(exit: Exit) -> Option<ErrorCode> {
    match exit {
        Exit::Ok => None,
        Exit::Internal | Exit::Usage => Some(ErrorCode::Internal),
        Exit::Config => Some(ErrorCode::Config),
        Exit::AuthRejected => Some(ErrorCode::AuthRejected),
        Exit::Connection => Some(ErrorCode::Connection),
        Exit::LocalNetwork => Some(ErrorCode::LocalNetwork),
        Exit::AlreadyRunning => Some(ErrorCode::AlreadyRunning),
    }
}

/// Code de sortie du client pour un code d'erreur du service.
pub(crate) fn exit_of(code: ErrorCode) -> Exit {
    match code {
        ErrorCode::BadRequest
        | ErrorCode::Timeout
        | ErrorCode::Internal
        | ErrorCode::Forbidden
        | ErrorCode::RateLimited => Exit::Internal,
        ErrorCode::Busy | ErrorCode::AlreadyRunning => Exit::AlreadyRunning,
        ErrorCode::Config => Exit::Config,
        ErrorCode::AuthRejected => Exit::AuthRejected,
        ErrorCode::Connection => Exit::Connection,
        ErrorCode::LocalNetwork => Exit::LocalNetwork,
    }
}

/// Issue d'une session pour le protocole.
pub(crate) fn outcome_of(reason: &DisconnectReason) -> Outcome {
    match error_code(exit::from_reason(reason)) {
        None => Outcome::requested(),
        Some(code) => Outcome::failed(code, run::describe_reason(reason)),
    }
}

/// Lit la configuration du service après avoir vérifié (via `check`) que le dossier
/// et le fichier sont réservés aux administrateurs : sans cela, un utilisateur
/// standard pourrait choisir l'hôte ou l'épinglage de certificat.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn load_protected_config(
    path: &Path,
    check: &dyn Fn(&Path) -> Result<(), String>,
) -> Result<Config, String> {
    if let Some(dir) = path.parent() {
        check(dir)?;
    }
    check(path)?;
    let config = config::load(path).map_err(|e| e.to_string())?;
    // Le service crée toujours le TUN système : `[proxy]` serait ignoré en silence
    // (point 7.1), donc refusé explicitement.
    if config.proxy.is_some() {
        return Err(
            "la section [proxy] n'est pas supportée en mode service (le service \
                    établit un tunnel système) ; retirez-la du fichier de configuration du \
                    service, ou utilisez `fortivpn connect` sans le service"
                .into(),
        );
    }
    Ok(config)
}

/// Rendu lisible de l'état (sans secret) : état, étapes et durées par étape.
pub(crate) fn render_status(report: &StatusReport) -> String {
    use std::fmt::Write as _;
    let label = match report.state {
        State::Idle => "déconnecté",
        State::Connecting => "connexion en cours",
        State::Authenticated => "authentifié (configuration en attente)",
        State::ConfigReceived => "configuration reçue (tunnel en cours de création)",
        State::TunnelUp => "tunnel actif",
        State::Disconnecting => "déconnexion en cours",
    };
    let mut out = format!("état : {label}");
    if let Some(ms) = report.connected_for_ms {
        let _ = write!(out, " depuis {} s", ms / 1000);
    }
    if let Some(tunnel) = &report.tunnel {
        let _ = write!(out, " ({tunnel})");
    }
    out.push('\n');
    let s = &report.steps;
    let marks = [
        ("connexion", s.connecting_ms),
        ("authentification", s.authenticated_ms),
        ("configuration", s.config_received_ms),
        ("tunnel", s.tunnel_up_ms),
    ];
    let mut prev = 0;
    let mut parts = Vec::new();
    for (name, at) in marks {
        if let Some(at) = at {
            parts.push(format!("{name} +{} ms", at.saturating_sub(prev)));
            prev = at;
        }
    }
    if !parts.is_empty() {
        let _ = writeln!(out, "étapes : {} (total {prev} ms)", parts.join(", "));
    }
    match &report.last_outcome {
        Some(Outcome { error: None, .. }) => out.push_str("dernière session : arrêt demandé\n"),
        Some(Outcome {
            error: Some(_),
            message,
        }) => {
            let _ = writeln!(out, "dernière session : échec : {message}");
        }
        None => {}
    }
    out
}

// ---------------------------------------------------------------------------
// Côté service : exécution des sessions
// ---------------------------------------------------------------------------

/// Exécute les sessions demandées par le pipe. Ne reçoit que le mot de passe.
#[derive(Debug)]
pub(crate) struct ServiceRunner {
    /// Chargeur de la configuration protégée (injectable pour les tests).
    load_config: fn() -> Result<Config, String>,
}

impl ServiceRunner {
    /// Runner de production : configuration sous `%ProgramData%`.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn production() -> Self {
        Self {
            load_config: production_config,
        }
    }
}

impl SessionRunner for ServiceRunner {
    fn run(
        &self,
        password: SecretString,
        stop: oneshot::Receiver<()>,
        events: &EventSink,
    ) -> Outcome {
        let config = match (self.load_config)() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("configuration du service inutilisable : {e}");
                return Outcome::failed(ErrorCode::Config, e);
            }
        };
        let transport = match transport::build_transport(&config) {
            Ok(t) => t,
            Err(e) => return Outcome::failed(ErrorCode::Internal, e.to_string()),
        };
        let backend = match crate::platform::backend() {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("initialisation du réseau impossible : {e}");
                let code = error_code(exit::from_backend_error(&e)).unwrap_or(ErrorCode::Internal);
                return Outcome::failed(code, format!("initialisation du réseau : {e}"));
            }
        };
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => return Outcome::failed(ErrorCode::Internal, e.to_string()),
        };
        let credentials = Credentials::new(config.username.clone(), password);
        let mut reporter = run::Reporter::default();
        let reason = runtime.block_on(run::run_session(
            transport,
            backend,
            credentials,
            SessionOptions::new(config.interface.clone()),
            async {
                // Signal reçu, ou contrôleur libéré : dans les deux cas, on s'arrête.
                let _ = stop.await;
            },
            |event| {
                tracing::info!("{}", reporter.observe(event));
                if let Some(stage) = stage_of(&event.state) {
                    events.stage(stage, event.elapsed);
                }
            },
        ));
        outcome_of(&reason)
    }
}

/// Configuration du service (`%ProgramData%\fortivpn-rs\config.toml`, admin-only).
fn production_config() -> Result<Config, String> {
    #[cfg(windows)]
    {
        let path = win::config_path()?;
        load_protected_config(&path, &|p| {
            netwin::ensure_admin_only(p).map_err(|e| e.to_string())
        })
    }
    #[cfg(not(windows))]
    {
        Err("le service n'existe que sous Windows".into())
    }
}

// ---------------------------------------------------------------------------
// Client (sans privilèges)
// ---------------------------------------------------------------------------

/// Commande adressée au service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientCommand {
    Connect,
    Disconnect,
    Status,
}

/// Un échange avec le service (pipe Windows).
#[cfg(windows)]
async fn exchange(request: &Request) -> Result<Response, String> {
    let mut pipe = fortivpn_service::connect_pipe()
        .await
        .map_err(|e| e.to_string())?;
    fortivpn_service::call(&mut pipe, request)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(not(windows))]
#[allow(clippy::unused_async)]
async fn exchange(_request: &Request) -> Result<Response, String> {
    Err("le mode service n'existe que sous Windows".into())
}

fn print_response(response: &Response) -> Exit {
    match response {
        Response::Ok { status } => {
            print!("{}", render_status(status));
            Exit::Ok
        }
        Response::Error { code, message } => {
            eprintln!("fortivpn : {message}");
            exit_of(*code)
        }
    }
}

/// Exécute `connect --service`, `disconnect` ou `status`.
pub(crate) fn run_client(command: ClientCommand) -> Exit {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fortivpn : démarrage du runtime impossible : {e}");
            return Exit::Internal;
        }
    };
    runtime.block_on(async {
        let request = match command {
            ClientCommand::Status => Request::Status {},
            ClientCommand::Disconnect => Request::Disconnect {},
            ClientCommand::Connect => {
                // Avant la saisie : service joignable et authentique, aucune
                // connexion déjà active.
                match exchange(&Request::Status {}).await {
                    Ok(Response::Ok { status }) if status.state == State::Idle => {}
                    Ok(Response::Ok { status }) => {
                        eprintln!("fortivpn : une connexion existe déjà.");
                        eprint!("{}", render_status(&status));
                        return Exit::AlreadyRunning;
                    }
                    Ok(other) => return print_response(&other),
                    Err(e) => {
                        eprintln!("fortivpn : {e}");
                        return Exit::Internal;
                    }
                }
                let password = match crate::read_password("Mot de passe VPN : ") {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("fortivpn : saisie du mot de passe impossible : {e}");
                        return Exit::Internal;
                    }
                };
                eprintln!("connexion en cours (via le service)…");
                Request::Connect { password }
            }
        };
        match exchange(&request).await {
            Ok(response) => print_response(&response),
            Err(e) => {
                eprintln!("fortivpn : {e}");
                Exit::Internal
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Administration du service
// ---------------------------------------------------------------------------

/// Exécute `service install|uninstall|start|stop|run`.
pub(crate) fn run_admin(action: ServiceAction) -> Exit {
    #[cfg(windows)]
    {
        win::run_admin(action)
    }
    #[cfg(not(windows))]
    {
        let _ = action;
        eprintln!("fortivpn : le service n'existe que sous Windows.");
        Exit::Internal
    }
}

#[cfg(windows)]
mod win {
    use std::path::PathBuf;

    use super::{ServiceAction, ServiceRunner};
    use crate::config;
    use crate::exit::Exit;

    /// `%ProgramData%\fortivpn-rs`.
    fn data_dir() -> Result<PathBuf, String> {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .map(|p| p.join(config::APP_DIR))
            .ok_or_else(|| "variable ProgramData absente ou invalide".to_owned())
    }

    pub(super) fn config_path() -> Result<PathBuf, String> {
        data_dir().map(|d| d.join(config::CONFIG_FILE))
    }

    fn admin_only(path: &std::path::Path) -> Result<(), String> {
        netwin::ensure_admin_only(path).map_err(|e| e.to_string())
    }

    fn admin_only_chain(path: &std::path::Path) -> Result<(), String> {
        netwin::ensure_admin_only_chain(path).map_err(|e| e.to_string())
    }

    /// Le service tourne en SYSTEM : l'exécutable, son dossier (où est aussi
    /// wintun.dll) et **tous les ancêtres** de ce dossier jusqu'à la racine du
    /// volume ne doivent pas être modifiables par un utilisateur standard (F1).
    /// Appelé à l'installation et à chaque démarrage du service.
    fn verify_install(exe: &std::path::Path) -> Result<(), String> {
        if let Some(dir) = exe.parent() {
            admin_only(dir)?;
            admin_only_chain(dir)?;
        }
        admin_only(exe)?;
        let dll = netwin::WinNetOptions::default().wintun_dll;
        if dll.exists() {
            admin_only(&dll)?;
        }
        Ok(())
    }

    fn install() -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        verify_install(&exe)?;
        let data = data_dir()?;
        fortivpn_service::create_admin_only_dir(&data).map_err(|e| e.to_string())?;
        admin_only(&data)?;
        fortivpn_service::install(&exe).map_err(|e| format!("installation : {e}"))?;
        fortivpn_service::start().map_err(|e| format!("démarrage : {e}"))?;
        println!(
            "service {} installé et démarré.",
            fortivpn_service::SERVICE_NAME
        );
        println!(
            "Créer {} (hôte, utilisateur…, voir `fortivpn check-config`) ; \
             wintun.dll doit être à côté de l'exécutable.",
            data.join(config::CONFIG_FILE).display()
        );
        Ok(())
    }

    /// Journal du service : fichier dans le dossier admin-only (pas de console).
    fn init_logging() {
        let file = data_dir().ok().and_then(|d| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(d.join("service.log"))
                .ok()
        });
        if let Some(file) = file {
            crate::logging::init_to_file(config::LogLevel::Info, file);
        }
    }

    fn run_service() -> Result<(), String> {
        init_logging();
        // Intégrité de l'installation rejouée à chaque démarrage (F1) : refus sinon.
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        verify_install(&exe).map_err(|e| format!("installation non sûre, service refusé : {e}"))?;
        if let Ok(dir) = data_dir() {
            admin_only(&dir)?;
            admin_only_chain(&dir)?;
        }
        // Résidus d'un crash précédent (routes, NRPT, journal d'état) : purgés
        // avant d'accepter la moindre connexion ; le backend (et son verrou) est
        // libéré aussitôt.
        match crate::platform::backend() {
            Ok(backend) => drop(backend),
            Err(e) => tracing::warn!(error = %e, "purge des résidus au démarrage impossible"),
        }
        fortivpn_service::run_service(ServiceRunner::production()).map_err(|e| e.to_string())
    }

    pub(super) fn run_admin(action: ServiceAction) -> Exit {
        let result = match action {
            ServiceAction::Install => install(),
            ServiceAction::Uninstall => fortivpn_service::uninstall()
                .map(|()| println!("service supprimé."))
                .map_err(|e| e.to_string()),
            ServiceAction::Start => fortivpn_service::start()
                .map(|()| println!("service démarré."))
                .map_err(|e| e.to_string()),
            ServiceAction::Stop => fortivpn_service::stop()
                .map(|()| println!("service arrêté."))
                .map_err(|e| e.to_string()),
            ServiceAction::Run => run_service(),
        };
        match result {
            Ok(()) => Exit::Ok,
            Err(e) => {
                // `run` : pas de console ; l'erreur est aussi dans le journal.
                tracing::error!("{e}");
                eprintln!("fortivpn : {e}");
                Exit::Internal
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use fortivpn_core::{
        DnsConfig, Ipv4Config, RoutingMode, TransportError, TunInfo, TunnelConfig,
    };
    use fortivpn_service::{Controller, StepTimings};

    use super::*;

    fn tunnel_up() -> SessionState {
        SessionState::TunnelUp {
            config: TunnelConfig {
                ipv4: Ipv4Config {
                    address: "10.1.2.3/32".parse().unwrap(),
                    peer: None,
                },
                ipv6: None,
                mtu: 1354,
                dns: DnsConfig {
                    servers: vec![],
                    search_domains: vec![],
                },
                routing: RoutingMode::Split { include: vec![] },
                gateway: "203.0.113.10".parse().unwrap(),
            },
            interface: TunInfo {
                name: "fortivpn".into(),
                index: Some(7),
            },
        }
    }

    #[test]
    fn session_states_map_to_stages() {
        assert_eq!(stage_of(&SessionState::Connecting), Some(Stage::Connecting));
        assert_eq!(
            stage_of(&SessionState::Authenticated),
            Some(Stage::Authenticated)
        );
        assert_eq!(
            stage_of(&SessionState::ConfigReceived),
            Some(Stage::ConfigReceived)
        );
        assert_eq!(
            stage_of(&tunnel_up()),
            Some(Stage::TunnelUp("fortivpn 10.1.2.3/32".into()))
        );
        assert_eq!(
            stage_of(&SessionState::Disconnected {
                reason: DisconnectReason::Requested
            }),
            None
        );
    }

    #[test]
    fn reasons_map_to_outcomes_and_back_to_exit_codes() {
        assert_eq!(
            outcome_of(&DisconnectReason::Requested),
            Outcome::requested()
        );
        let auth = outcome_of(&DisconnectReason::ConnectFailed(std::sync::Arc::new(
            TransportError::AuthFailed,
        )));
        assert_eq!(auth.error, Some(ErrorCode::AuthRejected));
        assert_eq!(exit_of(ErrorCode::AuthRejected), Exit::AuthRejected);
        assert_eq!(exit_of(ErrorCode::Busy), Exit::AlreadyRunning);
        assert_eq!(exit_of(ErrorCode::Config), Exit::Config);
        assert_eq!(
            outcome_of(&DisconnectReason::TunClosed).error,
            Some(ErrorCode::LocalNetwork)
        );
    }

    #[test]
    fn status_rendering() {
        let report = StatusReport {
            state: State::TunnelUp,
            steps: StepTimings {
                connecting_ms: Some(0),
                authenticated_ms: Some(120),
                config_received_ms: Some(180),
                tunnel_up_ms: Some(900),
            },
            connected_for_ms: Some(65_000),
            tunnel: Some("fortivpn 10.1.2.3/32".into()),
            last_outcome: Some(Outcome::failed(ErrorCode::Connection, "tunnel interrompu")),
        };
        let text = render_status(&report);
        assert!(
            text.contains("tunnel actif depuis 65 s (fortivpn 10.1.2.3/32)"),
            "{text}"
        );
        assert!(
            text.contains(
                "connexion +0 ms, authentification +120 ms, configuration +60 ms, \
                 tunnel +720 ms (total 900 ms)"
            ),
            "{text}"
        );
        assert!(text.contains("dernière session : échec : tunnel interrompu"));
        let idle = render_status(&StatusReport {
            state: State::Idle,
            steps: StepTimings::default(),
            connected_for_ms: None,
            tunnel: None,
            last_outcome: None,
        });
        assert_eq!(idle, "état : déconnecté\n");
    }

    #[test]
    fn protected_config_requires_admin_only_dir_and_file() {
        let dir = std::env::temp_dir().join(format!("fortivpn-svc-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "host = \"vpn.example.com\"\nusername = \"alice\"\n").unwrap();

        let ok = load_protected_config(&path, &|_| Ok(())).unwrap();
        assert_eq!(ok.host, "vpn.example.com");

        let checked = std::cell::RefCell::new(Vec::new());
        let deny_dir = |p: &Path| {
            checked.borrow_mut().push(p.to_path_buf());
            if p == dir {
                Err("dossier modifiable".to_owned())
            } else {
                Ok(())
            }
        };
        assert_eq!(
            load_protected_config(&path, &deny_dir).unwrap_err(),
            "dossier modifiable"
        );
        let deny_file = |p: &Path| {
            if p == path {
                Err("fichier modifiable".to_owned())
            } else {
                Ok(())
            }
        };
        assert_eq!(
            load_protected_config(&path, &deny_file).unwrap_err(),
            "fichier modifiable"
        );
        // Absent : erreur de configuration, pas de panique.
        assert!(load_protected_config(&dir.join("absent.toml"), &|_| Ok(())).is_err());
        // `[proxy]` : refusé en mode service.
        std::fs::write(
            &path,
            "host = \"vpn.example.com\"\nusername = \"alice\"\n[proxy]\n",
        )
        .unwrap();
        let err = load_protected_config(&path, &|_| Ok(())).unwrap_err();
        assert!(
            err.contains("[proxy]") && err.contains("mode service"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn runner_without_usable_config_reports_config_error() {
        let controller = Controller::with_timeouts(
            ServiceRunner {
                load_config: || Err("fichier non protégé".into()),
            },
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let response = controller
            .handle(
                Request::Connect {
                    password: zeroize::Zeroizing::new("pw".into()),
                },
                &fortivpn_service::Caller::new("S-1-5-21-1-2-3-1001", false),
            )
            .await;
        assert!(
            matches!(&response, Response::Error { code: ErrorCode::Config, message } if message == "fichier non protégé"),
            "{response:?}"
        );
    }
}
