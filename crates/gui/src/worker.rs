//! Travail asynchrone : runtime tokio sur un thread dédié.
//!
//! L'interface n'effectue **aucune** I/O : elle envoie des [`Command`] et affiche
//! l'état partagé ([`Shared`]) que le worker met à jour avant de la notifier
//! ([`Notice::Render`]). Le worker lit/écrit `config.toml`, ouvre le proxy local,
//! pilote la session (`core`) ou parle au service (named pipe).
//!
//! Le mot de passe ne transite que dans [`Command::Connect`] (`SecretString`), n'est
//! jamais copié dans [`Shared`] ni journalisé, et est consommé par la session.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use fortivpn_app::config::{self, Config};
use fortivpn_app::platform::{self, AnyBackend};
use fortivpn_app::run::run_session;
use fortivpn_app::sudo;
use fortivpn_app::svc::exchange;
use fortivpn_app::transport::build_transport;
use fortivpn_core::{
    Credentials, DisconnectReason, NetBackend, SecondFactorAnswer, SecondFactorChallenge,
    SecondFactorFuture, SecondFactorKind, SecondFactorProvider, SessionEvent, SessionOptions,
    Transport,
};
use fortivpn_service::{ErrorCode, Request, Response, State, StatusReport};
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use crate::model::{LogLevel, Mode, Phase, ProxyInfo, UiState};
use crate::settings::{
    SettingsForm, blank_config, load_close_to_tray, load_mode, save_close_to_tray, save_mode,
};

/// Notification du worker vers l'interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notice {
    /// L'état partagé a changé : redessiner.
    Render,
    /// Quitter l'application (arrêt propre terminé).
    Quit,
}

/// État partagé entre le worker (écriture) et l'interface (lecture, thread UI).
#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)] // drapeaux indépendants d'état d'interface
pub struct Shared {
    /// État d'affichage de la connexion.
    pub ui: UiState,
    /// Un chargement/enregistrement de réglages est en cours.
    pub busy: bool,
    /// Message de l'écran Réglages.
    pub settings_message: String,
    /// Le message de réglages est un succès.
    pub settings_ok: bool,
    /// Formulaire à pousser dans l'interface (consommé par le rendu : évite
    /// d'écraser la saisie en cours).
    pub pending_form: Option<SettingsForm>,
    /// Utilisateur à pousser dans le champ de l'écran principal.
    pub pending_username: Option<String>,
    /// Mode à pousser dans le sélecteur (dernier mode mémorisé).
    pub pending_mode: Option<Mode>,
    /// Le mode Service est utilisable (sonde du service réussie).
    pub service_available: bool,
    /// Demande d'ouverture de l'écran Réglages (consommée par le rendu).
    pub open_settings: bool,
    /// Fermer la fenêtre la réduit dans la zone de notification.
    pub close_to_tray: bool,
    /// Dernière phase ayant donné lieu à l'évaluation d'une notification.
    pub notified_phase: Phase,
}

impl Shared {
    /// État initial.
    pub fn new() -> Self {
        Self {
            ui: UiState::new(),
            service_available: true,
            close_to_tray: true,
            ..Self::default()
        }
    }
}

/// Canal d'écriture de l'état partagé + notification de l'interface.
#[derive(Clone)]
pub struct Sink {
    shared: Arc<Mutex<Shared>>,
    notify: Arc<dyn Fn(Notice) + Send + Sync>,
}

impl std::fmt::Debug for Sink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sink")
    }
}

/// Heure locale `HH:MM:SS` pour le journal.
fn timestamp() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

impl Sink {
    /// Crée le canal ; `notify` est appelé (depuis n'importe quel thread) après
    /// chaque modification.
    pub fn new(notify: impl Fn(Notice) + Send + Sync + 'static) -> Self {
        Self::with_shared(Arc::new(Mutex::new(Shared::new())), notify)
    }

    /// Comme [`new`](Self::new), sur un état partagé que `notify` peut aussi lire.
    pub fn with_shared(
        shared: Arc<Mutex<Shared>>,
        notify: impl Fn(Notice) + Send + Sync + 'static,
    ) -> Self {
        Self {
            shared,
            notify: Arc::new(notify),
        }
    }

    /// Accès en lecture/écriture à l'état (verrou bref : jamais d'I/O dedans).
    pub fn lock(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Modifie l'état puis notifie l'interface.
    pub fn update<R>(&self, f: impl FnOnce(&mut Shared, &str) -> R) -> R {
        let ts = timestamp();
        let r = f(&mut self.lock(), &ts);
        (self.notify)(Notice::Render);
        r
    }

    fn quit(&self) {
        (self.notify)(Notice::Quit);
    }

    fn event(&self, event: &SessionEvent) {
        self.update(|s, ts| s.ui.apply_event(event, ts, Instant::now()));
    }

    fn status(&self, status: &StatusReport) {
        self.update(|s, ts| s.ui.apply_status(status, ts, Instant::now()));
    }

    fn fail(&self, message: impl Into<String>) {
        let message = message.into();
        self.update(|s, ts| s.ui.fail(ts, message));
    }

    /// Garantit le retour à l'état déconnecté en fin de tâche.
    fn ensure_idle(&self) {
        self.update(|s, ts| {
            if s.ui.phase.is_active() {
                s.ui.finish(&DisconnectReason::Requested, ts);
            }
        });
    }
}

/// Ordre de l'interface vers le worker.
#[derive(Debug)]
pub enum Command {
    /// Se connecter (le mot de passe est consommé).
    Connect {
        /// Mode choisi.
        mode: Mode,
        /// Utilisateur saisi (vide : celui du fichier de configuration).
        username: String,
        /// Mot de passe, jamais stocké.
        password: SecretString,
    },
    /// Annuler la connexion en cours ou se déconnecter.
    Disconnect,
    /// Vérifier la présence du service (changement de mode).
    ProbeService,
    /// Démarrage : sonde du service, dernier mode, première utilisation.
    Startup,
    /// Relire `config.toml`.
    LoadSettings,
    /// Épingler l'empreinte proposée après un certificat refusé (action explicite).
    PinFingerprint,
    /// Valider et enregistrer les réglages.
    SaveSettings(SettingsForm),
    /// Se déconnecter proprement puis quitter.
    Quit,
    /// Réponse à la boîte de dialogue du second facteur (`None` : annulé).
    SecondFactor(Option<SecretString>),
    /// Interne : la tâche de session `id` est terminée.
    Ended(u64),
}

/// Poignée vers le worker (côté interface).
#[derive(Debug, Clone)]
pub struct WorkerHandle {
    tx: mpsc::UnboundedSender<Command>,
}

impl WorkerHandle {
    /// Envoie un ordre (non bloquant). Sans effet si le worker est arrêté.
    pub fn send(&self, command: Command) {
        let _ = self.tx.send(command);
    }
}

/// Démarre le worker sur un thread dédié (runtime tokio multi-thread de 2 threads).
pub fn spawn(
    sink: Sink,
    config_path: Option<PathBuf>,
) -> std::io::Result<(WorkerHandle, std::thread::JoinHandle<()>)> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let (tx, rx) = mpsc::unbounded_channel();
    let handle = WorkerHandle { tx: tx.clone() };
    let thread = std::thread::Builder::new()
        .name("fortivpn-worker".into())
        .spawn(move || runtime.block_on(main_loop(rx, tx, sink, config_path)))?;
    Ok((handle, thread))
}

/// Session en cours.
struct Active {
    id: u64,
    stop: Option<oneshot::Sender<()>>,
}

struct Worker {
    sink: Sink,
    tx: mpsc::UnboundedSender<Command>,
    path: Option<PathBuf>,
    active: Option<Active>,
    next_id: u64,
    quitting: bool,
    /// Dernière configuration lue (base des enregistrements).
    loaded: Option<Config>,
    /// Réponse attendue par le fournisseur de second facteur.
    answer: AnswerSlot,
}

/// Emplacement où le fournisseur attend la réponse de l'utilisateur.
type AnswerSlot = Arc<Mutex<Option<oneshot::Sender<Option<SecretString>>>>>;

/// Second facteur par boîte de dialogue : publie la demande dans l'état partagé puis
/// attend la réponse (`Command::SecondFactor`). Le code n'est ni stocké ni journalisé.
struct DialogSecondFactor {
    sink: Sink,
    slot: AnswerSlot,
}

impl SecondFactorProvider for DialogSecondFactor {
    fn second_factor<'a>(&'a self, challenge: &'a SecondFactorChallenge) -> SecondFactorFuture<'a> {
        Box::pin(async move {
            let push = challenge.kind == SecondFactorKind::Push;
            self.sink.update(|s, ts| {
                s.ui.ask_second_factor(ts, push, challenge.message.as_deref());
            });
            if push {
                // La boîte reste affichée jusqu'à l'approbation (changement d'état).
                return SecondFactorAnswer::Push;
            }
            let (tx, rx) = oneshot::channel();
            *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(tx);
            match rx.await {
                Ok(Some(code)) => SecondFactorAnswer::Code(code),
                _ => SecondFactorAnswer::Cancelled,
            }
        })
    }
}

async fn main_loop(
    mut rx: mpsc::UnboundedReceiver<Command>,
    tx: mpsc::UnboundedSender<Command>,
    sink: Sink,
    path: Option<PathBuf>,
) {
    let mut w = Worker {
        sink,
        tx,
        path,
        active: None,
        next_id: 0,
        quitting: false,
        loaded: None,
        answer: AnswerSlot::default(),
    };
    while let Some(command) = rx.recv().await {
        if w.handle(command).await {
            break;
        }
    }
}

impl Worker {
    /// Traite un ordre ; `true` : arrêter la boucle.
    async fn handle(&mut self, command: Command) -> bool {
        match command {
            Command::Connect {
                mode,
                username,
                password,
            } => self.connect(mode, &username, password).await,
            Command::Disconnect => self.disconnect(),
            Command::ProbeService => self.probe_service().await,
            Command::Startup => self.startup().await,
            Command::LoadSettings => {
                self.load_settings().await;
            }
            Command::PinFingerprint => self.pin_fingerprint().await,
            Command::SaveSettings(form) => self.save_settings(form).await,
            Command::Quit => {
                if self.active.is_some() {
                    self.quitting = true;
                    self.disconnect();
                } else {
                    self.sink.quit();
                    return true;
                }
            }
            Command::SecondFactor(answer) => {
                let sender = self
                    .answer
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                self.sink.update(|s, _| s.ui.second_factor = None);
                if let Some(tx) = sender {
                    let _ = tx.send(answer);
                }
            }
            Command::Ended(id) => {
                if self.active.as_ref().is_some_and(|a| a.id == id) {
                    self.active = None;
                    self.sink.ensure_idle();
                    if self.quitting {
                        self.sink.quit();
                        return true;
                    }
                }
            }
        }
        false
    }

    fn disconnect(&mut self) {
        // Une boîte de second facteur ouverte est annulée avec la session.
        if let Some(tx) = self
            .answer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = tx.send(None);
        }
        if let Some(stop) = self.active.as_mut().and_then(|a| a.stop.take()) {
            self.sink.update(|s, ts| s.ui.disconnecting(ts));
            let _ = stop.send(());
        }
    }

    /// Chemin de configuration : `--config`, ou le défaut (celui de `SUDO_USER` si
    /// l'interface a été lancée en root par `sudo`).
    fn resolved_path(&self) -> Result<sudo::Resolved, String> {
        let resolved =
            sudo::resolve(self.path.as_deref(), &sudo::SystemEnv).map_err(|e| e.to_string())?;
        if let Some(info) = resolved.info() {
            tracing::info!("{info}");
        }
        Ok(resolved)
    }

    fn config_path(&self) -> Result<PathBuf, String> {
        self.resolved_path().map(|r| r.path)
    }

    async fn read_config(&self) -> Result<(PathBuf, Option<Config>), String> {
        let resolved = self.resolved_path()?;
        let path = resolved.path.clone();
        let p = path.clone();
        let result = tokio::task::spawn_blocking(move || {
            if p.exists() {
                // Contexte sudo : refuse un fichier contrôlable par un tiers.
                resolved.verify().map_err(|e| e.to_string())?;
                config::load(&p)
                    .map(Some)
                    .map_err(|e| format!("{} : {e}", p.display()))
            } else {
                Ok(None)
            }
        })
        .await
        .map_err(|e| e.to_string())??;
        Ok((path, result))
    }

    /// Au démarrage : sonde du service, dernier mode, et ouverture directe des
    /// Réglages si la configuration n'existe pas encore (première utilisation).
    async fn startup(&mut self) {
        self.probe_service().await;
        let mode = self
            .config_path()
            .ok()
            .and_then(|p| load_mode(&p))
            .unwrap_or_default();
        let available = self.sink.lock().service_available;
        let mode = if mode == Mode::Service && !available {
            Mode::Proxy
        } else {
            mode
        };
        let close_to_tray = self
            .config_path()
            .ok()
            .is_none_or(|p| load_close_to_tray(&p));
        self.sink.update(|s, _| {
            s.pending_mode = Some(mode);
            s.close_to_tray = close_to_tray;
        });
        let first_run = self.load_settings().await;
        if first_run {
            self.sink.update(|s, _| s.open_settings = true);
        }
    }

    /// Épingle l'empreinte proposée (uniquement si aucun certificat n'est épinglé).
    async fn pin_fingerprint(&mut self) {
        let offer = self.sink.lock().ui.visible_pin_offer().map(str::to_owned);
        let Some(fp) = offer else { return };
        let Ok(fingerprint) = fp.parse::<fortivpn_core::sslvpn::CertFingerprint>() else {
            return;
        };
        let mut config = match self.read_config().await {
            Ok((_, Some(c))) => c,
            _ => self.loaded.clone().unwrap_or_else(blank_config),
        };
        if !config.trusted_cert.is_empty() {
            return;
        }
        config.trusted_cert = vec![fingerprint];
        match self.save(config.clone()).await {
            Ok(path) => {
                self.sink.update(|s, ts| {
                    s.ui.pin_offer = None;
                    s.ui.pin_allowed = false;
                    s.ui.error = None;
                    s.pending_form = Some(SettingsForm::from_config(&config));
                    s.ui.push_log(
                        ts,
                        LogLevel::Info,
                        format!(
                            "Empreinte épinglée ({}) : réessayez de vous connecter",
                            path.display()
                        ),
                    );
                });
                self.loaded = Some(config);
            }
            Err(e) => self.sink.update(|s, _| {
                s.ui.error = Some(format!("Épinglage impossible : {e}"));
            }),
        }
    }

    /// Charge les réglages ; renvoie `true` si le fichier n'existe pas (première
    /// utilisation). Le formulaire est toujours alimenté (vide en cas d'échec).
    async fn load_settings(&mut self) -> bool {
        self.sink.update(|s, _| s.busy = true);
        let result = self.read_config().await;
        match result {
            Ok((path, config)) => {
                let first_run = config.is_none();
                let message = if first_run {
                    format!(
                        "Première utilisation : renseignez la passerelle. Le fichier {} sera créé à l'enregistrement.",
                        path.display()
                    )
                } else {
                    String::new()
                };
                let c = config.unwrap_or_else(blank_config);
                self.sink.update(|s, _| {
                    let mut form = SettingsForm::from_config(&c);
                    form.close_to_tray = s.close_to_tray;
                    s.pending_form = Some(form);
                    s.pending_username = Some(c.username.clone());
                    s.ui.host.clone_from(&c.host);
                    s.ui.reconnect_auto = c.reconnect.enabled;
                    s.ui.pin_allowed = c.trusted_cert.is_empty();
                    s.settings_message = message;
                    s.settings_ok = first_run;
                    s.busy = false;
                });
                self.loaded = Some(c);
                first_run
            }
            Err(e) => {
                // Fichier illisible : l'écran Réglages reste utilisable (formulaire vide).
                let c = blank_config();
                self.sink.update(|s, _| {
                    let mut form = SettingsForm::from_config(&c);
                    form.close_to_tray = s.close_to_tray;
                    s.pending_form = Some(form);
                    s.settings_message = format!("Lecture impossible : {e}");
                    s.settings_ok = false;
                    s.busy = false;
                });
                self.loaded = Some(c);
                false
            }
        }
    }

    async fn save_settings(&mut self, form: SettingsForm) {
        self.sink.update(|s, _| s.busy = true);
        let base = self.loaded.clone().unwrap_or_else(blank_config);
        let close_to_tray = form.close_to_tray;
        let outcome = match form.to_config(&base) {
            Err(e) => Err(e),
            Ok(config) => match self.save(config.clone()).await {
                Ok(path) => Ok((config, path)),
                Err(e) => Err(e),
            },
        };
        match outcome {
            Ok((config, path)) => {
                if let Err(e) = save_close_to_tray(&path, close_to_tray) {
                    tracing::debug!("option de la zone de notification non mémorisée : {e}");
                }
                self.sink.update(|s, ts| {
                    s.close_to_tray = close_to_tray;
                    let mut form = SettingsForm::from_config(&config);
                    form.close_to_tray = close_to_tray;
                    s.pending_form = Some(form);
                    s.pending_username = Some(config.username.clone());
                    if !s.ui.phase.is_active() {
                        s.ui.host.clone_from(&config.host);
                    }
                    s.ui.reconnect_auto = config.reconnect.enabled;
                    "Réglages enregistrés.".clone_into(&mut s.settings_message);
                    s.settings_ok = true;
                    s.ui.push_log(
                        ts,
                        LogLevel::Info,
                        format!("Réglages enregistrés ({})", path.display()),
                    );
                    s.busy = false;
                });
                self.loaded = Some(config);
            }
            Err(e) => self.sink.update(|s, _| {
                s.settings_message = e;
                s.settings_ok = false;
                s.busy = false;
            }),
        }
    }

    async fn save(&self, config: Config) -> Result<PathBuf, String> {
        let path = self.config_path()?;
        let p = path.clone();
        tokio::task::spawn_blocking(move || config.save(&p).map_err(|e| e.to_string()))
            .await
            .map_err(|e| e.to_string())??;
        Ok(path)
    }

    async fn probe_service(&mut self) {
        let (available, hint) =
            match tokio::time::timeout(PROBE_TIMEOUT, exchange(&Request::Status {})).await {
                Ok(Ok(Response::Ok { .. })) => (true, String::new()),
                Ok(Ok(Response::Error { message, .. })) => (true, format!("Service : {message}")),
                Ok(Err(e)) => {
                    tracing::debug!("sonde du service : {e}");
                    (false, SERVICE_ABSENT.to_owned())
                }
                Err(_) => (false, SERVICE_ABSENT.to_owned()),
            };
        self.sink.update(|s, _| {
            s.service_available = available;
            s.ui.service_hint = hint;
        });
    }

    async fn connect(&mut self, mode: Mode, username: &str, password: SecretString) {
        if self.active.is_some() {
            return;
        }
        // Configuration (lecture hors du thread UI).
        let config = match self.read_config().await {
            Ok((_, Some(c))) => c,
            Ok((path, None)) => {
                self.sink.fail(format!(
                    "Aucun fichier de configuration ({}) : ouvrez Réglages, renseignez la passerelle puis enregistrez.",
                    path.display()
                ));
                return;
            }
            Err(e) => {
                self.sink.fail(format!("Configuration inutilisable : {e}"));
                return;
            }
        };
        let mut config = config;
        if !username.trim().is_empty() {
            username.trim().clone_into(&mut config.username);
        }
        self.loaded = Some(config.clone());
        let pin_allowed = config.trusted_cert.is_empty();
        self.sink.update(|s, _| s.ui.pin_allowed = pin_allowed);
        if let Ok(path) = self.config_path() {
            if let Err(e) = save_mode(&path, mode) {
                tracing::debug!("mode non mémorisé : {e}");
            }
        }

        self.next_id += 1;
        let id = self.next_id;
        let (stop_tx, stop_rx) = oneshot::channel();
        let sink = self.sink.clone();
        let done = self.tx.clone();
        match mode {
            Mode::Proxy => {
                let provider = Arc::new(DialogSecondFactor {
                    sink: self.sink.clone(),
                    slot: Arc::clone(&self.answer),
                });
                let (transport, backend, info) = match prepare_proxy(&config, provider) {
                    Ok(p) => p,
                    Err(e) => {
                        self.sink.fail(e);
                        return;
                    }
                };
                self.sink
                    .update(|s, ts| s.ui.begin(mode, &config.host, info, ts));
                let credentials = Credentials::new(config.username.clone(), password);
                let options = config.session_options();
                tokio::spawn(async move {
                    drive_session(transport, backend, credentials, options, stop_rx, &sink).await;
                    let _ = done.send(Command::Ended(id));
                });
            }
            Mode::Service => {
                self.sink
                    .update(|s, ts| s.ui.begin(mode, &config.host, ProxyInfo::default(), ts));
                let password = Zeroizing::new(password.expose_secret().to_owned());
                tokio::spawn(async move {
                    service_session(&sink, password, stop_rx).await;
                    let _ = done.send(Command::Ended(id));
                });
            }
        }
        self.active = Some(Active {
            id,
            stop: Some(stop_tx),
        });
    }
}

/// Explication affichée quand le mode Service est grisé.
pub const SERVICE_ABSENT: &str = "Service non installé — demandez à votre administrateur.";
/// Délai de la sonde du service.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// Période d'interrogation de l'état du service.
const POLL_PERIOD: Duration = Duration::from_millis(1000);

/// Transport et backend proxy (écoutes locales ouvertes tout de suite : échec
/// immédiat si un port est pris), avant même de lire le mot de passe.
fn prepare_proxy(
    config: &Config,
    provider: Arc<dyn SecondFactorProvider>,
) -> Result<(impl Transport + 'static, AnyBackend, ProxyInfo), String> {
    let transport = build_transport(config)
        .map_err(|e| format!("Transport impossible : {e}"))?
        .with_second_factor(provider);
    let proxy = config.proxy.clone().unwrap_or_default();
    let backend = platform::select_backend(Some(&proxy))
        .map_err(|e| format!("Ouverture du proxy local impossible : {e}"))?;
    let info = match &backend {
        AnyBackend::Proxy(p) => ProxyInfo {
            socks: p.socks_addr().map(|a| a.to_string()),
            forwards: p
                .forwards()
                .iter()
                .map(|(l, t)| (l.to_string(), t.to_string()))
                .collect(),
        },
        AnyBackend::System(_) => ProxyInfo::default(),
    };
    Ok((transport, backend, info))
}

/// Exécute la session jusqu'à sa fin, en publiant chaque événement.
pub async fn drive_session<T, B>(
    transport: T,
    backend: B,
    credentials: Credentials,
    options: SessionOptions,
    stop: oneshot::Receiver<()>,
    sink: &Sink,
) where
    T: Transport,
    B: NetBackend,
{
    let _ = run_session(
        transport,
        backend,
        credentials,
        options,
        async {
            // Demande d'arrêt, ou interface disparue : dans les deux cas, on s'arrête.
            let _ = stop.await;
            None
        },
        |event| sink.event(event),
    )
    .await;
    sink.ensure_idle();
}

fn service_unavailable(reason: &str) -> String {
    format!(
        "Service fortivpn-rs inaccessible ({reason}). Installez-le (« fortivpn service install », \
         en administrateur) puis démarrez-le, ou utilisez le mode Proxy."
    )
}

/// Session via le service (named pipe) : connexion, puis suivi de l'état jusqu'au retour
/// à `Idle`. Le mot de passe n'est envoyé que dans la requête `Connect`.
async fn service_session(
    sink: &Sink,
    password: Zeroizing<String>,
    mut stop: oneshot::Receiver<()>,
) {
    let adopt = match tokio::time::timeout(PROBE_TIMEOUT, exchange(&Request::Status {})).await {
        Ok(Ok(Response::Ok { status })) => (status.state != State::Idle).then_some(status),
        Ok(Ok(Response::Error { message, .. })) => {
            sink.fail(format!("Service : {message}"));
            return;
        }
        Ok(Err(e)) => {
            sink.fail(service_unavailable(&e));
            return;
        }
        Err(_) => {
            sink.fail(service_unavailable("délai dépassé"));
            return;
        }
    };
    let mut connect_done = false;
    let connect = async move {
        let request = Request::Connect { password };
        exchange(&request).await
    };
    tokio::pin!(connect);
    if let Some(status) = adopt {
        // Une connexion existe déjà : on la suit au lieu d'en ouvrir une autre.
        sink.status(&status);
        connect_done = true;
    }
    let mut stop_sent = false;
    let mut ticker =
        tokio::time::interval_at(tokio::time::Instant::now() + POLL_PERIOD, POLL_PERIOD);
    loop {
        tokio::select! {
            res = &mut connect, if !connect_done => {
                connect_done = true;
                match res {
                    Ok(Response::Ok { status }) => sink.status(&status),
                    Ok(Response::Error { code, message }) => {
                        if !stop_sent && code != ErrorCode::Busy {
                            sink.fail(message);
                        }
                        return;
                    }
                    Err(e) => {
                        if !stop_sent {
                            sink.fail(service_unavailable(&e));
                        }
                        return;
                    }
                }
            }
            _ = &mut stop, if !stop_sent => {
                stop_sent = true;
                if let Ok(Ok(Response::Ok { status })) =
                    tokio::time::timeout(Duration::from_secs(15), exchange(&Request::Disconnect {})).await
                {
                    sink.status(&status);
                }
                if connect_done || stop_sent {
                    // Le service est arrêté ; la requête `Connect` éventuelle se termine seule.
                    return;
                }
            }
            _ = ticker.tick() => {
                if let Ok(Ok(Response::Ok { status })) =
                    tokio::time::timeout(PROBE_TIMEOUT, exchange(&Request::Status {})).await
                {
                    // Avant la fin de `Connect`, un état `Idle` est transitoire : l'ignorer.
                    if status.state == State::Idle && !connect_done {
                        continue;
                    }
                    sink.status(&status);
                    if status.state == State::Idle {
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use fortivpn_core::fake::{FakeNetBackend, FakeTransport};
    use fortivpn_core::{DnsConfig, Ipv4Config, RoutingMode, TunnelConfig};

    use super::*;
    use crate::model::Phase;

    fn sample() -> TunnelConfig {
        TunnelConfig {
            ipv4: Ipv4Config {
                address: "10.212.134.200/32".parse().unwrap(),
                peer: Some(Ipv4Addr::new(169, 254, 2, 1)),
            },
            ipv6: None,
            mtu: 1354,
            dns: DnsConfig::default(),
            routing: RoutingMode::Split { include: vec![] },
            gateway: "203.0.113.10".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn session_events_reach_the_shared_state_and_stop_returns_to_idle() {
        let renders = Arc::new(Mutex::new(0u32));
        let counter = Arc::clone(&renders);
        let sink = Sink::new(move |n| {
            if n == Notice::Render {
                *counter.lock().unwrap() += 1;
            }
        });
        sink.update(|s, ts| {
            s.ui.begin(Mode::Proxy, "vpn.example.com", ProxyInfo::default(), ts);
        });
        let transport = FakeTransport::new(Credentials::new("alice", "pw-test"), sample());
        let (stop_tx, stop_rx) = oneshot::channel();
        let watcher = sink.clone();
        let task = tokio::spawn({
            let sink = sink.clone();
            async move {
                drive_session(
                    transport,
                    FakeNetBackend::new(),
                    Credentials::new("alice", "pw-test"),
                    SessionOptions::new("fvpn0"),
                    stop_rx,
                    &sink,
                )
                .await;
            }
        });
        // Attend le tunnel actif, puis demande l'arrêt.
        for _ in 0..200 {
            if watcher.lock().ui.phase == Phase::Connected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        {
            let g = watcher.lock();
            assert_eq!(g.ui.phase, Phase::Connected);
            assert_eq!(g.ui.address.as_deref(), Some("10.212.134.200"));
        }
        stop_tx.send(()).unwrap();
        task.await.unwrap();
        let g = sink.lock();
        assert_eq!(g.ui.phase, Phase::Idle);
        assert!(g.ui.error.is_none());
        assert!(*renders.lock().unwrap() >= 4);
        // Le journal ne contient jamais le mot de passe.
        assert!(g.ui.log.iter().all(|l| !l.text.contains("pw-test")));
    }

    #[tokio::test]
    async fn auth_failure_is_reported_as_error() {
        let sink = Sink::new(|_| {});
        sink.update(|s, ts| s.ui.begin(Mode::Proxy, "h", ProxyInfo::default(), ts));
        let transport = FakeTransport::new(Credentials::new("alice", "right"), sample());
        let (_stop_tx, stop_rx) = oneshot::channel();
        drive_session(
            transport,
            FakeNetBackend::new(),
            Credentials::new("alice", "wrong"),
            SessionOptions::new("fvpn0"),
            stop_rx,
            &sink,
        )
        .await;
        let g = sink.lock();
        assert_eq!(g.ui.phase, Phase::Idle);
        assert!(
            g.ui.error
                .as_deref()
                .unwrap()
                .contains("échec de la connexion")
        );
    }

    #[tokio::test]
    async fn settings_load_and_save_through_the_worker() {
        let dir = std::env::temp_dir().join(format!("fortivpn-gui-{}", std::process::id()));
        let path = dir.join("config.toml");
        let sink = Sink::new(|_| {});
        let (handle, thread) = spawn(sink.clone(), Some(path.clone())).unwrap();
        handle.send(Command::LoadSettings);
        for _ in 0..200 {
            if sink.lock().pending_form.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let form = {
            let mut g = sink.lock();
            assert!(g.settings_message.contains("Première utilisation"));
            g.pending_form.take().unwrap()
        };
        let form = SettingsForm {
            host: "vpn.example.com".into(),
            username: "alice".into(),
            ..form
        };
        handle.send(Command::SaveSettings(form));
        for _ in 0..200 {
            if sink.lock().settings_message == "Réglages enregistrés." {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("host = \"vpn.example.com\""), "{text}");
        assert!(!text.contains("password"));
        handle.send(Command::Quit);
        let _ = std::fs::remove_dir_all(&dir);
        tokio::task::spawn_blocking(move || thread.join())
            .await
            .unwrap()
            .unwrap();
    }
}
