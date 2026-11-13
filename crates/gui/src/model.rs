//! Modèle d'état de l'interface, **pur** (aucun affichage, aucune I/O) : traduit les
//! `SessionEvent` de `core` (mode proxy) et les `StatusReport` du service (mode
//! service) en état d'écran, étapes chronométrées et journal. Testable sans fenêtre.
//!
//! Ne contient jamais de secret : ni mot de passe, ni OTP, ni cookie.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use fortivpn_app::run::describe_reason;
use fortivpn_core::{DisconnectReason, SessionEvent, SessionState, TransportError};
use fortivpn_service::{State, StatusReport};

/// Nombre maximal de lignes conservées dans le journal.
pub const MAX_LOG_LINES: usize = 500;

/// Mode de connexion proposé par l'interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Tunnel complet via le service Windows (named pipe), si installé.
    Service,
    /// Proxy SOCKS5 + redirections en espace utilisateur, sans droits administrateur.
    #[default]
    Proxy,
}

impl Mode {
    /// Index du segment dans l'interface (0 : service, 1 : proxy).
    pub fn index(self) -> i32 {
        match self {
            Self::Service => 0,
            Self::Proxy => 1,
        }
    }

    /// Mode correspondant à l'index de l'interface (proxy par défaut).
    pub fn from_index(i: i32) -> Self {
        if i == 0 { Self::Service } else { Self::Proxy }
    }
}

/// Phase globale (détermine l'écran et la couleur : gris, orange, vert).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Phase {
    /// Déconnecté (gris).
    #[default]
    Idle,
    /// Connexion en cours (orange).
    Connecting,
    /// Reconnexion automatique en cours (orange).
    Reconnecting,
    /// Arrêt en cours (orange).
    Disconnecting,
    /// Tunnel actif (vert).
    Connected,
}

impl Phase {
    /// Couleur d'état : 0 gris, 1 orange, 2 vert.
    pub fn tone(self) -> i32 {
        match self {
            Self::Idle => 0,
            Self::Connecting | Self::Reconnecting | Self::Disconnecting => 1,
            Self::Connected => 2,
        }
    }

    /// Écran : 0 déconnecté, 1 connexion, 2 connecté.
    pub fn screen(self) -> i32 {
        match self {
            Self::Idle => 0,
            Self::Connecting | Self::Reconnecting | Self::Disconnecting => 1,
            Self::Connected => 2,
        }
    }

    /// Une session est en cours (ou en cours d'arrêt).
    pub fn is_active(self) -> bool {
        self != Self::Idle
    }
}

/// État d'une étape de connexion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StepState {
    /// Pas encore atteinte.
    #[default]
    Pending,
    /// En cours.
    Running,
    /// Terminée en `Duration`.
    Done(Duration),
}

/// Libellés des trois étapes de la maquette.
pub const STEP_LABELS: [&str; 3] = ["TLS / Authentification", "Configuration", "Tunnel"];

/// Niveau d'une ligne du journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Information.
    Info,
    /// Succès.
    Ok,
    /// Avertissement.
    Warn,
    /// Erreur.
    Err,
}

impl LogLevel {
    /// Index pour l'interface.
    pub fn index(self) -> i32 {
        match self {
            Self::Info => 0,
            Self::Ok => 1,
            Self::Warn => 2,
            Self::Err => 3,
        }
    }
}

/// Ligne du journal (texte sans secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// Heure locale `HH:MM:SS`.
    pub ts: String,
    /// Niveau.
    pub level: LogLevel,
    /// Message.
    pub text: String,
}

/// Demande de second facteur affichée dans la boîte de dialogue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecondFactorPrompt {
    /// Message de la passerelle (ou texte par défaut).
    pub message: String,
    /// Notification push à valider sur l'appareil (pas de champ de saisie).
    pub push: bool,
}

/// Information sur le proxy local, affichée une fois connecté.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyInfo {
    /// Adresse SOCKS5 (`None` : désactivé).
    pub socks: Option<String>,
    /// Redirections `(écoute locale, destination)`.
    pub forwards: Vec<(String, String)>,
}

/// Instants (depuis le début de la tentative) des étapes atteintes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Marks {
    /// Début.
    pub connecting: Option<Duration>,
    /// Authentification acceptée.
    pub authenticated: Option<Duration>,
    /// Configuration reçue.
    pub config_received: Option<Duration>,
    /// Tunnel actif.
    pub tunnel_up: Option<Duration>,
}

impl Marks {
    /// Les trois étapes de la maquette (`None` pour un repère manquant).
    pub fn steps(&self) -> [StepState; 3] {
        let start = self.connecting.unwrap_or_default();
        let bounds = [
            (start, self.authenticated),
            (self.authenticated.unwrap_or(start), self.config_received),
            (self.config_received.unwrap_or(start), self.tunnel_up),
        ];
        let mut out = [StepState::Pending; 3];
        let mut running_set = false;
        for (slot, (from, to)) in out.iter_mut().zip(bounds) {
            *slot = match to {
                Some(to) => StepState::Done(to.saturating_sub(from)),
                None if !running_set && self.connecting.is_some() => {
                    running_set = true;
                    StepState::Running
                }
                None => StepState::Pending,
            };
        }
        out
    }

    /// Durée totale jusqu'au tunnel actif.
    pub fn total(&self) -> Option<Duration> {
        Some(
            self.tunnel_up?
                .saturating_sub(self.connecting.unwrap_or_default()),
        )
    }
}

/// Extrait l'empreinte d'un refus de certificat dans la chaîne de causes de l'erreur
/// (texte `... sha256 : <64 hex>` ou `sha256=<64 hex>`).
pub fn untrusted_fingerprint(err: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(fp) = fingerprint_in(&e.to_string()) {
            return Some(fp);
        }
        cur = e.source();
    }
    None
}

fn fingerprint_in(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase().replace("sha-256", "sha256");
    let at = lower.find("sha256")? + "sha256".len();
    let rest = lower[at..].trim_start_matches([' ', ':', '=']);
    let hex: String = rest.chars().take(64).collect();
    (hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit())).then_some(hex)
}

/// État complet de l'interface.
#[derive(Debug, Clone, Default)]
pub struct UiState {
    /// Phase globale.
    pub phase: Phase,
    /// Étapes chronométrées de la tentative courante.
    pub marks: Marks,
    /// Adresse IP du tunnel.
    pub address: Option<String>,
    /// Début de la session active (durée affichée).
    pub connected_since: Option<Instant>,
    /// Proxy local (mode proxy).
    pub proxy: ProxyInfo,
    /// Reconnexion automatique activée (réglage).
    pub reconnect_auto: bool,
    /// Détail de la phase (par ex. « essai 2, dans 3 s »).
    pub detail: String,
    /// Dernière erreur à montrer sur l'écran « Déconnecté ».
    pub error: Option<String>,
    /// Indication sur le service (installé ou non).
    pub service_hint: String,
    /// Avertissement permanent (interface lancée en root).
    pub root_warning: String,
    /// Mode de la session courante ou choisi.
    pub mode: Mode,
    /// Passerelle affichée (`hôte`).
    pub host: String,
    /// Journal borné.
    pub log: VecDeque<LogLine>,
    /// Second facteur demandé (boîte de dialogue ouverte).
    pub second_factor: Option<SecondFactorPrompt>,
    /// Empreinte du certificat refusé lors de la dernière tentative (jamais épinglée
    /// automatiquement : l'utilisateur doit la confirmer).
    pub pin_offer: Option<String>,
    /// La configuration n'a aucun certificat épinglé : l'épinglage peut être proposé.
    pub pin_allowed: bool,
}

impl UiState {
    /// État initial.
    pub fn new() -> Self {
        Self {
            reconnect_auto: true,
            ..Self::default()
        }
    }

    /// Ajoute une ligne au journal (bornée).
    pub fn push_log(&mut self, ts: &str, level: LogLevel, text: impl Into<String>) {
        if self.log.len() == MAX_LOG_LINES {
            self.log.pop_front();
        }
        self.log.push_back(LogLine {
            ts: ts.to_owned(),
            level,
            text: text.into(),
        });
    }

    /// Début d'une session : remet l'affichage à zéro (le journal est conservé).
    pub fn begin(&mut self, mode: Mode, host: &str, proxy: ProxyInfo, ts: &str) {
        self.phase = Phase::Connecting;
        self.mode = mode;
        host.clone_into(&mut self.host);
        self.proxy = proxy;
        self.marks = Marks::default();
        self.address = None;
        self.connected_since = None;
        self.error = None;
        self.pin_offer = None;
        self.detail.clear();
        let target = match mode {
            Mode::Proxy => "mode proxy",
            Mode::Service => "mode service",
        };
        self.push_log(ts, LogLevel::Info, format!("Connexion à {host} ({target})"));
    }

    /// Échec avant ou hors session (configuration, service absent…).
    pub fn fail(&mut self, ts: &str, message: impl Into<String>) {
        let message = message.into();
        self.phase = Phase::Idle;
        self.connected_since = None;
        self.second_factor = None;
        self.push_log(ts, LogLevel::Err, message.clone());
        self.error = Some(message);
    }

    /// La passerelle demande un second facteur.
    pub fn ask_second_factor(&mut self, ts: &str, push: bool, message: Option<&str>) {
        let message = message.filter(|m| !m.is_empty()).map_or_else(
            || {
                if push {
                    "Validez la notification FortiToken sur votre appareil.".to_owned()
                } else {
                    "Saisissez le code de vérification (OTP / FortiToken).".to_owned()
                }
            },
            ToOwned::to_owned,
        );
        self.push_log(
            ts,
            LogLevel::Info,
            if push {
                "Validation push demandée"
            } else {
                "Code de vérification demandé"
            },
        );
        self.second_factor = Some(SecondFactorPrompt { message, push });
    }

    /// L'utilisateur demande l'arrêt.
    pub fn disconnecting(&mut self, ts: &str) {
        if self.phase.is_active() {
            self.phase = Phase::Disconnecting;
            self.push_log(ts, LogLevel::Info, "Déconnexion demandée");
        }
    }

    /// Applique un événement de session de `core`.
    pub fn apply_event(&mut self, event: &SessionEvent, ts: &str, now: Instant) {
        let at = event.elapsed;
        if !matches!(event.state, SessionState::Connecting) {
            self.second_factor = None;
        }
        match &event.state {
            SessionState::Connecting => {
                self.marks = Marks {
                    connecting: Some(at),
                    ..Marks::default()
                };
                if self.phase != Phase::Reconnecting && self.phase != Phase::Disconnecting {
                    self.phase = Phase::Connecting;
                }
                self.push_log(ts, LogLevel::Info, format!("Connexion à {}", self.host));
            }
            SessionState::Authenticated => {
                self.marks.authenticated = Some(at);
                let d = self.step_ms(0);
                self.push_log(
                    ts,
                    LogLevel::Info,
                    format!("TLS + authentification ({d} ms)"),
                );
            }
            SessionState::ConfigReceived => {
                self.marks.config_received = Some(at);
                let d = self.step_ms(1);
                self.push_log(ts, LogLevel::Info, format!("Configuration reçue ({d} ms)"));
            }
            SessionState::TunnelUp { config, .. } => {
                self.marks.tunnel_up = Some(at);
                let address = config.ipv4.address.addr().to_string();
                if self.phase != Phase::Disconnecting {
                    self.phase = Phase::Connected;
                }
                self.connected_since = Some(now);
                self.detail.clear();
                self.error = None;
                self.push_log(
                    ts,
                    LogLevel::Ok,
                    format!("Tunnel établi, IP {address} (total {} ms)", self.total_ms()),
                );
                self.address = Some(address);
            }
            SessionState::Reconnecting {
                attempt,
                delay,
                cause,
            } => {
                self.phase = Phase::Reconnecting;
                self.connected_since = None;
                self.address = None;
                self.marks = Marks::default();
                self.detail = format!("essai {attempt}, dans {} s", delay.as_secs().max(1));
                self.push_log(
                    ts,
                    LogLevel::Warn,
                    format!(
                        "{} ; reconnexion (essai {attempt})…",
                        describe_reason(cause)
                    ),
                );
            }
            SessionState::Disconnected { reason } => self.finish(reason, ts),
            _ => {}
        }
    }

    /// Fin de session.
    pub fn finish(&mut self, reason: &DisconnectReason, ts: &str) {
        self.phase = Phase::Idle;
        self.connected_since = None;
        self.address = None;
        self.detail.clear();
        self.second_factor = None;
        if matches!(reason, DisconnectReason::Requested) {
            self.error = None;
            self.push_log(ts, LogLevel::Info, "Déconnecté");
        } else if matches!(reason, DisconnectReason::ConnectFailed(e) if matches!(**e, TransportError::Cancelled))
        {
            // Annulation volontaire : ce n'est pas une erreur à afficher en rouge.
            self.error = None;
            self.push_log(ts, LogLevel::Info, "Connexion annulée");
        } else {
            let mut text = describe_reason(reason);
            if let DisconnectReason::ConnectFailed(e) = reason {
                if let Some(fp) = untrusted_fingerprint(&**e) {
                    text = format!(
                        "Certificat de la passerelle non reconnu. Empreinte SHA-256 : {fp}"
                    );
                    self.pin_offer = Some(fp);
                }
            }
            self.push_log(ts, LogLevel::Err, format!("Déconnecté : {text}"));
            self.error = Some(text);
        }
    }

    /// Empreinte à proposer d'épingler (certificat refusé et aucun certificat épinglé).
    pub fn visible_pin_offer(&self) -> Option<&str> {
        self.pin_offer.as_deref().filter(|_| self.pin_allowed)
    }

    /// Applique un état rapporté par le service (mode service).
    pub fn apply_status(&mut self, status: &StatusReport, ts: &str, now: Instant) {
        let before = self.phase;
        let ms = |v: Option<u64>| v.map(Duration::from_millis);
        self.marks = Marks {
            connecting: ms(status.steps.connecting_ms),
            authenticated: ms(status.steps.authenticated_ms),
            config_received: ms(status.steps.config_received_ms),
            tunnel_up: ms(status.steps.tunnel_up_ms),
        };
        let phase = match status.state {
            State::Idle => Phase::Idle,
            State::Connecting | State::Authenticated | State::ConfigReceived => Phase::Connecting,
            State::TunnelUp => Phase::Connected,
            State::Disconnecting => Phase::Disconnecting,
        };
        self.phase = phase;
        match phase {
            Phase::Connected => {
                if before != Phase::Connected {
                    let since = Duration::from_millis(status.connected_for_ms.unwrap_or(0));
                    self.connected_since = Some(now.checked_sub(since).unwrap_or(now));
                    // Description du service : « interface adresse/masque ».
                    self.address = status
                        .tunnel
                        .as_deref()
                        .and_then(|t| t.split_whitespace().nth(1))
                        .map(|a| a.split('/').next().unwrap_or(a).to_owned());
                    let ip = self.address.clone().unwrap_or_default();
                    self.push_log(ts, LogLevel::Ok, format!("Tunnel établi, IP {ip}"));
                }
            }
            Phase::Idle => {
                self.connected_since = None;
                self.address = None;
                if before.is_active() {
                    match &status.last_outcome {
                        Some(o) if o.error.is_some() => {
                            self.push_log(ts, LogLevel::Err, format!("Déconnecté : {}", o.message));
                            self.error = Some(o.message.clone());
                        }
                        _ => self.push_log(ts, LogLevel::Info, "Déconnecté"),
                    }
                }
            }
            _ => {}
        }
    }

    fn step_ms(&self, index: usize) -> u128 {
        match self.marks.steps()[index] {
            StepState::Done(d) => d.as_millis(),
            _ => 0,
        }
    }

    fn total_ms(&self) -> u128 {
        self.marks.total().map_or(0, |d| d.as_millis())
    }

    /// Texte d'état sous le nom de la passerelle.
    pub fn status_text(&self) -> String {
        match self.phase {
            Phase::Idle => "Déconnecté".to_owned(),
            Phase::Connecting => "Connexion en cours…".to_owned(),
            Phase::Reconnecting => format!("Reconnexion ({})…", self.detail),
            Phase::Disconnecting => "Déconnexion en cours…".to_owned(),
            Phase::Connected => format!("Connecté en {} ms", self.total_ms()),
        }
    }

    /// Avancement de la barre : étapes terminées sur 3 (+ moitié de l'étape en cours).
    pub fn progress(&self) -> f32 {
        let steps = self.marks.steps();
        let done = steps
            .iter()
            .filter(|s| matches!(s, StepState::Done(_)))
            .count();
        // `done` <= 3 : conversion exacte.
        #[allow(clippy::cast_precision_loss)]
        let done = done as f32;
        let running = if steps.contains(&StepState::Running) {
            0.5
        } else {
            0.0
        };
        ((done + running) / 3.0).clamp(0.0, 1.0)
    }

    /// « Étape N sur 3, … » sous la barre.
    pub fn step_hint(&self) -> String {
        let steps = self.marks.steps();
        let n = steps
            .iter()
            .position(|s| !matches!(s, StepState::Done(_)))
            .map_or(3, |i| i + 1);
        let what = [
            "authentification TLS",
            "récupération de la configuration",
            "établissement du tunnel PPP",
        ];
        format!("Étape {n} sur 3, {}", what[n - 1])
    }

    /// Durée de session `HH:MM:SS` à l'instant `now`.
    pub fn duration_text(&self, now: Instant) -> String {
        self.connected_since.map_or_else(
            || "--:--:--".to_owned(),
            |s| format_duration(now.saturating_duration_since(s)),
        )
    }
}

/// `HH:MM:SS`.
pub fn format_duration(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

/// Durée d'une étape pour l'affichage (`44 ms`, `1,2 s`), vide si inconnue.
pub fn format_step(state: StepState) -> String {
    match state {
        StepState::Done(d) if d >= Duration::from_secs(10) => format!("{} s", d.as_secs()),
        StepState::Done(d) => format!("{} ms", d.as_millis()),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use fortivpn_core::{
        DnsConfig, Ipv4Config, RoutingMode, TransportError, TunInfo, TunnelConfig,
    };
    use fortivpn_service::{ErrorCode, Outcome, StepTimings};

    use super::*;

    fn ev(state: SessionState, ms: u64) -> SessionEvent {
        SessionEvent {
            state,
            at: tokio::time::Instant::now(),
            elapsed: Duration::from_millis(ms),
        }
    }

    fn tunnel_up(ms: u64) -> SessionEvent {
        let config = TunnelConfig {
            ipv4: Ipv4Config {
                address: "10.242.2.2/32".parse().unwrap(),
                peer: Some(Ipv4Addr::new(169, 254, 2, 1)),
            },
            ipv6: None,
            mtu: 1354,
            dns: DnsConfig::default(),
            routing: RoutingMode::Split { include: vec![] },
            gateway: "203.0.113.10".parse().unwrap(),
        };
        let interface = TunInfo {
            name: "fvpn0".into(),
            index: Some(1),
        };
        ev(SessionState::TunnelUp { config, interface }, ms)
    }

    fn started() -> UiState {
        let mut s = UiState::new();
        s.begin(
            Mode::Proxy,
            "vpn.example.com",
            ProxyInfo::default(),
            "14:02:11",
        );
        s
    }

    #[test]
    fn connecting_events_drive_steps_and_durations() {
        let now = Instant::now();
        let mut s = started();
        assert_eq!(s.phase.screen(), 1);
        s.apply_event(&ev(SessionState::Connecting, 2), "t", now);
        assert_eq!(
            s.marks.steps(),
            [StepState::Running, StepState::Pending, StepState::Pending]
        );
        s.apply_event(&ev(SessionState::Authenticated, 46), "t", now);
        assert_eq!(
            s.marks.steps(),
            [
                StepState::Done(Duration::from_millis(44)),
                StepState::Running,
                StepState::Pending
            ]
        );
        assert!((s.progress() - 0.5).abs() < 0.01);
        assert_eq!(
            s.step_hint(),
            "Étape 2 sur 3, récupération de la configuration"
        );
        s.apply_event(&ev(SessionState::ConfigReceived, 76), "t", now);
        s.apply_event(&tunnel_up(105), "t", now);
        assert_eq!(s.phase, Phase::Connected);
        assert_eq!(s.phase.tone(), 2);
        assert_eq!(s.address.as_deref(), Some("10.242.2.2"));
        assert_eq!(s.status_text(), "Connecté en 103 ms");
        assert_eq!(
            s.marks.steps(),
            [
                StepState::Done(Duration::from_millis(44)),
                StepState::Done(Duration::from_millis(30)),
                StepState::Done(Duration::from_millis(29)),
            ]
        );
        assert!((s.progress() - 1.0).abs() < f32::EPSILON);
        assert_eq!(format_step(s.marks.steps()[0]), "44 ms");
        let last = s.log.back().unwrap();
        assert_eq!(last.level, LogLevel::Ok);
        assert!(last.text.contains("10.242.2.2"));
    }

    #[test]
    fn reconnecting_is_orange_then_connecting_keeps_reconnecting() {
        let now = Instant::now();
        let mut s = started();
        s.apply_event(&tunnel_up(100), "t", now);
        s.apply_event(
            &ev(
                SessionState::Reconnecting {
                    attempt: 2,
                    delay: Duration::from_secs(3),
                    cause: DisconnectReason::TransportClosed,
                },
                9000,
            ),
            "t",
            now,
        );
        assert_eq!(s.phase, Phase::Reconnecting);
        assert_eq!(s.phase.tone(), 1);
        assert_eq!(s.status_text(), "Reconnexion (essai 2, dans 3 s)…");
        assert!(s.connected_since.is_none());
        assert_eq!(s.log.back().unwrap().level, LogLevel::Warn);
        s.apply_event(&ev(SessionState::Connecting, 12000), "t", now);
        assert_eq!(s.phase, Phase::Reconnecting);
        s.apply_event(&tunnel_up(12100), "t", now);
        assert_eq!(s.phase, Phase::Connected);
    }

    #[test]
    fn disconnected_reason_sets_error_only_on_failure() {
        let now = Instant::now();
        let mut s = started();
        s.apply_event(
            &ev(
                SessionState::Disconnected {
                    reason: DisconnectReason::ConnectFailed(Arc::new(TransportError::AuthFailed)),
                },
                50,
            ),
            "t",
            now,
        );
        assert_eq!(s.phase, Phase::Idle);
        assert!(
            s.error
                .as_deref()
                .unwrap()
                .contains("échec de la connexion")
        );
        let mut s = started();
        s.disconnecting("t");
        assert_eq!(s.phase, Phase::Disconnecting);
        s.apply_event(
            &ev(
                SessionState::Disconnected {
                    reason: DisconnectReason::Requested,
                },
                50,
            ),
            "t",
            now,
        );
        assert_eq!(s.phase, Phase::Idle);
        assert!(s.error.is_none());
    }

    #[test]
    fn service_status_maps_to_phase_and_address() {
        let now = Instant::now();
        let mut s = started();
        let connecting = StatusReport {
            state: State::Authenticated,
            steps: StepTimings {
                connecting_ms: Some(0),
                authenticated_ms: Some(40),
                ..StepTimings::default()
            },
            connected_for_ms: None,
            tunnel: None,
            last_outcome: None,
        };
        s.apply_status(&connecting, "t", now);
        assert_eq!(s.phase, Phase::Connecting);
        assert_eq!(
            s.marks.steps()[0],
            StepState::Done(Duration::from_millis(40))
        );
        let up = StatusReport {
            state: State::TunnelUp,
            steps: StepTimings {
                connecting_ms: Some(0),
                authenticated_ms: Some(40),
                config_received_ms: Some(70),
                tunnel_up_ms: Some(100),
            },
            connected_for_ms: Some(65_000),
            tunnel: Some("fortivpn 10.0.0.5/32".into()),
            last_outcome: None,
        };
        s.apply_status(&up, "t", now);
        assert_eq!(s.phase, Phase::Connected);
        assert_eq!(s.address.as_deref(), Some("10.0.0.5"));
        assert_eq!(s.duration_text(now), "00:01:05");
        let idle = StatusReport {
            state: State::Idle,
            steps: StepTimings::default(),
            connected_for_ms: None,
            tunnel: None,
            last_outcome: Some(Outcome::failed(ErrorCode::Connection, "tunnel interrompu")),
        };
        s.apply_status(&idle, "t", now);
        assert_eq!(s.phase, Phase::Idle);
        assert_eq!(s.error.as_deref(), Some("tunnel interrompu"));
    }

    #[test]
    fn log_is_bounded_and_idle_has_no_session_duration() {
        let mut s = UiState::new();
        for i in 0..(MAX_LOG_LINES + 10) {
            s.push_log("t", LogLevel::Info, format!("ligne {i}"));
        }
        assert_eq!(s.log.len(), MAX_LOG_LINES);
        assert_eq!(s.log.front().unwrap().text, "ligne 10");
        assert_eq!(s.duration_text(Instant::now()), "--:--:--");
        assert_eq!(
            format_duration(Duration::from_secs(3 * 3600 + 125)),
            "03:02:05"
        );
    }

    #[test]
    fn second_factor_prompt_opens_and_closes_without_leaving_a_secret() {
        let now = Instant::now();
        let mut s = started();
        s.apply_event(&ev(SessionState::Connecting, 1), "t", now);
        s.ask_second_factor("t", false, Some("Entrez le code"));
        assert_eq!(s.second_factor.as_ref().unwrap().message, "Entrez le code");
        s.apply_event(&ev(SessionState::Authenticated, 50), "t", now);
        assert!(s.second_factor.is_none());
        s.ask_second_factor("t", true, None);
        assert!(s.second_factor.as_ref().unwrap().push);
        s.apply_event(
            &ev(
                SessionState::Disconnected {
                    reason: DisconnectReason::ConnectFailed(Arc::new(TransportError::Cancelled)),
                },
                60,
            ),
            "t",
            now,
        );
        assert!(s.second_factor.is_none());
        assert!(s.error.is_none(), "l'annulation n'est pas une erreur");
        assert_eq!(s.log.back().unwrap().text, "Connexion annulée");
    }

    #[test]
    fn untrusted_certificate_offers_the_fingerprint() {
        const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let io = std::io::Error::other(format!("certificat refusé (inconnu), sha256={FP}"));
        let err = TransportError::Io(io);
        assert_eq!(untrusted_fingerprint(&err).as_deref(), Some(FP));
        assert!(untrusted_fingerprint(&TransportError::AuthFailed).is_none());

        let mut s = started();
        s.pin_allowed = true;
        s.finish(
            &DisconnectReason::ConnectFailed(Arc::new(TransportError::Io(std::io::Error::other(
                format!("refusé ; empreinte SHA-256 : {}", FP.to_uppercase()),
            )))),
            "t",
        );
        assert_eq!(s.visible_pin_offer(), Some(FP));
        assert!(s.error.as_deref().unwrap().contains(FP));
        s.pin_allowed = false;
        assert!(
            s.visible_pin_offer().is_none(),
            "déjà épinglé : pas d'offre"
        );
        s.begin(Mode::Proxy, "h", ProxyInfo::default(), "t");
        assert!(s.pin_offer.is_none());
    }

    #[test]
    fn mode_defaults_to_proxy_and_round_trips() {
        assert_eq!(Mode::default(), Mode::Proxy);
        assert_eq!(Mode::from_index(Mode::Service.index()), Mode::Service);
        assert_eq!(Mode::from_index(Mode::Proxy.index()), Mode::Proxy);
    }
}
