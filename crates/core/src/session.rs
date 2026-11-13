//! Orchestration d'une session VPN, générique sur le transport et le backend réseau.
//!
//! [`Session::run`] enchaîne : connexion du [`Transport`] → création de la TUN et
//! application de la [`TunnelConfig`] ([`NetGuard`](crate::NetGuard)) → relais
//! bidirectionnel TUN ↔ transport → nettoyage. Le nettoyage (configuration réseau puis
//! déconnexion du transport) est fait dans **tous** les chemins de sortie de `run` :
//! arrêt demandé ([`SessionHandle::shutdown`]), fin ou erreur du transport, fermeture
//! de la TUN, échec de la connexion ou de la configuration réseau. Si la future de
//! `run` est abandonnée, le `Drop` du `NetGuard` annule tout de même la configuration
//! réseau (la déconnexion du transport, asynchrone, n'est alors pas faite).
//!
//! Chaque changement d'état est publié, horodaté, sur [`SessionEvents`] (base du
//! chronométrage de la story 4.4).
//!
//! # Reconnexion automatique (story 4.1)
//!
//! Selon [`SessionOptions::reconnect`] ([`ReconnectPolicy`], activée par défaut), une
//! coupure du tunnel **établi** (`DeadPeer`, `ClosedByPeer`, erreur d'E/S, fin du
//! transport) n'achève pas `run` : la configuration réseau est annulée, le transport
//! est suspendu ([`Transport::suspend`] : cookie conservé, pas de logout), un événement
//! [`SessionState::Reconnecting`] est publié, puis après le délai de backoff un nouveau
//! [`Transport::connect`] est tenté (réutilisation du cookie, ré-authentification si
//! la passerelle le refuse). Pas de reconnexion sur refus d'authentification, second
//! facteur exigé, erreur de protocole, erreur locale (TUN, configuration réseau) ni
//! arrêt demandé ; l'arrêt est pris en compte pendant l'attente.
//!
//! **Mot de passe** : pour pouvoir se ré-authentifier quand le cookie est refusé, le
//! mot de passe reste en mémoire dans les [`Credentials`] (`SecretString`, effacé à la
//! libération) **pendant toute la vie de la [`Session`]** ; il n'est copié nulle part
//! ailleurs ni journalisé.
//!
//! **Veille / changement de réseau** : faute d'API OS de notification réseau (pas
//! encore branchée), la session vérifie périodiquement l'horloge pendant que le tunnel
//! est actif ; un tick très en retard ou une horloge murale qui a avancé bien plus que
//! l'horloge monotone (sortie de veille) force une reconnexion immédiate
//! ([`DisconnectReason::ClockJump`]). Limites : un simple changement de réseau sans
//! veille n'est détecté que par l'échec des echo LCP (`DeadPeer`, ~quelques dizaines
//! de secondes) ou une erreur d'E/S ; un saut d'horloge pendant l'attente du backoff
//! ou pendant `connect` n'est pas détecté.
//!
//! Relais : les deux sens sont deux futures indépendantes (chacune n'attend que sur
//! son propre sens), ce qui évite tout interblocage par contre-pression croisée ; les
//! canaux bornés propagent la contre-pression de bout en bout.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, timeout};

use crate::config::TunnelConfig;
use crate::error::{NetError, TransportError};
use crate::net::{NetBackend, NetGuard, TunInfo, TunOptions};
use crate::packet::PacketChannel;
use crate::transport::{ConnectStep, Credentials, ProgressSink, SessionEnd, Transport};

mod reconnect;

pub use reconnect::ReconnectPolicy;

/// Délai maximal par défaut de [`Transport::disconnect`] lors du nettoyage.
pub const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Options de session.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SessionOptions {
    /// Paramètres de création de la TUN.
    pub tun: TunOptions,
    /// Délai maximal de la déconnexion du transport (défaut [`DISCONNECT_TIMEOUT`]).
    pub disconnect_timeout: Duration,
    /// Reconnexion automatique (défaut : activée, cf. [`ReconnectPolicy`]).
    pub reconnect: ReconnectPolicy,
}

impl SessionOptions {
    /// Options par défaut avec le nom d'interface donné.
    pub fn new(tun_name: impl Into<String>) -> Self {
        Self {
            tun: TunOptions::new(tun_name),
            disconnect_timeout: DISCONNECT_TIMEOUT,
            reconnect: ReconnectPolicy::default(),
        }
    }

    /// Remplace la politique de reconnexion.
    #[must_use]
    pub fn with_reconnect(mut self, policy: ReconnectPolicy) -> Self {
        self.reconnect = policy;
        self
    }
}

/// État publié par la session.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SessionState {
    /// Connexion au transport en cours.
    Connecting,
    /// Identifiants acceptés (si le transport le signale).
    Authenticated,
    /// Configuration reçue de la passerelle (si le transport le signale).
    ConfigReceived,
    /// Tunnel opérationnel : TUN créée et configurée.
    TunnelUp {
        /// Configuration appliquée.
        config: TunnelConfig,
        /// Interface utilisée.
        interface: TunInfo,
    },
    /// Tunnel coupé, reconnexion programmée : réseau annulé, transport suspendu ;
    /// nouvel essai (puis `Connecting`…) dans `delay`.
    Reconnecting {
        /// N° de l'essai depuis la dernière coupure (à partir de 1).
        attempt: u32,
        /// Attente avant l'essai (backoff avec jitter ; nul après un saut d'horloge).
        delay: Duration,
        /// Cause de la coupure ou de l'échec de l'essai précédent.
        cause: DisconnectReason,
    },
    /// Session terminée, nettoyage effectué.
    Disconnected {
        /// Raison de la fin.
        reason: DisconnectReason,
    },
}

/// Raison de fin de session.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DisconnectReason {
    /// Arrêt demandé via [`SessionHandle::shutdown`].
    Requested,
    /// Échec de la connexion (authentification, TLS, tunnel refusé…).
    ConnectFailed(Arc<TransportError>),
    /// Échec de la création ou de la configuration de la TUN.
    NetworkFailed(Arc<NetError>),
    /// Le transport s'est terminé sur une erreur (ex. `DeadPeer`, `ClosedByPeer`).
    TransportFailed(Arc<TransportError>),
    /// Le transport s'est terminé sans erreur.
    TransportClosed,
    /// L'interface TUN a été fermée.
    TunClosed,
    /// Saut d'horloge détecté (sortie de veille probable) : écart estimé. Ne termine
    /// la session que si la reconnexion est impossible.
    ClockJump(Duration),
}

impl DisconnectReason {
    fn from_end(result: Result<(), TransportError>) -> Self {
        match result {
            Ok(()) => Self::TransportClosed,
            Err(e) => Self::TransportFailed(Arc::new(e)),
        }
    }

    /// Coupure justifiant une reconnexion (`reconnecting` : le tunnel a déjà été établi
    /// pendant ce `run`, un échec de `connect` passager est alors réessayé).
    fn is_recoverable(&self, reconnecting: bool) -> bool {
        match self {
            Self::TransportFailed(e) => e.is_transient(),
            Self::TransportClosed | Self::ClockJump(_) => true,
            Self::ConnectFailed(e) => reconnecting && e.is_transient(),
            Self::Requested | Self::NetworkFailed(_) | Self::TunClosed => false,
        }
    }
}

/// Événement horodaté de la session.
#[derive(Debug, Clone)]
pub struct SessionEvent {
    /// Nouvel état.
    pub state: SessionState,
    /// Instant de l'événement.
    pub at: Instant,
    /// Temps écoulé depuis le début de la session (création de [`Session`]).
    pub elapsed: Duration,
}

/// Flux des événements d'une session.
#[derive(Debug)]
pub struct SessionEvents(mpsc::UnboundedReceiver<SessionEvent>);

impl SessionEvents {
    /// Prochain événement ; `None` quand la [`Session`] a été libérée.
    pub async fn recv(&mut self) -> Option<SessionEvent> {
        self.0.recv().await
    }

    /// Prochain événement déjà disponible, sans attendre.
    pub fn try_recv(&mut self) -> Option<SessionEvent> {
        self.0.try_recv().ok()
    }
}

/// Commande d'arrêt d'une session (clonable). Le libérer ne déclenche **pas** l'arrêt.
#[derive(Debug, Clone)]
pub struct SessionHandle {
    stop: Arc<watch::Sender<bool>>,
    /// Plafond (ms) de la déconnexion du transport ; [`NO_LIMIT`] : aucun.
    limit_ms: Arc<AtomicU64>,
}

/// Valeur de `limit_ms` sans plafond d'arrêt.
const NO_LIMIT: u64 = u64::MAX;

impl SessionHandle {
    /// Demande l'arrêt : la session se déconnecte et nettoie. Définitif : un nouvel
    /// appel à [`Session::run`] se termine aussitôt.
    pub fn shutdown(&self) {
        self.stop.send_replace(true);
    }

    /// Comme [`shutdown`](Self::shutdown), mais plafonne la déconnexion du transport à
    /// `limit` (au plus [`SessionOptions::disconnect_timeout`]) : pour un arrêt imposé
    /// par l'OS qui tue le processus après un court délai (fermeture de session…).
    pub fn shutdown_within(&self, limit: Duration) {
        let ms = u64::try_from(limit.as_millis()).unwrap_or(NO_LIMIT - 1);
        self.limit_ms.store(ms, Ordering::Relaxed);
        self.shutdown();
    }
}

#[derive(Debug, Clone)]
struct EventSink {
    tx: mpsc::UnboundedSender<SessionEvent>,
    start: Instant,
}

impl EventSink {
    fn emit(&self, state: SessionState) {
        let at = Instant::now();
        let elapsed = at.duration_since(self.start);
        match &state {
            SessionState::Disconnected { reason } => {
                tracing::info!(?elapsed, ?reason, "session : déconnectée");
            }
            SessionState::TunnelUp { interface, .. } => {
                tracing::info!(?elapsed, interface = %interface.name, "session : tunnel actif");
            }
            other => tracing::info!(?elapsed, state = ?other, "session"),
        }
        // Personne n'écoute : sans importance.
        let _ = self.tx.send(SessionEvent { state, at, elapsed });
    }
}

/// Attend la demande d'arrêt (jamais si toutes les commandes ont été libérées).
async fn shutdown_requested(rx: &mut watch::Receiver<bool>) {
    if rx.wait_for(|stop| *stop).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Session VPN : transport `T` + backend réseau `B`.
#[derive(Debug)]
pub struct Session<T, B: NetBackend> {
    transport: T,
    backend: B,
    credentials: Credentials,
    options: SessionOptions,
    events: EventSink,
    shutdown: watch::Receiver<bool>,
    limit_ms: Arc<AtomicU64>,
    /// Guard de la tentative précédente, conservé pendant `Reconnecting` si le backend
    /// le demande ([`NetBackend::keep_guard_during_reconnect`]).
    held_guard: Option<NetGuard<B::Cleanup>>,
}

impl<T: Transport, B: NetBackend> Session<T, B> {
    /// Prépare une session ; retourne aussi sa commande d'arrêt et son flux
    /// d'événements.
    pub fn new(
        transport: T,
        backend: B,
        credentials: Credentials,
        options: SessionOptions,
    ) -> (Self, SessionHandle, SessionEvents) {
        let (stop_tx, stop_rx) = watch::channel(false);
        let limit_ms = Arc::new(AtomicU64::new(NO_LIMIT));
        let (ev_tx, ev_rx) = mpsc::unbounded_channel();
        let session = Self {
            transport,
            backend,
            credentials,
            options,
            events: EventSink {
                tx: ev_tx,
                start: Instant::now(),
            },
            shutdown: stop_rx,
            limit_ms: Arc::clone(&limit_ms),
            held_guard: None,
        };
        (
            session,
            SessionHandle {
                stop: Arc::new(stop_tx),
                limit_ms,
            },
            SessionEvents(ev_rx),
        )
    }

    /// Transport sous-jacent.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Backend réseau sous-jacent.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Exécute une session complète jusqu'à sa fin (reconnexions automatiques
    /// comprises) ; le nettoyage est fait avant le retour. Peut être rappelée tant que
    /// l'arrêt n'a pas été demandé.
    pub async fn run(&mut self) -> DisconnectReason {
        let reason = self.run_inner().await;
        self.events.emit(SessionState::Disconnected {
            reason: reason.clone(),
        });
        reason
    }

    async fn run_inner(&mut self) -> DisconnectReason {
        if *self.shutdown.borrow() {
            return DisconnectReason::Requested;
        }
        let sink = self.events.clone();
        self.transport.set_progress(ProgressSink::new(move |step| {
            sink.emit(match step {
                ConnectStep::Authenticated => SessionState::Authenticated,
                ConnectStep::ConfigReceived => SessionState::ConfigReceived,
            });
        }));

        let policy = self.options.reconnect.clone();
        let clock = policy
            .enabled
            .then_some(policy.clock_jump_threshold)
            .flatten()
            .map(|threshold| ClockWatch {
                interval: policy.clock_check_interval,
                threshold,
            });
        let mut was_up = false;
        let mut attempt: u32 = 0;
        loop {
            let (reason, up) = self.connect_and_relay(clock).await;
            if up {
                was_up = true;
                attempt = 0;
            }
            if !(was_up && reason.is_recoverable(was_up) && policy.allows(attempt + 1)) {
                self.release_held_guard().await;
                self.disconnect_transport().await;
                return reason;
            }
            attempt += 1;
            self.suspend_transport().await;
            let delay = if matches!(reason, DisconnectReason::ClockJump(_)) {
                Duration::ZERO
            } else {
                policy.delay(attempt, reconnect::rand01())
            };
            self.events.emit(SessionState::Reconnecting {
                attempt,
                delay,
                cause: reason,
            });
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                () = shutdown_requested(&mut self.shutdown) => {
                    self.release_held_guard().await;
                    self.disconnect_transport().await;
                    return DisconnectReason::Requested;
                }
            }
        }
    }

    /// Une connexion jusqu'à sa fin, nettoyage réseau compris (le transport n'est ni
    /// déconnecté ni suspendu). Retourne aussi `true` si le tunnel a été établi.
    async fn connect_and_relay(&mut self, clock: Option<ClockWatch>) -> (DisconnectReason, bool) {
        self.events.emit(SessionState::Connecting);
        let connected = tokio::select! {
            r = self.transport.connect(&self.credentials) => r,
            () = shutdown_requested(&mut self.shutdown) => {
                return (DisconnectReason::Requested, false);
            }
        };
        let session = match connected {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "échec de la connexion");
                return (DisconnectReason::ConnectFailed(Arc::new(e)), false);
            }
        };
        let mut end = session.end;

        let tun = match self.backend.create_tun(&self.options.tun).await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(error = %e, "échec de création de la TUN");
                return (DisconnectReason::NetworkFailed(Arc::new(e)), false);
            }
        };
        let mut guard = match self.backend.apply(&tun.info, &session.config).await {
            Ok(g) => g,
            Err(e) => {
                tracing::error!(error = %e, "échec de la configuration réseau");
                return (DisconnectReason::NetworkFailed(Arc::new(e)), false);
            }
        };
        // Make-before-break : l'ancien guard (protection maintenue) n'est démonté
        // qu'une fois le nouveau `apply` réussi.
        self.release_held_guard().await;
        self.events.emit(SessionState::TunnelUp {
            config: session.config,
            interface: tun.info,
        });

        let reason = relay(
            tun.packets,
            session.packets,
            &mut end,
            &mut self.shutdown,
            clock,
        )
        .await;

        // Réseau d'abord (le DNS/les routes du tunnel ne doivent pas gêner le logout),
        // puis le transport (Terminate PPP, fermeture TLS, logout), par l'appelant.
        if self.backend.keep_guard_during_reconnect() {
            // Protection maintenue : le guard reste armé jusqu'au prochain `apply`
            // réussi ou à la fin de la session (`release_held_guard`).
            if let Err(e) = self.backend.suspend(&mut guard).await {
                tracing::error!(error = %e, "échec de la suspension réseau");
            }
            self.held_guard = Some(guard);
        } else if let Err(e) = guard.teardown().await {
            tracing::error!(error = %e, "échec du nettoyage réseau ; nouvel essai au Drop");
        }
        (reason, true)
    }

    /// Démonte le guard conservé pendant `Reconnecting`, s'il y en a un.
    async fn release_held_guard(&mut self) {
        if let Some(mut guard) = self.held_guard.take() {
            if let Err(e) = guard.teardown().await {
                tracing::error!(error = %e, "échec du nettoyage réseau ; nouvel essai au Drop");
            }
        }
    }

    /// Délai de déconnexion effectif (réduit par `shutdown_within`).
    fn effective_disconnect_timeout(&self) -> Duration {
        let ms = self.limit_ms.load(Ordering::Relaxed);
        if ms == NO_LIMIT {
            self.options.disconnect_timeout
        } else {
            self.options
                .disconnect_timeout
                .min(Duration::from_millis(ms))
        }
    }

    async fn suspend_transport(&mut self) {
        match timeout(
            self.effective_disconnect_timeout(),
            self.transport.suspend(),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "échec de la suspension du transport"),
            Err(_) => tracing::warn!("suspension du transport : délai dépassé"),
        }
    }

    async fn disconnect_transport(&mut self) {
        match timeout(
            self.effective_disconnect_timeout(),
            self.transport.disconnect(),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "échec de la déconnexion du transport"),
            Err(_) => tracing::warn!("déconnexion du transport : délai dépassé"),
        }
    }
}

/// Surveillance de l'horloge pendant le relais (cf. doc du module).
#[derive(Debug, Clone, Copy)]
struct ClockWatch {
    interval: Duration,
    threshold: Duration,
}

/// Se termine au premier saut d'horloge détecté (jamais si `watch` est `None`).
async fn clock_jumped(watch: Option<ClockWatch>) -> Duration {
    let Some(w) = watch.filter(|w| !w.interval.is_zero()) else {
        return std::future::pending().await;
    };
    let mut ticks = tokio::time::interval(w.interval);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticks.tick().await;
    let mut prev = (Instant::now(), SystemTime::now());
    loop {
        ticks.tick().await;
        let now = (Instant::now(), SystemTime::now());
        let mono = now.0.duration_since(prev.0);
        let wall = now.1.duration_since(prev.1).ok();
        if let Some(gap) = reconnect::clock_jump(mono, wall, w.interval, w.threshold) {
            tracing::info!(?gap, "saut d'horloge détecté (sortie de veille ?)");
            return gap;
        }
        prev = now;
    }
}

/// Côté qui a mis fin au relais.
enum Side {
    Tun,
    Transport,
}

/// Relaie les paquets jusqu'à l'arrêt demandé ou la fin d'un côté.
async fn relay(
    tun: PacketChannel,
    gateway: PacketChannel,
    end: &mut SessionEnd,
    shutdown: &mut watch::Receiver<bool>,
    clock: Option<ClockWatch>,
) -> DisconnectReason {
    let (tun_tx, mut tun_rx) = tun.split();
    let (gw_tx, mut gw_rx) = gateway.split();
    let up = async {
        while let Some(p) = tun_rx.recv().await {
            if gw_tx.send(p).await.is_err() {
                return Side::Transport;
            }
        }
        Side::Tun
    };
    let down = async {
        while let Some(p) = gw_rx.recv().await {
            if tun_tx.send(p).await.is_err() {
                return Side::Tun;
            }
        }
        Side::Transport
    };
    let side = tokio::select! {
        biased;
        () = shutdown_requested(shutdown) => return DisconnectReason::Requested,
        r = end.wait() => return DisconnectReason::from_end(r),
        gap = clock_jumped(clock) => return DisconnectReason::ClockJump(gap),
        side = up => side,
        side = down => side,
    };
    match side {
        Side::Tun => DisconnectReason::TunClosed,
        // Le transport publie sa raison avant de fermer le canal.
        Side::Transport => end.try_result().map_or(
            DisconnectReason::TransportClosed,
            DisconnectReason::from_end,
        ),
    }
}

#[cfg(test)]
mod tests;
