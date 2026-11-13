//! Implémentations fictives en mémoire de [`NetBackend`] et [`Transport`], pour
//! les tests (feature `test-util` pour les autres crates).
//!
//! Elles enregistrent les opérations effectuées et exposent l'autre extrémité
//! des canaux de paquets pour injecter/lire des paquets.

use std::future::{Future, ready};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use ipnet::IpNet;
use secrecy::ExposeSecret;

use crate::config::{DnsConfig, RoutingMode, TunnelConfig};
use crate::error::{NetError, TransportError};
use crate::net::{NetBackend, NetCleanup, NetGuard, TunDevice, TunInfo, TunOptions};
use crate::packet::PacketChannel;
use crate::transport::{
    ConnectStep, Credentials, ProgressSink, SessionEndNotifier, Transport, TransportSession,
    session_end,
};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// FakeNetBackend
// ---------------------------------------------------------------------------

/// Chemin emprunté par une route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteVia {
    /// Via l'interface TUN.
    Tunnel,
    /// Via la route par défaut d'origine (hors tunnel).
    Underlay,
}

/// Route installée par le fake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FakeRoute {
    /// Destination.
    pub dest: IpNet,
    /// Chemin.
    pub via: RouteVia,
}

/// Opération enregistrée par [`FakeNetBackend`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetOp {
    /// Création de l'interface.
    CreateTun(String),
    /// Adresse IPv4 posée.
    SetAddress(ipnet::Ipv4Net),
    /// MTU posée.
    SetMtu(u16),
    /// Route ajoutée.
    AddRoute(FakeRoute),
    /// DNS configuré.
    SetDns(DnsConfig),
    /// Début d'annulation (`blocking` = depuis `Drop`).
    TeardownStart {
        /// Annulation bloquante (depuis `Drop`) ou async.
        blocking: bool,
    },
    /// DNS retiré.
    RemoveDns,
    /// Route retirée.
    RemoveRoute(FakeRoute),
    /// Adresse retirée.
    RemoveAddress(ipnet::Ipv4Net),
    /// [`NetBackend::suspend`] appelée (protection maintenue, config tunnel retirée).
    Suspend,
}

/// Étape à laquelle injecter un échec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailPoint {
    /// `create_tun`.
    CreateTun,
    /// Pose de l'adresse.
    Address,
    /// Ajout des routes.
    Routes,
    /// Configuration DNS.
    Dns,
    /// Annulation async (le chemin bloquant du `Drop` réussit toujours).
    Teardown,
}

#[derive(Debug, Default)]
struct Installed {
    address: Option<ipnet::Ipv4Net>,
    routes: Vec<FakeRoute>,
    dns: bool,
}

#[derive(Debug, Default)]
struct NetState {
    ops: Vec<NetOp>,
    installed: Installed,
    fail_at: Option<FailPoint>,
    tun_peers: Vec<PacketChannel>,
    tun_count: u32,
    /// Le backend demande à garder la protection pendant la reconnexion.
    keep_guard: bool,
    /// Protection factice maintenue après `suspend`, jusqu'au démontage du guard.
    protected: bool,
    /// Génération du dernier `apply` (un guard périmé ne retire plus rien).
    generation: u32,
}

impl NetState {
    fn check(&self, point: FailPoint) -> Result<(), NetError> {
        if self.fail_at == Some(point) {
            Err(NetError::Os {
                op: "fake",
                reason: format!("échec injecté : {point:?}"),
            })
        } else {
            Ok(())
        }
    }

    fn install(&mut self, config: &TunnelConfig) -> Result<(), NetError> {
        self.check(FailPoint::Address)?;
        self.ops.push(NetOp::SetAddress(config.ipv4.address));
        self.installed.address = Some(config.ipv4.address);
        self.ops.push(NetOp::SetMtu(config.mtu));

        let mut routes = vec![FakeRoute {
            dest: IpNet::from(config.gateway),
            via: RouteVia::Underlay,
        }];
        match &config.routing {
            RoutingMode::Split { include } => {
                routes.extend(include.iter().map(|&dest| FakeRoute {
                    dest,
                    via: RouteVia::Tunnel,
                }));
            }
            RoutingMode::Full { exclude } => {
                for half in ["0.0.0.0/1", "128.0.0.0/1"] {
                    if let Ok(dest) = half.parse() {
                        routes.push(FakeRoute {
                            dest,
                            via: RouteVia::Tunnel,
                        });
                    }
                }
                routes.extend(exclude.iter().map(|&dest| FakeRoute {
                    dest,
                    via: RouteVia::Underlay,
                }));
            }
        }
        for route in routes {
            self.check(FailPoint::Routes)?;
            self.ops.push(NetOp::AddRoute(route));
            self.installed.routes.push(route);
        }

        self.check(FailPoint::Dns)?;
        self.ops.push(NetOp::SetDns(config.dns.clone()));
        self.installed.dns = true;
        Ok(())
    }

    /// Retire ce qui reste installé, dans l'ordre inverse.
    fn uninstall(&mut self, blocking: bool) {
        self.ops.push(NetOp::TeardownStart { blocking });
        if std::mem::take(&mut self.installed.dns) {
            self.ops.push(NetOp::RemoveDns);
        }
        while let Some(route) = self.installed.routes.pop() {
            self.ops.push(NetOp::RemoveRoute(route));
        }
        if let Some(addr) = self.installed.address.take() {
            self.ops.push(NetOp::RemoveAddress(addr));
        }
    }
}

/// [`NetBackend`] en mémoire. Clonable : les clones partagent le même état, ce
/// qui permet d'observer le backend après l'avoir passé au code testé.
#[derive(Debug, Clone, Default)]
pub struct FakeNetBackend {
    state: Arc<Mutex<NetState>>,
}

impl FakeNetBackend {
    /// Nouveau backend vierge.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fait échouer les prochains appels à l'étape donnée (`None` : plus d'échec).
    pub fn fail_at(&self, point: Option<FailPoint>) {
        lock(&self.state).fail_at = point;
    }

    /// Journal des opérations.
    pub fn ops(&self) -> Vec<NetOp> {
        lock(&self.state).ops.clone()
    }

    /// Routes actuellement installées.
    pub fn installed_routes(&self) -> Vec<FakeRoute> {
        lock(&self.state).installed.routes.clone()
    }

    /// Vrai si plus rien n'est installé (adresse, routes, DNS) ni protégé
    /// (cf. [`set_keep_guard_during_reconnect`](Self::set_keep_guard_during_reconnect)).
    pub fn is_clean(&self) -> bool {
        let s = lock(&self.state);
        s.installed.address.is_none()
            && s.installed.routes.is_empty()
            && !s.installed.dns
            && !s.protected
    }

    /// Active le maintien du guard pendant `Reconnecting` (défaut : non).
    pub fn set_keep_guard_during_reconnect(&self, keep: bool) {
        lock(&self.state).keep_guard = keep;
    }

    /// Vrai si une protection est maintenue (après `suspend`, avant démontage).
    pub fn is_protected(&self) -> bool {
        lock(&self.state).protected
    }

    /// Côté « OS » de la plus ancienne TUN non encore récupérée : `send` simule un
    /// paquet émis par une application, `recv` lit un paquet injecté par le client.
    pub fn take_tun_peer(&self) -> Option<PacketChannel> {
        let mut s = lock(&self.state);
        if s.tun_peers.is_empty() {
            None
        } else {
            Some(s.tun_peers.remove(0))
        }
    }
}

// Les fakes n'ont rien à attendre : les opérations sont exécutées de manière
// synchrone à l'appel, et la future retournée est déjà prête.
impl NetBackend for FakeNetBackend {
    type Cleanup = FakeCleanup;

    fn create_tun(
        &self,
        options: &TunOptions,
    ) -> impl Future<Output = Result<TunDevice, NetError>> + Send {
        ready(self.create_tun_now(options))
    }

    fn apply(
        &self,
        tun: &TunInfo,
        config: &TunnelConfig,
    ) -> impl Future<Output = Result<NetGuard<FakeCleanup>, NetError>> + Send {
        ready(self.apply_now(tun, config))
    }

    fn keep_guard_during_reconnect(&self) -> bool {
        lock(&self.state).keep_guard
    }

    fn suspend(
        &self,
        _guard: &mut NetGuard<FakeCleanup>,
    ) -> impl Future<Output = Result<(), NetError>> + Send {
        let mut s = lock(&self.state);
        s.ops.push(NetOp::Suspend);
        s.uninstall(false);
        s.protected = true;
        ready(Ok(()))
    }
}

impl FakeNetBackend {
    fn create_tun_now(&self, options: &TunOptions) -> Result<TunDevice, NetError> {
        let mut s = lock(&self.state);
        s.check(FailPoint::CreateTun)?;
        s.ops.push(NetOp::CreateTun(options.name.clone()));
        s.tun_count += 1;
        let index = s.tun_count;
        let (ours, peer) = PacketChannel::pair(options.queue_capacity);
        s.tun_peers.push(peer);
        Ok(TunDevice {
            info: TunInfo {
                name: options.name.clone(),
                index: Some(index),
            },
            packets: ours,
        })
    }

    fn apply_now(
        &self,
        _tun: &TunInfo,
        config: &TunnelConfig,
    ) -> Result<NetGuard<FakeCleanup>, NetError> {
        config.validate()?;
        if config.ipv6.is_some() {
            return Err(NetError::Unsupported("IPv6"));
        }
        let mut s = lock(&self.state);
        if let Err(e) = s.install(config) {
            // Contrat : pas d'état partiel en cas d'erreur.
            s.uninstall(false);
            return Err(e);
        }
        s.generation += 1;
        let generation = s.generation;
        Ok(NetGuard::new(FakeCleanup {
            state: Arc::clone(&self.state),
            generation,
        }))
    }
}

/// Annulation du [`FakeNetBackend`].
#[derive(Debug)]
pub struct FakeCleanup {
    state: Arc<Mutex<NetState>>,
    generation: u32,
}

impl FakeCleanup {
    fn run(&self, blocking: bool) {
        let mut s = lock(&self.state);
        if self.generation == s.generation {
            s.uninstall(blocking);
        }
        // Un guard périmé (remplacé par un `apply` plus récent) ne retire que la
        // protection maintenue, qui est désormais adoptée par le nouveau guard.
        s.protected = false;
    }
}

impl NetCleanup for FakeCleanup {
    fn cleanup(&mut self) -> impl Future<Output = Result<(), NetError>> + Send {
        let s = lock(&self.state);
        let result = s.check(FailPoint::Teardown);
        drop(s);
        if result.is_ok() {
            self.run(false);
        }
        ready(result)
    }

    fn cleanup_blocking(&mut self) -> Result<(), NetError> {
        self.run(true);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FakeTransport
// ---------------------------------------------------------------------------

/// Événement enregistré par [`FakeTransport`] (jamais le mot de passe).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportEvent {
    /// Connexion réussie pour cet utilisateur.
    Connected(String),
    /// Authentification refusée pour cet utilisateur.
    AuthRejected(String),
    /// Déconnexion (y compris redondante).
    Disconnected,
    /// Suspension en vue d'une reconnexion ([`Transport::suspend`]).
    Suspended,
    /// Échec injecté par [`FakeTransport::fail_next_connect`].
    ConnectFailed,
}

#[derive(Debug)]
struct TransportState {
    expected: Credentials,
    config: TunnelConfig,
    connected: bool,
    events: Vec<TransportEvent>,
    gateway_peer: Option<PacketChannel>,
    end: Option<SessionEndNotifier>,
    progress: Option<ProgressSink>,
    connect_errors: std::collections::VecDeque<TransportError>,
}

/// [`Transport`] en mémoire : accepte uniquement les identifiants attendus et
/// retourne la configuration fournie. Clonable (état partagé).
#[derive(Debug, Clone)]
pub struct FakeTransport {
    state: Arc<Mutex<TransportState>>,
}

impl FakeTransport {
    /// `expected` : identifiants acceptés ; `config` : configuration remise.
    pub fn new(expected: Credentials, config: TunnelConfig) -> Self {
        Self {
            state: Arc::new(Mutex::new(TransportState {
                expected,
                config,
                connected: false,
                events: Vec::new(),
                gateway_peer: None,
                end: None,
                progress: None,
                connect_errors: std::collections::VecDeque::new(),
            })),
        }
    }

    /// Fait échouer un prochain `connect` avec `error` (file : un échec par appel).
    pub fn fail_next_connect(&self, error: TransportError) {
        lock(&self.state).connect_errors.push_back(error);
    }

    /// Nombre de connexions réussies.
    pub fn connect_count(&self) -> usize {
        lock(&self.state)
            .events
            .iter()
            .filter(|e| matches!(e, TransportEvent::Connected(_)))
            .count()
    }

    /// Journal des événements.
    pub fn events(&self) -> Vec<TransportEvent> {
        lock(&self.state).events.clone()
    }

    /// Vrai si une session est active.
    pub fn is_connected(&self) -> bool {
        lock(&self.state).connected
    }

    /// Côté « passerelle » de la session courante : `send` simule un paquet venu
    /// du réseau distant, `recv` lit un paquet émis par le client.
    pub fn take_gateway_peer(&self) -> Option<PacketChannel> {
        lock(&self.state).gateway_peer.take()
    }

    /// Simule la fin de session côté passerelle : signale `result` sur
    /// [`TransportSession::end`] puis ferme le côté passerelle s'il n'a pas été
    /// récupéré (sinon, au test de le libérer).
    pub fn end_session(&self, result: Result<(), TransportError>) {
        let mut s = lock(&self.state);
        if let Some(end) = s.end.take() {
            end.finish(result);
        }
        s.gateway_peer = None;
    }
}

impl Transport for FakeTransport {
    fn connect(
        &mut self,
        credentials: &Credentials,
    ) -> impl Future<Output = Result<TransportSession, TransportError>> + Send {
        ready(self.connect_now(credentials))
    }

    fn disconnect(&mut self) -> impl Future<Output = Result<(), TransportError>> + Send {
        self.close(TransportEvent::Disconnected);
        ready(Ok(()))
    }

    fn suspend(&mut self) -> impl Future<Output = Result<(), TransportError>> + Send {
        self.close(TransportEvent::Suspended);
        ready(Ok(()))
    }

    fn set_progress(&mut self, sink: ProgressSink) {
        lock(&self.state).progress = Some(sink);
    }
}

impl FakeTransport {
    fn close(&self, event: TransportEvent) {
        let mut s = lock(&self.state);
        s.connected = false;
        if let Some(end) = s.end.take() {
            end.finish(Ok(()));
        }
        // Ferme le côté passerelle s'il n'a pas été récupéré par le test.
        s.gateway_peer = None;
        s.events.push(event);
    }

    fn connect_now(&self, credentials: &Credentials) -> Result<TransportSession, TransportError> {
        let mut s = lock(&self.state);
        if s.connected {
            return Err(TransportError::AlreadyConnected);
        }
        if let Some(e) = s.connect_errors.pop_front() {
            s.events.push(TransportEvent::ConnectFailed);
            return Err(e);
        }
        let ok = credentials.username == s.expected.username
            && credentials.password.expose_secret() == s.expected.password.expose_secret();
        if !ok {
            s.events
                .push(TransportEvent::AuthRejected(credentials.username.clone()));
            return Err(TransportError::AuthFailed);
        }
        if let Some(p) = &s.progress {
            p.report(ConnectStep::Authenticated);
        }
        s.config.validate()?;
        if let Some(p) = &s.progress {
            p.report(ConnectStep::ConfigReceived);
        }
        let (ours, peer) = PacketChannel::pair(256);
        let (notifier, end) = session_end();
        s.gateway_peer = Some(peer);
        s.end = Some(notifier);
        s.connected = true;
        s.events
            .push(TransportEvent::Connected(credentials.username.clone()));
        Ok(TransportSession {
            config: s.config.clone(),
            packets: ours,
            end,
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::config::tests::sample;

    async fn tun_and_guard(backend: &FakeNetBackend) -> (TunDevice, NetGuard<FakeCleanup>) {
        let tun = backend.create_tun(&TunOptions::new("fvpn0")).await.unwrap();
        let guard = backend.apply(&tun.info, &sample()).await.unwrap();
        (tun, guard)
    }

    #[tokio::test]
    async fn apply_installs_gateway_route_split_routes_and_dns() {
        let backend = FakeNetBackend::new();
        let (_tun, guard) = tun_and_guard(&backend).await;
        assert!(guard.is_active());
        assert_eq!(
            backend.installed_routes(),
            vec![
                FakeRoute {
                    dest: "203.0.113.10/32".parse().unwrap(),
                    via: RouteVia::Underlay,
                },
                FakeRoute {
                    dest: "10.0.0.0/8".parse().unwrap(),
                    via: RouteVia::Tunnel,
                },
            ]
        );
        let ops = backend.ops();
        assert_eq!(ops[0], NetOp::CreateTun("fvpn0".into()));
        assert!(ops.contains(&NetOp::SetMtu(1354)));
        assert!(ops.contains(&NetOp::SetDns(sample().dns)));
        assert!(!backend.is_clean());
    }

    #[tokio::test]
    async fn full_tunnel_keeps_exclusions_out() {
        let backend = FakeNetBackend::new();
        let tun = backend.create_tun(&TunOptions::new("fvpn0")).await.unwrap();
        let mut config = sample();
        let lan: IpNet = "192.168.1.0/24".parse().unwrap();
        config.routing = RoutingMode::Full { exclude: vec![lan] };
        let _guard = backend.apply(&tun.info, &config).await.unwrap();
        let routes = backend.installed_routes();
        assert!(routes.contains(&FakeRoute {
            dest: lan,
            via: RouteVia::Underlay
        }));
        assert!(routes.contains(&FakeRoute {
            dest: "0.0.0.0/1".parse().unwrap(),
            via: RouteVia::Tunnel
        }));
    }

    #[tokio::test]
    async fn dropping_guard_tears_down() {
        let backend = FakeNetBackend::new();
        let (_tun, guard) = tun_and_guard(&backend).await;
        drop(guard);
        assert!(backend.is_clean());
        assert!(
            backend
                .ops()
                .contains(&NetOp::TeardownStart { blocking: true })
        );
    }

    #[tokio::test]
    async fn teardown_is_idempotent_and_disarms_drop() {
        let backend = FakeNetBackend::new();
        let (_tun, mut guard) = tun_and_guard(&backend).await;
        guard.teardown().await.unwrap();
        assert!(backend.is_clean());
        assert!(!guard.is_active());
        let after_first = backend.ops();

        guard.teardown().await.unwrap();
        drop(guard);
        assert_eq!(
            backend.ops(),
            after_first,
            "aucune opération supplémentaire"
        );
        let starts = after_first
            .iter()
            .filter(|op| matches!(op, NetOp::TeardownStart { .. }))
            .count();
        assert_eq!(starts, 1);
        assert_eq!(
            after_first.last(),
            Some(&NetOp::RemoveAddress(sample().ipv4.address))
        );
    }

    #[tokio::test]
    async fn failed_teardown_keeps_guard_armed_then_drop_cleans() {
        let backend = FakeNetBackend::new();
        let (_tun, mut guard) = tun_and_guard(&backend).await;
        backend.fail_at(Some(FailPoint::Teardown));
        assert!(guard.teardown().await.is_err());
        assert!(guard.is_active());
        assert!(!backend.is_clean());
        drop(guard);
        assert!(backend.is_clean());
    }

    #[tokio::test]
    async fn failed_apply_rolls_back() {
        for point in [FailPoint::Address, FailPoint::Routes, FailPoint::Dns] {
            let backend = FakeNetBackend::new();
            let tun = backend.create_tun(&TunOptions::new("fvpn0")).await.unwrap();
            backend.fail_at(Some(point));
            assert!(backend.apply(&tun.info, &sample()).await.is_err());
            assert!(backend.is_clean(), "{point:?}");
        }
    }

    #[tokio::test]
    async fn apply_rejects_invalid_and_ipv6_config() {
        let backend = FakeNetBackend::new();
        let tun = backend.create_tun(&TunOptions::new("fvpn0")).await.unwrap();
        let mut bad = sample();
        bad.mtu = 100;
        assert!(matches!(
            backend.apply(&tun.info, &bad).await,
            Err(NetError::InvalidConfig(_))
        ));
        let mut v6 = sample();
        v6.ipv6 = Some(crate::config::Ipv6Config {
            address: "fd00::2/64".parse().unwrap(),
            peer: None,
        });
        assert!(matches!(
            backend.apply(&tun.info, &v6).await,
            Err(NetError::Unsupported(_))
        ));
        assert!(
            backend
                .ops()
                .iter()
                .all(|op| matches!(op, NetOp::CreateTun(_)))
        );
    }

    #[tokio::test]
    async fn tun_packet_round_trip() {
        let backend = FakeNetBackend::new();
        let mut tun = backend.create_tun(&TunOptions::new("fvpn0")).await.unwrap();
        let mut os = backend.take_tun_peer().unwrap();

        os.send(Bytes::from_static(b"\x45outbound")).await.unwrap();
        assert_eq!(
            tun.packets.recv().await.unwrap(),
            Bytes::from_static(b"\x45outbound")
        );
        tun.packets
            .send(Bytes::from_static(b"\x45inbound"))
            .await
            .unwrap();
        assert_eq!(os.recv().await.unwrap(), Bytes::from_static(b"\x45inbound"));
    }

    fn creds(password: &str) -> Credentials {
        Credentials::new("alice", password.to_owned())
    }

    #[tokio::test]
    async fn transport_rejects_bad_password() {
        let mut t = FakeTransport::new(creds("good"), sample());
        assert!(matches!(
            t.connect(&creds("bad")).await,
            Err(TransportError::AuthFailed)
        ));
        assert!(!t.is_connected());
        assert_eq!(
            t.events(),
            vec![TransportEvent::AuthRejected("alice".into())]
        );
    }

    #[tokio::test]
    async fn transport_connect_disconnect_and_packets() {
        let mut t = FakeTransport::new(creds("good"), sample());
        let mut session = t.connect(&creds("good")).await.unwrap();
        assert_eq!(session.config, sample());
        assert!(matches!(
            t.connect(&creds("good")).await,
            Err(TransportError::AlreadyConnected)
        ));

        let mut gw = t.take_gateway_peer().unwrap();
        session
            .packets
            .send(Bytes::from_static(b"to-gw"))
            .await
            .unwrap();
        assert_eq!(gw.recv().await.unwrap(), Bytes::from_static(b"to-gw"));
        gw.send(Bytes::from_static(b"from-gw")).await.unwrap();
        assert_eq!(
            session.packets.recv().await.unwrap(),
            Bytes::from_static(b"from-gw")
        );

        t.disconnect().await.unwrap();
        t.disconnect().await.unwrap();
        assert!(!t.is_connected());
        assert_eq!(
            t.events(),
            vec![
                TransportEvent::Connected("alice".into()),
                TransportEvent::Disconnected,
                TransportEvent::Disconnected,
            ]
        );
    }

    #[tokio::test]
    async fn disconnect_closes_untaken_gateway_side() {
        let mut t = FakeTransport::new(creds("good"), sample());
        let mut session = t.connect(&creds("good")).await.unwrap();
        t.disconnect().await.unwrap();
        assert!(session.packets.recv().await.is_none());
    }

    /// Bout en bout : TUN fictive <-> transport fictif via une boucle de relais.
    #[tokio::test]
    async fn end_to_end_relay_through_fakes() {
        let backend = FakeNetBackend::new();
        let mut transport = FakeTransport::new(creds("good"), sample());
        let session = transport.connect(&creds("good")).await.unwrap();
        let tun = backend.create_tun(&TunOptions::new("fvpn0")).await.unwrap();
        let mut guard = backend.apply(&tun.info, &session.config).await.unwrap();

        let (tun_tx, mut tun_rx) = tun.packets.split();
        let (gw_tx, mut gw_rx) = session.packets.split();
        let up = tokio::spawn(async move {
            while let Some(p) = tun_rx.recv().await {
                if gw_tx.send(p).await.is_err() {
                    break;
                }
            }
        });
        let down = tokio::spawn(async move {
            while let Some(p) = gw_rx.recv().await {
                if tun_tx.send(p).await.is_err() {
                    break;
                }
            }
        });

        let mut os = backend.take_tun_peer().unwrap();
        let mut gw = transport.take_gateway_peer().unwrap();
        os.send(Bytes::from_static(b"echo-request")).await.unwrap();
        let req = gw.recv().await.unwrap();
        assert_eq!(req, Bytes::from_static(b"echo-request"));
        gw.send(Bytes::from_static(b"echo-reply")).await.unwrap();
        assert_eq!(os.recv().await.unwrap(), Bytes::from_static(b"echo-reply"));

        drop(gw);
        drop(os);
        up.await.unwrap();
        down.await.unwrap();
        guard.teardown().await.unwrap();
        transport.disconnect().await.unwrap();
        assert!(backend.is_clean());
    }
}
