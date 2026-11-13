//! [`NetBackend`] du mode proxy : aucune modification du système.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use fortivpn_core::{
    NetBackend, NetCleanup, NetError, NetGuard, PacketChannel, TunDevice, TunInfo, TunOptions,
    TunnelConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

use crate::config::{ProxyConfig, ProxyConfigError, Target};
use crate::owner::{self, OwnerCheck};
use crate::socks::{self, Reply, SocksError};
use crate::stack::{self, CHUNK, StackConfig, StackHandle, StackStream};

/// Erreur de création du backend proxy.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProxyError {
    /// Configuration invalide.
    #[error(transparent)]
    Config(#[from] ProxyConfigError),
    /// Port déjà utilisé par une autre application.
    #[error(
        "le port {addr} est déjà utilisé par une autre application (os error {code}) ; \
         changez le port dans la section [proxy] (`socks` ou `forward`)"
    )]
    AddrInUse {
        /// Adresse demandée.
        addr: SocketAddr,
        /// Code d'erreur OS (`WSAEADDRINUSE` 10048, `EADDRINUSE` 98…).
        code: i32,
    },
    /// Accès refusé : port réservé par Windows (plages exclues) ou privilégié.
    #[error(
        "impossible d'écouter sur {addr} : port réservé par Windows (plages exclues \
         Hyper-V/WSL) ou accès refusé (os error {code}) ; choisissez un autre port dans \
         [proxy] (ex. 18080) — vérification : netsh int ipv4 show excludedportrange protocol=tcp"
    )]
    PortReserved {
        /// Adresse demandée.
        addr: SocketAddr,
        /// Code d'erreur OS (`WSAEACCES` 10013, `EACCES` 13).
        code: i32,
    },
    /// Écoute impossible (droits, adresse invalide…).
    #[error("écoute sur {addr} impossible : {source}")]
    Bind {
        /// Adresse demandée.
        addr: SocketAddr,
        /// Cause.
        #[source]
        source: std::io::Error,
    },
}

/// Rôle d'un écouteur.
#[derive(Debug, Clone)]
enum Role {
    Socks,
    Forward(Target),
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// État partagé avec les tâches d'écoute.
#[derive(Debug)]
struct Shared {
    /// Pile du tunnel courant (`None` : tunnel non établi ou en reconnexion).
    current: Mutex<Option<StackHandle>>,
    config: ProxyConfig,
    /// Clients en cours de négociation/connexion, tous écouteurs (M2).
    handshakes: Arc<Semaphore>,
    /// Contrôle du propriétaire du client (`None` : désactivé).
    owner: Option<Arc<dyn OwnerCheck>>,
}

impl Shared {
    fn current(&self) -> Option<StackHandle> {
        lock(&self.current).clone()
    }
}

/// Backend « proxy » : la TUN est remplacée par une pile TCP/IP `smoltcp` en
/// espace utilisateur, exposée localement par un proxy SOCKS5 et des
/// redirections de ports. Ne nécessite aucun droit d'administration et ne
/// modifie ni routes, ni DNS, ni interfaces du système.
///
/// Les écoutes sont ouvertes par [`ProxyBackend::new`] (échec immédiat si un
/// port est pris) et servies dès le premier [`NetBackend::create_tun`] ; elles
/// survivent aux reconnexions (pendant une coupure, les nouvelles demandes sont
/// refusées). Elles sont fermées à la libération du backend.
#[derive(Debug)]
pub struct ProxyBackend {
    shared: Arc<Shared>,
    socks: Option<SocketAddr>,
    forwards: Vec<(SocketAddr, Target)>,
    /// Écoutes ouvertes, pas encore servies (en attente d'un runtime tokio).
    pending: Mutex<Vec<(std::net::TcpListener, Role)>>,
    accept_tasks: Mutex<Vec<JoinHandle<()>>>,
    /// Extrémité « pile » du canal créé par `create_tun`, reprise par `apply`.
    channel: Mutex<Option<PacketChannel>>,
}

impl ProxyBackend {
    /// Valide la configuration et ouvre les écoutes (sans runtime tokio requis).
    pub fn new(config: ProxyConfig) -> Result<Self, ProxyError> {
        let owner = config.owner_check.then(owner::system_check);
        Self::with_owner(config, owner)
    }

    fn with_owner(
        config: ProxyConfig,
        owner: Option<Arc<dyn OwnerCheck>>,
    ) -> Result<Self, ProxyError> {
        config.validate()?;
        let bind = |addr: SocketAddr| -> Result<std::net::TcpListener, ProxyError> {
            crate::listen::bind_exclusive(addr)
        };
        let mut pending = Vec::new();
        let mut socks = None;
        if let Some(addr) = config.socks {
            let l = bind(addr)?;
            socks = Some(l.local_addr().unwrap_or(addr));
            pending.push((l, Role::Socks));
        }
        let mut forwards = Vec::new();
        for f in &config.forwards {
            let l = bind(f.listen)?;
            forwards.push((l.local_addr().unwrap_or(f.listen), f.target.clone()));
            pending.push((l, Role::Forward(f.target.clone())));
        }
        let handshakes = Arc::new(Semaphore::new(config.limits.max_handshakes.max(1)));
        Ok(Self {
            shared: Arc::new(Shared {
                current: Mutex::new(None),
                config,
                handshakes,
                owner,
            }),
            socks,
            forwards,
            pending: Mutex::new(pending),
            accept_tasks: Mutex::new(Vec::new()),
            channel: Mutex::new(None),
        })
    }

    /// Adresse effective du proxy SOCKS5, s'il est activé.
    pub fn socks_addr(&self) -> Option<SocketAddr> {
        self.socks
    }

    /// Redirections effectives : adresse d'écoute → destination.
    pub fn forwards(&self) -> &[(SocketAddr, Target)] {
        &self.forwards
    }

    /// Lance le service des écoutes (au premier appel, dans le runtime).
    fn ensure_listening(&self) -> Result<(), NetError> {
        let pending = std::mem::take(&mut *lock(&self.pending));
        let mut tasks = lock(&self.accept_tasks);
        let limits = self.shared.config.limits;
        for (listener, role) in pending {
            let cap = match role {
                Role::Socks => limits.socks_connections,
                Role::Forward(_) => limits.forward_connections,
            };
            let slots = Arc::new(Semaphore::new(cap.max(1)));
            let listener = TcpListener::from_std(listener).map_err(|source| NetError::Io {
                op: "proxy_listen",
                source,
            })?;
            tasks.push(tokio::spawn(accept_loop(
                listener,
                role,
                slots,
                Arc::clone(&self.shared),
            )));
        }
        Ok(())
    }
}

impl Drop for ProxyBackend {
    fn drop(&mut self) {
        for task in lock(&self.accept_tasks).drain(..) {
            task.abort();
        }
        *lock(&self.shared.current) = None;
    }
}

impl NetBackend for ProxyBackend {
    type Cleanup = ProxyCleanup;

    fn create_tun(
        &self,
        options: &TunOptions,
    ) -> impl Future<Output = Result<TunDevice, NetError>> + Send {
        std::future::ready(self.create_tun_now(options))
    }

    fn apply(
        &self,
        tun: &TunInfo,
        config: &TunnelConfig,
    ) -> impl Future<Output = Result<NetGuard<ProxyCleanup>, NetError>> + Send {
        std::future::ready(self.apply_now(tun, config))
    }
}

impl ProxyBackend {
    fn create_tun_now(&self, options: &TunOptions) -> Result<TunDevice, NetError> {
        self.ensure_listening()?;
        let (ours, theirs) = PacketChannel::pair(options.queue_capacity);
        *lock(&self.channel) = Some(ours);
        Ok(TunDevice {
            info: TunInfo {
                name: options.name.clone(),
                index: None,
            },
            packets: theirs,
        })
    }

    fn apply_now(
        &self,
        _tun: &TunInfo,
        config: &TunnelConfig,
    ) -> Result<NetGuard<ProxyCleanup>, NetError> {
        config.validate()?;
        let channel = lock(&self.channel).take().ok_or(NetError::Os {
            op: "proxy_apply",
            reason: "aucune interface créée".to_owned(),
        })?;
        if config.ipv6.is_some() {
            tracing::debug!("mode proxy : adressage IPv6 du tunnel ignoré");
        }
        let dns: Vec<Ipv4Addr> = config
            .dns
            .servers
            .iter()
            .filter_map(|ip| match ip {
                std::net::IpAddr::V4(v4) => Some(*v4),
                std::net::IpAddr::V6(_) => None,
            })
            .collect();
        if dns.is_empty() {
            tracing::warn!(
                "mode proxy : aucun serveur DNS IPv4 fourni par le tunnel, seules les \
                 destinations en adresse IP fonctionneront"
            );
        }
        let address = config.ipv4.address.addr();
        let stack_config = StackConfig {
            address,
            prefix_len: config.ipv4.address.prefix_len(),
            gateway: config.ipv4.peer.unwrap_or(address),
            dns,
            mtu: config.mtu,
            limits: self.shared.config.limits,
        };
        let (handle, task) = stack::spawn(channel, &stack_config);
        *lock(&self.shared.current) = Some(handle);
        tracing::info!(
            socks = ?self.socks,
            forwards = self.forwards.len(),
            "mode proxy actif (aucune modification réseau du système)"
        );
        Ok(NetGuard::new(ProxyCleanup {
            shared: Arc::clone(&self.shared),
            task: Some(task),
        }))
    }
}

/// Arrêt de la pile du tunnel : les connexions en cours sont coupées, les
/// écoutes restent ouvertes (nouvelles demandes refusées jusqu'au prochain
/// `apply`).
#[derive(Debug)]
pub struct ProxyCleanup {
    shared: Arc<Shared>,
    task: Option<JoinHandle<()>>,
}

impl ProxyCleanup {
    fn stop(&mut self) {
        *lock(&self.shared.current) = None;
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl NetCleanup for ProxyCleanup {
    fn cleanup(&mut self) -> impl Future<Output = Result<(), NetError>> + Send {
        self.stop();
        std::future::ready(Ok(()))
    }

    fn cleanup_blocking(&mut self) -> Result<(), NetError> {
        self.stop();
        Ok(())
    }
}

// --- Clients locaux -------------------------------------------------------------

async fn accept_loop(
    listener: TcpListener,
    role: Role,
    slots: Arc<Semaphore>,
    shared: Arc<Shared>,
) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                // Ex. plus de descripteurs : ne pas boucler à vide.
                tracing::warn!(error = %e, "proxy : accept a échoué");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            tracing::warn!("proxy : trop de clients simultanés sur cet écouteur, refusé");
            continue;
        };
        let Ok(hs_permit) = Arc::clone(&shared.handshakes).try_acquire_owned() else {
            tracing::warn!("proxy : trop de négociations en cours, connexion refusée");
            continue;
        };
        let role = role.clone();
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let _permit = permit;
            if !owner_allowed(&shared, &tcp, peer).await {
                return;
            }
            serve_client(tcp, role, &shared, hs_permit).await;
        });
    }
}

/// Contrôle M1 : le client doit appartenir à l'utilisateur courant.
async fn owner_allowed(shared: &Shared, tcp: &TcpStream, peer: SocketAddr) -> bool {
    let Some(check) = shared.owner.clone() else {
        return true;
    };
    let Ok(local) = tcp.local_addr() else {
        return false;
    };
    let ok = tokio::task::spawn_blocking(move || check.allowed(peer, local))
        .await
        .unwrap_or(false);
    if !ok {
        tracing::debug!(%peer, "proxy : client d'un autre utilisateur ou inconnu, refusé");
    }
    ok
}

async fn serve_client(
    mut tcp: TcpStream,
    role: Role,
    shared: &Shared,
    handshake_permit: OwnedSemaphorePermit,
) {
    let _ = tcp.set_nodelay(true);
    let limits = shared.config.limits;
    let unbound = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    let (target, is_socks) = match role {
        Role::Forward(target) => (target, false),
        Role::Socks => {
            let handshake = async {
                socks::negotiate_method(&mut tcp).await?;
                socks::read_request(&mut tcp).await
            };
            match tokio::time::timeout(limits.handshake_timeout, handshake).await {
                Ok(Ok(target)) => (target, true),
                Ok(Err(SocksError::Refused(code))) => {
                    tracing::debug!(?code, "SOCKS : requête refusée");
                    let _ = socks::write_reply(&mut tcp, code, unbound).await;
                    return;
                }
                Ok(Err(e)) => {
                    tracing::debug!(error = %e, "SOCKS : négociation échouée");
                    return;
                }
                Err(_) => {
                    tracing::debug!("SOCKS : délai de négociation dépassé");
                    return;
                }
            }
        }
    };
    let result = match shared.current() {
        None => Err(stack::ConnectError::TunnelDown),
        Some(stack) => {
            // Le délai est appliqué par la pile ; marge de sécurité ici.
            let guard = limits.connect_timeout + Duration::from_secs(5);
            tokio::time::timeout(guard, stack.connect(target.clone()))
                .await
                .unwrap_or(Err(stack::ConnectError::Timeout))
        }
    };
    match result {
        Ok(stream) => {
            tracing::debug!(%target, "proxy : connexion établie");
            if is_socks
                && socks::write_reply(&mut tcp, Reply::Succeeded, stream.local)
                    .await
                    .is_err()
            {
                return;
            }
            drop(handshake_permit);
            bridge(tcp, stream, limits.idle_timeout).await;
        }
        Err(e) => {
            tracing::debug!(%target, error = %e, "proxy : connexion impossible");
            if is_socks {
                let _ = socks::write_reply(&mut tcp, e.reply(), unbound).await;
            }
        }
    }
}

/// Horloge d'activité d'une connexion (millisecondes depuis sa création).
#[derive(Debug, Clone)]
struct Activity {
    start: tokio::time::Instant,
    last: Arc<AtomicU64>,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: tokio::time::Instant::now(),
            last: Arc::new(AtomicU64::new(0)),
        }
    }

    fn touch(&self) {
        let ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last.store(ms, Ordering::Relaxed);
    }

    /// Se termine après `idle` sans `touch`.
    async fn expired(&self, idle: Duration) {
        loop {
            let last = self.start + Duration::from_millis(self.last.load(Ordering::Relaxed));
            let deadline = last + idle;
            if tokio::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    }
}

/// Relaie les octets entre le client local et la connexion du tunnel, dans les
/// deux sens, avec demi-fermetures. Une erreur d'écriture vers le client coupe
/// la connexion (la pile émet alors un RST).
async fn bridge(tcp: TcpStream, stream: StackStream, idle: Duration) {
    let (mut rd, mut wr) = tcp.into_split();
    let StackStream {
        tx, mut rx, wake, ..
    } = stream;
    let up_wake = Arc::clone(&wake);
    let clock = Activity::new();
    let up_clock = clock.clone();
    let down_clock = clock.clone();
    let up = async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            up_clock.touch();
            if tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                break;
            }
            up_wake.notify_one();
        }
        // Fin d'émission du client : FIN dans le tunnel.
        drop(tx);
        up_wake.notify_one();
    };
    let down = async move {
        while let Some(chunk) = rx.recv().await {
            wake.notify_one();
            down_clock.touch();
            if wr.write_all(&chunk).await.is_err() {
                drop(rx);
                wake.notify_one();
                return false;
            }
        }
        let _ = wr.shutdown().await;
        true
    };
    let watchdog = clock.expired(idle);
    tokio::pin!(up, down, watchdog);
    let mut up_done = false;
    let mut down_done = false;
    while !(up_done && down_done) {
        tokio::select! {
            () = &mut watchdog => {
                tracing::debug!("proxy : connexion inactive, coupée");
                break;
            }
            () = &mut up, if !up_done => up_done = true,
            ok = &mut down, if !down_done => {
                down_done = true;
                if !ok {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use tokio::io::AsyncReadExt;
    use tokio::sync::mpsc;

    #[derive(Debug)]
    struct Fixed(bool, Arc<AtomicBool>);

    impl OwnerCheck for Fixed {
        fn allowed(&self, _: SocketAddr, _: SocketAddr) -> bool {
            self.1.store(true, Ordering::Relaxed);
            self.0
        }
    }

    async fn started(
        mut cfg: ProxyConfig,
        owner: Option<Arc<dyn OwnerCheck>>,
    ) -> (ProxyBackend, SocketAddr) {
        cfg.socks = Some("127.0.0.1:0".parse().unwrap());
        let b = ProxyBackend::with_owner(cfg, owner).unwrap();
        let addr = b.socks_addr().unwrap();
        b.create_tun(&TunOptions::new("proxy")).await.unwrap();
        (b, addr)
    }

    #[tokio::test]
    async fn owner_refused_closes_connection() {
        let asked = Arc::new(AtomicBool::new(false));
        let deny: Arc<dyn OwnerCheck> = Arc::new(Fixed(false, Arc::clone(&asked)));
        let (_b, addr) = started(ProxyConfig::default(), Some(deny)).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        let _ = c.write_all(&[5, 1, 0]).await;
        let mut buf = [0u8; 2];
        let n = c.read(&mut buf).await.unwrap_or(0);
        assert_eq!(n, 0, "aucune réponse SOCKS pour un client refusé");
        assert!(asked.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn owner_accepted_gets_socks_reply() {
        let allow: Arc<dyn OwnerCheck> = Arc::new(Fixed(true, Arc::default()));
        let (_b, addr) = started(ProxyConfig::default(), Some(allow)).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut buf = [0u8; 2];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [5, 0]);
    }

    #[tokio::test]
    async fn listener_semaphore_limits_clients() {
        let mut cfg = ProxyConfig::default();
        cfg.limits.socks_connections = 2;
        let (_b, addr) = started(cfg, None).await;
        // Deux clients muets occupent les deux places.
        let mut c1 = TcpStream::connect(addr).await.unwrap();
        let _c2 = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Le troisième est fermé sans réponse.
        let mut c3 = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(c3.read(&mut buf).await.unwrap_or(0), 0);
        // Un client existant garde sa place : une salutation reçoit une réponse.
        c1.write_all(&[5, 1, 0]).await.unwrap();
        let mut r = [0u8; 2];
        c1.read_exact(&mut r).await.unwrap();
        assert_eq!(r, [5, 0]);
    }

    #[tokio::test]
    async fn handshake_cap_applies_across_listeners() {
        let mut cfg = ProxyConfig::default();
        cfg.limits.max_handshakes = 1;
        let (_b, addr) = started(cfg, None).await;
        let _c1 = TcpStream::connect(addr).await.unwrap(); // négociation muette
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut c2 = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(c2.read(&mut buf).await.unwrap_or(0), 0);
    }

    fn stream_pair() -> (StackStream, mpsc::Receiver<Bytes>, mpsc::Sender<Bytes>) {
        let (tx, up_rx) = mpsc::channel(4);
        let (down_tx, rx) = mpsc::channel(4);
        let s = StackStream {
            tx,
            rx,
            wake: Arc::new(tokio::sync::Notify::new()),
            local: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        };
        (s, up_rx, down_tx)
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (s, _) = l.accept().await.unwrap();
        (c, s)
    }

    #[tokio::test(start_paused = true)]
    async fn bridge_cut_after_idle() {
        let (_client, server) = tcp_pair().await;
        let (stream, _up_rx, _down_tx) = stream_pair();
        let t0 = tokio::time::Instant::now();
        bridge(server, stream, Duration::from_secs(300)).await;
        let el = t0.elapsed();
        assert!(
            el >= Duration::from_secs(300) && el < Duration::from_secs(310),
            "{el:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn bridge_activity_postpones_idle() {
        let (mut client, server) = tcp_pair().await;
        let (stream, mut up_rx, _down_tx) = stream_pair();
        let t0 = tokio::time::Instant::now();
        let task = tokio::spawn(bridge(server, stream, Duration::from_secs(300)));
        tokio::time::sleep(Duration::from_secs(200)).await;
        client.write_all(b"x").await.unwrap();
        // Horloge en pause : laisser l'événement d'E/S arriver (réel) avant toute avance auto.
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(up_rx.recv().await.unwrap().as_ref(), b"x");
        task.await.unwrap();
        let el = t0.elapsed();
        assert!(
            el >= Duration::from_secs(500) && el < Duration::from_secs(510),
            "{el:?}"
        );
    }
}
