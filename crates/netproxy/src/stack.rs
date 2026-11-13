//! Pile TCP/IP `smoltcp` alimentée par le canal de paquets du tunnel.
//!
//! Une tâche tokio unique possède l'interface smoltcp (médium IP, sans ARP), ses
//! sockets et l'extrémité « OS » du [`PacketChannel`]. Les clients locaux (SOCKS,
//! redirections) lui demandent des connexions par un canal de commandes ; chaque
//! connexion établie est ensuite reliée au client par deux canaux bornés
//! d'octets ([`StackStream`]).
//!
//! Pilotage : la boucle attend (sans attente active) le premier de ces
//! événements : paquet reçu du tunnel, place libre vers le tunnel, commande,
//! réveil par un client (données écrites ou lues, via un [`Notify`]), ou
//! l'échéance calculée par `Interface::poll_delay` (retransmissions, keep-alive,
//! DNS) et par les délais de connexion.

use std::collections::{HashSet, VecDeque};
use std::hash::BuildHasher;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use fortivpn_core::{PacketChannel, PacketReceiver, PacketSender};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::dns::{self, GetQueryResultError, QueryHandle};
use smoltcp::socket::tcp;
use smoltcp::wire::{DnsQueryType, HardwareAddress, IpAddress, IpCidr, Ipv4Cidr};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::config::{Host, Limits, Target};
use crate::socks::Reply;

/// Taille maximale d'un bloc d'octets échangé avec un client.
pub(crate) const CHUNK: usize = 16 * 1024;
/// Blocs en attente par sens et par connexion.
const CHANNEL_CHUNKS: usize = 4;
/// Paquets lus du tunnel par itération.
const RX_BATCH: usize = 64;
/// Paquets en attente d'émission vers le tunnel (au-delà, smoltcp retient).
const TX_QUEUE: usize = 256;
/// Commandes en attente.
const COMMAND_QUEUE: usize = 64;
/// Attente maximale quand rien n'est programmé.
const IDLE_WAIT: Duration = Duration::from_secs(60);
/// Plage des ports locaux éphémères (IANA).
const EPHEMERAL: std::ops::RangeInclusive<u16> = 49152..=65535;
/// Nombre de serveurs DNS utilisés (dans l'ordre, repli sur échec).
const MAX_DNS_SERVERS: usize = 3;

/// Paramètres de la pile, dérivés de la configuration du tunnel.
#[derive(Debug, Clone)]
pub(crate) struct StackConfig {
    /// Adresse locale du tunnel et préfixe.
    pub(crate) address: Ipv4Addr,
    pub(crate) prefix_len: u8,
    /// Routeur par défaut (pair PPP, ou l'adresse locale : en médium IP le
    /// prochain saut n'est pas utilisé, seule l'existence d'une route compte).
    pub(crate) gateway: Ipv4Addr,
    /// Serveurs DNS IPv4 du tunnel.
    pub(crate) dns: Vec<Ipv4Addr>,
    /// MTU du tunnel.
    pub(crate) mtu: u16,
    /// Limites.
    pub(crate) limits: Limits,
}

/// Échec d'une demande de connexion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ConnectError {
    #[error("tunnel non établi")]
    TunnelDown,
    #[error("trop de connexions simultanées")]
    TooManyConnections,
    #[error("aucun serveur DNS dans le tunnel")]
    NoDns,
    #[error("résolution DNS échouée")]
    ResolveFailed,
    #[error("délai de connexion dépassé")]
    Timeout,
    #[error("connexion refusée")]
    Refused,
    #[error("destination injoignable")]
    Unaddressable,
}

impl ConnectError {
    /// Code de réponse SOCKS5 correspondant.
    pub(crate) fn reply(self) -> Reply {
        match self {
            Self::TunnelDown => Reply::NetworkUnreachable,
            Self::TooManyConnections => Reply::GeneralFailure,
            Self::NoDns | Self::ResolveFailed | Self::Timeout | Self::Unaddressable => {
                Reply::HostUnreachable
            }
            Self::Refused => Reply::ConnectionRefused,
        }
    }
}

type ConnectReply = oneshot::Sender<Result<StackStream, ConnectError>>;

enum Command {
    Connect { target: Target, reply: ConnectReply },
}

/// Accès à la pile depuis les tâches clientes (clonable).
#[derive(Debug, Clone)]
pub(crate) struct StackHandle {
    cmd: mpsc::Sender<Command>,
}

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect { target, .. } => write!(f, "Connect({target})"),
        }
    }
}

impl StackHandle {
    /// Ouvre une connexion TCP vers `target` à travers le tunnel.
    pub(crate) async fn connect(&self, target: Target) -> Result<StackStream, ConnectError> {
        let (reply, rx) = oneshot::channel();
        self.cmd
            .send(Command::Connect { target, reply })
            .await
            .map_err(|_| ConnectError::TunnelDown)?;
        rx.await.map_err(|_| ConnectError::TunnelDown)?
    }
}

/// Connexion établie dans le tunnel, vue du client local.
#[derive(Debug)]
pub(crate) struct StackStream {
    /// Octets à envoyer (libérer l'émetteur = fin d'émission, FIN).
    pub(crate) tx: mpsc::Sender<Bytes>,
    /// Octets reçus (`None` = fin de flux distante ou connexion coupée).
    pub(crate) rx: mpsc::Receiver<Bytes>,
    /// À notifier après chaque envoi ou réception.
    pub(crate) wake: Arc<Notify>,
    /// Adresse locale de la connexion dans le tunnel.
    pub(crate) local: SocketAddrV4,
}

/// Lance la pile sur `channel`. La tâche se termine quand le tunnel ferme le canal
/// (ou quand elle est annulée) ; toutes les connexions sont alors coupées.
pub(crate) fn spawn(channel: PacketChannel, config: &StackConfig) -> (StackHandle, JoinHandle<()>) {
    let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_QUEUE);
    let (tx, rx) = channel.split();
    let task = tokio::spawn(run(Stack::new(config), tx, rx, cmd_rx));
    (StackHandle { cmd: cmd_tx }, task)
}

// --- Périphérique smoltcp sur files mémoire ---------------------------------

struct QueueDevice {
    rx: VecDeque<Bytes>,
    tx: VecDeque<Bytes>,
    mtu: usize,
}

struct Rx(Bytes);

struct Tx<'a>(&'a mut VecDeque<Bytes>);

impl RxToken for Rx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(Bytes::from(buf));
        r
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((Rx(packet), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        (self.tx.len() < TX_QUEUE).then_some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

// --- État de la pile ----------------------------------------------------------

/// Côté pile d'une connexion.
struct Conn {
    handle: SocketHandle,
    port: u16,
    /// Données du client (fermé = FIN côté client).
    from_client: mpsc::Receiver<Bytes>,
    /// Reliquat non encore accepté par la socket.
    pending: Bytes,
    client_eof: bool,
    /// Vers le client ; `None` après la fin de flux distante.
    to_client: Option<mpsc::Sender<Bytes>>,
    /// En cours d'établissement : réponse à donner et extrémité cliente.
    connecting: Option<(ConnectReply, StackStream, Instant)>,
    /// Abandonnée : retirée à l'itération suivante (après émission du RST).
    dead: bool,
}

/// Résolution DNS en cours.
struct Resolving {
    query: QueryHandle,
    server: usize,
    name: String,
    port: u16,
    reply: ConnectReply,
    deadline: Instant,
}

struct Stack {
    iface: Interface,
    device: QueueDevice,
    sockets: SocketSet<'static>,
    dns: Vec<SocketHandle>,
    conns: Vec<Conn>,
    resolving: Vec<Resolving>,
    ports: HashSet<u16>,
    next_port: u16,
    local: Ipv4Addr,
    limits: Limits,
    wake: Arc<Notify>,
    start: Instant,
}

fn random_seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::collections::hash_map::RandomState::new().hash_one(nanos)
}

fn to_std(d: smoltcp::time::Duration) -> Duration {
    Duration::from_micros(d.total_micros())
}

impl Stack {
    fn new(config: &StackConfig) -> Self {
        let mut device = QueueDevice {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu: usize::from(config.mtu),
        };
        let start = Instant::now();
        let seed = random_seed();
        let mut iface_config = IfaceConfig::new(HardwareAddress::Ip);
        iface_config.random_seed = seed;
        let mut iface = Interface::new(iface_config, &mut device, smoltcp::time::Instant::ZERO);
        iface.update_ip_addrs(|addrs| {
            // Capacité ≥ 1 : ne peut échouer.
            let _ = addrs.push(IpCidr::Ipv4(Ipv4Cidr::new(
                config.address,
                config.prefix_len.min(32),
            )));
        });
        // Route par défaut : tout passe par le tunnel. Échoue seulement si la
        // table est pleine (elle est vide ici).
        let _ = iface.routes_mut().add_default_ipv4_route(config.gateway);

        let mut sockets = SocketSet::new(Vec::new());
        let dns = config
            .dns
            .iter()
            .take(MAX_DNS_SERVERS)
            .map(|&server| {
                sockets.add(dns::Socket::new(
                    &[IpAddress::Ipv4(server)],
                    Vec::<Option<dns::DnsQuery>>::new(),
                ))
            })
            .collect();
        let span = u64::from(EPHEMERAL.end() - EPHEMERAL.start()) + 1;
        let offset = u16::try_from(seed % span).unwrap_or(0);
        Self {
            iface,
            device,
            sockets,
            dns,
            conns: Vec::new(),
            resolving: Vec::new(),
            ports: HashSet::new(),
            next_port: EPHEMERAL.start() + offset,
            local: config.address,
            limits: config.limits,
            wake: Arc::new(Notify::new()),
            start,
        }
    }

    fn smol_now(&self) -> smoltcp::time::Instant {
        let micros = i64::try_from(self.start.elapsed().as_micros()).unwrap_or(i64::MAX);
        smoltcp::time::Instant::from_micros(micros)
    }

    fn poll(&mut self) {
        let now = self.smol_now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
    }

    fn alloc_port(&mut self) -> Option<u16> {
        for _ in EPHEMERAL {
            let port = self.next_port;
            self.next_port = if port == *EPHEMERAL.end() {
                *EPHEMERAL.start()
            } else {
                port + 1
            };
            if self.ports.insert(port) {
                return Some(port);
            }
        }
        None
    }

    fn handle_command(&mut self, cmd: Command) {
        let Command::Connect { target, reply } = cmd;
        if self.conns.len() + self.resolving.len() >= self.limits.max_connections {
            let _ = reply.send(Err(ConnectError::TooManyConnections));
            return;
        }
        let deadline = Instant::now() + self.limits.connect_timeout;
        match target.host {
            Host::Ip(ip) => self.open(ip, target.port, reply, deadline),
            Host::Domain(name) => self.resolve(name, 0, target.port, reply, deadline),
        }
    }

    fn resolve(
        &mut self,
        name: String,
        server: usize,
        port: u16,
        reply: ConnectReply,
        deadline: Instant,
    ) {
        let Some(&handle) = self.dns.get(server) else {
            let err = if server == 0 {
                ConnectError::NoDns
            } else {
                ConnectError::ResolveFailed
            };
            let _ = reply.send(Err(err));
            return;
        };
        let socket = self.sockets.get_mut::<dns::Socket>(handle);
        match socket.start_query(self.iface.context(), &name, DnsQueryType::A) {
            Ok(query) => {
                tracing::debug!(%name, server, "résolution DNS via le tunnel");
                self.resolving.push(Resolving {
                    query,
                    server,
                    name,
                    port,
                    reply,
                    deadline,
                });
            }
            Err(e) => {
                tracing::debug!(%name, error = ?e, "requête DNS impossible");
                let _ = reply.send(Err(ConnectError::ResolveFailed));
            }
        }
    }

    fn open(&mut self, ip: Ipv4Addr, port: u16, reply: ConnectReply, deadline: Instant) {
        let Some(local_port) = self.alloc_port() else {
            let _ = reply.send(Err(ConnectError::TooManyConnections));
            return;
        };
        let size = self.limits.socket_buffer.max(1024);
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; size]),
            tcp::SocketBuffer::new(vec![0u8; size]),
        );
        socket.set_nagle_enabled(false);
        socket.set_timeout(Some(smoltcp::time::Duration::from_micros(
            u64::try_from(self.limits.tcp_timeout.as_micros()).unwrap_or(u64::MAX),
        )));
        socket.set_keep_alive(Some(smoltcp::time::Duration::from_micros(
            u64::try_from(self.limits.keep_alive.as_micros()).unwrap_or(u64::MAX),
        )));
        if let Err(e) = socket.connect(
            self.iface.context(),
            (IpAddress::Ipv4(ip), port),
            (IpAddress::Ipv4(self.local), local_port),
        ) {
            tracing::debug!(%ip, port, error = ?e, "connexion impossible");
            self.ports.remove(&local_port);
            let _ = reply.send(Err(ConnectError::Unaddressable));
            return;
        }
        let handle = self.sockets.add(socket);
        let (client_tx, from_client) = mpsc::channel(CHANNEL_CHUNKS);
        let (to_client, client_rx) = mpsc::channel(CHANNEL_CHUNKS);
        let stream = StackStream {
            tx: client_tx,
            rx: client_rx,
            wake: Arc::clone(&self.wake),
            local: SocketAddrV4::new(self.local, local_port),
        };
        tracing::debug!(%ip, port, local_port, "connexion TCP dans le tunnel");
        self.conns.push(Conn {
            handle,
            port: local_port,
            from_client,
            pending: Bytes::new(),
            client_eof: false,
            to_client: Some(to_client),
            connecting: Some((reply, stream, deadline)),
            dead: false,
        });
    }

    /// Avance les résolutions DNS terminées ou expirées.
    fn service_dns(&mut self) {
        let now = Instant::now();
        let mut i = 0;
        while i < self.resolving.len() {
            let r = &self.resolving[i];
            let socket = self.sockets.get_mut::<dns::Socket>(self.dns[r.server]);
            let outcome = match socket.get_query_result(r.query) {
                Err(GetQueryResultError::Pending) if now >= r.deadline => {
                    socket.cancel_query(r.query);
                    Some(Err(ConnectError::Timeout))
                }
                Err(GetQueryResultError::Pending) => None,
                Err(GetQueryResultError::Failed) => Some(Err(ConnectError::ResolveFailed)),
                Ok(addrs) => Some(
                    addrs
                        .iter()
                        .find_map(|a| match a {
                            IpAddress::Ipv4(ip) => Some(*ip),
                            #[allow(unreachable_patterns)]
                            _ => None,
                        })
                        .ok_or(ConnectError::ResolveFailed),
                ),
            };
            let Some(outcome) = outcome else {
                i += 1;
                continue;
            };
            let r = self.resolving.swap_remove(i);
            match outcome {
                Ok(ip) => {
                    tracing::debug!(name = %r.name, %ip, "nom résolu");
                    self.open(ip, r.port, r.reply, r.deadline);
                }
                Err(ConnectError::ResolveFailed) if r.server + 1 < self.dns.len() => {
                    self.resolve(r.name, r.server + 1, r.port, r.reply, r.deadline);
                }
                Err(e) => {
                    tracing::debug!(name = %r.name, error = %e, "résolution échouée");
                    let _ = r.reply.send(Err(e));
                }
            }
        }
    }

    /// Fait avancer toutes les connexions ; retire celles qui sont terminées.
    fn service_conns(&mut self) {
        let now = Instant::now();
        let mut i = 0;
        while i < self.conns.len() {
            let keep = service_conn(&mut self.conns[i], &mut self.sockets, now);
            if keep {
                i += 1;
            } else {
                let conn = self.conns.swap_remove(i);
                self.sockets.remove(conn.handle);
                self.ports.remove(&conn.port);
            }
        }
    }

    /// Prochaine échéance de délai de connexion ou de résolution.
    fn next_deadline(&self) -> Option<Instant> {
        self.conns
            .iter()
            .filter_map(|c| c.connecting.as_ref().map(|(_, _, d)| *d))
            .chain(self.resolving.iter().map(|r| r.deadline))
            .min()
    }
}

/// Fait avancer une connexion ; `false` quand elle doit être retirée.
fn service_conn(conn: &mut Conn, sockets: &mut SocketSet<'_>, now: Instant) -> bool {
    if conn.dead {
        return false;
    }
    let socket = sockets.get_mut::<tcp::Socket>(conn.handle);

    if let Some((_, _, deadline)) = &conn.connecting {
        let deadline = *deadline;
        match socket.state() {
            tcp::State::SynSent | tcp::State::SynReceived => {
                if now >= deadline {
                    socket.abort();
                    fail_connect(conn, ConnectError::Timeout);
                }
                return true;
            }
            tcp::State::Closed | tcp::State::TimeWait => {
                fail_connect(conn, ConnectError::Refused);
                return false;
            }
            _ => {
                let Some((reply, stream, _)) = conn.connecting.take() else {
                    return true;
                };
                if reply.send(Ok(stream)).is_err() {
                    // Client parti entre-temps.
                    socket.abort();
                    conn.dead = true;
                    return true;
                }
            }
        }
    }

    // Client → tunnel.
    loop {
        if conn.pending.is_empty() {
            if conn.client_eof {
                break;
            }
            match conn.from_client.try_recv() {
                Ok(chunk) => conn.pending = chunk,
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    conn.client_eof = true;
                    socket.close();
                    break;
                }
            }
        }
        if !socket.can_send() {
            if !socket.may_send() {
                // Le pair a coupé l'émission de notre côté : données perdues.
                conn.pending = Bytes::new();
            }
            break;
        }
        match socket.send_slice(&conn.pending) {
            Ok(n) if n > 0 => conn.pending.advance(n),
            _ => break,
        }
    }

    // Tunnel → client.
    if let Some(to_client) = &conn.to_client {
        while socket.can_recv() {
            match to_client.try_reserve() {
                Ok(permit) => {
                    let chunk = socket.recv(|buf| {
                        let n = buf.len().min(CHUNK);
                        (n, Bytes::copy_from_slice(&buf[..n]))
                    });
                    match chunk {
                        Ok(chunk) if !chunk.is_empty() => permit.send(chunk),
                        _ => break,
                    }
                }
                Err(mpsc::error::TrySendError::Full(())) => break,
                Err(mpsc::error::TrySendError::Closed(())) => {
                    // Le client a abandonné la connexion.
                    socket.abort();
                    conn.dead = true;
                    return true;
                }
            }
        }
        if !socket.may_recv() {
            // Fin de flux distante (FIN ou RST) : le client voit la fin du flux.
            conn.to_client = None;
        }
    }

    match socket.state() {
        tcp::State::Closed => false,
        // Fermeture active terminée et tout a été remis au client.
        tcp::State::TimeWait => conn.to_client.is_none(),
        _ => true,
    }
}

fn fail_connect(conn: &mut Conn, error: ConnectError) {
    if let Some((reply, _, _)) = conn.connecting.take() {
        let _ = reply.send(Err(error));
    }
    conn.dead = true;
}

/// Boucle de la pile.
async fn run(
    mut stack: Stack,
    tunnel_tx: PacketSender,
    mut tunnel_rx: PacketReceiver,
    mut cmd_rx: mpsc::Receiver<Command>,
) {
    let wake = Arc::clone(&stack.wake);
    let mut commands_open = true;
    loop {
        stack.poll();
        stack.service_dns();
        stack.service_conns();
        // Émet ce que les clients viennent de fournir.
        stack.poll();

        // Vers le tunnel, sans attendre.
        loop {
            match tunnel_tx.try_reserve() {
                Ok(Some(permit)) => match stack.device.tx.pop_front() {
                    Some(packet) => permit.send(packet),
                    None => break,
                },
                Ok(None) => break,
                Err(_) => return,
            }
        }
        let tx_full = stack.device.tx.len() >= TX_QUEUE;
        let now = stack.smol_now();
        let mut delay = stack
            .iface
            .poll_delay(now, &stack.sockets)
            .map_or(IDLE_WAIT, to_std);
        if let Some(deadline) = stack.next_deadline() {
            delay = delay.min(deadline.saturating_duration_since(Instant::now()));
        }
        if tx_full {
            // La pile attend de la place : seul le tunnel peut la libérer.
            delay = IDLE_WAIT;
        }

        tokio::select! {
            biased;
            permit = tunnel_tx.reserve(), if !stack.device.tx.is_empty() => {
                let Ok(permit) = permit else { break };
                if let Some(packet) = stack.device.tx.pop_front() {
                    permit.send(packet);
                }
            }
            packet = tunnel_rx.recv() => {
                let Some(packet) = packet else {
                    tracing::debug!("pile proxy : canal du tunnel fermé");
                    break;
                };
                stack.device.rx.push_back(packet);
                while stack.device.rx.len() < RX_BATCH {
                    match tunnel_rx.try_recv() {
                        Ok(Some(p)) => stack.device.rx.push_back(p),
                        Ok(None) | Err(_) => break,
                    }
                }
            }
            cmd = cmd_rx.recv(), if commands_open => match cmd {
                Some(cmd) => {
                    stack.handle_command(cmd);
                    while let Ok(cmd) = cmd_rx.try_recv() {
                        stack.handle_command(cmd);
                    }
                }
                None => commands_open = false,
            },
            () = wake.notified() => {}
            () = tokio::time::sleep(delay) => {}
        }
    }
}
