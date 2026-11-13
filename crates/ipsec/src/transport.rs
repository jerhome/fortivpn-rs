//! [`IpsecTransport`] : implémentation tokio/UDP du trait [`Transport`] de core (story 6.T).
//!
//! - Résolution de la passerelle (IPv4 d'abord ; seul IPv4 est pris en charge), un socket
//!   UDP unique à port local éphémère. IKE_SA_INIT part vers `gw:500`, la suite vers
//!   `gw:4500` (NAT-T forcé, cf. `docs/protocol-ipsec.md` §2.2).
//! - [`IkeInitiator`] (sans-io) est piloté ici : datagrammes, échéances
//!   (`next_deadline` / `handle_timeout`), entropie du CSPRNG système.
//! - Une fois `Established`, une tâche relaie le [`PacketChannel`] de la session vers
//!   l'ESP/UDP et inversement : keepalive NAT-T, `note_inbound_traffic`, application de
//!   `ChildRekeyed` / `OldChildExpired`, publication de la fin de session.
//!
//! Aucun secret (PSK, mot de passe, clés) n'est journalisé.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use fortivpn_core::config::{DnsConfig, Ipv4Config, RoutingMode};
use fortivpn_core::transport::{
    ConnectStep, Credentials, ProgressSink, Transport, TransportSession, session_end,
};
use fortivpn_core::tunnel::TunnelError;
use fortivpn_core::{PacketChannel, PacketReceiver, PacketSender, TransportError, TunnelConfig};
use ipnet::{IpNet, Ipv4Net, Ipv4Subnets};
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::SecretString;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::crypto::DhGroup;
use crate::crypto::IkeSuite;
use crate::esp::{self, Datagram, EspTunnel, Inbound};
use crate::ike::{
    self, ChildSaKeys, CloseReason, EspProposal, Event, FailReason, IKE_PORT, IkeConfig,
    IkeInitiator, Lifetimes, NATT_PORT, Output, ResponderAuth,
};

/// MTU de l'interface TUN (`docs/protocol-ipsec.md` §4 : 1400 recommandé).
pub const DEFAULT_MTU: u16 = 1400;
/// Capacité de chaque sens du canal de paquets remis à la session.
const CHANNEL_CAPACITY: usize = 256;
/// Taille du tampon de réception UDP.
const RECV_BUF: usize = 65_536;

/// Options de [`IpsecTransport`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IpsecOptions {
    /// Nom d'hôte ou adresse de la passerelle.
    pub host: String,
    /// Port IKE (500 ; configurable pour les tests).
    pub ike_port: u16,
    /// Port NAT-T (4500 ; configurable pour les tests).
    pub natt_port: u16,
    /// Clé pré-partagée de la passerelle.
    pub psk: SecretString,
    /// IDi (type, données) ; défaut : ID_FQDN `fortivpn-client`.
    pub idi: Option<(u8, Vec<u8>)>,
    /// IDr imposé (type, données) ; défaut : n'importe lequel. Recommandé, vérifié s'il est
    /// fourni.
    pub expected_idr: Option<(u8, Vec<u8>)>,
    /// Authentification exigée de la passerelle (défaut : PSK). Recommandé :
    /// [`ResponderAuth::CertPinned`] avec l'empreinte SHA-256 du certificat de la passerelle
    /// (cf. `docs/security/review-6.5-ipsec.md`, M1).
    pub responder_auth: ResponderAuth,
    /// Propositions IKE (défaut : `docs/protocol-ipsec.md` §2.3).
    pub ike_suites: Option<Vec<IkeSuite>>,
    /// Groupes DH (défaut : MODP-2048 puis ECP-256).
    pub dh_groups: Option<Vec<DhGroup>>,
    /// Propositions ESP (défaut : §2.3).
    pub esp_proposals: Option<Vec<EspProposal>>,
    /// Délai de base de retransmission IKE.
    pub retransmit_base: Option<Duration>,
    /// Nombre total d'envois d'une requête IKE avant abandon.
    pub max_sends: Option<u8>,
    /// Durées de vie des SA.
    pub lifetimes: Option<Lifetimes>,
    /// Silence entrant avant émission d'un DPD.
    pub dpd_idle: Option<Duration>,
    /// Durée maximale de la négociation (IKE_SA_INIT + IKE_AUTH).
    pub connect_timeout: Duration,
    /// Période de keepalive NAT-T (inactivité sortante).
    pub keepalive: Duration,
    /// MTU de l'interface TUN.
    pub mtu: u16,
    /// Attente maximale de l'arrêt de la tâche de relais dans `disconnect`.
    pub disconnect_grace: Duration,
}

impl IpsecOptions {
    /// Options par défaut vers `host` avec la PSK donnée.
    pub fn new(host: impl Into<String>, psk: impl Into<SecretString>) -> Self {
        Self {
            host: host.into(),
            ike_port: IKE_PORT,
            natt_port: NATT_PORT,
            psk: psk.into(),
            idi: None,
            expected_idr: None,
            responder_auth: ResponderAuth::Psk,
            ike_suites: None,
            dh_groups: None,
            esp_proposals: None,
            retransmit_base: None,
            max_sends: None,
            lifetimes: None,
            dpd_idle: None,
            connect_timeout: Duration::from_secs(60),
            keepalive: Duration::from_secs(20),
            mtu: DEFAULT_MTU,
            disconnect_grace: Duration::from_secs(3),
        }
    }

    fn ike_config(&self, gw: Ipv4Addr, local_port: u16, creds: &Credentials) -> IkeConfig {
        let mut c = IkeConfig::new(
            gw.octets(),
            [0; 4],
            local_port,
            self.psk.clone(),
            creds.username.clone(),
            creds.password.clone(),
        );
        if let Some(v) = &self.idi {
            c.idi.clone_from(v);
        }
        c.expected_idr.clone_from(&self.expected_idr);
        c.responder_auth.clone_from(&self.responder_auth);
        if let Some(v) = &self.ike_suites {
            c.ike_suites.clone_from(v);
        }
        if let Some(v) = &self.dh_groups {
            c.dh_groups.clone_from(v);
        }
        if let Some(v) = &self.esp_proposals {
            c.esp_proposals.clone_from(v);
        }
        if let Some(v) = self.retransmit_base {
            c.retransmit_base = v;
        }
        if let Some(v) = self.max_sends {
            c.max_sends = v;
        }
        if let Some(v) = self.lifetimes {
            c.lifetimes = v;
        }
        if let Some(v) = self.dpd_idle {
            c.dpd_idle = v;
        }
        c
    }
}

/// Tâche de relais en cours.
#[derive(Debug)]
struct Active {
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

/// Transport IPsec (IKEv2 + ESP en espace utilisateur) : cf. documentation du module.
#[derive(Debug)]
pub struct IpsecTransport {
    options: IpsecOptions,
    progress: Option<ProgressSink>,
    active: Option<Active>,
}

impl IpsecTransport {
    /// Crée le transport (aucune I/O avant [`Transport::connect`]).
    pub fn new(options: IpsecOptions) -> Self {
        Self {
            options,
            progress: None,
            active: None,
        }
    }

    fn report(&self, step: ConnectStep) {
        if let Some(p) = &self.progress {
            p.report(step);
        }
    }
}

impl Transport for IpsecTransport {
    async fn connect(
        &mut self,
        credentials: &Credentials,
    ) -> Result<TransportSession, TransportError> {
        if let Some(a) = &self.active {
            if a.task.is_finished() {
                self.active = None;
            } else {
                return Err(TransportError::AlreadyConnected);
            }
        }
        let gw = resolve(&self.options.host, self.options.ike_port).await?;
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        let local_port = sock.local_addr()?.port();

        let rng_failed = Arc::new(AtomicBool::new(false));
        let cfg = self.options.ike_config(gw, local_port, credentials);
        let mut ini = IkeInitiator::new(cfg, entropy(&rng_failed))
            .map_err(|e| TransportError::Protocol(e.to_string()))?;
        let mut link = Link {
            sock,
            gw,
            ike_port: self.options.ike_port,
            natt_port: self.options.natt_port,
            last_tx: Instant::now(),
            rng_failed,
        };
        info!(gateway = %gw, "négociation IKEv2");
        let est =
            tokio::time::timeout(self.options.connect_timeout, handshake(&mut link, &mut ini))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "négociation IKE trop longue")
                })??;
        self.report(ConnectStep::Authenticated);

        let config = to_core_config(&est.0, gw, self.options.mtu)?;
        config.validate()?;
        let tunnel = EspTunnel::new(&est.1, false)
            .map_err(|e| TransportError::Protocol(format!("CHILD SA invalide : {e}")))?;
        self.report(ConnectStep::ConfigReceived);

        let (session_side, relay_side) = PacketChannel::pair(CHANNEL_CAPACITY);
        let (to_session, from_session) = relay_side.split();
        let (notifier, end) = session_end();
        let (stop_tx, stop_rx) = oneshot::channel();
        let relay = Relay {
            link,
            ini,
            esp: tunnel,
            aead: est.1.encr.is_aead(),
            to_session,
            from_session,
            stop: stop_rx,
            keepalive: self.options.keepalive,
            rng: SystemRandom::new(),
        };
        let task = tokio::spawn(async move {
            let result = relay.run().await;
            if let Err(e) = &result {
                info!(error = %e, "tunnel IPsec terminé");
            }
            // Raison publiée avant la fermeture du canal (libéré en fin de `run`).
            notifier.finish(result);
        });
        self.active = Some(Active {
            stop: Some(stop_tx),
            task,
        });
        Ok(TransportSession {
            config,
            packets: session_side,
            end,
        })
    }

    async fn disconnect(&mut self) -> Result<(), TransportError> {
        let Some(mut a) = self.active.take() else {
            return Ok(());
        };
        if let Some(stop) = a.stop.take() {
            // Le récepteur peut déjà avoir disparu (tâche terminée).
            let _ = stop.send(());
        }
        if tokio::time::timeout(self.options.disconnect_grace, &mut a.task)
            .await
            .is_err()
        {
            warn!("arrêt de la tâche IPsec trop long : abandon");
            a.task.abort();
        }
        Ok(())
    }

    fn set_progress(&mut self, sink: ProgressSink) {
        self.progress = Some(sink);
    }
}

// ---------------------------------------------------------------------------
// Socket, entropie, démultiplexage
// ---------------------------------------------------------------------------

/// Résout `host` (IPv4 uniquement ; IPv4 préféré à toute autre famille).
async fn resolve(host: &str, port: u16) -> Result<Ipv4Addr, TransportError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    addrs
        .iter()
        .find_map(|a| match a.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| {
            TransportError::Protocol(format!("aucune adresse IPv4 pour la passerelle « {host} »"))
        })
}

/// Entropie CSPRNG système ; un échec (improbable) est signalé via `failed`, vérifié par
/// l'appelant (on ne peut pas retourner d'erreur depuis `Entropy::fill`).
fn entropy(failed: &Arc<AtomicBool>) -> Box<dyn ike::Entropy + Send> {
    let rng = SystemRandom::new();
    let failed = Arc::clone(failed);
    Box::new(move |out: &mut [u8]| {
        if rng.fill(out).is_err() {
            failed.store(true, Ordering::SeqCst);
        }
    })
}

/// Charge UDP reçue, classée.
enum Demux<'a> {
    Ike(&'a [u8]),
    Esp(&'a [u8]),
    Ignore,
}

struct Link {
    sock: UdpSocket,
    gw: Ipv4Addr,
    ike_port: u16,
    natt_port: u16,
    last_tx: Instant,
    rng_failed: Arc<AtomicBool>,
}

impl Link {
    fn wire_port(&self, port: u16) -> u16 {
        match port {
            IKE_PORT => self.ike_port,
            NATT_PORT => self.natt_port,
            p => p,
        }
    }

    async fn send(&mut self, port: u16, data: &[u8]) {
        let to = SocketAddr::new(IpAddr::V4(self.gw), port);
        self.last_tx = Instant::now();
        if let Err(e) = self.sock.send_to(data, to).await {
            // Perte de paquet : retransmission IKE / DPD s'en chargent.
            debug!(error = %e, "échec d'envoi UDP");
        }
    }

    /// Envoie les datagrammes et retourne les événements.
    async fn dispatch(&mut self, outs: Vec<Output>) -> Result<Vec<Event>, TransportError> {
        if self.rng_failed.load(Ordering::SeqCst) {
            return Err(io::Error::other("CSPRNG système indisponible").into());
        }
        let mut events = Vec::new();
        for o in outs {
            match o {
                Output::Send { port, data } => {
                    let port = self.wire_port(port);
                    self.send(port, &data).await;
                }
                Output::Event(e) => events.push(e),
            }
        }
        Ok(events)
    }

    /// Classe une charge reçue ; ignore les expéditeurs inattendus.
    fn demux<'a>(&self, from: SocketAddr, data: &'a [u8]) -> Demux<'a> {
        if from.ip() != IpAddr::V4(self.gw) {
            return Demux::Ignore;
        }
        if from.port() == self.ike_port && self.ike_port != self.natt_port {
            return Demux::Ike(data);
        }
        if from.port() != self.natt_port {
            return Demux::Ignore;
        }
        match esp::classify(data) {
            Ok(Datagram::Ike(m)) => Demux::Ike(m),
            Ok(Datagram::Esp(m)) => Demux::Esp(m),
            Ok(Datagram::Keepalive) | Err(_) => Demux::Ignore,
        }
    }
}

/// Erreur de `recv_from` ignorable (Windows : ICMP port unreachable → `ConnectionReset`).
fn recv_ignorable(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused
    )
}

fn sleep_until_std(at: Instant) -> tokio::time::Sleep {
    tokio::time::sleep_until(tokio::time::Instant::from_std(at))
}

// ---------------------------------------------------------------------------
// Négociation
// ---------------------------------------------------------------------------

type Established = (Box<ike::TunnelConfig>, Box<ChildSaKeys>);

fn fail_to_error(r: &FailReason) -> TransportError {
    match r {
        FailReason::CredentialsRejected | FailReason::PeerNotify(24) => TransportError::AuthFailed,
        FailReason::Timeout => io::Error::new(io::ErrorKind::TimedOut, r.to_string()).into(),
        FailReason::DeadPeer => TunnelError::DeadPeer.into(),
        FailReason::Expired => io::Error::other(r.to_string()).into(),
        _ => TransportError::Protocol(r.to_string()),
    }
}

async fn handshake(link: &mut Link, ini: &mut IkeInitiator) -> Result<Established, TransportError> {
    let mut buf = vec![0u8; RECV_BUF];
    let mut outs = ini.start(Instant::now());
    loop {
        for ev in link.dispatch(outs).await? {
            match ev {
                Event::Established {
                    config,
                    child_sa_keys,
                } => return Ok((config, child_sa_keys)),
                Event::Failed(r) => return Err(fail_to_error(&r)),
                Event::Closed(_) => return Err(TransportError::Closed),
                Event::ChildRekeyed { .. } | Event::OldChildExpired { .. } => {}
            }
        }
        if ini.is_finished() {
            return Err(TransportError::Closed);
        }
        let deadline = ini
            .next_deadline()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(1));
        tokio::select! {
            r = link.sock.recv_from(&mut buf) => {
                outs = match r {
                    Ok((n, from)) => match link.demux(from, &buf[..n]) {
                        Demux::Ike(m) => ini.handle_datagram(Instant::now(), m),
                        Demux::Esp(_) | Demux::Ignore => Vec::new(),
                    },
                    Err(e) if recv_ignorable(&e) => Vec::new(),
                    Err(e) => return Err(e.into()),
                };
            }
            () = sleep_until_std(deadline) => {
                outs = ini.handle_timeout(Instant::now());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Conversion de configuration
// ---------------------------------------------------------------------------

fn mask_prefix(mask: [u8; 4]) -> Option<u8> {
    let m = u32::from_be_bytes(mask);
    let ones = m.leading_ones();
    let contiguous = if ones == 32 { true } else { m << ones == 0 };
    contiguous.then(|| u8::try_from(ones).unwrap_or(32))
}

/// Convertit la configuration négociée en [`TunnelConfig`] de core.
///
/// Routes : sous-réseaux `INTERNAL_IP4_SUBNET` s'il y en a ; sinon le TSr accepté (tout
/// 0.0.0.0/0 → full-tunnel, la route de la passerelle étant gérée par le backend).
fn to_core_config(
    c: &ike::TunnelConfig,
    gateway: Ipv4Addr,
    mtu: u16,
) -> Result<TunnelConfig, TransportError> {
    let proto = |m: &str| TransportError::Protocol(m.to_owned());
    let prefix = match c.netmask {
        Some(m) => mask_prefix(m).ok_or_else(|| proto("masque réseau non contigu"))?,
        None => 32,
    };
    let address =
        Ipv4Net::new(Ipv4Addr::from(c.ip), prefix).map_err(|_| proto("préfixe invalide"))?;

    let mut include = Vec::new();
    for (net, mask) in &c.subnets {
        let p = mask_prefix(*mask).ok_or_else(|| proto("masque de sous-réseau non contigu"))?;
        let n = Ipv4Net::new(Ipv4Addr::from(*net), p).map_err(|_| proto("sous-réseau invalide"))?;
        include.push(IpNet::V4(n.trunc()));
    }
    let routing = if include.is_empty() {
        let full = c
            .ts_remote
            .iter()
            .any(|t| t.start == [0; 4] && t.end == [255; 4]);
        if full {
            RoutingMode::Full { exclude: vec![] }
        } else {
            for t in &c.ts_remote {
                include.extend(
                    Ipv4Subnets::new(Ipv4Addr::from(t.start), Ipv4Addr::from(t.end), 0)
                        .map(IpNet::V4),
                );
            }
            if include.is_empty() {
                return Err(proto("aucune route fournie par la passerelle"));
            }
            RoutingMode::Split { include }
        }
    } else {
        RoutingMode::Split { include }
    };

    Ok(TunnelConfig {
        ipv4: Ipv4Config {
            address,
            peer: None,
        },
        ipv6: None,
        mtu,
        dns: DnsConfig {
            servers: c
                .dns
                .iter()
                .map(|d| IpAddr::V4(Ipv4Addr::from(*d)))
                .collect(),
            search_domains: c.dns_domains.clone(),
        },
        routing,
        gateway: IpAddr::V4(gateway),
    })
}

// ---------------------------------------------------------------------------
// Relais
// ---------------------------------------------------------------------------

struct Relay {
    link: Link,
    ini: IkeInitiator,
    esp: EspTunnel,
    aead: bool,
    to_session: PacketSender,
    from_session: PacketReceiver,
    stop: oneshot::Receiver<()>,
    keepalive: Duration,
    rng: SystemRandom,
}

impl Relay {
    /// Boucle de relais ; retourne la raison de fin (publiée par l'appelant).
    async fn run(mut self) -> Result<(), TransportError> {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            let ka_at = self.link.last_tx + self.keepalive;
            let deadline = self.ini.next_deadline().map_or(ka_at, |d| d.min(ka_at));
            tokio::select! {
                _ = &mut self.stop => return self.close().await,
                r = self.link.sock.recv_from(&mut buf) => match r {
                    Ok((n, from)) => {
                        let outs = match self.link.demux(from, &buf[..n]) {
                            Demux::Ike(m) => self.ini.handle_datagram(Instant::now(), m),
                            Demux::Esp(m) => {
                                self.inbound_esp(m);
                                Vec::new()
                            }
                            Demux::Ignore => Vec::new(),
                        };
                        self.process(outs).await?;
                    }
                    Err(e) if recv_ignorable(&e) => {}
                    Err(e) => return Err(e.into()),
                },
                p = self.from_session.recv() => match p {
                    Some(p) => self.outbound(&p).await,
                    None => return self.close().await,
                },
                () = sleep_until_std(deadline) => {
                    let outs = self.ini.handle_timeout(Instant::now());
                    self.process(outs).await?;
                    if Instant::now() >= self.link.last_tx + self.keepalive {
                        let port = self.link.natt_port;
                        self.link.send(port, &esp::KEEPALIVE).await;
                    }
                }
            }
        }
    }

    /// Fermeture locale : Delete(IKE) émis une fois, sans attente de réponse.
    async fn close(&mut self) -> Result<(), TransportError> {
        let outs = self.ini.close();
        self.link.dispatch(outs).await?;
        Ok(())
    }

    /// Émet les datagrammes et applique les événements ; `Err`/`Ok` = fin de session.
    async fn process(&mut self, outs: Vec<Output>) -> Result<(), TransportError> {
        for ev in self.link.dispatch(outs).await? {
            match ev {
                Event::ChildRekeyed { keys, old_spi } => {
                    self.esp.rekey(&keys).map_err(|e| {
                        TransportError::Protocol(format!("rekey CHILD SA invalide : {e}"))
                    })?;
                    self.aead = keys.encr.is_aead();
                    debug!(old_spi, "CHILD SA renouvelée");
                }
                Event::OldChildExpired { spi } => self.esp.drop_old(spi),
                Event::Closed(CloseReason::PeerDeletedIke | CloseReason::PeerDeletedChild) => {
                    return Err(TunnelError::ClosedByPeer.into());
                }
                Event::Failed(r) => return Err(fail_to_error(&r)),
                Event::Closed(CloseReason::Local) | Event::Established { .. } => {}
            }
        }
        Ok(())
    }

    /// ESP entrant : décapsule, repousse le DPD, remet le paquet à la session.
    fn inbound_esp(&mut self, data: &[u8]) {
        match self.esp.open(data) {
            Ok(inb) => {
                self.ini.note_inbound_traffic(Instant::now());
                if let Inbound::Packet(p) = inb {
                    match self.to_session.try_reserve() {
                        Ok(Some(permit)) => permit.send(Bytes::from(p)),
                        Ok(None) => debug!("canal de paquets plein : paquet abandonné"),
                        Err(_) => {} // session libérée : détecté côté `from_session`
                    }
                }
            }
            Err(e) => debug!(error = %e, "paquet ESP rejeté"),
        }
    }

    /// Paquet IP de la session vers l'ESP.
    async fn outbound(&mut self, packet: &[u8]) {
        if packet.first().is_none_or(|b| b >> 4 != 4) {
            debug!("paquet non IPv4 abandonné");
            return;
        }
        let mut iv = [0u8; 16];
        let iv_ref = if self.aead {
            None
        } else if self.rng.fill(&mut iv).is_ok() {
            Some(&iv)
        } else {
            return;
        };
        match self.esp.seal(packet, iv_ref) {
            Ok(d) => {
                let port = self.link.natt_port;
                self.link.send(port, &d).await;
            }
            Err(e) => debug!(error = %e, "encapsulation ESP impossible"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::TrafficSelector;
    use secrecy::ExposeSecret;

    fn base() -> ike::TunnelConfig {
        ike::TunnelConfig {
            ip: [10, 10, 2, 7],
            netmask: Some([255; 4]),
            dns: vec![[10, 20, 0, 53]],
            subnets: vec![([10, 20, 0, 0], [255, 255, 255, 0])],
            dns_domains: vec!["corp.example.test".into()],
            ts_local: vec![],
            ts_remote: vec![TrafficSelector::any()],
        }
    }

    #[test]
    fn maps_split_config() {
        let gw = Ipv4Addr::new(198, 51, 100, 1);
        let c = to_core_config(&base(), gw, 1400).unwrap();
        assert_eq!(c.ipv4.address.to_string(), "10.10.2.7/32");
        assert_eq!(c.gateway, IpAddr::V4(gw));
        assert_eq!(c.mtu, 1400);
        assert_eq!(
            c.dns.servers,
            vec![IpAddr::V4(Ipv4Addr::new(10, 20, 0, 53))]
        );
        assert_eq!(c.dns.search_domains, vec!["corp.example.test".to_owned()]);
        let RoutingMode::Split { include } = &c.routing else {
            panic!("split attendu");
        };
        assert_eq!(include, &["10.20.0.0/24".parse::<IpNet>().unwrap()]);
        c.validate().unwrap();
    }

    #[test]
    fn falls_back_to_ts_then_full_tunnel() {
        let gw = Ipv4Addr::new(198, 51, 100, 1);
        let mut b = base();
        b.subnets.clear();
        assert!(matches!(
            to_core_config(&b, gw, 1400).unwrap().routing,
            RoutingMode::Full { .. }
        ));
        let mut ts = TrafficSelector::any();
        ts.start = [10, 0, 0, 0];
        ts.end = [10, 0, 255, 255];
        b.ts_remote = vec![ts];
        let RoutingMode::Split { include } = to_core_config(&b, gw, 1400).unwrap().routing else {
            panic!("split attendu");
        };
        assert_eq!(include, vec!["10.0.0.0/16".parse::<IpNet>().unwrap()]);
        b.ts_remote.clear();
        assert!(to_core_config(&b, gw, 1400).is_err());
    }

    #[test]
    fn rejects_non_contiguous_mask() {
        assert_eq!(mask_prefix([255, 255, 255, 0]), Some(24));
        assert_eq!(mask_prefix([0; 4]), Some(0));
        assert_eq!(mask_prefix([255, 0, 255, 0]), None);
    }

    #[test]
    fn failure_mapping() {
        assert!(matches!(
            fail_to_error(&FailReason::CredentialsRejected),
            TransportError::AuthFailed
        ));
        assert!(fail_to_error(&FailReason::Timeout).is_transient());
        assert!(fail_to_error(&FailReason::DeadPeer).is_transient());
        assert!(!fail_to_error(&FailReason::GatewayAuthFailed).is_transient());
    }

    #[test]
    fn options_debug_hides_psk() {
        let o = IpsecOptions::new("gw.example.test", "psk-ultra-secrete");
        assert!(!format!("{o:?}").contains("psk-ultra-secrete"));
        let _ = o.psk.expose_secret();
    }
}
