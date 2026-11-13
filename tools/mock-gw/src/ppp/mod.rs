//! Pair PPP côté passerelle (docs/protocol.md §7, §9) : framing `0x5050`, LCP, IPCP,
//! écho ICMP, et pannes injectables ([`PppFault`]).
//!
//! C'est un automate **indépendant** de `proto::ppp::PppSession` (l'automate client) : seuls
//! les types paquets/options et le framing de `proto` sont réutilisés, ce qui fait des tests
//! client ↔ [`PppPeer`] un vrai test d'interopérabilité.
//!
//! Comportement nominal (configuration par défaut = vecteurs `lcp.hex` / `ipcp.hex`) :
//! - à l'ouverture du tunnel, émet son LCP Configure-Request (MRU 1354, magic
//!   `0x5e6f7081`), retransmis toutes les [`PppPeerConfig::restart_interval`] ;
//! - Configure-Request LCP du client : Ack (MRU, magic), Nak (magic en boucle), Reject
//!   (ACCM, PFC, ACFC, authentification, inconnues) ;
//! - LCP ouvert : IPCP Configure-Request (variante A avec adresse ou variante B vide,
//!   [`GatewayIpcpRequest`]) et, en option, IPV6CP (que le client doit rejeter) ;
//! - IPCP du client : Nak de `0.0.0.0` avec `assigned_addr` et les DNS 129/131 du
//!   [`crate::TunnelConfig`], Reject des options inconnues (VJ, NBNS) ou d'un DNS absent de
//!   la configuration, puis Ack ;
//! - IPCP ouvert : événement exposé par [`PppObserver`] (et `tracing::info!`) ;
//! - Echo-Request → Echo-Reply ; Terminate-Request → Terminate-Ack puis `close_notify` ;
//!   protocole inconnu → Protocol-Reject ; code LCP inconnu → Code-Reject ;
//! - IPv4 : ICMP Echo Request vers [`PppPeerConfig::icmp_target`] → Echo Reply.

mod machine;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::BytesMut;
use proto::frame::FrameError;
use proto::ppp::Protocol;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::Instant;

use crate::config::Ipv4Config;
use crate::tunnel::{TunnelContext, TunnelFuture, TunnelHandler, TunnelStream};

use machine::{CloseMode, Machine};

/// Magic-Number LCP par défaut de la passerelle (`lcp.hex:lcp_confreq_gateway`).
pub const DEFAULT_GATEWAY_MAGIC: u32 = 0x5e6f_7081;
/// Adresse PPP par défaut annoncée dans l'IPCP Configure-Request (`ipcp_confreq_gateway`).
pub const DEFAULT_GATEWAY_PPP_ADDR: Ipv4Addr = Ipv4Addr::new(169, 254, 1, 1);
/// Premier identifiant IP des réponses ICMP (`ip.hex:ipv4_icmp_echo_reply`).
pub const DEFAULT_REPLY_IP_ID: u16 = 0xabcd;

/// Forme de l'IPCP Configure-Request émis par la passerelle (§9.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayIpcpRequest {
    /// Variante A : option IP-Address avec l'adresse PPP de la passerelle.
    Address(Ipv4Addr),
    /// Variante B : aucune option (longueur 4).
    Empty,
}

impl Default for GatewayIpcpRequest {
    fn default() -> Self {
        Self::Address(DEFAULT_GATEWAY_PPP_ADDR)
    }
}

/// Moment de déclenchement d'une panne.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultTrigger {
    /// Dès l'ouverture du tunnel, avant toute trame PPP.
    Start,
    /// À l'ouverture de LCP.
    LcpUp,
    /// À l'ouverture d'IPCP.
    IpcpUp,
    /// Ce délai après l'ouverture d'IPCP.
    AfterIpcpUp(Duration),
}

/// Trame `0x5050` invalide émise par [`PppFault::MalformedFrame`] (vecteurs
/// `framing.hex:err_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedFrame {
    /// `err_bad_magic` : magic `50 51`.
    BadMagic,
    /// `err_inconsistent_lengths` : `total_len` 23 ≠ 6 + 16.
    InconsistentLengths,
    /// `err_total_too_small` : `total_len` 6 < 7.
    TotalTooSmall,
}

impl MalformedFrame {
    /// Octets exacts émis sur le flux TLS.
    pub fn bytes(self) -> &'static [u8] {
        match self {
            Self::BadMagic => &[
                0x00, 0x16, 0x50, 0x51, 0x00, 0x10, 0xc0, 0x21, 0x01, 0x01, 0x00, 0x0e, 0x01, 0x04,
                0x05, 0x4a, 0x05, 0x06, 0x5e, 0x6f, 0x70, 0x81,
            ],
            Self::InconsistentLengths => &[
                0x00, 0x17, 0x50, 0x50, 0x00, 0x10, 0xc0, 0x21, 0x01, 0x01, 0x00, 0x0e, 0x01, 0x04,
                0x05, 0x4a, 0x05, 0x06, 0x5e, 0x6f, 0x70, 0x81, 0x00,
            ],
            Self::TotalTooSmall => &[0x00, 0x06, 0x50, 0x50, 0x00, 0x00],
        }
    }
}

/// Panne injectée par le pair PPP.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum PppFault {
    /// Comportement nominal.
    #[default]
    None,
    /// Les LCP Echo-Request du client restent sans réponse et la passerelle n'émet plus
    /// d'Echo-Request (test `DeadPeer`). Le reste (ICMP, terminaison) fonctionne.
    IgnoreEchoRequests,
    /// Émet une trame `0x5050` invalide au moment `when`, puis continue de lire jusqu'à ce
    /// que le client ferme.
    MalformedFrame {
        kind: MalformedFrame,
        when: FaultTrigger,
    },
    /// La passerelle envoie un LCP Terminate-Request au moment `when`, attend le
    /// Terminate-Ack au plus [`PppPeerConfig::terminate_timeout`], puis `close_notify`.
    GatewayTerminate { when: FaultTrigger },
    /// Coupure de la connexion au moment `when` **sans** `close_notify` ni trame PPP.
    AbortTls { when: FaultTrigger },
    /// Répond `HTTP/1.1 <status>` au lieu de basculer en PPP (vecteur
    /// `framing.hex:err_http_instead_of_ppp` pour 403), puis ferme proprement.
    HttpInsteadOfPpp { status: u16 },
    /// IPCP ne converge jamais : chaque Configure-Request IPCP du client reçoit un Nak
    /// proposant une adresse différente de celle demandée.
    IpcpNeverConverges,
}

/// Configuration du pair PPP. Défauts = vecteurs `lcp.hex`, `ipcp.hex`, `ip.hex`.
#[derive(Debug, Clone)]
pub struct PppPeerConfig {
    /// Magic-Number LCP (défaut [`DEFAULT_GATEWAY_MAGIC`]).
    pub magic: u32,
    /// MRU annoncé (défaut 1354) ; `None` : option absente.
    pub mru: Option<u16>,
    /// IPCP Configure-Request de la passerelle (défaut : variante A, 169.254.1.1).
    pub ipcp_request: GatewayIpcpRequest,
    /// Seule destination dont les ICMP Echo Request reçoivent une réponse ; `None` :
    /// toutes les destinations (défaut).
    pub icmp_target: Option<Ipv4Addr>,
    /// Identifiant IP de la première réponse ICMP (incrémenté ensuite).
    pub reply_ip_id: u16,
    /// Envoyer un IPV6CP Configure-Request une fois LCP ouvert (`ipv6cp_confreq_gateway`)
    /// pour vérifier le Protocol-Reject du client.
    pub offer_ipv6cp: bool,
    /// Intervalle des LCP Echo-Request émis par la passerelle une fois LCP ouvert ;
    /// `None` (défaut) : jamais.
    pub echo_interval: Option<Duration>,
    /// Retransmission des Configure-Request de la passerelle (défaut 3 s).
    pub restart_interval: Duration,
    /// Nombre max de Configure-Request par protocole avant abandon (défaut 10).
    pub max_configure: u32,
    /// Attente du Terminate-Ack après un Terminate-Request de la passerelle (défaut 1 s).
    pub terminate_timeout: Duration,
    /// Panne injectée.
    pub fault: PppFault,
}

impl Default for PppPeerConfig {
    fn default() -> Self {
        Self {
            magic: DEFAULT_GATEWAY_MAGIC,
            mru: Some(1354),
            ipcp_request: GatewayIpcpRequest::default(),
            icmp_target: None,
            reply_ip_id: DEFAULT_REPLY_IP_ID,
            offer_ipv6cp: false,
            echo_interval: None,
            restart_interval: Duration::from_secs(3),
            max_configure: 10,
            terminate_timeout: Duration::from_secs(1),
            fault: PppFault::None,
        }
    }
}

/// Fin d'une session PPP côté passerelle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerEnd {
    /// Terminate-Request du client reçu, Terminate-Ack envoyé, `close_notify`.
    ClientTerminated,
    /// Terminate-Request de la passerelle ([`PppFault::GatewayTerminate`]) ; `acked` :
    /// Terminate-Ack reçu avant le délai.
    GatewayTerminated { acked: bool },
    /// Le client a fermé la connexion (EOF).
    Eof,
    /// Erreur d'entrée/sortie (coupure TCP, TLS sans `close_notify`...).
    Io(std::io::ErrorKind),
    /// Flux `0x5050` invalide reçu du client.
    BadFrame(FrameError),
    /// Nombre max de Configure-Request atteint pour ce protocole.
    NegotiationFailed(Protocol),
    /// Le client a rejeté IPCP (Protocol-Reject).
    IpcpRejected,
    /// Coupure volontaire sans `close_notify` ([`PppFault::AbortTls`]).
    Aborted,
    /// Réponse HTTP envoyée à la place du PPP ([`PppFault::HttpInsteadOfPpp`]).
    HttpSent(u16),
}

/// Paramètres obtenus à l'ouverture d'IPCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcpUp {
    pub conn_id: u64,
    /// Adresse acquittée pour le client.
    pub client_ip: Ipv4Addr,
    /// DNS acquittés (primaire puis secondaire).
    pub dns: Vec<Ipv4Addr>,
    /// Adresse PPP annoncée par la passerelle (`None` : variante vide).
    pub gateway_ip: Option<Ipv4Addr>,
    /// Magic-Number LCP du client.
    pub client_magic: Option<u32>,
    /// MRU annoncé par le client (1500 s'il est absent, RFC 1661).
    pub client_mru: u16,
}

/// Phase de la session courante.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PeerPhase {
    /// Aucune session encore.
    #[default]
    Idle,
    /// Négociation LCP.
    Lcp,
    /// LCP ouvert, négociation IPCP.
    Ipcp,
    /// IPCP ouvert : trafic IPv4.
    Up,
    /// Terminate-Request de la passerelle envoyé.
    Terminating,
    /// Session terminée (voir [`PppStatus::end`]).
    Closed,
}

/// État de la **dernière** session PPP servie.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PppStatus {
    /// Numéro de connexion (cf. [`crate::LoggedRequest::conn_id`]).
    pub conn_id: Option<u64>,
    pub phase: PeerPhase,
    /// Renseigné à l'ouverture d'IPCP.
    pub ipcp: Option<IpcpUp>,
    /// Le client a envoyé un Protocol-Reject pour IPV6CP.
    pub ipv6cp_rejected: bool,
    /// Renseigné à la fin de la session.
    pub end: Option<PeerEnd>,
}

/// Compteurs cumulés sur toutes les sessions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PppCounters {
    /// Sessions PPP démarrées.
    pub sessions: u64,
    /// Sessions ayant atteint IPCP ouvert.
    pub ipcp_up: u64,
    /// Trames `0x5050` reçues / émises (y compris contrôle).
    pub frames_rx: u64,
    pub frames_tx: u64,
    /// Datagrammes IPv4 reçus (IPCP ouvert) / émis.
    pub ipv4_rx: u64,
    pub ipv4_tx: u64,
    /// ICMP Echo Request ayant reçu une réponse.
    pub icmp_echo_replied: u64,
    /// IPv4 ignorés (IPCP fermé, autre destination, pas un Echo Request, invalide).
    pub ipv4_dropped: u64,
    /// LCP Echo-Request reçus du client / Echo-Reply envoyés / Echo-Request ignorés.
    pub lcp_echo_requests_rx: u64,
    pub lcp_echo_replies_tx: u64,
    pub lcp_echo_requests_ignored: u64,
    /// LCP Echo-Request émis par la passerelle / Echo-Reply reçus du client.
    pub lcp_echo_requests_tx: u64,
    pub lcp_echo_replies_rx: u64,
    /// Protocol-Reject reçus du client / émis par la passerelle.
    pub protocol_rejects_rx: u64,
    pub protocol_rejects_tx: u64,
    /// Trames PPP ignorées (mal formées, IPCP avant LCP ouvert, identifiant périmé...).
    pub ignored: u64,
}

#[derive(Debug, Default)]
pub(crate) struct AtomicCounters {
    pub(crate) sessions: AtomicU64,
    pub(crate) ipcp_up: AtomicU64,
    pub(crate) frames_rx: AtomicU64,
    pub(crate) frames_tx: AtomicU64,
    pub(crate) ipv4_rx: AtomicU64,
    pub(crate) ipv4_tx: AtomicU64,
    pub(crate) icmp_echo_replied: AtomicU64,
    pub(crate) ipv4_dropped: AtomicU64,
    pub(crate) lcp_echo_requests_rx: AtomicU64,
    pub(crate) lcp_echo_replies_tx: AtomicU64,
    pub(crate) lcp_echo_requests_ignored: AtomicU64,
    pub(crate) lcp_echo_requests_tx: AtomicU64,
    pub(crate) lcp_echo_replies_rx: AtomicU64,
    pub(crate) protocol_rejects_rx: AtomicU64,
    pub(crate) protocol_rejects_tx: AtomicU64,
    pub(crate) ignored: AtomicU64,
}

pub(crate) fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

impl AtomicCounters {
    fn snapshot(&self) -> PppCounters {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        PppCounters {
            sessions: g(&self.sessions),
            ipcp_up: g(&self.ipcp_up),
            frames_rx: g(&self.frames_rx),
            frames_tx: g(&self.frames_tx),
            ipv4_rx: g(&self.ipv4_rx),
            ipv4_tx: g(&self.ipv4_tx),
            icmp_echo_replied: g(&self.icmp_echo_replied),
            ipv4_dropped: g(&self.ipv4_dropped),
            lcp_echo_requests_rx: g(&self.lcp_echo_requests_rx),
            lcp_echo_replies_tx: g(&self.lcp_echo_replies_tx),
            lcp_echo_requests_ignored: g(&self.lcp_echo_requests_ignored),
            lcp_echo_requests_tx: g(&self.lcp_echo_requests_tx),
            lcp_echo_replies_rx: g(&self.lcp_echo_replies_rx),
            protocol_rejects_rx: g(&self.protocol_rejects_rx),
            protocol_rejects_tx: g(&self.protocol_rejects_tx),
            ignored: g(&self.ignored),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) status: watch::Sender<PppStatus>,
    pub(crate) counters: AtomicCounters,
}

/// Pair PPP de la passerelle ; à passer à [`crate::MockGatewayBuilder::tunnel_handler`].
///
/// Clonable : les clones partagent l'état observable ([`PppPeer::observer`]).
#[derive(Debug, Clone)]
pub struct PppPeer {
    cfg: Arc<PppPeerConfig>,
    shared: Arc<Shared>,
}

impl Default for PppPeer {
    fn default() -> Self {
        Self::new(PppPeerConfig::default())
    }
}

impl PppPeer {
    pub fn new(cfg: PppPeerConfig) -> Self {
        let (status, _) = watch::channel(PppStatus::default());
        Self {
            cfg: Arc::new(cfg),
            shared: Arc::new(Shared {
                status,
                counters: AtomicCounters::default(),
            }),
        }
    }

    /// Pair nominal avec la panne `fault`.
    pub fn with_fault(fault: PppFault) -> Self {
        Self::new(PppPeerConfig {
            fault,
            ..PppPeerConfig::default()
        })
    }

    pub fn config(&self) -> &PppPeerConfig {
        &self.cfg
    }

    /// Observateur de l'état (IPCP up, fin de session) et des compteurs.
    pub fn observer(&self) -> PppObserver {
        PppObserver {
            rx: self.shared.status.subscribe(),
            shared: Arc::clone(&self.shared),
        }
    }

    /// Sert une session PPP sur `stream` (déjà en mode tunnel) jusqu'à sa fin, puis ferme
    /// le flux : `shutdown` (`close_notify` en TLS) sauf [`PeerEnd::Aborted`] (simple
    /// abandon du flux, sans `close_notify`).
    ///
    /// `ipv4` fournit l'adresse et les DNS attribués par IPCP. Générique pour permettre des
    /// tests en mémoire (`tokio::io::duplex`).
    pub async fn serve<S>(&self, mut stream: S, ipv4: &Ipv4Config, conn_id: u64) -> PeerEnd
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        inc(&self.shared.counters.sessions);
        self.shared.status.send_replace(PppStatus {
            conn_id: Some(conn_id),
            phase: PeerPhase::Lcp,
            ..PppStatus::default()
        });
        tracing::debug!(conn_id, "mock-gw ppp: session démarrée");

        if let PppFault::HttpInsteadOfPpp { status } = self.cfg.fault {
            let _ = stream.write_all(&http_refusal(status)).await;
            let _ = stream.shutdown().await;
            return self.finish(PeerEnd::HttpSent(status));
        }

        let mut m = Machine::new(&self.cfg, &self.shared, ipv4, conn_id, Instant::now());
        let mut rx = BytesMut::with_capacity(4096);
        let (end, mode) = loop {
            if let Err(e) = flush(&mut stream, m.take_output()).await {
                break (PeerEnd::Io(e.kind()), CloseMode::Abort);
            }
            if let Some(exit) = m.exit() {
                break exit;
            }
            let deadline = m.next_deadline();
            rx.reserve(4096);
            tokio::select! {
                r = stream.read_buf(&mut rx) => match r {
                    Ok(0) => break (PeerEnd::Eof, CloseMode::Clean),
                    Ok(_) => m.handle_bytes(&mut rx, Instant::now()),
                    Err(e) => break (PeerEnd::Io(e.kind()), CloseMode::Abort),
                },
                () = sleep_until_opt(deadline) => m.handle_timeout(Instant::now()),
            }
        };
        match mode {
            CloseMode::Clean => {
                let _ = flush(&mut stream, m.take_output()).await;
                let _ = stream.shutdown().await;
            }
            CloseMode::Abort => drop(stream),
        }
        self.finish(end)
    }

    fn finish(&self, end: PeerEnd) -> PeerEnd {
        tracing::info!(end = ?end, "mock-gw ppp: session terminée");
        self.shared.status.send_modify(|s| {
            s.phase = PeerPhase::Closed;
            s.end = Some(end.clone());
        });
        end
    }
}

impl TunnelHandler for PppPeer {
    fn handle(&self, stream: TunnelStream, ctx: TunnelContext) -> TunnelFuture {
        let peer = self.clone();
        Box::pin(async move {
            peer.serve(stream, &ctx.config.ipv4, ctx.conn_id).await;
        })
    }
}

/// Lecture de l'état d'un [`PppPeer`].
#[derive(Debug, Clone)]
pub struct PppObserver {
    rx: watch::Receiver<PppStatus>,
    shared: Arc<Shared>,
}

impl PppObserver {
    /// État courant.
    pub fn status(&self) -> PppStatus {
        self.rx.borrow().clone()
    }

    /// Compteurs cumulés.
    pub fn counters(&self) -> PppCounters {
        self.shared.counters.snapshot()
    }

    /// Attend l'ouverture d'IPCP de la session courante ; `None` si elle se termine avant.
    pub async fn wait_ipcp_up(&mut self) -> Option<IpcpUp> {
        let s = self
            .rx
            .wait_for(|s| s.ipcp.is_some() || s.end.is_some())
            .await
            .ok()?;
        s.ipcp.clone()
    }

    /// Attend la fin de la session courante.
    pub async fn wait_end(&mut self) -> PeerEnd {
        loop {
            if let Ok(s) = self.rx.wait_for(|s| s.end.is_some()).await {
                if let Some(end) = s.end.clone() {
                    return end;
                }
            }
        }
    }

    /// Attend la prochaine modification de l'état (les modifications rapprochées peuvent
    /// être fusionnées) ; `None` si le pair n'existe plus.
    pub async fn changed(&mut self) -> Option<PppStatus> {
        self.rx.changed().await.ok()?;
        Some(self.rx.borrow_and_update().clone())
    }

    /// Attend que `pred` soit vrai sur l'état.
    pub async fn wait_for(&mut self, mut pred: impl FnMut(&PppStatus) -> bool) -> PppStatus {
        // L'émetteur vit aussi longtemps que `shared` : `wait_for` ne peut échouer.
        loop {
            if let Ok(s) = self.rx.wait_for(&mut pred).await {
                return s.clone();
            }
        }
    }
}

async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

async fn flush<S: AsyncWrite + Unpin>(stream: &mut S, out: BytesMut) -> std::io::Result<()> {
    if out.is_empty() {
        return Ok(());
    }
    stream.write_all(&out).await?;
    stream.flush().await
}

/// Réponse HTTP envoyée à la place du flux PPP.
fn http_refusal(status: u16) -> Vec<u8> {
    let reason = match status {
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\
         Connection: close\r\n\r\n"
    )
    .into_bytes()
}
