//! Boucle tunnel SSL-VPN : framing `0x5050` + PPP sur un flux TLS (`docs/protocol.md`
//! §6, §7, §9, §11, §12).
//!
//! Générique sur un flux `AsyncRead + AsyncWrite` (le flux TLS sur lequel
//! `GET /remote/sslvpn-tunnel` a été envoyé, cf. [`send_tunnel_request`]) :
//!
//! 1. [`open`] pilote l'automate [`PppSession`] jusqu'à `IpcpUp` (première trame
//!    attendue au plus [`TunnelOptions::first_frame_timeout`], 15 s par défaut),
//!    puis lance la boucle de relais dans une tâche tokio.
//! 2. La boucle relaie les datagrammes IPv4 entre le flux et le [`PacketChannel`]
//!    de [`Tunnel::packets`], sert les timers PPP (retransmissions, keepalive) et
//!    répond au trafic de contrôle.
//! 3. Fin : sur demande ([`TunnelHandle::close`]) ou libération du canal de
//!    paquets, LCP Terminate-Request (Ack attendu ≤ 1 s) puis fermeture TLS
//!    (`shutdown` du flux). La raison de fin est publiée sur [`Tunnel::end`].
//!
//! Conception :
//! - **une seule tâche** possède le flux, séparé en moitiés lecture/écriture
//!   ([`tokio::io::split`]) pour lire et écrire de façon concurrente dans un même
//!   `select!` : un seul écrivain, pas de verrou applicatif ;
//! - les trames sortantes sont accumulées dans un tampon d'émission ; tant qu'il
//!   dépasse [`WRITE_HIGH_WATER`], la boucle cesse de prélever des paquets IP sur le
//!   canal (contre-pression vers la TUN) ;
//! - en réception, chaque datagramme est remis au canal par un `send` qui attend
//!   de la place (contre-pression vers TLS/TCP) ; les trames et paquets IP reçus
//!   sont des tranches du tampon de lecture ([`Bytes`]), sans copie ;
//! - en émission, un paquet IP est copié une seule fois, derrière son en-tête de
//!   8 octets, dans le tampon d'émission.

use std::fmt::Write as _;
use std::io;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::time::Duration;

use bytes::BytesMut;
use proto::auth::SessionCookie;
use proto::frame::{self, FrameDecoder, FrameError};
use proto::ppp::{ControlSummary, DownReason, PppConfig, PppEvent, PppSession, Protocol};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until, timeout, timeout_at};

use crate::error::TransportError;
use crate::packet::PacketChannel;
use crate::transport::{SessionEnd, session_end};

/// Délai maximal entre l'ouverture du tunnel et la première trame reçue (§11).
pub const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(15);
/// Au-delà de ce volume en attente d'émission, la boucle ne prélève plus de paquets IP.
pub const WRITE_HIGH_WATER: usize = 64 * 1024;
/// Borne dure du tampon d'émission : au-delà, les trames de contrôle reçues sont
/// ignorées (pas de réponse Echo/Reject) pour ne pas croître sans limite (F3).
const OUT_HARD_LIMIT: usize = 1024 * 1024;
/// Trames de contrôle ignorées de suite au-delà de la borne avant de conclure à `DeadPeer`.
const MAX_IGNORED_CONTROL: u32 = 1024;
/// Délai accordé à l'envoi des dernières trames puis à la fermeture TLS.
const CLOSE_IO_TIMEOUT: Duration = Duration::from_secs(1);
/// Délai accordé pour lire la ligne de statut d'une réponse HTTP de refus.
const HTTP_STATUS_WAIT: Duration = Duration::from_secs(1);
/// Octets de réponse HTTP lus au plus pour en extraire le statut.
const HTTP_PEEK_MAX: usize = 1024;
/// Réserve minimale du tampon de lecture avant chaque lecture.
const READ_RESERVE: usize = 16 * 1024;

/// Erreur du tunnel (§12). Toutes sont fatales pour la session.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TunnelError {
    /// Erreur d'entrée/sortie sur le flux TLS.
    #[error("erreur d'entrée/sortie du tunnel")]
    Io(#[from] io::Error),
    /// La passerelle a répondu en HTTP au lieu d'ouvrir le tunnel (§6) : mode tunnel
    /// refusé, cookie expiré ou déjà consommé. Une ré-authentification complète est
    /// recommandée.
    #[error("mode tunnel refusé par la passerelle (statut HTTP {status:?})")]
    TunnelRefused {
        /// Code de statut HTTP, s'il a pu être lu.
        status: Option<u16>,
    },
    /// En-tête `0x5050` invalide (§7.2).
    #[error("trame invalide reçue")]
    BadFrame(#[source] FrameError),
    /// Aucune trame reçue dans le délai imparti après `sslvpn-tunnel` (§11).
    #[error("aucune trame reçue {0:?} après l'ouverture du tunnel")]
    FirstFrameTimeout(Duration),
    /// Négociation LCP/IPCP en échec (max Configure-Request, option ou protocole
    /// indispensable refusé).
    #[error("échec de la négociation PPP ({0})")]
    PppNegotiationFailed(Protocol),
    /// La passerelle a relancé une négociation sur un lien ouvert (traité comme une
    /// coupure, §9.3).
    #[error("renégociation {0} demandée par la passerelle")]
    Renegotiation(Protocol),
    /// Echo LCP sans réponse (§9.7).
    #[error("la passerelle ne répond plus (LCP echo)")]
    DeadPeer,
    /// Terminate-Request reçu ou fin du flux TLS (§9.8).
    #[error("session fermée par la passerelle")]
    ClosedByPeer,
}

impl TunnelError {
    /// Erreur correspondant à une fin PPP ; `None` pour une fermeture locale.
    fn from_down(reason: DownReason) -> Option<Self> {
        Some(match reason {
            DownReason::LocalClose => return None,
            DownReason::DeadPeer => Self::DeadPeer,
            DownReason::Renegotiation(p) => Self::Renegotiation(p),
            DownReason::ProtocolRejected(p) | DownReason::NegotiationFailed(p) => {
                Self::PppNegotiationFailed(p)
            }
            // `ClosedByPeer`, et toute nouvelle raison (`DownReason` est
            // `non_exhaustive`) : coupure côté passerelle.
            _ => Self::ClosedByPeer,
        })
    }

    /// Vrai si une ré-authentification complète est nécessaire avant de réessayer
    /// (le cookie n'est plus accepté, §6 / §10.3).
    pub fn requires_reauth(&self) -> bool {
        matches!(self, Self::TunnelRefused { .. })
    }
}

/// Paramètres réseau négociés par IPCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelParams {
    /// Adresse locale (IPCP fait foi, §5.3).
    pub local_ip: Ipv4Addr,
    /// Adresse PPP de la passerelle, si annoncée.
    pub peer: Option<Ipv4Addr>,
    /// DNS obtenus par IPCP (ordre de préférence).
    pub dns: Vec<Ipv4Addr>,
    /// MTU de l'interface : min(MRU du pair, notre MRU).
    pub mtu: u16,
}

/// Pont vers la fusion XML + IPCP de [`crate::sslvpn::tunnel_config`].
impl From<TunnelParams> for crate::sslvpn::NegotiatedIpv4 {
    fn from(p: TunnelParams) -> Self {
        Self {
            address: p.local_ip,
            peer: p.peer,
            mtu: p.mtu,
            dns: p.dns,
        }
    }
}

/// Options du tunnel.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TunnelOptions {
    /// Paramètres PPP (MRU, magic, timers ; défauts §9.2/§11).
    pub ppp: PppConfig,
    /// Délai d'attente de la première trame (défaut [`FIRST_FRAME_TIMEOUT`]).
    pub first_frame_timeout: Duration,
    /// Capacité du canal de paquets par direction (défaut 256).
    pub queue_capacity: usize,
}

impl TunnelOptions {
    /// Options par défaut avec un Magic-Number aléatoire.
    pub fn new() -> Self {
        Self::with_magic(random_magic())
    }

    /// Options par défaut avec le Magic-Number donné (tests déterministes).
    pub fn with_magic(magic: NonZeroU32) -> Self {
        Self {
            ppp: PppConfig::new(magic),
            first_frame_timeout: FIRST_FRAME_TIMEOUT,
            queue_capacity: 256,
        }
    }
}

impl Default for TunnelOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Magic-Number LCP non nul (aléa non cryptographique : il ne sert qu'à détecter les
/// boucles).
fn random_magic() -> NonZeroU32 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        h.write_u128(d.as_nanos());
    }
    let b = h.finish().to_le_bytes();
    NonZeroU32::new(
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]) ^ u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
    )
    .unwrap_or(NonZeroU32::MIN)
}

/// Envoie `GET /remote/sslvpn-tunnel` (§6, forme openfortivpn) sur `stream`.
/// Le cookie n'est jamais journalisé ; le tampon de la requête est effacé.
pub async fn send_tunnel_request<W>(stream: &mut W, cookie: &SessionCookie) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let request = proto::http::tunnel_request(cookie);
    stream.write_all(&request).await?;
    stream.flush().await?;
    tracing::debug!("GET /remote/sslvpn-tunnel envoyé");
    Ok(())
}

/// Tunnel établi (IPCP ouvert) dont la boucle tourne dans une tâche tokio.
#[derive(Debug)]
pub struct Tunnel {
    /// Paramètres négociés par IPCP.
    pub params: TunnelParams,
    /// Paquets IP : `recv` = reçus de la passerelle, `send` = à émettre.
    /// Libérer cette extrémité ferme proprement le tunnel.
    pub packets: PacketChannel,
    /// Raison de la fin du tunnel (publiée avant la fermeture de `packets`).
    pub end: SessionEnd,
    /// Contrôle de la tâche du tunnel.
    pub handle: TunnelHandle,
}

/// Contrôle de la tâche du tunnel. Le libérer demande la fermeture propre.
#[derive(Debug)]
pub struct TunnelHandle {
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl TunnelHandle {
    /// Demande la fermeture propre (Terminate LCP puis fermeture TLS), sans attendre.
    pub fn request_close(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }

    /// Demande la fermeture propre et attend la fin de la tâche (≤ ~3 s : Terminate-Ack
    /// 1 s, vidage et fermeture TLS 1 s chacun).
    pub async fn close(mut self) {
        self.request_close();
        self.join().await;
    }

    /// Attend la fin de la tâche sans demander la fermeture.
    pub async fn join(self) {
        let Self { stop, task } = self;
        if let Err(e) = task.await {
            tracing::error!(error = %e, "tâche du tunnel interrompue");
        }
        drop(stop);
    }

    /// Vrai si la tâche est terminée.
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

/// Ouvre le tunnel sur `stream` (requête `sslvpn-tunnel` déjà envoyée) : négociation
/// PPP jusqu'à `IpcpUp`, puis lancement de la boucle dans une tâche tokio.
///
/// En cas d'erreur, le flux est libéré sans Terminate.
pub async fn open<S>(stream: S, options: TunnelOptions) -> Result<Tunnel, TunnelError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    open_with_buffered(stream, &[], options).await
}

/// Variante de [`open`] lorsque des octets du flux ont déjà été lus (ex. reliquat de
/// `GatewayConnection::into_parts`) : ils sont traités avant toute lecture.
pub async fn open_with_buffered<S>(
    stream: S,
    buffered: &[u8],
    options: TunnelOptions,
) -> Result<Tunnel, TunnelError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut driver = Driver::new(stream, options.ppp);
    driver.dec.push(buffered);
    let params = driver.establish(options.first_frame_timeout).await?;
    tracing::info!(
        ip = %params.local_ip,
        mtu = params.mtu,
        dns = ?params.dns,
        "tunnel PPP établi (IPCP ouvert)"
    );
    let (ours, mut theirs) = PacketChannel::pair(options.queue_capacity);
    let (notifier, end) = session_end();
    let (stop_tx, stop_rx) = oneshot::channel();
    let up_since = Instant::now();
    let task = tokio::spawn(async move {
        let result = driver.run(&mut theirs, stop_rx).await;
        let uptime = up_since.elapsed();
        match &result {
            Ok(()) => tracing::info!(?uptime, "tunnel fermé"),
            Err(e) => tracing::warn!(error = %e, ?uptime, "fin du tunnel"),
        }
        // Raison publiée avant la fermeture du canal (contrat de `TransportSession`).
        notifier.finish(result.map_err(TransportError::from));
        drop(theirs);
    });
    Ok(Tunnel {
        params,
        packets: ours,
        end,
        handle: TunnelHandle {
            stop: Some(stop_tx),
            task,
        },
    })
}

/// Issue du traitement des événements PPP.
enum Flow {
    Continue,
    Up(TunnelParams),
    Down(DownReason),
}

fn now() -> std::time::Instant {
    Instant::now().into_std()
}

async fn sleep_opt(deadline: Option<Instant>) {
    match deadline {
        Some(d) => sleep_until(d).await,
        None => std::future::pending().await,
    }
}

/// Une étape d'écriture : écrit une partie du tampon, ou le vide (`flush`) s'il est
/// vide. Retourne `true` après un `flush`. Annulable sans perte (`write_buf` ne
/// consomme le tampon qu'une fois l'écriture faite).
async fn write_step<W: AsyncWrite + Unpin>(wr: &mut W, out: &mut BytesMut) -> io::Result<bool> {
    if out.is_empty() {
        wr.flush().await?;
        return Ok(true);
    }
    if wr.write_buf(out).await? == 0 {
        return Err(io::ErrorKind::WriteZero.into());
    }
    Ok(false)
}

/// Octets de trame affichés au plus par la trace des trames de contrôle.
const TRACE_HEX_MAX: usize = 64;

/// Trace (`-vv`) d'une trame PPP de contrôle : direction, protocole, code, id,
/// longueur et hexdump borné. Les datagrammes de données ne sont jamais journalisés
/// (contenu utilisateur) ; les trames de contrôle ne portent aucun secret.
fn trace_control(direction: &'static str, ppp: &[u8]) {
    if !tracing::enabled!(tracing::Level::TRACE) {
        return;
    }
    let Some(s) = ControlSummary::of(ppp) else {
        return;
    };
    let shown = &ppp[..ppp.len().min(TRACE_HEX_MAX)];
    let mut hex = String::with_capacity(shown.len() * 3);
    for (i, b) in shown.iter().enumerate() {
        if i > 0 {
            hex.push(' ');
        }
        let _ = write!(hex, "{b:02x}");
    }
    tracing::trace!(
        direction,
        protocol = %s.protocol,
        code = ?s.code,
        id = s.id,
        declared_len = s.declared_len,
        frame_len = ppp.len(),
        truncated = ppp.len() > shown.len(),
        hex = %hex,
        "trame PPP de contrôle"
    );
}

/// Datagramme IPv4 plausible : version 4, en-tête >= 20 octets, longueur totale
/// cohérente. Un autre contenu (IPv6 émis par l'OS sur la TUN : RS, MLD…) ne doit pas
/// partir sous le protocole PPP `0x0021`.
fn is_ipv4_datagram(p: &[u8]) -> bool {
    p.len() >= 20
        && p[0] >> 4 == 4
        && usize::from(p[0] & 0x0f) >= 5
        && usize::from(u16::from_be_bytes([p[2], p[3]])) <= p.len()
}

/// État de la boucle : flux, décodeur, tampon d'émission, automate PPP.
struct Driver<S> {
    rd: ReadHalf<S>,
    wr: WriteHalf<S>,
    dec: FrameDecoder,
    out: BytesMut,
    unflushed: bool,
    got_frame: bool,
    /// Le consommateur du canal de paquets est parti.
    consumer_gone: bool,
    /// Trames de contrôle ignorées tant que `out` dépasse [`OUT_HARD_LIMIT`].
    ignored_control: u32,
    ppp: PppSession,
}

impl<S: AsyncRead + AsyncWrite> Driver<S> {
    fn new(stream: S, ppp: PppConfig) -> Self {
        let (rd, wr) = tokio::io::split(stream);
        Self {
            rd,
            wr,
            dec: FrameDecoder::new(),
            out: BytesMut::new(),
            unflushed: false,
            got_frame: false,
            consumer_gone: false,
            ignored_control: 0,
            ppp: PppSession::new(ppp),
        }
    }

    /// Encapsule les trames PPP en attente dans le tampon d'émission.
    fn queue_transmits(&mut self) {
        while let Some(ppp) = self.ppp.poll_transmit() {
            trace_control("tx", &ppp);
            if let Err(e) = frame::encode_frame(&ppp, &mut self.out) {
                tracing::warn!(error = %e, "trame PPP de contrôle non encapsulable, ignorée");
            }
        }
    }

    /// Encapsule un datagramme IPv4 à émettre.
    fn queue_ip(&mut self, packet: &[u8]) {
        if !self.ppp.is_ip_up() {
            tracing::trace!("paquet IP ignoré : IPCP non ouvert");
            return;
        }
        if !is_ipv4_datagram(packet) {
            tracing::debug!(
                len = packet.len(),
                version = packet.first().map(|b| b >> 4),
                "paquet non IPv4 ignoré (non émis sous le protocole PPP 0x0021)"
            );
            return;
        }
        if let Err(e) = frame::encode_ppp_frame(Protocol::IPV4, packet, &mut self.out) {
            tracing::debug!(error = %e, len = packet.len(), "paquet IP ignoré");
        }
    }

    fn prepare_read(&mut self) {
        self.dec.buffer_mut().reserve(READ_RESERVE);
    }

    /// Vide entièrement le tampon d'émission.
    async fn flush_all(&mut self) -> io::Result<()> {
        self.wr.write_all_buf(&mut self.out).await?;
        self.wr.flush().await?;
        self.unflushed = false;
        Ok(())
    }

    /// Envoie les dernières trames (ex. Terminate-Ack) puis ferme le flux en écriture
    /// (`close_notify` TLS), chaque étape bornée ; erreurs ignorées.
    async fn finish(&mut self) {
        self.queue_transmits();
        match timeout(CLOSE_IO_TIMEOUT, self.flush_all()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::debug!(error = %e, "vidage final du tunnel"),
            Err(_) => tracing::debug!("vidage final du tunnel : délai dépassé"),
        }
        match timeout(CLOSE_IO_TIMEOUT, self.wr.shutdown()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::debug!(error = %e, "fermeture du flux du tunnel"),
            Err(_) => tracing::debug!("fermeture du flux du tunnel : délai dépassé"),
        }
    }

    /// Fin PPP : termine les I/O et traduit la raison.
    async fn end(&mut self, reason: DownReason) -> Result<(), TunnelError> {
        tracing::debug!(?reason, "fin de session PPP");
        self.finish().await;
        TunnelError::from_down(reason).map_or(Ok(()), Err)
    }

    /// Réponse HTTP au lieu du tunnel : tente brièvement de lire le statut.
    async fn refused(&mut self, mut status: Option<u16>) -> TunnelError {
        let deadline = Instant::now() + HTTP_STATUS_WAIT;
        while status.is_none() && self.dec.buffered().len() < HTTP_PEEK_MAX {
            self.prepare_read();
            match timeout_at(deadline, self.rd.read_buf(self.dec.buffer_mut())).await {
                Ok(Ok(n)) if n > 0 => status = frame::parse_http_status(self.dec.buffered()),
                _ => break,
            }
        }
        tracing::warn!(?status, "réponse HTTP reçue à la place du tunnel");
        TunnelError::TunnelRefused { status }
    }

    /// Erreur d'écriture pendant l'établissement : la passerelle a peut-être déjà
    /// répondu en HTTP puis fermé (§6). Avant de conclure à une erreur d'E/S, lit
    /// brièvement ce qui reste et privilégie [`TunnelError::TunnelRefused`].
    async fn write_failed(&mut self, error: io::Error) -> TunnelError {
        if self.got_frame {
            return error.into();
        }
        let deadline = Instant::now() + HTTP_STATUS_WAIT;
        while self.dec.buffered().len() < HTTP_PEEK_MAX
            && frame::parse_http_status(self.dec.buffered()).is_none()
        {
            self.prepare_read();
            match timeout_at(deadline, self.rd.read_buf(self.dec.buffer_mut())).await {
                Ok(Ok(n)) if n > 0 => {}
                _ => break,
            }
        }
        if self.dec.buffered().starts_with(frame::HTTP_PREFIX) {
            let status = frame::parse_http_status(self.dec.buffered());
            return self.refused(status).await;
        }
        tracing::debug!(error = %error, "écriture impossible pendant l'établissement du tunnel");
        error.into()
    }

    /// Traite les événements PPP en attente. Les datagrammes sont remis à `inbound`
    /// (attente si le canal est plein) ; sans `inbound`, ils sont ignorés.
    async fn drain_events(&mut self, inbound: Option<&PacketChannel>) -> Flow {
        while let Some(event) = self.ppp.poll_event() {
            match event {
                PppEvent::Ipv4(packet) => match inbound {
                    Some(ch) if !self.consumer_gone => {
                        if ch.send(packet).await.is_err() {
                            self.consumer_gone = true;
                        }
                    }
                    _ => tracing::trace!("datagramme reçu sans destinataire, ignoré"),
                },
                PppEvent::IpcpUp {
                    local_ip,
                    dns,
                    peer,
                    mtu,
                } => {
                    return Flow::Up(TunnelParams {
                        local_ip,
                        peer,
                        dns,
                        mtu,
                    });
                }
                PppEvent::Down(reason) => return Flow::Down(reason),
            }
        }
        Flow::Continue
    }

    /// Décode et traite les trames complètes du tampon de lecture. S'arrête au premier
    /// changement d'état (les trames suivantes restent en tampon).
    async fn process_input(
        &mut self,
        inbound: Option<&PacketChannel>,
    ) -> Result<Flow, TunnelError> {
        loop {
            let frame = match self.dec.next_frame() {
                Ok(Some(f)) => f,
                Ok(None) => return Ok(Flow::Continue),
                Err(FrameError::HttpResponse { status }) => return Err(self.refused(status).await),
                Err(e) => {
                    tracing::warn!(error = %e, "en-tête 0x5050 invalide");
                    return Err(TunnelError::BadFrame(e));
                }
            };
            self.got_frame = true;
            trace_control("rx", &frame);
            if self.out.len() > OUT_HARD_LIMIT {
                // Pair qui n'acquitte plus TCP : ne pas répondre aux trames de contrôle.
                if !frame.starts_with(&Protocol::IPV4.0.to_be_bytes()) {
                    self.ignored_control += 1;
                    if self.ignored_control > MAX_IGNORED_CONTROL {
                        tracing::warn!("tampon d'émission saturé : passerelle considérée morte");
                        return Ok(Flow::Down(DownReason::DeadPeer));
                    }
                    continue;
                }
            } else {
                self.ignored_control = 0;
            }
            self.ppp.handle_frame(now(), frame);
            match self.drain_events(inbound).await {
                Flow::Continue => {}
                flow => return Ok(flow),
            }
        }
    }

    /// Négociation jusqu'à `IpcpUp`.
    async fn establish(
        &mut self,
        first_frame_timeout: Duration,
    ) -> Result<TunnelParams, TunnelError> {
        self.ppp.open(now());
        let first_deadline = Instant::now() + first_frame_timeout;
        // Octets éventuellement fournis par `open_with_buffered`.
        let mut flow = self.process_input(None).await?;
        loop {
            match flow {
                Flow::Continue => {}
                Flow::Up(params) => {
                    // Ex. notre Configure-Ack IPCP : à émettre avant de rendre la main.
                    self.queue_transmits();
                    if let Err(e) = self.flush_all().await {
                        return Err(self.write_failed(e).await);
                    }
                    return Ok(params);
                }
                Flow::Down(reason) => {
                    return Err(self
                        .end(reason)
                        .await
                        .err()
                        .unwrap_or(TunnelError::ClosedByPeer));
                }
            }
            self.queue_transmits();
            self.prepare_read();
            let ppp_deadline = self.ppp.poll_timeout().map(Instant::from_std);
            let first = (!self.got_frame).then_some(first_deadline);
            // `biased` : une réponse déjà reçue (ex. refus HTTP) est traitée avant
            // une erreur d'écriture concurrente.
            flow = tokio::select! {
                biased;
                r = self.rd.read_buf(self.dec.buffer_mut()) => {
                    if r? == 0 {
                        return Err(TunnelError::ClosedByPeer);
                    }
                    self.process_input(None).await?
                }
                r = write_step(&mut self.wr, &mut self.out), if !self.out.is_empty() || self.unflushed => {
                    match r {
                        Ok(flushed) => self.unflushed = !flushed,
                        Err(e) => return Err(self.write_failed(e).await),
                    }
                    Flow::Continue
                }
                () = sleep_opt(ppp_deadline) => {
                    self.ppp.handle_timeout(now());
                    self.drain_events(None).await
                }
                () = sleep_opt(first) => {
                    return Err(TunnelError::FirstFrameTimeout(first_frame_timeout));
                }
            };
        }
    }

    fn begin_close(&mut self, closing: &mut bool) {
        if !*closing {
            *closing = true;
            tracing::debug!("fermeture du tunnel : LCP Terminate-Request");
            self.ppp.close(now());
        }
    }

    /// Boucle de relais, après `IpcpUp`.
    async fn run(
        &mut self,
        packets: &mut PacketChannel,
        mut stop: oneshot::Receiver<()>,
    ) -> Result<(), TunnelError> {
        let mut closing = false;
        // Trames reçues avec l'IpcpUp, restées en tampon.
        if let Flow::Down(reason) = self.process_input(Some(&*packets)).await? {
            return self.end(reason).await;
        }
        loop {
            if self.consumer_gone {
                self.begin_close(&mut closing);
            }
            self.queue_transmits();
            self.prepare_read();
            let ppp_deadline = self.ppp.poll_timeout().map(Instant::from_std);
            let can_pull = !closing && self.out.len() < WRITE_HIGH_WATER;
            // Non biaisé : sous fort trafic entrant, une lecture toujours prête
            // affamerait l'émission. Le refus HTTP ne survient qu'à l'établissement.
            let flow = tokio::select! {
                r = self.rd.read_buf(self.dec.buffer_mut()) => match r {
                    Ok(0) | Err(_) if closing => {
                        self.finish().await;
                        return Ok(());
                    }
                    Ok(0) => {
                        tracing::debug!("fin du flux TLS");
                        self.finish().await;
                        return Err(TunnelError::ClosedByPeer);
                    }
                    Ok(_) => self.process_input(Some(&*packets)).await?,
                    Err(e) => return Err(e.into()),
                },
                r = write_step(&mut self.wr, &mut self.out), if !self.out.is_empty() || self.unflushed => match r {
                    Ok(flushed) => {
                        self.unflushed = !flushed;
                        Flow::Continue
                    }
                    Err(_) if closing => return Ok(()),
                    Err(e) => return Err(e.into()),
                },
                () = sleep_opt(ppp_deadline) => {
                    self.ppp.handle_timeout(now());
                    self.drain_events(Some(&*packets)).await
                }
                packet = packets.recv(), if can_pull => {
                    match packet {
                        Some(p) => self.queue_ip(&p),
                        None => self.consumer_gone = true,
                    }
                    Flow::Continue
                }
                _ = &mut stop, if !closing => {
                    self.begin_close(&mut closing);
                    Flow::Continue
                }
            };
            match flow {
                Flow::Continue | Flow::Up(_) => {}
                Flow::Down(reason) => return self.end(reason).await,
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
