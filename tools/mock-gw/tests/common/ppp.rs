//! Outils PPP de test : lecture stricte de trames `0x5050` et client piloté par
//! `proto::ppp::PppSession` (sans `core`).

use std::io;
use std::num::NonZeroU32;
use std::time::Instant;

use bytes::BytesMut;
use mock_gw::{PeerEnd, PppPeer, TunnelConfig};
use proto::frame::{FrameDecoder, FrameError, encode_frame, encode_ppp_frame};
use proto::ppp::{DownReason, PppConfig, PppEvent, PppSession, Protocol};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;

use super::TIMEOUT;

/// Lance `peer` sur un flux en mémoire ; renvoie le côté client et la tâche du pair.
pub(crate) fn spawn_peer(
    peer: &PppPeer,
    config: &TunnelConfig,
) -> (DuplexStream, JoinHandle<PeerEnd>) {
    let (client, server) = tokio::io::duplex(256 * 1024);
    let peer = peer.clone();
    let ipv4 = config.ipv4.clone();
    let task = tokio::spawn(async move { peer.serve(server, &ipv4, 7).await });
    (client, task)
}

/// Fin de la tâche du pair (avec délai).
pub(crate) async fn peer_end(task: JoinHandle<PeerEnd>) -> PeerEnd {
    tokio::time::timeout(TIMEOUT, task)
        .await
        .expect("le pair aurait dû se terminer")
        .expect("tâche du pair")
}

/// Lit exactement une trame `0x5050` (en-tête inclus), sans la valider au-delà des
/// longueurs. `Ok(None)` sur EOF propre avant tout octet.
pub(crate) async fn read_wire_frame<S: AsyncRead + Unpin>(
    s: &mut S,
) -> io::Result<Option<Vec<u8>>> {
    let mut head = [0u8; 6];
    let n = tokio::time::timeout(TIMEOUT, s.read(&mut head[..1])).await??;
    if n == 0 {
        return Ok(None);
    }
    tokio::time::timeout(TIMEOUT, s.read_exact(&mut head[1..])).await??;
    let ppp_len = usize::from(u16::from_be_bytes([head[4], head[5]]));
    let mut out = head.to_vec();
    out.resize(6 + ppp_len, 0);
    tokio::time::timeout(TIMEOUT, s.read_exact(&mut out[6..])).await??;
    Ok(Some(out))
}

/// Attend la trame `expected` (octets exacts).
pub(crate) async fn expect_frame<S: AsyncRead + Unpin>(s: &mut S, expected: &[u8], what: &str) {
    let got = read_wire_frame(s)
        .await
        .unwrap_or_else(|e| panic!("{what}: {e}"))
        .unwrap_or_else(|| panic!("{what}: EOF"));
    assert_eq!(hex(&got), hex(expected), "{what}");
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Fin observée par le client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClientEnd {
    /// EOF propre (`close_notify` en TLS, fin du duplex).
    Eof,
    Io(io::ErrorKind),
    Frame(FrameError),
    Down(DownReason),
}

/// Configuration client déterministe pour les tests (keepalive désactivé).
pub(crate) fn client_config() -> PppConfig {
    let mut cfg = PppConfig::new(NonZeroU32::new(0x1a2b_3c4d).unwrap());
    cfg.echo_interval = None;
    cfg
}

/// Client PPP : `PppSession` + framing, sur n'importe quel flux.
pub(crate) struct PppClient<S> {
    pub(crate) stream: S,
    pub(crate) session: PppSession,
    dec: FrameDecoder,
}

impl<S: AsyncRead + AsyncWrite + Unpin> PppClient<S> {
    pub(crate) fn new(stream: S, cfg: PppConfig) -> Self {
        Self {
            stream,
            session: PppSession::new(cfg),
            dec: FrameDecoder::new(),
        }
    }

    pub(crate) async fn flush(&mut self) -> io::Result<()> {
        let mut out = BytesMut::new();
        while let Some(f) = self.session.poll_transmit() {
            encode_frame(&f, &mut out).expect("trame encodable");
        }
        if !out.is_empty() {
            self.stream.write_all(&out).await?;
            self.stream.flush().await?;
        }
        Ok(())
    }

    /// Envoie un datagramme IPv4 (IPCP doit être ouvert).
    pub(crate) async fn send_ipv4(&mut self, ip: &[u8]) -> io::Result<()> {
        assert!(self.session.is_ip_up());
        let mut out = BytesMut::new();
        encode_ppp_frame(Protocol::IPV4, ip, &mut out).unwrap();
        self.stream.write_all(&out).await?;
        self.stream.flush().await
    }

    /// Fait tourner l'automate jusqu'à un événement satisfaisant `pred` (renvoyé), ou une
    /// fin (`Err`). `Down` est toujours une fin, sauf si `pred` l'accepte.
    pub(crate) async fn run_until(
        &mut self,
        mut pred: impl FnMut(&PppEvent) -> bool,
    ) -> Result<PppEvent, ClientEnd> {
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        loop {
            self.flush().await.map_err(|e| ClientEnd::Io(e.kind()))?;
            while let Some(ev) = self.session.poll_event() {
                if pred(&ev) {
                    self.flush().await.map_err(|e| ClientEnd::Io(e.kind()))?;
                    return Ok(ev);
                }
                if let PppEvent::Down(r) = ev {
                    self.flush().await.map_err(|e| ClientEnd::Io(e.kind()))?;
                    return Err(ClientEnd::Down(r));
                }
            }
            // Une trame à la fois : les événements qu'elle produit passent avant une
            // éventuelle erreur de framing sur la trame suivante.
            match self.dec.next_frame() {
                Ok(Some(f)) => {
                    self.session.handle_frame(Instant::now(), f);
                    continue;
                }
                Ok(None) => {}
                Err(e) => return Err(ClientEnd::Frame(e)),
            }
            let wake = self
                .session
                .poll_timeout()
                .map(tokio::time::Instant::from_std);
            let buf = self.dec.buffer_mut();
            buf.reserve(4096);
            tokio::select! {
                r = self.stream.read_buf(buf) => match r {
                    Ok(0) => return Err(ClientEnd::Eof),
                    Ok(_) => {}
                    Err(e) => return Err(ClientEnd::Io(e.kind())),
                },
                () = async {
                    match wake {
                        Some(w) => tokio::time::sleep_until(w).await,
                        None => std::future::pending().await,
                    }
                } => self.session.handle_timeout(Instant::now()),
                () = tokio::time::sleep_until(deadline) => panic!("délai de test dépassé"),
            }
        }
    }

    /// Ouvre la session et attend `IpcpUp`.
    pub(crate) async fn connect(&mut self) -> Result<PppEvent, ClientEnd> {
        self.session.open(Instant::now());
        self.run_until(|e| matches!(e, PppEvent::IpcpUp { .. }))
            .await
    }

    /// Lit jusqu'à la fin du flux après la fin de session.
    pub(crate) async fn drain(&mut self) -> ClientEnd {
        let mut buf = [0u8; 4096];
        loop {
            let r = tokio::time::timeout(TIMEOUT, self.stream.read(&mut buf))
                .await
                .expect("le pair n'a pas fermé le flux");
            match r {
                Ok(0) => return ClientEnd::Eof,
                Ok(_) => {}
                Err(e) => return ClientEnd::Io(e.kind()),
            }
        }
    }
}
