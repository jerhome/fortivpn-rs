//! Bascule en flux binaire après `GET /remote/sslvpn-tunnel` (docs/protocol.md §6).
//!
//! La passerelle n'envoie **aucune** réponse HTTP en cas de succès : la connexion TLS est
//! remise telle quelle à un [`TunnelHandler`]. Le pair PPP ([`crate::PppPeer`] : framing
//! 0x5050, LCP/IPCP, écho ICMP) en est un.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use crate::config::TunnelConfig;

/// Futur renvoyé par un [`TunnelHandler`].
pub type TunnelFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Flux TLS brut d'une connexion passée en mode tunnel.
///
/// Les octets éventuellement reçus dans le même enregistrement TLS que la requête
/// `GET /remote/sslvpn-tunnel` (un client peut envoyer sa première trame LCP aussitôt) sont
/// restitués en premier par `poll_read`.
pub struct TunnelStream {
    pending: Vec<u8>,
    pos: usize,
    inner: TlsStream<TcpStream>,
}

impl std::fmt::Debug for TunnelStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelStream")
            .field("pending_len", &(self.pending.len() - self.pos))
            .finish_non_exhaustive()
    }
}

impl TunnelStream {
    pub(crate) fn new(inner: TlsStream<TcpStream>, pending: Vec<u8>) -> Self {
        Self {
            pending,
            pos: 0,
            inner,
        }
    }

    /// Octets reçus avec la requête et pas encore lus.
    pub fn pending(&self) -> &[u8] {
        &self.pending[self.pos..]
    }

    /// Socket TCP sous-jacent (adresses, options).
    pub fn tcp(&self) -> &TcpStream {
        self.inner.get_ref().0
    }

    /// Coupe la connexion **sans** `close_notify` (simule une coupure réseau / RST
    /// applicatif) : il suffit de ne pas appeler `shutdown`.
    pub fn abort(self) {
        drop(self);
    }

    /// Fermeture propre (`close_notify` puis FIN).
    pub async fn close(mut self) -> io::Result<()> {
        self.inner.shutdown().await
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.pending.len() {
            let n = (this.pending.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.pending[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.pending.len() {
                this.pending = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Informations de session transmises au [`TunnelHandler`].
#[derive(Debug, Clone)]
pub struct TunnelContext {
    /// Numéro de connexion (cf. [`crate::LoggedRequest::conn_id`]).
    pub conn_id: u64,
    pub peer: SocketAddr,
    /// Utilisateur authentifié propriétaire du cookie.
    pub username: String,
    /// Configuration servie dans le XML (adresse à attribuer par IPCP, DNS...).
    pub config: Arc<TunnelConfig>,
}

/// Traitement d'une connexion passée en mode tunnel.
///
/// Implémenté automatiquement pour toute closure
/// `Fn(TunnelStream, TunnelContext) -> impl Future<Output = ()> + Send`.
pub trait TunnelHandler: Send + Sync + 'static {
    fn handle(&self, stream: TunnelStream, ctx: TunnelContext) -> TunnelFuture;
}

impl<F, Fut> TunnelHandler for F
where
    F: Fn(TunnelStream, TunnelContext) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    fn handle(&self, stream: TunnelStream, ctx: TunnelContext) -> TunnelFuture {
        Box::pin(self(stream, ctx))
    }
}

/// Handler par défaut : ferme proprement la connexion (`close_notify`) sans rien envoyer.
#[derive(Debug, Clone, Copy, Default)]
pub struct CloseTunnel;

impl TunnelHandler for CloseTunnel {
    fn handle(&self, stream: TunnelStream, _ctx: TunnelContext) -> TunnelFuture {
        Box::pin(async move {
            let _ = stream.close().await;
        })
    }
}
