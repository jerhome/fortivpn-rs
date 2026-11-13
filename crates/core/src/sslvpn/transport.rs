//! [`Transport`] SSL-VPN complet (story 5.4) : HTTPS (auth, configuration XML) puis
//! tunnel PPP sur la connexion de configuration (`docs/protocol.md` §1, §6, §10).
//!
//! `connect` enchaîne :
//!
//! 1. [`SslVpnClient::authenticate`] → [`ConnectStep::Authenticated`] (sauté si un
//!    cookie encore valide est détenu, cf. [`SslVpnTransport::close_tunnel`]) ;
//! 2. [`SslVpnClient::fetch_config`] → [`ConnectStep::ConfigReceived`] ;
//! 3. `GET /remote/sslvpn-tunnel` sur la même connexion, puis négociation PPP
//!    ([`tunnel::open_with_buffered`]) ;
//! 4. fusion XML + IPCP ([`tunnel_config`]).
//!
//! Avec un cookie réutilisé, un refus (`SessionExpired`, tunnel refusé en HTTP…)
//! déclenche une seule ré-authentification complète.
//!
//! `suspend` (reconnexion automatique) ferme seulement le tunnel et garde le cookie ;
//! `disconnect` ferme le tunnel (LCP Terminate puis TLS, borné ~3 s) puis fait le
//! logout (best effort, borné par [`Timeouts::logout`](super::Timeouts)).

use std::fmt;
use std::sync::Arc;

use proto::auth::SessionCookie;

use super::client::{SslVpnClient, SslVpnOptions};
use super::config::tunnel_config;
use super::error::SslVpnError;
use crate::error::TransportError;
use crate::transport::{
    ConnectStep, Credentials, ProgressSink, SecondFactorProvider, Transport, TransportSession,
};
use crate::tunnel::{self, TunnelError, TunnelHandle, TunnelOptions};

/// Transport SSL-VPN (TLS + HTTP + PPP sur `0x5050`).
pub struct SslVpnTransport {
    client: SslVpnClient,
    /// Options PPP imposées (tests) ; `None` : défauts avec Magic-Number aléatoire
    /// tiré à chaque connexion.
    tunnel_options: Option<TunnelOptions>,
    progress: Option<ProgressSink>,
    second_factor: Option<Arc<dyn SecondFactorProvider>>,
    cookie: Option<SessionCookie>,
    tunnel: Option<TunnelHandle>,
}

impl fmt::Debug for SslVpnTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Le cookie n'est jamais affiché : seulement sa présence.
        f.debug_struct("SslVpnTransport")
            .field("client", &self.client)
            .field("second_factor", &self.second_factor.is_some())
            .field("has_cookie", &self.cookie.is_some())
            .field("tunnel_open", &self.tunnel.is_some())
            .finish_non_exhaustive()
    }
}

/// Étape en échec d'une tentative de connexion, pour décider d'une ré-authentification.
enum Attempt {
    /// Le cookie n'est plus accepté.
    CookieRefused(TransportError),
    /// Autre échec.
    Failed(TransportError),
}

impl SslVpnTransport {
    /// Transport vers la passerelle décrite par `opts` (configuration TLS construite
    /// ici ; aucune connexion n'est ouverte).
    pub fn new(opts: &SslVpnOptions) -> Result<Self, SslVpnError> {
        Ok(Self::from_client(SslVpnClient::new(opts)?))
    }

    /// Transport utilisant un client déjà construit.
    pub fn from_client(client: SslVpnClient) -> Self {
        Self {
            client,
            tunnel_options: None,
            progress: None,
            second_factor: None,
            cookie: None,
            tunnel: None,
        }
    }

    /// Impose les options du tunnel (MRU, Magic-Number, timers PPP…), ex. pour des
    /// tests déterministes.
    #[must_use]
    pub fn with_tunnel_options(mut self, options: TunnelOptions) -> Self {
        self.tunnel_options = Some(options);
        self
    }

    /// Injecte le fournisseur de second facteur (OTP / FortiToken). Sans lui (défaut),
    /// un challenge donne [`TransportError::SecondFactorRequired`].
    #[must_use]
    pub fn with_second_factor(mut self, provider: Arc<dyn SecondFactorProvider>) -> Self {
        self.second_factor = Some(provider);
        self
    }

    /// Client HTTPS sous-jacent.
    pub fn client(&self) -> &SslVpnClient {
        &self.client
    }

    /// Vrai si un cookie de session est détenu (réutilisable par le prochain
    /// `connect`).
    pub fn has_session_cookie(&self) -> bool {
        self.cookie.is_some()
    }

    /// Ferme le tunnel **sans** logout : le cookie est conservé pour qu'un prochain
    /// [`connect`](Transport::connect) rouvre le tunnel sans ré-authentification
    /// (si la passerelle l'accepte, sinon ré-authentification automatique).
    pub async fn close_tunnel(&mut self) {
        if let Some(handle) = self.tunnel.take() {
            handle.close().await;
        }
    }

    fn report(&self, step: ConnectStep) {
        if let Some(p) = &self.progress {
            p.report(step);
        }
    }

    /// Cookie à utiliser : celui détenu, sinon authentification complète.
    async fn ensure_cookie(&mut self, credentials: &Credentials) -> Result<bool, TransportError> {
        if self.cookie.is_some() {
            tracing::debug!("réutilisation du cookie de session");
            return Ok(true);
        }
        let cookie = self
            .client
            .authenticate_with(credentials, self.second_factor.as_deref())
            .await?;
        self.cookie = Some(cookie);
        self.report(ConnectStep::Authenticated);
        Ok(false)
    }

    /// Configuration + tunnel avec le cookie détenu.
    async fn open_session(&mut self) -> Result<TransportSession, Attempt> {
        let Some(cookie) = self.cookie.as_ref() else {
            return Err(Attempt::CookieRefused(TransportError::AuthFailed));
        };
        let (xml, conn) = match self.client.fetch_config(cookie).await {
            Ok(r) => r,
            Err(e @ (SslVpnError::SessionExpired | SslVpnError::AuthFailed)) => {
                return Err(Attempt::CookieRefused(e.into()));
            }
            Err(e) => return Err(Attempt::Failed(e.into())),
        };
        self.report(ConnectStep::ConfigReceived);
        let gateway_ip = conn.peer_addr().ip();
        let (mut stream, leftover) = conn.into_parts();
        tunnel::send_tunnel_request(&mut stream, cookie)
            .await
            .map_err(|e| Attempt::Failed(e.into()))?;
        let options = self.tunnel_options.clone().unwrap_or_default();
        let tun = tunnel::open_with_buffered(stream, &leftover, options)
            .await
            .map_err(Attempt::from)?;
        drop(leftover);
        let config = match tunnel_config(&xml, gateway_ip, &tun.params.clone().into()) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "configuration du tunnel invalide");
                tun.handle.close().await;
                return Err(Attempt::Failed(e.into()));
            }
        };
        self.tunnel = Some(tun.handle);
        Ok(TransportSession {
            config,
            packets: tun.packets,
            end: tun.end,
        })
    }
}

impl Transport for SslVpnTransport {
    async fn connect(
        &mut self,
        credentials: &Credentials,
    ) -> Result<TransportSession, TransportError> {
        if self.tunnel.as_ref().is_some_and(|h| !h.is_finished()) {
            return Err(TransportError::AlreadyConnected);
        }
        // Tâche d'un tunnel précédent terminé de lui-même : rien à fermer.
        self.tunnel = None;
        let reused = self.ensure_cookie(credentials).await?;
        match self.open_session().await {
            Ok(s) => Ok(s),
            Err(Attempt::CookieRefused(e)) if reused => {
                tracing::info!(error = %e, "cookie refusé : ré-authentification");
                if let Some(old) = self.cookie.take() {
                    // Best effort : libère la session côté passerelle si elle existe.
                    if let Err(e) = self.client.logout(&old).await {
                        tracing::debug!(error = %e, "logout de l'ancien cookie (ignoré)");
                    }
                }
                self.ensure_cookie(credentials).await?;
                self.open_session().await.map_err(|a| match a {
                    Attempt::CookieRefused(e) | Attempt::Failed(e) => e,
                })
            }
            // Cookie neuf refusé ou autre échec : pas de nouvel essai. Le cookie est
            // conservé pour le logout de `disconnect` (§10.1).
            Err(Attempt::CookieRefused(e) | Attempt::Failed(e)) => Err(e),
        }
    }

    async fn disconnect(&mut self) -> Result<(), TransportError> {
        self.close_tunnel().await;
        if let Some(cookie) = self.cookie.take() {
            match self.client.logout(&cookie).await {
                Ok(()) => tracing::info!("déconnexion (logout) effectuée"),
                Err(e) => tracing::debug!(error = %e, "logout en échec (ignoré)"),
            }
        }
        Ok(())
    }

    /// Reconnexion : [`close_tunnel`](Self::close_tunnel) (cookie conservé, pas de
    /// logout).
    async fn suspend(&mut self) -> Result<(), TransportError> {
        self.close_tunnel().await;
        Ok(())
    }

    fn set_progress(&mut self, sink: ProgressSink) {
        self.progress = Some(sink);
    }
}

impl From<TunnelError> for Attempt {
    fn from(e: TunnelError) -> Self {
        if e.requires_reauth() {
            Self::CookieRefused(e.into())
        } else {
            Self::Failed(e.into())
        }
    }
}
