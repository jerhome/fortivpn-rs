//! Client HTTPS de la passerelle : authentification, allocation, configuration XML,
//! logout (`docs/protocol.md` §1, §4, §5, §10.1, §11).

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use proto::auth::{AuthOutcome, SessionCookie, interpret_logincheck};
use proto::config::{VpnConfig, parse_config};
use proto::http::{self, ConfigQuery, Gateway, HttpResponse, ResponseParser};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

use super::error::SslVpnError;
use super::tls::{self, TlsOptions, TlsSetup};
use crate::transport::Credentials;

/// Délais (§11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Résolution DNS + connexion TCP (15 s).
    pub connect: Duration,
    /// Poignée de main TLS (15 s).
    pub tls_handshake: Duration,
    /// Envoi d'une requête et réception complète de la réponse (30 s).
    pub http: Duration,
    /// Logout complet, connexion comprise (5 s).
    pub logout: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(15),
            tls_handshake: Duration::from_secs(15),
            http: Duration::from_secs(30),
            logout: Duration::from_secs(5),
        }
    }
}

/// Paramètres de connexion à une passerelle SSL-VPN.
#[derive(Debug, Clone)]
pub struct SslVpnOptions {
    /// Nom d'hôte ou adresse IP de la passerelle.
    pub host: String,
    /// Port TCP (443 par défaut, souvent 10443).
    pub port: u16,
    /// Realm (`realm=` toujours envoyé, vide par défaut).
    pub realm: String,
    /// `User-Agent` (défaut `Mozilla/5.0 SV1`).
    pub user_agent: Option<String>,
    /// Options TLS (racines, épinglage, SNI).
    pub tls: TlsOptions,
    /// Délais.
    pub timeouts: Timeouts,
    /// Faire l'« allocation » `/remote/index` + `/remote/fortisslvpn` après
    /// l'authentification (§4.4, défaut : oui, comme openfortivpn).
    pub allocation: bool,
    /// Variante de la requête de configuration.
    pub config_query: ConfigQuery,
}

impl SslVpnOptions {
    /// Options par défaut pour `host:port`.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            realm: String::new(),
            user_agent: None,
            tls: TlsOptions::default(),
            timeouts: Timeouts::default(),
            allocation: true,
            config_query: ConfigQuery::default(),
        }
    }
}

/// Connexion TLS établie vers la passerelle, utilisée pour des échanges HTTP.
pub struct GatewayConnection {
    stream: TlsStream<TcpStream>,
    peer: SocketAddr,
    leftover: Zeroizing<Vec<u8>>,
    http_timeout: Duration,
}

impl fmt::Debug for GatewayConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayConnection")
            .field("peer", &self.peer)
            .field("leftover", &self.leftover.len())
            .finish_non_exhaustive()
    }
}

impl GatewayConnection {
    /// Adresse de la passerelle effectivement jointe (pour la route hors tunnel).
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Envoie une requête et lit la réponse complète (délai HTTP §11).
    pub async fn request(&mut self, request: &[u8]) -> Result<HttpResponse, SslVpnError> {
        timeout(self.http_timeout, self.request_inner(request))
            .await
            .map_err(|_| SslVpnError::Timeout("réponse HTTP"))?
    }

    async fn request_inner(&mut self, request: &[u8]) -> Result<HttpResponse, SslVpnError> {
        self.stream.write_all(request).await?;
        self.stream.flush().await?;
        let mut parser = ResponseParser::new();
        let pending = std::mem::take(&mut self.leftover);
        if !pending.is_empty() {
            if let Some(resp) = parser.push(&pending)? {
                self.leftover = parser.take_remaining();
                return Ok(resp);
            }
        }
        let mut buf = Zeroizing::new(vec![0u8; 8192]);
        loop {
            let n = match self.stream.read(&mut buf[..]).await {
                Ok(n) => n,
                // Fermeture TCP sans close_notify : traitée comme une fin de flux. Les
                // corps utiles (XML) sont auto-délimités, une troncature y est détectée.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                return Ok(parser.finish()?);
            }
            if let Some(resp) = parser.push(&buf[..n])? {
                self.leftover = parser.take_remaining();
                return Ok(resp);
            }
        }
    }

    /// Ferme proprement (`close_notify`), sans attendre plus d'une seconde.
    pub async fn shutdown(mut self) {
        let _ = timeout(Duration::from_secs(1), self.stream.shutdown()).await;
    }

    /// Flux TLS brut et octets déjà reçus non consommés (pour le passage en mode
    /// tunnel, story 2.2).
    pub fn into_parts(self) -> (TlsStream<TcpStream>, Zeroizing<Vec<u8>>) {
        (self.stream, self.leftover)
    }
}

/// Client SSL-VPN d'une passerelle (configuration TLS construite une seule fois).
#[derive(Clone)]
pub struct SslVpnClient {
    gateway: Gateway,
    tls: TlsSetup,
    realm: String,
    timeouts: Timeouts,
    allocation: bool,
    config_query: ConfigQuery,
}

impl fmt::Debug for SslVpnClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SslVpnClient")
            .field("gateway", &self.gateway)
            .field("realm", &self.realm)
            .field("timeouts", &self.timeouts)
            .field("allocation", &self.allocation)
            .finish_non_exhaustive()
    }
}

impl SslVpnClient {
    /// Prépare un client (charge les racines de confiance).
    pub fn new(opts: &SslVpnOptions) -> Result<Self, SslVpnError> {
        let mut gateway = Gateway::new(&opts.host, opts.port)
            .map_err(|e| SslVpnError::InvalidOptions(e.to_string()))?;
        if let Some(ua) = &opts.user_agent {
            gateway = gateway
                .with_user_agent(ua)
                .map_err(|e| SslVpnError::InvalidOptions(e.to_string()))?;
        }
        let tls = tls::setup(gateway.host(), &opts.tls)?;
        Ok(Self {
            gateway,
            tls,
            realm: opts.realm.clone(),
            timeouts: opts.timeouts,
            allocation: opts.allocation,
            config_query: opts.config_query,
        })
    }

    /// Cible HTTP.
    pub fn gateway(&self) -> &Gateway {
        &self.gateway
    }

    /// Ouvre une nouvelle connexion TCP + TLS (délais §11).
    pub async fn connect(&self) -> Result<GatewayConnection, SslVpnError> {
        let tcp = timeout(self.timeouts.connect, self.connect_tcp())
            .await
            .map_err(|_| SslVpnError::Timeout("connexion TCP"))??;
        let peer = tcp.peer_addr()?;
        let connector = TlsConnector::from(self.tls.config.clone());
        let stream = timeout(
            self.timeouts.tls_handshake,
            connector.connect(self.tls.connect_name.clone(), tcp),
        )
        .await
        .map_err(|_| SslVpnError::Timeout("poignée de main TLS"))?
        .map_err(|e| match tls::untrusted_from_io(&e) {
            Some((fp, reason)) => {
                tracing::warn!(sha256 = %fp, %reason, "certificat de la passerelle refusé");
                SslVpnError::TlsUntrusted {
                    sha256_hex: fp.to_hex(),
                    reason,
                }
            }
            None => SslVpnError::Tls(e),
        })?;
        tracing::debug!(%peer, "connexion TLS établie");
        Ok(GatewayConnection {
            stream,
            peer,
            leftover: Zeroizing::new(Vec::new()),
            http_timeout: self.timeouts.http,
        })
    }

    async fn connect_tcp(&self) -> Result<TcpStream, SslVpnError> {
        let mut addrs: Vec<_> = tokio::net::lookup_host((self.gateway.host(), self.gateway.port()))
            .await
            .map_err(SslVpnError::Resolve)?
            .collect();
        // IPv4 d'abord : les backends réseau ne gèrent qu'une passerelle IPv4 (la route
        // /32 vers la passerelle et le blocage IPv6 du full-tunnel en dépendent). Une
        // passerelle double pile (A + AAAA) doit donc être jointe en IPv4 ; l'IPv6 ne
        // sert qu'en dernier recours. Tri stable : l'ordre DNS est conservé par famille.
        addrs.sort_by_key(std::net::SocketAddr::is_ipv6);
        let mut last_err = None;
        for addr in addrs {
            match TcpStream::connect(addr).await {
                Ok(s) => {
                    // §2.1 : TCP_NODELAY dès la connexion.
                    s.set_nodelay(true)?;
                    return Ok(s);
                }
                Err(e) => {
                    tracing::debug!(%addr, error = %e, "connexion TCP échouée");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.map_or_else(
            || {
                SslVpnError::Resolve(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "aucune adresse",
                ))
            },
            SslVpnError::Connect,
        ))
    }

    /// Authentification login/mot de passe (§4.2–§4.4) : `POST /remote/logincheck` sur
    /// une connexion neuve (rejouée une fois sur nouvelle connexion en cas d'erreur
    /// d'E/S, comme openfortivpn), puis « allocation » si activée, puis fermeture.
    pub async fn authenticate(&self, creds: &Credentials) -> Result<SessionCookie, SslVpnError> {
        let request =
            http::logincheck_request(&self.gateway, &creds.username, &creds.password, &self.realm);
        let (mut conn, response) = match self.connect_and_request(&request).await {
            Err(SslVpnError::Io(e)) => {
                tracing::debug!(error = %e, "logincheck : erreur d'E/S, nouvelle tentative");
                self.connect_and_request(&request).await?
            }
            other => other?,
        };
        drop(request);
        tracing::debug!(status = response.status(), "réponse logincheck");
        let cookie = match interpret_logincheck(&response) {
            AuthOutcome::Success { cookie } => cookie,
            AuthOutcome::BadCredentials => return Err(SslVpnError::AuthFailed),
            AuthOutcome::UnsupportedChallenge => return Err(SslVpnError::UnsupportedChallenge),
            AuthOutcome::TwoFactorRequired(_) => return Err(SslVpnError::SecondFactorRequired),
            AuthOutcome::Redirect { status, location } => {
                return Err(SslVpnError::Redirect { status, location });
            }
            AuthOutcome::HttpStatus(s) => return Err(SslVpnError::HttpStatus(s)),
            AuthOutcome::InvalidCookie(e) => return Err(SslVpnError::InvalidCookie(e)),
            // NoCookie et variantes futures.
            _ => return Err(SslVpnError::NoCookie),
        };
        tracing::info!(host = self.gateway.host(), "authentification réussie");

        let allocation = if self.allocation {
            self.allocate(&mut conn, &cookie).await
        } else {
            Ok(())
        };
        if let Err(e) = allocation {
            conn.shutdown().await;
            // §10.1 : logout aussi en cas d'échec après l'authentification.
            if let Err(le) = self.logout(&cookie).await {
                tracing::debug!(error = %le, "logout après échec d'allocation");
            }
            return Err(e);
        }
        conn.shutdown().await;
        Ok(cookie)
    }

    async fn connect_and_request(
        &self,
        request: &[u8],
    ) -> Result<(GatewayConnection, HttpResponse), SslVpnError> {
        let mut conn = self.connect().await?;
        let response = conn.request(request).await?;
        Ok((conn, response))
    }

    /// `GET /remote/index` puis `GET /remote/fortisslvpn`, réponses ignorées sauf
    /// erreur de transport ou marqueur « permission refusée » (§3.2, §4.4).
    async fn allocate(
        &self,
        conn: &mut GatewayConnection,
        cookie: &SessionCookie,
    ) -> Result<(), SslVpnError> {
        for request in http::allocation_requests(&self.gateway, cookie) {
            let response = conn.request(&request).await?;
            tracing::debug!(status = response.status(), "réponse d'allocation");
            if response.is_permission_denied() {
                return Err(SslVpnError::AuthFailed);
            }
        }
        Ok(())
    }

    /// `GET /remote/fortisslvpn_xml` sur une connexion **neuve** (§1, §5). Une seule
    /// tentative (redemander la configuration peut invalider le cookie). Renvoie la
    /// configuration et la connexion, sur laquelle openfortivpn envoie ensuite
    /// `GET /remote/sslvpn-tunnel` (§6).
    pub async fn fetch_config(
        &self,
        cookie: &SessionCookie,
    ) -> Result<(VpnConfig, GatewayConnection), SslVpnError> {
        let mut conn = self.connect().await?;
        let request = http::config_request(&self.gateway, cookie, self.config_query);
        let response = conn.request(&request).await?;
        drop(request);
        tracing::debug!(status = response.status(), "réponse fortisslvpn_xml");
        if response.is_permission_denied() {
            return Err(SslVpnError::AuthFailed);
        }
        match response.status() {
            200 => {}
            401 | 403 => return Err(SslVpnError::SessionExpired),
            s @ 300..=399 => {
                let location = response.location().map(str::to_owned);
                if location
                    .as_deref()
                    .is_some_and(|l| l.contains("/remote/login"))
                {
                    return Err(SslVpnError::SessionExpired);
                }
                return Err(SslVpnError::Redirect {
                    status: s,
                    location,
                });
            }
            s => return Err(SslVpnError::HttpStatus(s)),
        }
        let config = parse_config(response.body())?;
        tracing::info!(
            split = config.is_split_tunnel(),
            routes = config.ipv4.include_routes.len(),
            excluded = config.ipv4.exclude_routes.len(),
            dns = config.ipv4.dns_servers.len(),
            "configuration reçue"
        );
        Ok((config, conn))
    }

    /// `GET /remote/logout` sur une connexion neuve, réponse ignorée, délai global de
    /// 5 s (§10.1). Les erreurs peuvent être ignorées par l'appelant.
    pub async fn logout(&self, cookie: &SessionCookie) -> Result<(), SslVpnError> {
        timeout(self.timeouts.logout, async {
            let mut conn = self.connect().await?;
            let response = conn
                .request(&http::logout_request(&self.gateway, cookie))
                .await?;
            tracing::debug!(status = response.status(), "réponse logout");
            conn.shutdown().await;
            Ok(())
        })
        .await
        .map_err(|_| SslVpnError::Timeout("logout"))?
    }
}
