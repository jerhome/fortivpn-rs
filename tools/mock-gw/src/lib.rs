//! Fausse passerelle FortiGate pour les tests (TLS + auth + XML + PPP).
//!
//! Ne contacte jamais une vraie passerelle : sert de pair aux tests d'intégration et e2e.
//! Implémente la partie HTTPS de docs/protocol.md (§3 à §6, §10.1) :
//!
//! | Requête | Comportement |
//! |---|---|
//! | `GET /remote/login[?..]` | 200, page HTML |
//! | `POST /remote/logincheck` | `ret=1` + `SVPNCOOKIE`, ou échec selon [`LoginFailure`] / [`Scenario`] |
//! | `GET /remote/index`, `GET /remote/fortisslvpn` | « allocation » : 200 si cookie valide, sinon 302 vers `/remote/login` |
//! | `GET /remote/fortisslvpn_xml[?dual_stack=1]` | XML généré depuis [`TunnelConfig`] ; cookie invalide → [`ExpiredSession`] |
//! | `GET /remote/sslvpn-tunnel` | cookie valide : aucune réponse, flux remis au [`TunnelHandler`] ; sinon 403 |
//! | `GET /remote/logout` | 200, cookie effacé et session fermée |
//!
//! Le flux tunnel est servi par [`PppPeer`] (LCP/IPCP, écho ICMP, pannes [`PppFault`]) si
//! on le passe à [`MockGatewayBuilder::tunnel_handler`] ; défaut : [`CloseTunnel`].
//!
//! ```no_run
//! # async fn demo() -> std::io::Result<()> {
//! use mock_gw::{MockGateway, Scenario};
//! let gw = MockGateway::builder()
//!     .credentials("jdoe", "S3cr3t!&= é")
//!     .scenario(Scenario::Nominal)
//!     .start()
//!     .await?;
//! println!("{} {}", gw.addr(), gw.cert().sha256_hex());
//! gw.shutdown().await;
//! # Ok(()) }
//! ```

mod config;
mod http;
mod icmp;
mod log;
mod ppp;
mod server;
mod tls;
mod tunnel;

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

pub use crate::config::{
    AuthSession, ClientConfig, DnsServer, DtlsConfig, FosVersion, Ipv4Config, Ipv6Config, SplitDns,
    TunnelConfig,
};
pub use crate::icmp::{IcmpDrop, REPLY_TTL, icmp_echo_reply, internet_checksum, ipv4_addrs};
pub use crate::log::{
    AuthOutcome, CookieCheck, LoggedRequest, LoggedResponse, REDACTED, RequestLog,
};
pub use crate::ppp::{
    DEFAULT_GATEWAY_MAGIC, DEFAULT_GATEWAY_PPP_ADDR, DEFAULT_REPLY_IP_ID, FaultTrigger,
    GatewayIpcpRequest, IpBridge, IpLink, IpcpUp, MalformedFrame, PeerEnd, PeerPhase, PppCounters,
    PppFault, PppObserver, PppPeer, PppPeerConfig, PppStatus,
};
pub use crate::tls::GatewayCert;
pub use crate::tunnel::{CloseTunnel, TunnelContext, TunnelFuture, TunnelHandler, TunnelStream};

/// Utilisateur par défaut (fictif, cf. docs/vectors/README.md).
pub const DEFAULT_USERNAME: &str = "jdoe";
/// Mot de passe par défaut (fictif, cf. `logincheck_request.http`).
pub const DEFAULT_PASSWORD: &str = "S3cr3t!&= é";

/// Forme de la réponse à des identifiants refusés (docs/protocol.md §4.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LoginFailure {
    /// 200 + `ret=0` + `SVPNCOOKIE` vide (`logincheck_failure.http`).
    #[default]
    Ret0,
    /// `405 Method Not Allowed` (`logincheck_failure_405.http`).
    Status405,
}

/// Réponse de `/remote/fortisslvpn_xml` quand le cookie est absent/invalide (§5.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ExpiredSession {
    /// `302 Found`, `Location: /remote/login` (anciens FortiOS).
    #[default]
    RedirectToLogin,
    /// `403 Forbidden`.
    Forbidden,
    /// `401 Unauthorized`.
    Unauthorized,
}

/// Point de coupure pour [`Scenario::DropAfterAuth`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropPoint {
    /// Réponse `ret=1` envoyée, puis connexion coupée sans `close_notify`.
    AfterLoginResponse,
    /// Toute requête d'allocation (`/remote/index`, `/remote/fortisslvpn`) ou de config
    /// (`/remote/fortisslvpn_xml`) avec un cookie valide : coupure sans réponse.
    BeforeConfig,
    /// `GET /remote/sslvpn-tunnel` avec un cookie valide : coupure sans réponse.
    BeforeTunnel,
}

/// Scénario de comportement de la passerelle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Scenario {
    /// Comportement nominal (un mauvais mot de passe est refusé selon [`LoginFailure`]).
    #[default]
    Nominal,
    /// Identifiants corrects mais 2FA exigée : 200 + `tokeninfo=`, sans cookie
    /// (`logincheck_2fa_tokeninfo.http`).
    SecondFactorRequired,
    /// Un cookie est émis au login mais n'est jamais reconnu ensuite (session expirée /
    /// consommée) : config → [`ExpiredSession`], tunnel → 403.
    CookieRejected,
    /// Coupure TLS après une authentification réussie.
    DropAfterAuth(DropPoint),
}

/// Point d'entrée : `MockGateway::builder()`.
#[derive(Debug, Clone, Copy)]
pub struct MockGateway;

impl MockGateway {
    pub fn builder() -> MockGatewayBuilder {
        MockGatewayBuilder::default()
    }
}

/// Options internes partagées par les connexions.
pub(crate) struct Options {
    pub(crate) username: String,
    pub(crate) password: Zeroizing<String>,
    pub(crate) realm: Option<String>,
    pub(crate) login_failure: LoginFailure,
    pub(crate) expired_session: ExpiredSession,
    pub(crate) scenario: Scenario,
    pub(crate) fixed_cookie: Option<Zeroizing<String>>,
    pub(crate) io_timeout: Duration,
}

/// Configuration de la fausse passerelle.
pub struct MockGatewayBuilder {
    listen: SocketAddr,
    hostnames: Vec<String>,
    opts: Options,
    tunnel_config: TunnelConfig,
    handler: Arc<dyn TunnelHandler>,
}

impl std::fmt::Debug for MockGatewayBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockGatewayBuilder")
            .field("listen", &self.listen)
            .field("hostnames", &self.hostnames)
            .field("username", &self.opts.username)
            .field("password", &REDACTED)
            .field("realm", &self.opts.realm)
            .field("login_failure", &self.opts.login_failure)
            .field("expired_session", &self.opts.expired_session)
            .field("scenario", &self.opts.scenario)
            .field("tunnel_config", &self.tunnel_config)
            .finish_non_exhaustive()
    }
}

impl Default for MockGatewayBuilder {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            hostnames: vec![
                "vpn.example.com".into(),
                "localhost".into(),
                "127.0.0.1".into(),
            ],
            opts: Options {
                username: DEFAULT_USERNAME.into(),
                password: Zeroizing::new(DEFAULT_PASSWORD.into()),
                realm: None,
                login_failure: LoginFailure::default(),
                expired_session: ExpiredSession::default(),
                scenario: Scenario::default(),
                fixed_cookie: None,
                io_timeout: Duration::from_secs(30),
            },
            tunnel_config: TunnelConfig::default(),
            handler: Arc::new(CloseTunnel),
        }
    }
}

impl MockGatewayBuilder {
    /// Adresse d'écoute (défaut `127.0.0.1:0`, port choisi par l'OS).
    #[must_use]
    pub fn listen(mut self, addr: SocketAddr) -> Self {
        self.listen = addr;
        self
    }

    /// Noms (DNS ou IP littérales) mis dans le SAN du certificat auto-signé.
    /// Défaut : `vpn.example.com`, `localhost`, `127.0.0.1`.
    #[must_use]
    pub fn hostnames<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.hostnames = names.into_iter().map(Into::into).collect();
        self
    }

    /// Identifiants attendus (défaut : [`DEFAULT_USERNAME`] / [`DEFAULT_PASSWORD`]).
    #[must_use]
    pub fn credentials(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.opts.username = username.into();
        self.opts.password = Zeroizing::new(password.into());
        self
    }

    /// Realm exigé ; `None` (défaut) accepte n'importe quel realm, y compris vide.
    #[must_use]
    pub fn realm(mut self, realm: Option<String>) -> Self {
        self.opts.realm = realm;
        self
    }

    #[must_use]
    pub fn login_failure(mut self, mode: LoginFailure) -> Self {
        self.opts.login_failure = mode;
        self
    }

    #[must_use]
    pub fn expired_session(mut self, mode: ExpiredSession) -> Self {
        self.opts.expired_session = mode;
        self
    }

    #[must_use]
    pub fn scenario(mut self, scenario: Scenario) -> Self {
        self.opts.scenario = scenario;
        self
    }

    /// Valeur fixe du `SVPNCOOKIE` émis (défaut : 32 octets aléatoires en hexadécimal par
    /// login). Permet de rejouer les vecteurs qui contiennent un cookie.
    #[must_use]
    pub fn session_cookie(mut self, value: impl Into<String>) -> Self {
        self.opts.fixed_cookie = Some(Zeroizing::new(value.into()));
        self
    }

    /// Délai max de handshake TLS et d'attente d'une requête HTTP (défaut 30 s).
    #[must_use]
    pub fn io_timeout(mut self, timeout: Duration) -> Self {
        self.opts.io_timeout = timeout;
        self
    }

    /// Configuration renvoyée par `/remote/fortisslvpn_xml` (défaut
    /// [`TunnelConfig::vector_split`]).
    #[must_use]
    pub fn tunnel_config(mut self, config: TunnelConfig) -> Self {
        self.tunnel_config = config;
        self
    }

    /// Traitement des connexions passées en mode tunnel (défaut [`CloseTunnel`]).
    #[must_use]
    pub fn tunnel_handler(mut self, handler: impl TunnelHandler) -> Self {
        self.handler = Arc::new(handler);
        self
    }

    /// Génère le certificat, ouvre l'écoute et lance la boucle d'acceptation (tâche tokio).
    pub async fn start(self) -> io::Result<RunningGateway> {
        let (cert, server_config) = tls::generate(&self.hostnames)?;
        let listener = TcpListener::bind(self.listen).await?;
        let addr = listener.local_addr()?;
        let log = RequestLog::default();
        let shared = Arc::new(server::Shared::new(
            self.opts,
            Arc::new(self.tunnel_config),
            self.handler,
            log.clone(),
        ));
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(server::accept_loop(listener, server_config, shared, rx));
        Ok(RunningGateway {
            addr,
            cert,
            log,
            shutdown: Some(tx),
            task: Some(task),
        })
    }
}

/// Passerelle en cours d'exécution. L'arrêter avec [`RunningGateway::shutdown`] ; le
/// `Drop` déclenche aussi l'arrêt (sans l'attendre).
#[derive(Debug)]
pub struct RunningGateway {
    addr: SocketAddr,
    cert: GatewayCert,
    log: RequestLog,
    shutdown: Option<watch::Sender<bool>>,
    task: Option<JoinHandle<()>>,
}

impl RunningGateway {
    /// Adresse d'écoute effective.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Certificat serveur (DER + empreinte SHA-256 pour l'épinglage).
    pub fn cert(&self) -> &GatewayCert {
        &self.cert
    }

    /// Journal des requêtes reçues (secrets masqués).
    pub fn log(&self) -> &RequestLog {
        &self.log
    }

    /// Arrête l'écoute, interrompt toutes les connexions (y compris les tunnels) et attend
    /// la fin de la tâche d'acceptation.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(true);
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for RunningGateway {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(true);
        }
    }
}
