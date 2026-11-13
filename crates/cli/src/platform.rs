//! Éléments dépendant de l'OS : backend réseau, durcissement, signaux d'arrêt.

use std::io;
use std::time::Duration;

use fortivpn_core::{
    NetBackend, NetCleanup, NetError, NetGuard, TunDevice, TunInfo, TunOptions, TunnelConfig,
};

/// Durcissement du processus, à appeler en tout début de `main`.
#[cfg(windows)]
pub fn harden_process() -> Result<(), NetError> {
    netwin::harden_dll_search()
}

/// Durcissement du processus (rien à faire hors Windows).
#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps)]
pub fn harden_process() -> Result<(), NetError> {
    Ok(())
}

/// Backend réseau de l'OS.
#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps)]
pub fn backend() -> Result<netlinux::LinuxNetBackend, NetError> {
    // DNS ignoré : le backend Linux sert aux tests e2e dans WSL.
    Ok(netlinux::LinuxNetBackend::new())
}

/// Backend réseau de l'OS : prend le verrou d'instance unique, purge les résidus
/// d'une exécution interrompue et avertit si des règles NRPT de GPO sont présentes.
#[cfg(windows)]
pub fn backend() -> Result<netwin::WinNetBackend, NetError> {
    let backend = netwin::WinNetBackend::new(netwin::WinNetOptions::default())?;
    match backend.recover_stale() {
        Ok(report) => tracing::debug!(?report, "récupération des résidus réseau"),
        // `apply` refait la récupération : on continue.
        Err(e) => tracing::warn!(error = %e, "récupération des résidus réseau impossible"),
    }
    match backend.gpo_nrpt_active() {
        Ok(true) => tracing::warn!("{GPO_NRPT_WARNING}"),
        Ok(false) => {}
        Err(e) => tracing::debug!(error = %e, "détection des règles NRPT de GPO impossible"),
    }
    Ok(backend)
}

/// Backend réseau du système, selon l'OS.
#[cfg(target_os = "linux")]
pub type SystemBackend = netlinux::LinuxNetBackend;
/// Backend réseau du système, selon l'OS.
#[cfg(windows)]
pub type SystemBackend = netwin::WinNetBackend;

/// Backend choisi par la configuration : système (TUN, routes, DNS ; droits
/// administrateur) ou proxy en espace utilisateur (section `[proxy]`, aucun droit).
#[derive(Debug)]
pub enum AnyBackend {
    System(SystemBackend),
    Proxy(netproxy::ProxyBackend),
}

/// Annulation correspondant à [`AnyBackend`].
#[derive(Debug)]
pub enum AnyCleanup {
    System(<SystemBackend as NetBackend>::Cleanup),
    Proxy(netproxy::ProxyCleanup),
}

/// Choisit le backend. En mode proxy, le backend système n'est **pas** créé : ni
/// verrou d'instance, ni récupération des résidus, ni aucun appel privilégié
/// (seul le durcissement du chargement des DLL, fait en début de `main`, reste).
pub fn select_backend(proxy: Option<&netproxy::ProxyConfig>) -> Result<AnyBackend, NetError> {
    match proxy {
        None => backend().map(AnyBackend::System),
        Some(config) => {
            let proxy = netproxy::ProxyBackend::new(config.clone()).map_err(|e| match e {
                netproxy::ProxyError::Bind { source, .. } => NetError::Io {
                    op: "proxy_listen",
                    source,
                },
                other => NetError::Os {
                    op: "proxy_config",
                    reason: other.to_string(),
                },
            })?;
            if let Some(addr) = proxy.socks_addr() {
                tracing::info!("mode proxy : SOCKS5 sur {addr}");
            }
            for (listen, target) in proxy.forwards() {
                tracing::info!("mode proxy : redirection {listen} -> {target}");
            }
            Ok(AnyBackend::Proxy(proxy))
        }
    }
}

impl NetBackend for AnyBackend {
    type Cleanup = AnyCleanup;

    async fn create_tun(&self, options: &TunOptions) -> Result<TunDevice, NetError> {
        match self {
            Self::System(b) => b.create_tun(options).await,
            Self::Proxy(b) => b.create_tun(options).await,
        }
    }

    async fn apply(
        &self,
        tun: &TunInfo,
        config: &TunnelConfig,
    ) -> Result<NetGuard<AnyCleanup>, NetError> {
        match self {
            Self::System(b) => Ok(b.apply(tun, config).await?.map(AnyCleanup::System)),
            Self::Proxy(b) => Ok(b.apply(tun, config).await?.map(AnyCleanup::Proxy)),
        }
    }

    fn keep_guard_during_reconnect(&self) -> bool {
        match self {
            Self::System(b) => b.keep_guard_during_reconnect(),
            Self::Proxy(b) => b.keep_guard_during_reconnect(),
        }
    }

    #[cfg_attr(not(windows), allow(clippy::unused_async_trait_impl))]
    async fn suspend(&self, _guard: &mut NetGuard<AnyCleanup>) -> Result<(), NetError> {
        // Le backend système suit lui-même sa dernière configuration appliquée ;
        // le mode proxy n'a rien à maintenir (comportement par défaut).
        match self {
            #[cfg(windows)]
            Self::System(b) => b.suspend_protection().await,
            #[cfg(not(windows))]
            Self::System(_) => Ok(()),
            Self::Proxy(_) => Ok(()),
        }
    }
}

impl NetCleanup for AnyCleanup {
    async fn cleanup(&mut self) -> Result<(), NetError> {
        match self {
            Self::System(c) => c.cleanup().await,
            Self::Proxy(c) => c.cleanup().await,
        }
    }

    fn cleanup_blocking(&mut self) -> Result<(), NetError> {
        match self {
            Self::System(c) => c.cleanup_blocking(),
            Self::Proxy(c) => c.cleanup_blocking(),
        }
    }
}

/// Avertissement affiché quand des règles NRPT de stratégie de groupe existent
/// (décision produit : avertir et continuer, ne jamais toucher à la clé Policies).
#[cfg_attr(not(windows), allow(dead_code))]
pub const GPO_NRPT_WARNING: &str = "Windows ignore les règles DNS du tunnel (stratégie de \
     groupe) ; en tunnel complet, la fuite DNS est bloquée par le pare-feu ; en \
     split-tunnel, les noms internes peuvent être résolus par le DNS local.";

/// Plafond de la déconnexion du transport quand Windows impose l'arrêt
/// (`ctrl_close`, `ctrl_logoff`, `ctrl_shutdown`) : il tue le processus après ≈ 5 s.
#[cfg_attr(not(windows), allow(dead_code))]
pub const URGENT_DISCONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// Attente des signaux d'arrêt, installés dès la création.
#[derive(Debug)]
pub struct ShutdownSignals {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(windows)]
    ctrl_c: tokio::signal::windows::CtrlC,
    #[cfg(windows)]
    ctrl_break: tokio::signal::windows::CtrlBreak,
    #[cfg(windows)]
    close: tokio::signal::windows::CtrlClose,
    #[cfg(windows)]
    logoff: tokio::signal::windows::CtrlLogoff,
    #[cfg(windows)]
    shutdown: tokio::signal::windows::CtrlShutdown,
}

impl ShutdownSignals {
    /// Installe les gestionnaires (à appeler dans le runtime tokio). Dès lors, ces
    /// signaux ne terminent plus le processus : ils sont mis en attente pour
    /// [`recv`](Self::recv).
    ///
    /// Unix : `SIGINT` (Ctrl+C), `SIGTERM`. Windows : Ctrl+C, Ctrl+Break, fermeture de
    /// la console, fermeture de session, arrêt du système ; pour ces trois derniers,
    /// Windows termine le processus après un délai (≈ 5 s) : la session nettoie le
    /// réseau avant de déconnecter le transport.
    pub fn install() -> io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self {
                interrupt: signal(SignalKind::interrupt())?,
                terminate: signal(SignalKind::terminate())?,
            })
        }
        #[cfg(windows)]
        {
            use tokio::signal::windows;
            Ok(Self {
                ctrl_c: windows::ctrl_c()?,
                ctrl_break: windows::ctrl_break()?,
                close: windows::ctrl_close()?,
                logoff: windows::ctrl_logoff()?,
                shutdown: windows::ctrl_shutdown()?,
            })
        }
    }

    /// Attend le prochain signal d'arrêt : son nom, et le plafond de déconnexion si
    /// l'OS va tuer le processus ([`URGENT_DISCONNECT_TIMEOUT`]).
    pub async fn recv(&mut self) -> (&'static str, Option<Duration>) {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.interrupt.recv() => ("Ctrl+C", None),
                _ = self.terminate.recv() => ("SIGTERM", None),
            }
        }
        #[cfg(windows)]
        {
            let urgent = Some(URGENT_DISCONNECT_TIMEOUT);
            tokio::select! {
                _ = self.ctrl_c.recv() => ("Ctrl+C", None),
                _ = self.ctrl_break.recv() => ("Ctrl+Break", None),
                _ = self.close.recv() => ("fermeture de la console", urgent),
                _ = self.logoff.recv() => ("fermeture de session", urgent),
                _ = self.shutdown.recv() => ("arrêt du système", urgent),
            }
        }
    }
}
