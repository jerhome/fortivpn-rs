//! Backend Windows : [`WinNetBackend`] (Wintun + IP Helper + NRPT).

mod ffi;
mod security;
mod tun;
mod wfp;

use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fortivpn_core::{
    NetBackend, NetCleanup, NetError, NetGuard, TunDevice, TunInfo, TunOptions, TunnelConfig,
};

use crate::engine::{self, RecoveryReport, Tracker};
use crate::{integrity, plan, wfp as wfp_plan};
use ffi::{RegistryStore, WinOps};
use security::InstanceLock;
pub use security::{INSTANCE_LOCK_FILE, harden_dll_search};
use wfp::Firewall;

/// Options du backend Windows.
///
/// Fixées par le processus privilégié lui-même : ne jamais les laisser
/// renseigner par un client non privilégié (futur named pipe, story 4.3). Le
/// journal d'état n'est pas configurable (`HKLM\SOFTWARE\fortivpn-rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WinNetOptions {
    /// Chemin absolu de `wintun.dll` (défaut : à côté de l'exécutable). Son
    /// dossier doit être réservé aux administrateurs.
    pub wintun_dll: PathBuf,
    /// Empreinte SHA-256 attendue de `wintun.dll` (défaut :
    /// [`crate::WINTUN_DLL_SHA256`]). `None` : empreinte seulement journalisée.
    pub wintun_sha256: Option<[u8; 32]>,
    /// Filtres WFP en session dynamique (défaut : `true`). Appliqués en
    /// full-tunnel seulement : blocage IPv6 et LLMNR / NBT-NS / mDNS hors
    /// tunnel ; kill-switch sans résidu (retirés si le processus meurt).
    pub wfp_filters: bool,
}

impl Default for WinNetOptions {
    fn default() -> Self {
        let wintun_dll = std::env::current_exe().map_or_else(
            |_| PathBuf::from(plan::WINTUN_DLL_NAME),
            |exe| plan::wintun_path_next_to(&exe),
        );
        Self {
            wintun_dll,
            wintun_sha256: integrity::WINTUN_DLL_SHA256,
            wfp_filters: true,
        }
    }
}

impl WinNetOptions {
    /// Remplace le chemin de `wintun.dll`.
    #[must_use]
    pub fn with_wintun_dll(mut self, path: impl Into<PathBuf>) -> Self {
        self.wintun_dll = path.into();
        self
    }

    /// Remplace l'empreinte SHA-256 attendue de `wintun.dll`.
    #[must_use]
    pub fn with_wintun_sha256(mut self, digest: Option<[u8; 32]>) -> Self {
        self.wintun_sha256 = digest;
        self
    }

    /// Active ou désactive les filtres WFP (full-tunnel seulement).
    #[must_use]
    pub fn with_wfp_filters(mut self, enabled: bool) -> Self {
        self.wfp_filters = enabled;
        self
    }
}

/// `NetBackend` Windows.
///
/// Instance unique par machine : [`WinNetBackend::new`] prend le verrou fichier
/// [`INSTANCE_LOCK_FILE`], tenu jusqu'à ce que le backend, ses clones et tous
/// les [`WinCleanup`] soient libérés.
#[derive(Debug, Clone)]
pub struct WinNetBackend {
    options: WinNetOptions,
    lock: Arc<InstanceLock>,
    /// État du dernier `apply` (pour `suspend`, qui ne reçoit qu'un guard opaque).
    last: Arc<Mutex<Option<Shared>>>,
}

impl WinNetBackend {
    /// Backend avec les options données. Échoue si une autre instance est
    /// active (ou sans droits administrateur).
    pub fn new(options: WinNetOptions) -> Result<Self, NetError> {
        let lock = Arc::new(InstanceLock::acquire()?);
        Ok(Self {
            options,
            lock,
            last: Arc::new(Mutex::new(None)),
        })
    }

    /// Suspension de la dernière configuration appliquée (cf.
    /// `NetBackend::suspend`) : retire routes et DNS, **garde** un bloc WFP de tout
    /// le trafic hors bouclage / passerelle / DHCP jusqu'au démontage du guard
    /// (revue 5.3 passe 2, M2). Sans effet hors full-tunnel ou sans filtres WFP.
    /// Exposée pour les enveloppes de backend qui ne peuvent pas passer le guard.
    pub fn suspend_protection(&self) -> impl Future<Output = Result<(), NetError>> + Send {
        let shared = lock_mutex(&self.last).clone();
        async move {
            let Some(shared) = shared else {
                return Ok(());
            };
            tokio::task::spawn_blocking(move || suspend_blocking(&shared))
                .await
                .map_err(join_err("suspend"))?
        }
    }

    /// Options effectives.
    pub fn options(&self) -> &WinNetOptions {
        &self.options
    }

    /// Purge les résidus laissés par une exécution interrompue (crash, arrêt
    /// brutal), bloquant ; à appeler au démarrage, avant toute connexion.
    ///
    /// Chaque entrée du journal est vérifiée avant retrait : routes seulement
    /// si elles portent nos marques, adresses / DNS d'interface jamais (notre
    /// adaptateur Wintun a disparu avec son processus, et eux avec lui),
    /// règles NRPT seulement sous notre préfixe ; puis règles NRPT fortivpn-rs
    /// orphelines. Erreur si un objet vérifié n'a pas pu être retiré (il reste
    /// dans le journal pour un nouvel essai).
    pub fn recover_stale(&self) -> Result<RecoveryReport, NetError> {
        engine::recover(WinOps, RegistryStore, None)
    }

    /// Diagnostic (lecture seule) : vrai si des règles NRPT de stratégie de
    /// groupe existent. Windows ignore alors les règles NRPT locales posées
    /// par fortivpn-rs : noms internes possiblement résolus hors tunnel, fuite
    /// DNS possible en full-tunnel (revue 5.3, M3). `apply` le signale aussi
    /// par un avertissement, sans refuser la connexion ; rien n'est écrit sous
    /// la clé de stratégie de groupe.
    pub fn gpo_nrpt_active(&self) -> Result<bool, NetError> {
        use crate::engine::SystemOps as _;
        WinOps.nrpt_policy_active()
    }
}

/// Vérifie que `path` (fichier ou dossier) appartient à SYSTEM / Administrateurs /
/// `TrustedInstaller` et n'est modifiable que par eux (liens suivis). Sert au
/// service pour sa configuration et à l'installation (revue 5.3, M4).
pub fn ensure_admin_only(path: &std::path::Path) -> Result<(), NetError> {
    security::check_admin_only(path)
}

/// Comme [`ensure_admin_only`], et contrôle aussi **tous les ancêtres** jusqu'à la
/// racine du volume (aucun ne doit permettre de renommer / supprimer un enfant).
/// À appeler à l'installation du service et à chacun de ses démarrages (revue 5.3
/// passe 2, F1).
pub fn ensure_admin_only_chain(path: &std::path::Path) -> Result<(), NetError> {
    security::check_admin_only_chain(path)
}

fn join_err(op: &'static str) -> impl FnOnce(tokio::task::JoinError) -> NetError {
    move |e| NetError::Os {
        op,
        reason: e.to_string(),
    }
}

/// LUID de notre adaptateur, vérifié : celui dérivé de son GUID déterministe
/// doit être celui désigné par `tun` (revue 5.3, F3 / E1).
fn tunnel_luid(tun: &TunInfo) -> Result<u64, NetError> {
    let by_guid =
        ffi::luid_from_guid(plan::adapter_guid(&tun.name))?.ok_or_else(|| NetError::Os {
            op: "tunnel_luid",
            reason: format!("adaptateur fortivpn-rs « {} » introuvable", tun.name),
        })?;
    let designated = match tun.index {
        Some(index) => ffi::luid_from_index(index)?,
        None => ffi::luid_from_alias(&tun.name)?,
    };
    if designated != by_guid {
        return Err(NetError::Os {
            op: "tunnel_luid",
            reason: format!(
                "l'interface « {} » n'est pas l'adaptateur créé par fortivpn-rs",
                tun.name
            ),
        });
    }
    Ok(by_guid)
}

fn apply_blocking(
    tun: &TunInfo,
    config: &TunnelConfig,
    lock: Arc<InstanceLock>,
    wfp_enabled: bool,
    last: &Mutex<Option<Shared>>,
) -> Result<NetGuard<WinCleanup>, NetError> {
    let luid = tunnel_luid(tun)?;
    // Filtres d'abord : pas de fenêtre de fuite IPv6 / LLMNR. Si la suite
    // échoue, `firewall` est lâché (Drop) : filtres retirés (rollback).
    let firewall = wfp::install(&wfp_plan::plan_filters(config, luid, wfp_enabled))?;
    let tracker = engine::apply_config(WinOps, RegistryStore, luid, config)?;
    tracing::info!(
        interface = %tun.name,
        objects = tracker.installed().len(),
        gpo_nrpt = tracker.gpo_nrpt_detected(),
        wfp = firewall.is_some(),
        "configuration réseau appliquée"
    );
    let shared = Shared {
        tracker: Arc::new(Mutex::new(tracker)),
        firewall: Arc::new(Mutex::new(firewall)),
        hold: Arc::new(Mutex::new(None)),
        hold_specs: Arc::new(wfp_plan::plan_hold_filters(config, wfp_enabled)),
    };
    *lock_mutex(last) = Some(shared.clone());
    Ok(NetGuard::new(WinCleanup {
        shared,
        _lock: lock,
    }))
}

impl NetBackend for WinNetBackend {
    type Cleanup = WinCleanup;

    fn create_tun(
        &self,
        options: &TunOptions,
    ) -> impl Future<Output = Result<TunDevice, NetError>> + Send {
        let dll = self.options.wintun_dll.clone();
        let sha256 = self.options.wintun_sha256;
        let options = options.clone();
        async move {
            let runtime = tokio::runtime::Handle::current();
            tokio::task::spawn_blocking(move || {
                tun::create_tun(&runtime, &dll, sha256.as_ref(), &options)
            })
            .await
            .map_err(join_err("create_tun"))?
        }
    }

    fn keep_guard_during_reconnect(&self) -> bool {
        // Seulement si les filtres WFP sont actifs (sinon rien à maintenir).
        self.options.wfp_filters
    }

    fn suspend(
        &self,
        _guard: &mut NetGuard<WinCleanup>,
    ) -> impl Future<Output = Result<(), NetError>> + Send {
        self.suspend_protection()
    }

    fn apply(
        &self,
        tun: &TunInfo,
        config: &TunnelConfig,
    ) -> impl Future<Output = Result<NetGuard<WinCleanup>, NetError>> + Send {
        let tun = tun.clone();
        let config = config.clone();
        let lock = Arc::clone(&self.lock);
        let wfp_enabled = self.options.wfp_filters;
        let last = Arc::clone(&self.last);
        async move {
            // Rejet immédiat (IPv6, config invalide) sans appel système.
            plan::check_supported(&config)?;
            // Si cette future est abandonnée, la tâche bloquante va à son terme
            // et le guard produit est lâché : son Drop annule la configuration.
            tokio::task::spawn_blocking(move || {
                apply_blocking(&tun, &config, lock, wfp_enabled, &last)
            })
            .await
            .map_err(join_err("apply"))?
        }
    }
}

fn lock_mutex<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Éléments d'une configuration appliquée, partagés entre le guard
/// ([`WinCleanup`]) et le backend (pour `suspend`).
#[derive(Debug, Clone)]
struct Shared {
    // Mutex : sérialise une annulation async en cours (thread bloquant) et
    // l'annulation bloquante du Drop ; chacune ne retire que ce qui reste.
    tracker: Arc<Mutex<Tracker<WinOps, RegistryStore>>>,
    /// Session WFP dynamique du tunnel : sa fermeture retire les filtres.
    firewall: Arc<Mutex<Option<Firewall>>>,
    /// Session WFP de **protection pendant la reconnexion** (M2 passe 2) : bloc de
    /// tout le trafic sauf bouclage / passerelle / DHCP, installée par `suspend`
    /// et retirée seulement quand ce guard est démonté ou lâché (donc après le
    /// `apply` suivant réussi, ou à la déconnexion finale).
    hold: Arc<Mutex<Option<Firewall>>>,
    hold_specs: Arc<Vec<wfp_plan::FilterSpec>>,
}

/// Suspension : retire routes / DNS du tunnel mort mais garde une protection WFP.
/// Make-before-break : la protection est posée **avant** le retrait des filtres du
/// tunnel, il n'y a donc aucune fenêtre de fuite.
fn suspend_blocking(shared: &Shared) -> Result<(), NetError> {
    if !shared.hold_specs.is_empty() && lock_mutex(&shared.hold).is_none() {
        let hold = wfp::install_in(&shared.hold_specs, wfp_plan::HOLD_SUBLAYER_GUID)?;
        *lock_mutex(&shared.hold) = hold;
    }
    lock_mutex(&shared.tracker).uninstall()?;
    // Les filtres du tunnel (même sous-couche que le prochain `apply`) sont
    // retirés ; la protection reste.
    drop(lock_mutex(&shared.firewall).take());
    Ok(())
}

/// Annulation de la configuration appliquée par [`WinNetBackend`] : retire
/// exactement ce qui a été installé (journalisé), en ordre inverse.
#[derive(Debug)]
pub struct WinCleanup {
    shared: Shared,
    /// Verrou d'instance tenu tant que la configuration peut être annulée.
    _lock: Arc<InstanceLock>,
}

/// Routes / DNS d'abord ; puis, seulement si leur annulation a réussi (sinon la
/// protection reste : le Drop du guard ou la mort du processus la ferme), la
/// fermeture des sessions WFP (filtres du tunnel et protection de reconnexion).
fn uninstall_all(shared: &Shared) -> Result<(), NetError> {
    lock_mutex(&shared.tracker).uninstall()?;
    drop(lock_mutex(&shared.firewall).take());
    drop(lock_mutex(&shared.hold).take());
    Ok(())
}

impl NetCleanup for WinCleanup {
    fn cleanup(&mut self) -> impl Future<Output = Result<(), NetError>> + Send {
        let shared = self.shared.clone();
        async move {
            tokio::task::spawn_blocking(move || uninstall_all(&shared))
                .await
                .map_err(join_err("cleanup"))?
        }
    }

    fn cleanup_blocking(&mut self) -> Result<(), NetError> {
        uninstall_all(&self.shared)
    }
}
