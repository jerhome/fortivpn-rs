//! Implémentation Windows de `NetBackend` (Wintun, IP Helper, NRPT).
//!
//! # Organisation
//!
//! - `plan`, `state`, `engine` : logique **pure**, compilée et testée sur toutes
//!   les plateformes (`cargo test -p netwin` dans WSL) — plan de routes et DNS,
//!   nommage NRPT, journal d'état persistant, ordre d'installation / rollback,
//!   récupération vérifiée des résidus, plan des filtres WFP (`wfp`) ; `integrity` : décision ACL et
//!   empreinte SHA-256 de `wintun.dll`.
//! - `win` (`cfg(windows)`) : appels système (Wintun, IP Helper, registre) ;
//!   seul code `unsafe` du projet, compilé en cross (`x86_64-pc-windows-gnu`),
//!   jamais exécuté depuis WSL.
//!
//! # Déploiement
//!
//! - **`wintun.dll`** (<https://www.wintun.net>, build `amd64`, signée) doit être
//!   livrée **dans le répertoire de l'exécutable** : elle est chargée par chemin
//!   absolu ([`WinNetOptions::wintun_dll`], par défaut
//!   `<répertoire de l'exe>\wintun.dll`), jamais via le chemin de recherche DLL.
//!   Le répertoire de l'exécutable et la DLL doivent appartenir à
//!   SYSTEM / Administrateurs / `TrustedInstaller` et n'être modifiables que par
//!   eux (vérifié avant chargement : installer sous `C:\Program Files`).
//!   Empreinte SHA-256 optionnelle ([`WINTUN_DLL_SHA256`],
//!   `WinNetOptions::with_wintun_sha256`).
//! - **`harden_dll_search()`** doit être appelée au tout début de `main`
//!   (`SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`).
//! - Une seule instance : mutex nommé `Global\fortivpn-rs-netwin`, pris par
//!   `WinNetBackend::new` et tenu jusqu'à la libération du backend et de ses
//!   guards.
//! - Droits administrateur requis (création d'adaptateur, routes, NRPT).
//! - Windows 10 2004 (build 19041) minimum (`SetInterfaceDnsSettings`).
//! - Journal d'état : valeur `NetwinState` de `HKLM\SOFTWARE\fortivpn-rs`
//!   (non configurable). Appeler `WinNetBackend::recover_stale` au démarrage
//!   pour purger les résidus d'un crash (fait aussi automatiquement par
//!   `apply`) ; chaque entrée est vérifiée contre l'état du système.
#![cfg_attr(not(windows), allow(dead_code))]

mod engine;
mod integrity;
mod plan;
mod state;
mod wfp;
#[cfg(windows)]
mod win;

pub use engine::RecoveryReport;
pub use integrity::WINTUN_DLL_SHA256;
pub use plan::{NRPT_RULE_PREFIX, WINTUN_DLL_NAME};
#[cfg(windows)]
pub use win::{
    INSTANCE_MUTEX_NAME, WinCleanup, WinNetBackend, WinNetOptions, ensure_admin_only,
    harden_dll_search,
};
