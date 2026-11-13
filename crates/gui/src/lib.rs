//! Interface graphique Slint de fortivpn-rs (`fortivpn-gui`).
//!
//! - [`model`] : état d'affichage pur (événements de session → écrans, étapes, journal) ;
//! - [`settings`] : formulaire ⇄ `config.toml` (jamais de mot de passe) ;
//! - [`worker`] : runtime tokio sur un thread dédié (I/O, session, service) ;
//! - [`app`] : fenêtre Slint, rendu de l'état et câblage des callbacks.
//!
//! Ce crate n'écrit aucun `unsafe` ; seul le code généré par les macros de Slint
//! (module `ui`) en contient, d'où `unsafe_code = "deny"` au lieu de `forbid`.

pub mod app;
pub mod model;
pub mod settings;
pub mod worker;

#[allow(
    unsafe_code,
    unreachable_pub,
    missing_debug_implementations,
    clippy::all,
    clippy::todo,
    clippy::dbg_macro,
    clippy::unimplemented,
    clippy::pedantic
)]
pub(crate) mod ui {
    slint::include_modules!();
}
