//! Journalisation (`tracing-subscriber`) sur la sortie d'erreur.
//!
//! Les crates du projet journalisent au niveau demandé, les dépendances seulement
//! leurs avertissements. Pas de pont `log` → `tracing` (rustls reste muet) ni de
//! filtre par variable d'environnement. Aucun secret n'est journalisé par le projet
//! (identifiants masqués dans `Debug`, mot de passe jamais formaté).

use std::io::IsTerminal;

use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::LogLevel;

/// Cibles (`module_path!` racines) des crates du projet.
const PROJECT_TARGETS: &[&str] = &[
    "fortivpn",
    "fortivpn_core",
    "proto",
    "netlinux",
    "netwin",
    "ipsec",
];

fn level_filter(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Trace => LevelFilter::TRACE,
    }
}

/// Filtre : projet au niveau `level`, dépendances en `WARN` (ou moins si `level`
/// est plus strict).
pub(crate) fn filter(level: LogLevel) -> Targets {
    let project = level_filter(level);
    Targets::new()
        .with_default(project.min(LevelFilter::WARN))
        .with_targets(PROJECT_TARGETS.iter().map(|&t| (t, project)))
}

/// Installe l'abonné global (une seule fois ; sans effet ensuite).
pub(crate) fn init(level: LogLevel) {
    // Couleurs seulement sur un terminal Unix (la console Windows classique ne
    // les interprète pas sans activation explicite).
    let ansi = cfg!(unix) && std::io::stderr().is_terminal();
    let layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(ansi)
        .with_target(level >= LogLevel::Debug);
    let _ = tracing_subscriber::registry()
        .with(layer)
        .with(filter(level))
        .try_init();
}

/// Installe l'abonné global écrivant dans `file` (service Windows : pas de console).
#[cfg(windows)]
pub(crate) fn init_to_file(level: LogLevel, file: std::fs::File) {
    let layer = tracing_subscriber::fmt::layer()
        .with_writer(std::sync::Mutex::new(file))
        .with_ansi(false)
        .with_target(level >= LogLevel::Debug);
    let _ = tracing_subscriber::registry()
        .with(layer)
        .with(filter(level))
        .try_init();
}

#[cfg(test)]
mod tests {
    use tracing::Level;

    use super::*;

    #[test]
    fn project_follows_level_dependencies_stay_quiet() {
        let f = filter(LogLevel::Debug);
        assert!(f.would_enable("fortivpn_core::session", &Level::DEBUG));
        assert!(f.would_enable("fortivpn", &Level::DEBUG));
        assert!(!f.would_enable("fortivpn", &Level::TRACE));
        assert!(!f.would_enable("rustls::client", &Level::INFO));
        assert!(f.would_enable("rustls::client", &Level::WARN));

        let f = filter(LogLevel::Error);
        assert!(!f.would_enable("fortivpn_core", &Level::WARN));
        assert!(!f.would_enable("hyper", &Level::WARN));
    }
}
