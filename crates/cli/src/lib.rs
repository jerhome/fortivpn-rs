//! Logique partagée du client : configuration TOML, choix du backend réseau,
//! construction du transport, exécution d'une session, client du service Windows.
//!
//! Utilisée par le binaire `fortivpn` (CLI) et par `fortivpn-gui` (Slint).

pub mod cli;
pub mod config;
pub mod exit;
pub mod logging;
pub mod platform;
pub mod run;
pub mod svc;
pub mod transport;

use zeroize::Zeroizing;

/// Saisie sans écho ; le résultat est effacé à la libération. Refuse le vide.
pub fn read_password(prompt: &str) -> std::io::Result<Zeroizing<String>> {
    let typed = Zeroizing::new(rpassword::prompt_password(prompt)?);
    if typed.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "mot de passe vide",
        ));
    }
    Ok(typed)
}
