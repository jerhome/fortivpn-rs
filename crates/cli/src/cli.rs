//! Ligne de commande.

use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand};

/// Client Fortinet SSL VPN.
#[derive(Debug, Parser)]
#[command(
    name = "fortivpn",
    version,
    about = "Client Fortinet SSL VPN",
    long_about = "Client Fortinet SSL VPN.\n\n\
        Le mot de passe est demandé à chaque connexion (saisie sans écho) et n'est \
        jamais stocké : il ne peut être passé ni en argument, ni par variable \
        d'environnement, ni dans le fichier de configuration.",
    after_help = crate::exit::HELP,
)]
pub(crate) struct Cli {
    /// Fichier de configuration TOML (défaut : %APPDATA%\fortivpn-rs\config.toml
    /// sous Windows, ~/.config/fortivpn-rs/config.toml sous Linux).
    #[arg(short, long, global = true, value_name = "CHEMIN")]
    pub(crate) config: Option<PathBuf>,

    /// Journalisation plus détaillée (-v : debug, -vv : trace), relativement au
    /// niveau `log_level` de la configuration.
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub(crate) verbose: u8,

    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

/// Options de `connect`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Args)]
pub(crate) struct ConnectArgs {
    /// Se connecter via le service Windows (SYSTEM) au lieu de ce processus : le
    /// service lit lui-même sa configuration (`%ProgramData%\fortivpn-rs\config.toml`),
    /// seul le mot de passe est envoyé ; aucune élévation de privilèges requise.
    #[arg(long)]
    pub(crate) service: bool,
}

/// Actions de `service` (réservées aux administrateurs, sauf `run`, lancé par le
/// gestionnaire de services).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Subcommand)]
pub(crate) enum ServiceAction {
    /// Installer le service (démarrage automatique, compte SYSTEM) et le démarrer.
    Install,
    /// Arrêter et supprimer le service.
    Uninstall,
    /// Démarrer le service.
    Start,
    /// Arrêter le service (coupe la connexion et nettoie le réseau).
    Stop,
    /// Corps du service (lancé par le gestionnaire de services, pas à la main).
    #[command(hide = true)]
    Run,
}

/// Sous-commandes (`connect` par défaut).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Subcommand)]
pub(crate) enum Command {
    /// Se connecter (commande par défaut) ; Ctrl+C pour se déconnecter proprement.
    Connect(ConnectArgs),
    /// Couper la connexion établie par le service.
    Disconnect,
    /// État de la connexion du service (étapes et durées).
    Status,
    /// Gérer le service Windows (administrateur).
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Valider la configuration et l'afficher (sans secret).
    CheckConfig,
    /// Afficher la version.
    Version,
}

impl Cli {
    /// Sous-commande effective.
    pub(crate) fn subcommand(&self) -> Command {
        self.command
            .unwrap_or(Command::Connect(ConnectArgs::default()))
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("fortivpn").chain(args.iter().copied()))
    }

    #[test]
    fn definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn connect_is_default() {
        let cli = parse(&[]).unwrap();
        assert_eq!(cli.subcommand(), Command::Connect(ConnectArgs::default()));
        assert_eq!(cli.config, None);
        assert_eq!(cli.verbose, 0);
    }

    #[test]
    fn options_and_subcommands() {
        let cli = parse(&["check-config", "--config", "/tmp/c.toml", "-vv"]).unwrap();
        assert_eq!(cli.subcommand(), Command::CheckConfig);
        assert_eq!(
            cli.config.as_deref(),
            Some(std::path::Path::new("/tmp/c.toml"))
        );
        assert_eq!(cli.verbose, 2);
        assert_eq!(
            parse(&["-v", "version"]).unwrap().subcommand(),
            Command::Version
        );
        assert_eq!(
            parse(&["connect"]).unwrap().subcommand(),
            Command::Connect(ConnectArgs::default())
        );
        assert_eq!(
            parse(&["connect", "--service"]).unwrap().subcommand(),
            Command::Connect(ConnectArgs { service: true })
        );
        assert_eq!(parse(&["status"]).unwrap().subcommand(), Command::Status);
        assert_eq!(
            parse(&["disconnect"]).unwrap().subcommand(),
            Command::Disconnect
        );
        assert_eq!(
            parse(&["service", "install"]).unwrap().subcommand(),
            Command::Service {
                action: ServiceAction::Install
            }
        );
        assert!(parse(&["service"]).is_err());
    }

    #[test]
    fn no_password_option() {
        assert!(parse(&["--password", "x"]).is_err());
        assert!(parse(&["connect", "-p", "x"]).is_err());
        assert_eq!(
            parse(&["--bogus"]).unwrap_err().exit_code(),
            i32::from(crate::exit::Exit::Usage.code())
        );
    }
}
