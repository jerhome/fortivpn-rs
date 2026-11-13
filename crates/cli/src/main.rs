//! Binaire `fortivpn` : client Fortinet SSL VPN en ligne de commande.
//!
//! - `fortivpn [connect]` : lit la configuration, demande le mot de passe (sans
//!   écho, jamais stocké), établit le tunnel et le maintient jusqu'à Ctrl+C (ou
//!   fermeture de la console sous Windows), puis nettoie le réseau et se déconnecte.
//! - `fortivpn connect --service` / `disconnect` / `status` : pilotent le service Windows
//!   (SYSTEM) par named pipe, sans privilèges ; `fortivpn service install|uninstall|
//!   start|stop` l'administrent (voir [`svc`]).
//! - `fortivpn check-config` : valide et affiche la configuration.
//! - `fortivpn version`.
//!
//! Codes de sortie : voir [`exit::Exit`].

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use fortivpn_core::Credentials;
use secrecy::SecretString;

use fortivpn_app::cli::{Cli, Command, ConnectArgs};
use fortivpn_app::config::{self, Config};
use fortivpn_app::exit::Exit;
use fortivpn_app::svc::ClientCommand;
use fortivpn_app::{exit, logging, platform, read_password, run, svc, transport};

fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn main() -> ExitCode {
    // Tout début de `main`, avant tout chargement de DLL (Windows) :
    // `netwin::harden_dll_search()` limite la recherche des DLL à System32.
    if let Err(e) = platform::harden_process() {
        eprintln!("fortivpn : durcissement du processus impossible : {e}");
        return Exit::Internal.into();
    }
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // `--help`/`--version` passent aussi par ici (sortie standard, code 0).
            let _ = e.print();
            return if e.use_stderr() {
                Exit::Usage
            } else {
                Exit::Ok
            }
            .into();
        }
    };
    match cli.subcommand() {
        Command::Version => {
            println!("fortivpn {}", version());
            Exit::Ok.into()
        }
        Command::CheckConfig => match load_config(&cli) {
            Ok((path, config)) => {
                print!("{}", config.render(&path));
                Exit::Ok.into()
            }
            Err(exit) => exit.into(),
        },
        Command::Connect(ConnectArgs { service: false }) => connect(&cli).into(),
        Command::Connect(ConnectArgs { service: true }) => {
            service_client(&cli, ClientCommand::Connect)
        }
        Command::Disconnect => service_client(&cli, ClientCommand::Disconnect),
        Command::Status => service_client(&cli, ClientCommand::Status),
        Command::Service { action } => svc::run_admin(action).into(),
    }
}

/// Commandes adressées au service : le client ne choisit aucune option (la
/// configuration est celle du service), `--config` est donc refusé.
fn service_client(cli: &Cli, command: ClientCommand) -> ExitCode {
    if cli.config.is_some() {
        eprintln!(
            "fortivpn : --config est incompatible avec le mode service (la configuration \
             est lue par le service dans %ProgramData%\\fortivpn-rs\\config.toml)"
        );
        return Exit::Usage.into();
    }
    svc::run_client(command).into()
}

/// Charge la configuration (`--config` ou chemin par défaut) ; affiche l'erreur.
fn load_config(cli: &Cli) -> Result<(PathBuf, Config), Exit> {
    let path = match &cli.config {
        Some(p) => p.clone(),
        None => config::default_path().map_err(|e| config_error(&e))?,
    };
    match config::load(&path) {
        Ok(c) => Ok((path, c)),
        Err(e) => {
            eprintln!("fortivpn : {} : {e}", path.display());
            Err(Exit::Config)
        }
    }
}

fn config_error(e: &config::ConfigError) -> Exit {
    eprintln!("fortivpn : {e}");
    Exit::Config
}

/// Sous-commande `connect`.
fn connect(cli: &Cli) -> Exit {
    let (path, config) = match load_config(cli) {
        Ok(c) => c,
        Err(exit) => return exit,
    };
    logging::init(config.log_level.raised(cli.verbose));
    tracing::debug!(config = %path.display(), "configuration chargée");

    // Avant la saisie du mot de passe : échouer au plus tôt.
    let transport = match transport::build_transport(&config) {
        Ok(t) => t.with_second_factor(transport::TerminalSecondFactor::provider()),
        Err(e) => {
            tracing::error!("{e}");
            return Exit::Internal;
        }
    };
    // Avant la saisie aussi : verrou d'instance unique (Windows), résidus, GPO NRPT ;
    // en mode proxy (`[proxy]`) : ouverture des écoutes locales, rien de privilégié.
    let backend = match platform::select_backend(config.proxy.as_ref()) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("initialisation du réseau impossible : {e}");
            return exit::from_backend_error(&e);
        }
    };

    let password = match prompt_password(&config) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("saisie du mot de passe impossible : {e}");
            return Exit::Internal;
        }
    };
    let credentials = Credentials::new(config.username.clone(), password);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "démarrage du runtime impossible");
            return Exit::Internal;
        }
    };
    runtime.block_on(async move {
        let mut signals = match platform::ShutdownSignals::install() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "installation des gestionnaires de signaux impossible");
                return Exit::Internal;
            }
        };
        let stop = async move {
            let (name, limit) = signals.recv().await;
            tracing::info!("{name} reçu");
            limit
        };
        let mut reporter = run::Reporter::default();
        let reason = run::run_session(
            transport,
            backend,
            credentials,
            config.session_options(),
            stop,
            |event| {
                tracing::info!("{}", reporter.observe(event));
                if matches!(event.state, fortivpn_core::SessionState::TunnelUp { .. })
                    && let Some(summary) = reporter.summary()
                {
                    tracing::info!("{summary} ; Ctrl+C pour se déconnecter");
                }
            },
        )
        .await;
        let exit = exit::from_reason(&reason);
        if exit == Exit::Ok {
            tracing::info!("déconnecté proprement");
        } else {
            tracing::error!(code = exit.code(), "{}", run::describe_reason(&reason));
        }
        exit
    })
}

/// Demande le mot de passe sur le terminal, sans écho. Il n'existe qu'en mémoire,
/// effacé à la libération (`Zeroizing` puis `SecretString`).
fn prompt_password(config: &Config) -> std::io::Result<SecretString> {
    let typed = read_password(&format!(
        "Mot de passe pour {}@{} : ",
        config.username, config.host
    ))?;
    // Copie à la taille exacte ; `typed` est effacé à la sortie.
    Ok(SecretString::from(typed.as_str()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::version().is_empty());
    }
}
