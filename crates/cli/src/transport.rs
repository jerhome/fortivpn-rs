//! Construction du transport SSL-VPN à partir de la configuration.

use std::sync::Arc;

use fortivpn_core::sslvpn::{SslVpnError, SslVpnOptions, SslVpnTransport};
use fortivpn_core::{
    SecondFactorAnswer, SecondFactorChallenge, SecondFactorFuture, SecondFactorKind,
    SecondFactorProvider,
};
use secrecy::SecretString;

use crate::config::Config;

/// Options SSL-VPN (hôte, port, realm, épinglage) tirées de la configuration.
pub fn ssl_vpn_options(config: &Config) -> SslVpnOptions {
    let mut options = SslVpnOptions::new(config.host.clone(), config.port);
    if let Some(realm) = &config.realm {
        options.realm.clone_from(realm);
    }
    options
        .tls
        .pinned
        .extend(config.trusted_cert.iter().copied());
    options
}

/// Construit le transport vers la passerelle décrite par `config`.
///
/// Appelée **avant** la saisie du mot de passe, pour échouer au plus tôt
/// (options TLS invalides, racines système illisibles…).
pub fn build_transport(config: &Config) -> Result<SslVpnTransport, SslVpnError> {
    let options = ssl_vpn_options(config);
    tracing::debug!(
        host = %options.host,
        port = options.port,
        pinned = options.tls.pinned.len(),
        "options SSL-VPN"
    );
    SslVpnTransport::new(&options)
}

/// Second facteur sur le terminal : code saisi sans écho (jamais stocké ni journalisé),
/// ou simple invitation à valider la notification push. Une saisie vide ou impossible
/// annule la connexion.
#[derive(Debug, Default, Clone, Copy)]
pub struct TerminalSecondFactor;

impl TerminalSecondFactor {
    /// Fournisseur prêt à injecter dans le transport.
    pub fn provider() -> Arc<dyn SecondFactorProvider> {
        Arc::new(Self)
    }
}

impl SecondFactorProvider for TerminalSecondFactor {
    fn second_factor<'a>(&'a self, challenge: &'a SecondFactorChallenge) -> SecondFactorFuture<'a> {
        Box::pin(async move {
            let message = challenge.message.clone().unwrap_or_default();
            if challenge.kind == SecondFactorKind::Push {
                eprintln!(
                    "{}",
                    if message.is_empty() {
                        "Validez la notification FortiToken sur votre appareil…"
                    } else {
                        message.as_str()
                    }
                );
                return SecondFactorAnswer::Push;
            }
            let prompt = if message.is_empty() {
                "Code de vérification : ".to_owned()
            } else {
                format!("{message} : ")
            };
            // Saisie bloquante hors des threads du runtime.
            let typed = tokio::task::spawn_blocking(move || crate::read_password(&prompt)).await;
            match typed {
                Ok(Ok(code)) => SecondFactorAnswer::Code(SecretString::from(code.as_str())),
                _ => SecondFactorAnswer::Cancelled,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn options_carry_host_port_realm_and_pin() {
        let c = config::parse(&format!(
            "host = \"vpn.example.com\"\nport = 10443\nusername = \"alice\"\n\
             realm = \"staff\"\ntrusted_cert = \"{FP}\"\n"
        ))
        .unwrap();
        let o = ssl_vpn_options(&c);
        assert_eq!(o.host, "vpn.example.com");
        assert_eq!(o.port, 10443);
        assert_eq!(o.realm, "staff");
        assert_eq!(o.tls.pinned.len(), 1);
        assert_eq!(o.tls.pinned[0].to_hex(), FP);
        assert!(o.tls.use_system_roots);
    }

    #[test]
    fn options_without_realm_or_pin() {
        let c = config::parse("host = \"h\"\nusername = \"u\"\n").unwrap();
        let o = ssl_vpn_options(&c);
        assert_eq!(o.port, 443);
        assert!(o.realm.is_empty());
        assert!(o.tls.pinned.is_empty());
    }

    #[test]
    fn transport_is_built_from_config() {
        let c = config::parse("host = \"vpn.example.com\"\nusername = \"u\"\n").unwrap();
        assert!(build_transport(&c).is_ok());
    }
}
