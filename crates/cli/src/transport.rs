//! Construction du transport SSL-VPN à partir de la configuration.

use fortivpn_core::sslvpn::{SslVpnError, SslVpnOptions, SslVpnTransport};

use crate::config::Config;

/// Options SSL-VPN (hôte, port, realm, épinglage) tirées de la configuration.
pub(crate) fn ssl_vpn_options(config: &Config) -> SslVpnOptions {
    let mut options = SslVpnOptions::new(config.host.clone(), config.port);
    if let Some(realm) = &config.realm {
        options.realm.clone_from(realm);
    }
    options.tls.pinned.extend(config.trusted_cert.iter().copied());
    options
}

/// Construit le transport vers la passerelle décrite par `config`.
///
/// Appelée **avant** la saisie du mot de passe, pour échouer au plus tôt
/// (options TLS invalides, racines système illisibles…).
pub(crate) fn build_transport(config: &Config) -> Result<SslVpnTransport, SslVpnError> {
    let options = ssl_vpn_options(config);
    tracing::debug!(
        host = %options.host,
        port = options.port,
        pinned = options.tls.pinned.len(),
        "options SSL-VPN"
    );
    SslVpnTransport::new(&options)
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
