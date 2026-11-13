//! Réglages : formulaire texte ⇄ [`Config`] (fichier `config.toml` de la CLI).
//!
//! Ne manipule **jamais** de mot de passe : la structure n'en a pas, et le fichier
//! écrit n'en contient pas (la validation de `config` refuse ces clés).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use fortivpn_app::config::{self, Config};
use fortivpn_core::sslvpn::CertFingerprint;
use netproxy::{DEFAULT_SOCKS, Forward, ProxyConfig};

use crate::model::Mode;

/// Valeurs saisies dans l'écran « Réglages » (texte brut).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingsForm {
    /// Passerelle (nom d'hôte ou IP).
    pub host: String,
    /// Port (texte).
    pub port: String,
    /// Utilisateur.
    pub username: String,
    /// Empreinte SHA-256 du certificat (vide : aucune).
    pub fingerprint: String,
    /// Adresse d'écoute SOCKS5 (vide ou `off` : désactivé).
    pub socks_addr: String,
    /// Port d'écoute SOCKS5.
    pub socks_port: String,
    /// Redirections `écoute=hôte:port`, séparées par des virgules ou des retours à la ligne.
    pub forwards: String,
    /// Reconnexion automatique.
    pub reconnect: bool,
}

impl SettingsForm {
    /// Formulaire correspondant à une configuration (valeurs proxy par défaut si absente).
    pub fn from_config(config: &Config) -> Self {
        let proxy = config.proxy.clone().unwrap_or_default();
        let (socks_addr, socks_port) = match proxy.socks {
            Some(a) => (a.ip().to_string(), a.port().to_string()),
            None => ("off".to_owned(), String::new()),
        };
        Self {
            host: config.host.clone(),
            port: config.port.to_string(),
            username: config.username.clone(),
            fingerprint: config
                .trusted_cert
                .first()
                .map(CertFingerprint::to_hex)
                .unwrap_or_default(),
            socks_addr,
            socks_port,
            forwards: proxy
                .forwards
                .iter()
                .map(|f| format!("{}={}", f.listen, f.target))
                .collect::<Vec<_>>()
                .join(", "),
            reconnect: config.reconnect.enabled,
        }
    }

    /// Applique le formulaire sur `base` (les clés non éditables — realm, interface,
    /// niveau de journal, délais de reconnexion — sont conservées) et valide le
    /// résultat avec les mêmes règles que la CLI.
    ///
    /// Si `base` n'avait pas de section `[proxy]` et que le formulaire garde les
    /// valeurs par défaut, la section n'est pas créée (la CLI garde son mode).
    pub fn to_config(&self, base: &Config) -> Result<Config, String> {
        let mut config = base.clone();
        self.host.trim().clone_into(&mut config.host);
        config.port = self
            .port
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|&p| p != 0)
            .ok_or("Port : entier entre 1 et 65535 attendu")?;
        self.username.trim().clone_into(&mut config.username);
        let fp = self.fingerprint.trim();
        config.trusted_cert = if fp.is_empty() {
            Vec::new()
        } else {
            vec![
                fp.to_ascii_lowercase()
                    .parse::<CertFingerprint>()
                    .map_err(|_| "Empreinte : 64 caractères hexadécimaux attendus (SHA-256)")?,
            ]
        };
        config.reconnect.enabled = self.reconnect;

        let proxy = self.proxy()?;
        config.proxy = if base.proxy.is_none() && proxy == ProxyConfig::default() {
            None
        } else {
            Some(proxy)
        };
        // Validation complète (hôte, utilisateur, proxy…) par le parseur de la CLI :
        // le texte relu est exactement ce qui serait écrit sur disque.
        config::parse(&config.to_toml()).map_err(|e| e.to_string())
    }

    fn proxy(&self) -> Result<ProxyConfig, String> {
        let addr = self.socks_addr.trim();
        let socks = if addr.is_empty() || addr.eq_ignore_ascii_case("off") {
            None
        } else {
            let ip = addr
                .parse::<std::net::IpAddr>()
                .map_err(|_| "SOCKS5 : adresse IP attendue (ex. 127.0.0.1) ou « off »")?;
            let port = if self.socks_port.trim().is_empty() {
                DEFAULT_SOCKS.port()
            } else {
                self.socks_port
                    .trim()
                    .parse::<u16>()
                    .ok()
                    .filter(|&p| p != 0)
                    .ok_or("SOCKS5 : port entre 1 et 65535 attendu")?
            };
            Some(SocketAddr::new(ip, port))
        };
        let forwards = self
            .forwards
            .split([',', '\n', ';'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse::<Forward>()
                    .map_err(|e| format!("Redirection : {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ProxyConfig::new(socks, forwards))
    }
}

/// Configuration utilisée par défaut quand le fichier n'existe pas encore.
pub fn blank_config() -> Config {
    // Valeurs vides : l'utilisateur doit renseigner passerelle et utilisateur.
    Config {
        host: String::new(),
        port: config::DEFAULT_PORT,
        username: String::new(),
        realm: None,
        trusted_cert: Vec::new(),
        interface: config::DEFAULT_INTERFACE.to_owned(),
        log_level: config::LogLevel::Info,
        proxy: None,
        reconnect: config::ReconnectConfig::default(),
    }
}

/// Fichier d'état non secret voisin de la configuration (dernier mode choisi).
pub fn state_path(config_path: &Path) -> PathBuf {
    config_path.with_file_name("gui-state.toml")
}

/// Dernier mode mémorisé (`None` : fichier absent ou illisible).
pub fn load_mode(config_path: &Path) -> Option<Mode> {
    let text = std::fs::read_to_string(state_path(config_path)).ok()?;
    text.lines().find_map(|l| {
        match l
            .trim()
            .strip_prefix("mode")?
            .trim()
            .strip_prefix('=')?
            .trim()
        {
            "\"service\"" => Some(Mode::Service),
            "\"proxy\"" => Some(Mode::Proxy),
            _ => None,
        }
    })
}

/// Mémorise le mode (création du dossier ; meilleur effort, l'erreur est renvoyée).
pub fn save_mode(config_path: &Path, mode: Mode) -> std::io::Result<()> {
    let path = state_path(config_path);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let name = match mode {
        Mode::Service => "service",
        Mode::Proxy => "proxy",
    };
    std::fs::write(path, format!("mode = \"{name}\"\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_mode_round_trips_and_creates_the_directory() {
        let dir = std::env::temp_dir().join(format!("fvpn-gui-mode-{}", std::process::id()));
        let cfg = dir.join("sub").join("config.toml");
        assert_eq!(load_mode(&cfg), None);
        save_mode(&cfg, Mode::Service).unwrap();
        assert_eq!(load_mode(&cfg), Some(Mode::Service));
        save_mode(&cfg, Mode::Proxy).unwrap();
        assert_eq!(load_mode(&cfg), Some(Mode::Proxy));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn base() -> Config {
        config::parse("host = \"vpn.example.com\"\nusername = \"alice\"\nrealm = \"staff\"\n")
            .unwrap()
    }

    #[test]
    fn form_round_trips_and_keeps_hidden_keys() {
        let mut b = base();
        b.proxy = Some(ProxyConfig::new(
            Some("127.0.0.1:1080".parse().unwrap()),
            vec!["127.0.0.1:2222=10.0.0.10:22".parse().unwrap()],
        ));
        let form = SettingsForm::from_config(&b);
        assert_eq!(form.forwards, "127.0.0.1:2222=10.0.0.10:22");
        assert_eq!(form.socks_port, "1080");
        let c = form.to_config(&b).unwrap();
        assert_eq!(c, b);
        assert_eq!(c.realm.as_deref(), Some("staff"));
    }

    #[test]
    fn edits_are_applied_and_validated() {
        let b = base();
        let mut form = SettingsForm::from_config(&b);
        form.host = " gw.example.org ".into();
        form.port = "10443".into();
        form.fingerprint = FP.to_ascii_uppercase();
        form.reconnect = false;
        form.forwards = "127.0.0.1:3390=10.0.0.20:3389\n127.0.0.1:2222=srv.corp:22".into();
        let c = form.to_config(&b).unwrap();
        assert_eq!(c.host, "gw.example.org");
        assert_eq!(c.port, 10443);
        assert_eq!(c.trusted_cert[0].to_hex(), FP);
        assert!(!c.reconnect.enabled);
        assert_eq!(c.proxy.unwrap().forwards.len(), 2);
    }

    #[test]
    fn default_proxy_values_do_not_create_a_proxy_section() {
        let b = base();
        let c = SettingsForm::from_config(&b).to_config(&b).unwrap();
        assert!(c.proxy.is_none());
    }

    #[test]
    fn invalid_values_are_rejected_with_a_message() {
        let b = base();
        let ok = SettingsForm::from_config(&b);
        for (mutate, needle) in [
            (
                (|f: &mut SettingsForm| f.port = "0".into()) as fn(&mut SettingsForm),
                "Port",
            ),
            (|f| f.port = "abc".into(), "Port"),
            (|f| f.host = "https://vpn".into(), "host"),
            (|f| f.host = String::new(), "host"),
            (|f| f.username = String::new(), "username"),
            (|f| f.fingerprint = "zz".into(), "Empreinte"),
            (|f| f.socks_addr = "pas-une-ip".into(), "SOCKS5"),
            (|f| f.forwards = "n'importe quoi".into(), "Redirection"),
            (|f| f.socks_addr = "0.0.0.0".into(), "proxy"),
        ] {
            let mut f = ok.clone();
            mutate(&mut f);
            let err = f.to_config(&b).unwrap_err();
            assert!(err.contains(needle), "{needle} absent de « {err} »");
        }
    }

    #[test]
    fn written_file_never_contains_a_secret_key() {
        let b = base();
        let text = SettingsForm::from_config(&b)
            .to_config(&b)
            .unwrap()
            .to_toml();
        for key in ["password", "pass", "otp", "cookie"] {
            assert!(!text.to_ascii_lowercase().contains(key), "{text}");
        }
    }
}
