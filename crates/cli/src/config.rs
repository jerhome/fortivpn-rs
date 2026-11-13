//! Fichier de configuration TOML (story 4.2).
//!
//! Format (clés au premier niveau, toutes les autres sont refusées) :
//!
//! ```toml
//! host = "vpn.example.com"     # obligatoire : nom d'hôte ou adresse IP
//! port = 443                   # optionnel (443)
//! username = "alice"           # obligatoire
//! realm = "staff"              # optionnel
//! trusted_cert = "0123…cdef"   # optionnel : SHA-256 du certificat, 64 hex minuscules
//!                              # (ou une liste : ["…", "…"] pour une rotation)
//! interface = "fortivpn"       # optionnel (fortivpn)
//! log_level = "info"           # optionnel : error | warn | info | debug | trace
//!
//! [proxy]                      # optionnel : mode proxy sans droits administrateur
//! socks = "127.0.0.1:1080"     # optionnel (127.0.0.1:1080) ; "off" : pas de SOCKS
//! forward = ["127.0.0.1:13389=srv.corp:3389"]   # optionnel : redirections TCP
//! allow_non_loopback = false   # optionnel : autorise une écoute hors loopback
//! ```
//!
//! Avec `[proxy]`, aucune interface, route ni DNS du système n'est modifié : le
//! tunnel est exposé par un proxy SOCKS5 et des redirections de ports locales
//! (crate `netproxy`), utilisables sans droits d'administration.
//!
//! **Aucun secret** : la présence d'une clé de type mot de passe / OTP / cookie, à
//! n'importe quel niveau, est une erreur. Le mot de passe est demandé à chaque
//! connexion. Les erreurs de syntaxe sont rapportées sans recopier la ligne fautive
//! (qui pourrait contenir un secret collé par erreur).

use std::fmt::{self, Write as _};
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use fortivpn_core::sslvpn::CertFingerprint;
use serde::Deserialize;

/// Port HTTPS par défaut de la passerelle.
pub(crate) const DEFAULT_PORT: u16 = 443;
/// Nom d'interface TUN par défaut.
pub(crate) const DEFAULT_INTERFACE: &str = "fortivpn";
/// Répertoire de l'application sous le répertoire de configuration de l'utilisateur.
pub(crate) const APP_DIR: &str = "fortivpn-rs";
/// Nom du fichier de configuration.
pub(crate) const CONFIG_FILE: &str = "config.toml";
/// Taille maximale acceptée du fichier.
const MAX_FILE_SIZE: u64 = 64 * 1024;
/// Longueur maximale du nom d'interface (`IFNAMSIZ - 1` sous Linux).
const MAX_INTERFACE_LEN: usize = 15;
/// Clés refusées car elles désigneraient un secret (comparaison insensible à la casse).
const SECRET_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pass",
    "pwd",
    "otp",
    "cookie",
    "svpncookie",
];

/// Niveau de journalisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    /// Niveau relevé de `steps` crans (`-v`, `-vv`…), plafonné à `Trace`.
    pub(crate) fn raised(self, steps: u8) -> Self {
        const ORDER: [LogLevel; 5] = [
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Trace,
        ];
        let idx = ORDER.iter().position(|&l| l == self).unwrap_or(2);
        ORDER[(idx + usize::from(steps)).min(ORDER.len() - 1)]
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LogLevel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        match s.to_ascii_lowercase().as_str() {
            "error" => Ok(Self::Error),
            "warn" | "warning" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err(()),
        }
    }
}

/// Configuration validée. Ne contient aucun secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Config {
    /// Nom d'hôte ou adresse IP de la passerelle.
    pub(crate) host: String,
    /// Port TCP de la passerelle.
    pub(crate) port: u16,
    /// Nom d'utilisateur.
    pub(crate) username: String,
    /// Realm éventuel.
    pub(crate) realm: Option<String>,
    /// Empreintes SHA-256 épinglées du certificat de la passerelle (vide : aucune ;
    /// plusieurs : rotation de certificat sans indisponibilité).
    pub(crate) trusted_cert: Vec<CertFingerprint>,
    /// Nom de l'interface TUN.
    pub(crate) interface: String,
    /// Niveau de journalisation configuré (avant `-v`).
    pub(crate) log_level: LogLevel,
    /// Mode proxy en espace utilisateur (section `[proxy]`), à la place du
    /// backend réseau du système.
    pub(crate) proxy: Option<netproxy::ProxyConfig>,
}

/// Erreur de configuration.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    /// Aucun répertoire de configuration utilisateur connu.
    #[error("répertoire de configuration utilisateur introuvable : utilisez --config CHEMIN")]
    NoDefaultPath,
    /// Lecture impossible.
    #[error("lecture impossible : {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Fichier trop gros.
    #[error("fichier trop volumineux (maximum {MAX_FILE_SIZE} octets)")]
    TooLarge { path: PathBuf },
    /// Erreur de syntaxe TOML (sans recopie de la ligne).
    #[error("syntaxe TOML invalide{location} : {message}")]
    Syntax { location: Location, message: String },
    /// Clé désignant un secret.
    #[error(
        "clé « {key} » interdite : aucun secret ne doit figurer dans le fichier de \
         configuration ; supprimez-la (le mot de passe est demandé à chaque connexion)"
    )]
    SecretInFile { key: String },
    /// Structure inattendue (clé inconnue, type, clé obligatoire manquante).
    #[error("configuration invalide : {0}")]
    Structure(String),
    /// Valeur invalide.
    #[error("valeur de « {field} » invalide : {reason}")]
    Invalid { field: &'static str, reason: String },
}

/// Position d'une erreur de syntaxe (ligne, colonne ; 1-based).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Location(Option<(usize, usize)>);

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some((line, col)) => write!(f, " (ligne {line}, colonne {col})"),
            None => Ok(()),
        }
    }
}

impl Location {
    fn of(text: &str, offset: usize) -> Self {
        let before = text.get(..offset).unwrap_or(text);
        let line = before.matches('\n').count() + 1;
        let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
        Self(Some((line, col)))
    }
}

/// `trusted_cert` : une empreinte, ou une liste d'empreintes (rotation).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum TrustedCert {
    One(String),
    Many(Vec<String>),
}

/// Nombre maximal d'empreintes épinglées.
const MAX_PINS: usize = 8;

/// Champs bruts, avant validation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    host: String,
    port: Option<i64>,
    username: String,
    realm: Option<String>,
    trusted_cert: Option<TrustedCert>,
    interface: Option<String>,
    log_level: Option<String>,
    proxy: Option<RawProxy>,
}

/// Section `[proxy]` brute.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProxy {
    socks: Option<String>,
    forward: Option<Vec<String>>,
    allow_non_loopback: Option<bool>,
}

/// Chemin par défaut : `<config utilisateur>/fortivpn-rs/config.toml`
/// (`%APPDATA%\fortivpn-rs\config.toml` sous Windows,
/// `$XDG_CONFIG_HOME` ou `~/.config/fortivpn-rs/config.toml` sous Linux).
pub(crate) fn default_path() -> Result<PathBuf, ConfigError> {
    dirs::config_dir()
        .map(|base| default_path_in(&base))
        .ok_or(ConfigError::NoDefaultPath)
}

/// Chemin par défaut sous un répertoire de configuration donné.
pub(crate) fn default_path_in(config_dir: &Path) -> PathBuf {
    config_dir.join(APP_DIR).join(CONFIG_FILE)
}

/// Lit et valide le fichier.
pub(crate) fn load(path: &Path) -> Result<Config, ConfigError> {
    let io_err = |source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    };
    let len = std::fs::metadata(path).map_err(io_err)?.len();
    if len > MAX_FILE_SIZE {
        return Err(ConfigError::TooLarge {
            path: path.to_path_buf(),
        });
    }
    let text = std::fs::read_to_string(path).map_err(io_err)?;
    parse(&text)
}

/// Analyse et valide un texte TOML.
pub(crate) fn parse(text: &str) -> Result<Config, ConfigError> {
    let table: toml::Table = toml::from_str(text).map_err(|e| ConfigError::Syntax {
        location: e
            .span()
            .map_or_else(Location::default, |s| Location::of(text, s.start)),
        // `message()` seul : le `Display` complet recopie la ligne fautive.
        message: e.message().trim_end().to_owned(),
    })?;
    reject_secrets(&table)?;
    let raw: RawConfig = toml::Value::Table(table)
        .try_into()
        .map_err(|e: toml::de::Error| ConfigError::Structure(e.message().trim_end().to_owned()))?;
    validate(raw)
}

/// Refuse toute clé de secret, à n'importe quelle profondeur.
fn reject_secrets(table: &toml::Table) -> Result<(), ConfigError> {
    for (key, value) in table {
        if SECRET_KEYS.iter().any(|s| key.eq_ignore_ascii_case(s)) {
            return Err(ConfigError::SecretInFile { key: key.clone() });
        }
        reject_secrets_in(value)?;
    }
    Ok(())
}

fn reject_secrets_in(value: &toml::Value) -> Result<(), ConfigError> {
    match value {
        toml::Value::Table(t) => reject_secrets(t),
        toml::Value::Array(items) => items.iter().try_for_each(reject_secrets_in),
        _ => Ok(()),
    }
}

fn invalid(field: &'static str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        field,
        reason: reason.into(),
    }
}

fn validate(raw: RawConfig) -> Result<Config, ConfigError> {
    validate_host(&raw.host)?;
    let port = match raw.port {
        None => DEFAULT_PORT,
        Some(p) => u16::try_from(p)
            .ok()
            .filter(|&p| p != 0)
            .ok_or_else(|| invalid("port", format!("{p} hors de 1..=65535")))?,
    };
    if raw.username.is_empty() {
        return Err(invalid("username", "vide"));
    }
    reject_controls("username", &raw.username)?;
    if let Some(realm) = &raw.realm {
        if realm.is_empty() {
            return Err(invalid(
                "realm",
                "vide (retirez la clé s'il n'y a pas de realm)",
            ));
        }
        reject_controls("realm", realm)?;
    }
    let trusted_cert = parse_pins(raw.trusted_cert)?;
    let interface = raw
        .interface
        .unwrap_or_else(|| DEFAULT_INTERFACE.to_owned());
    validate_interface(&interface)?;
    let log_level = match raw.log_level {
        None => LogLevel::Info,
        Some(l) => l.parse().map_err(|()| {
            invalid(
                "log_level",
                format!("« {l} » (attendu : error, warn, info, debug ou trace)"),
            )
        })?,
    };
    let proxy = raw.proxy.map(validate_proxy).transpose()?;
    Ok(Config {
        host: raw.host,
        port,
        username: raw.username,
        realm: raw.realm,
        trusted_cert,
        interface,
        log_level,
        proxy,
    })
}

/// Valeur de `socks` désactivant le proxy SOCKS (redirections seules).
const SOCKS_OFF: &str = "off";

fn validate_proxy(raw: RawProxy) -> Result<netproxy::ProxyConfig, ConfigError> {
    let socks = match raw.socks.as_deref().map(str::trim) {
        None => Some(netproxy::DEFAULT_SOCKS),
        Some(SOCKS_OFF) => None,
        Some(s) => {
            let addr: std::net::SocketAddr = s.parse().map_err(|_| {
                invalid(
                    "proxy.socks",
                    format!("« {s} » (attendu : IP:PORT, par ex. 127.0.0.1:1080, ou « off »)"),
                )
            })?;
            if addr.port() == 0 {
                return Err(invalid("proxy.socks", "port nul"));
            }
            Some(addr)
        }
    };
    let forwards = raw
        .forward
        .unwrap_or_default()
        .iter()
        .map(|f| f.parse())
        .collect::<Result<Vec<netproxy::Forward>, _>>()
        .map_err(|e: netproxy::ProxyConfigError| invalid("proxy.forward", e.to_string()))?;
    let config = netproxy::ProxyConfig::new(socks, forwards)
        .with_allow_non_loopback(raw.allow_non_loopback.unwrap_or(false));
    config
        .validate()
        .map_err(|e| invalid("proxy", e.to_string()))?;
    Ok(config)
}

fn reject_controls(field: &'static str, value: &str) -> Result<(), ConfigError> {
    if value.chars().any(char::is_control) {
        Err(invalid(field, "caractère de contrôle"))
    } else {
        Ok(())
    }
}

fn validate_host(host: &str) -> Result<(), ConfigError> {
    const FIELD: &str = "host";
    if host.is_empty() {
        return Err(invalid(FIELD, "vide"));
    }
    if host.len() > 253 {
        return Err(invalid(FIELD, "trop long"));
    }
    if host.contains("://") {
        return Err(invalid(
            FIELD,
            "indiquez le nom d'hôte seul, sans « https:// »",
        ));
    }
    if host
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '@' | '?' | '#'))
    {
        return Err(invalid(
            FIELD,
            "caractère interdit (nom d'hôte ou adresse IP attendu)",
        ));
    }
    if host.contains(':') && host.parse::<Ipv6Addr>().is_err() {
        return Err(invalid(FIELD, "le port se règle avec la clé « port »"));
    }
    Ok(())
}

/// Empreintes épinglées : chaîne unique ou liste (dédupliquée, bornée).
fn parse_pins(raw: Option<TrustedCert>) -> Result<Vec<CertFingerprint>, ConfigError> {
    let list = match raw {
        None => return Ok(Vec::new()),
        Some(TrustedCert::One(s)) => vec![s],
        Some(TrustedCert::Many(v)) => v,
    };
    if list.len() > MAX_PINS {
        return Err(invalid(
            "trusted_cert",
            format!("{MAX_PINS} empreintes au plus"),
        ));
    }
    let mut out: Vec<CertFingerprint> = Vec::with_capacity(list.len());
    for s in &list {
        let fp = parse_fingerprint(s)?;
        if !out.contains(&fp) {
            out.push(fp);
        }
    }
    Ok(out)
}

/// Empreinte stricte : 64 caractères hexadécimaux minuscules, sans séparateur.
fn parse_fingerprint(s: &str) -> Result<CertFingerprint, ConfigError> {
    const FIELD: &str = "trusted_cert";
    let well_formed = s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !well_formed {
        return Err(invalid(
            FIELD,
            "empreinte SHA-256 attendue : 64 caractères hexadécimaux minuscules, sans « : »",
        ));
    }
    s.parse()
        .map_err(|e: fortivpn_core::sslvpn::InvalidFingerprint| invalid(FIELD, e.to_string()))
}

fn validate_interface(name: &str) -> Result<(), ConfigError> {
    const FIELD: &str = "interface";
    if name.is_empty() || name.len() > MAX_INTERFACE_LEN {
        return Err(invalid(
            FIELD,
            format!("1 à {MAX_INTERFACE_LEN} caractères attendus"),
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(invalid(FIELD, "caractères autorisés : A-Z a-z 0-9 - _ ."));
    }
    Ok(())
}

impl Config {
    fn render_proxy(&self) -> String {
        let Some(p) = &self.proxy else {
            return "mode : système (interface TUN, routes, DNS ; droits administrateur)\n"
                .to_owned();
        };
        let mut out = String::from("mode : proxy (sans droits administrateur)\n");
        match p.socks {
            Some(a) => {
                let _ = writeln!(out, "\x20 socks        = {a}");
            }
            None => out.push_str("\x20 socks        = (désactivé)\n"),
        }
        for f in &p.forwards {
            let _ = writeln!(out, "\x20 forward      = {} -> {}", f.listen, f.target);
        }
        if p.allow_non_loopback {
            out.push_str("\x20 allow_non_loopback = true (écoute accessible depuis le réseau)\n");
        }
        out
    }

    /// Rendu lisible pour `check-config` (ne contient aucun secret).
    pub(crate) fn render(&self, path: &Path) -> String {
        let realm = self.realm.as_deref().unwrap_or("(aucun)");
        let cert = if self.trusted_cert.is_empty() {
            "(aucun : validation par les autorités de certification du système)".to_owned()
        } else {
            self.trusted_cert
                .iter()
                .map(CertFingerprint::to_hex)
                .collect::<Vec<_>>()
                .join(", ")
        };
        format!(
            "configuration : {path}\n\
             \x20 host         = {host}\n\
             \x20 port         = {port}\n\
             \x20 username     = {user}\n\
             \x20 realm        = {realm}\n\
             \x20 trusted_cert = {cert}\n\
             \x20 interface    = {iface}\n\
             \x20 log_level    = {level}\n\
             {proxy}\
             mot de passe : demandé à chaque connexion, jamais stocké\n",
            path = path.display(),
            host = self.host,
            port = self.port,
            user = self.username,
            iface = self.interface,
            level = self.log_level,
            proxy = self.render_proxy(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn full() -> String {
        format!(
            "host = \"vpn.example.com\"\nport = 10443\nusername = \"alice\"\n\
             realm = \"staff\"\ntrusted_cert = \"{FP}\"\ninterface = \"fvpn0\"\n\
             log_level = \"debug\"\n"
        )
    }

    fn err_field(text: &str) -> &'static str {
        match parse(text) {
            Err(ConfigError::Invalid { field, .. }) => field,
            other => panic!("erreur Invalid attendue, obtenu {other:?}"),
        }
    }

    #[test]
    fn full_config() {
        let c = parse(&full()).unwrap();
        assert_eq!(c.host, "vpn.example.com");
        assert_eq!(c.port, 10443);
        assert_eq!(c.username, "alice");
        assert_eq!(c.realm.as_deref(), Some("staff"));
        assert_eq!(c.trusted_cert.len(), 1);
        assert_eq!(c.trusted_cert[0].to_hex(), FP);
        assert_eq!(c.interface, "fvpn0");
        assert_eq!(c.log_level, LogLevel::Debug);
    }

    #[test]
    fn trusted_cert_accepts_a_list() {
        let other = "f".repeat(64);
        let t = format!(
            "host = \"h\"\nusername = \"u\"\ntrusted_cert = [\"{FP}\", \"{other}\", \"{FP}\"]\n"
        );
        let c = parse(&t).unwrap();
        assert_eq!(c.trusted_cert.len(), 2, "doublon retiré");
        assert_eq!(c.trusted_cert[1].to_hex(), other);
        assert!(c.render(Path::new("c.toml")).contains(&other));
        let t = "host = \"h\"\nusername = \"u\"\ntrusted_cert = [\"zz\"]\n";
        assert_eq!(err_field(t), "trusted_cert");
        let many = format!("\"{FP}\",").repeat(9);
        let t = format!("host = \"h\"\nusername = \"u\"\ntrusted_cert = [{many}]\n");
        assert_eq!(err_field(&t), "trusted_cert");
        let t = "host = \"h\"\nusername = \"u\"\ntrusted_cert = []\n";
        assert!(parse(t).unwrap().trusted_cert.is_empty());
    }

    #[test]
    fn minimal_config_uses_defaults() {
        let c = parse("host = \"203.0.113.10\"\nusername = \"bob\"\n").unwrap();
        assert_eq!(c.port, DEFAULT_PORT);
        assert_eq!(c.realm, None);
        assert!(c.trusted_cert.is_empty());
        assert_eq!(c.interface, DEFAULT_INTERFACE);
        assert_eq!(c.log_level, LogLevel::Info);
    }

    #[test]
    fn ipv6_host_accepted() {
        let c = parse("host = \"2001:db8::1\"\nusername = \"bob\"\n").unwrap();
        assert_eq!(c.host, "2001:db8::1");
    }

    #[test]
    fn invalid_ports() {
        for port in ["0", "65536", "-1", "100000"] {
            let t = format!("host = \"h\"\nusername = \"u\"\nport = {port}\n");
            assert_eq!(err_field(&t), "port", "port {port}");
        }
        let t = "host = \"h\"\nusername = \"u\"\nport = \"443\"\n";
        assert!(matches!(parse(t), Err(ConfigError::Structure(_))));
    }

    #[test]
    fn malformed_fingerprints() {
        let bad = [
            "",
            &FP[..63],
            &format!("{FP}0"),
            &FP.to_uppercase(),
            &FP.replace('0', "g"),
            "01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef",
        ];
        for fp in bad {
            let t = format!("host = \"h\"\nusername = \"u\"\ntrusted_cert = \"{fp}\"\n");
            assert_eq!(err_field(&t), "trusted_cert", "empreinte {fp:?}");
        }
    }

    #[test]
    fn password_key_is_refused() {
        let t = "host = \"h\"\nusername = \"u\"\npassword = \"hunter2-s3cr3t\"\n";
        let e = parse(t).unwrap_err();
        assert!(matches!(&e, ConfigError::SecretInFile { key } if key == "password"));
        let msg = e.to_string();
        assert!(msg.contains("password"));
        assert!(!msg.contains("hunter2-s3cr3t"));
    }

    #[test]
    fn secret_keys_refused_anywhere_and_any_case() {
        for t in [
            "host = \"h\"\nusername = \"u\"\nPassword = \"x\"\n",
            "host = \"h\"\nusername = \"u\"\n[gateway]\npassword = \"x\"\n",
            "host = \"h\"\nusername = \"u\"\n[[profiles]]\notp = \"123456\"\n",
            "host = \"h\"\nusername = \"u\"\ncookie = \"SVPNCOOKIE=x\"\n",
        ] {
            assert!(
                matches!(parse(t), Err(ConfigError::SecretInFile { .. })),
                "{t}"
            );
        }
    }

    #[test]
    fn syntax_error_does_not_echo_the_line() {
        let t = "host = \"h\"\nusername = \"u\"\npassword = \"hunter2-s3cr3t\n";
        let e = parse(t).unwrap_err();
        assert!(matches!(e, ConfigError::Syntax { .. }), "{e:?}");
        let msg = e.to_string();
        assert!(!msg.contains("hunter2"), "{msg}");
        assert!(msg.contains("ligne 3"), "{msg}");
    }

    #[test]
    fn unknown_and_missing_keys() {
        let t = "host = \"h\"\nusername = \"u\"\nhots = \"x\"\n";
        assert!(matches!(parse(t), Err(ConfigError::Structure(m)) if m.contains("hots")));
        assert!(matches!(
            parse("host = \"h\"\n"),
            Err(ConfigError::Structure(m)) if m.contains("username")
        ));
    }

    #[test]
    fn invalid_hosts() {
        for host in [
            "",
            "https://vpn.example.com",
            "vpn.example.com:443",
            "vpn example",
            "vpn/remote",
            "user@vpn",
        ] {
            let t = format!("host = \"{host}\"\nusername = \"u\"\n");
            assert_eq!(err_field(&t), "host", "hôte {host:?}");
        }
    }

    #[test]
    fn invalid_other_fields() {
        assert_eq!(err_field("host = \"h\"\nusername = \"\"\n"), "username");
        assert_eq!(
            err_field("host = \"h\"\nusername = \"u\"\nrealm = \"\"\n"),
            "realm"
        );
        assert_eq!(
            err_field("host = \"h\"\nusername = \"u\"\ninterface = \"a-very-long-name0\"\n"),
            "interface"
        );
        assert_eq!(
            err_field("host = \"h\"\nusername = \"u\"\ninterface = \"tun 0\"\n"),
            "interface"
        );
        assert_eq!(
            err_field("host = \"h\"\nusername = \"u\"\nlog_level = \"loud\"\n"),
            "log_level"
        );
    }

    #[test]
    fn proxy_section() {
        let base = "host = \"h\"\nusername = \"u\"\n";
        assert_eq!(parse(base).unwrap().proxy, None);
        let c = parse(&format!("{base}[proxy]\n")).unwrap();
        let p = c.proxy.unwrap();
        assert_eq!(p.socks, Some(netproxy::DEFAULT_SOCKS));
        assert!(p.forwards.is_empty());
        let c = parse(&format!(
            "{base}[proxy]\nsocks = \"127.0.0.1:9050\"\n\
             forward = [\"127.0.0.1:13389=srv.corp:3389\", \"127.0.0.1:8443=10.0.0.8:443\"]\n"
        ))
        .unwrap();
        let p = c.proxy.clone().unwrap();
        assert_eq!(p.socks, Some("127.0.0.1:9050".parse().unwrap()));
        assert_eq!(p.forwards.len(), 2);
        assert_eq!(p.forwards[0].target.to_string(), "srv.corp:3389");
        let out = c.render(Path::new("/x.toml"));
        assert!(out.contains("mode : proxy"), "{out}");
        assert!(out.contains("127.0.0.1:13389 -> srv.corp:3389"), "{out}");
        let c = parse(&format!(
            "{base}[proxy]\nsocks = \"off\"\nforward = [\"127.0.0.1:2222=git.corp:22\"]\n"
        ))
        .unwrap();
        assert_eq!(c.proxy.unwrap().socks, None);
    }

    #[test]
    fn invalid_proxy_section() {
        let base = "host = \"h\"\nusername = \"u\"\n[proxy]\n";
        assert_eq!(
            err_field(&format!("{base}socks = \"0.0.0.0:1080\"\n")),
            "proxy"
        );
        assert_eq!(
            err_field(&format!("{base}socks = \"localhost\"\n")),
            "proxy.socks"
        );
        assert_eq!(
            err_field(&format!("{base}socks = \"127.0.0.1:0\"\n")),
            "proxy.socks"
        );
        assert_eq!(err_field(&format!("{base}socks = \"off\"\n")), "proxy");
        assert_eq!(
            err_field(&format!("{base}forward = [\"127.0.0.1:80=srv\"]\n")),
            "proxy.forward"
        );
        assert_eq!(
            err_field(&format!("{base}forward = [\"10.0.0.1:80=srv:80\"]\n")),
            "proxy"
        );
        assert_eq!(
            err_field(&format!("{base}forward = [\"127.0.0.1:1080=srv:80\"]\n")),
            "proxy"
        );
        let ok = parse(&format!(
            "{base}socks = \"0.0.0.0:1080\"\nallow_non_loopback = true\n"
        ))
        .unwrap();
        assert!(ok.proxy.unwrap().allow_non_loopback);
        assert!(matches!(
            parse(&format!("{base}sock = \"127.0.0.1:1\"\n")),
            Err(ConfigError::Structure(_))
        ));
    }

    #[test]
    fn default_paths() {
        let base = Path::new("/home/alice/.config");
        assert_eq!(
            default_path_in(base),
            Path::new("/home/alice/.config/fortivpn-rs/config.toml")
        );
        // Chemin réel : sous le répertoire de configuration de l'OS
        // (%APPDATA% sous Windows, ~/.config sous Linux).
        if let Some(dir) = dirs::config_dir() {
            let p = default_path().unwrap();
            assert!(p.starts_with(dir));
            assert!(p.ends_with(Path::new(APP_DIR).join(CONFIG_FILE)));
        }
    }

    #[test]
    fn load_reads_file_and_reports_missing() {
        let dir = std::env::temp_dir().join(format!("fortivpn-cli-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(CONFIG_FILE);
        std::fs::write(&path, full()).unwrap();
        assert_eq!(load(&path).unwrap().username, "alice");
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(load(&path), Err(ConfigError::Io { .. })));
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn log_level_raise() {
        assert_eq!(LogLevel::Info.raised(0), LogLevel::Info);
        assert_eq!(LogLevel::Info.raised(1), LogLevel::Debug);
        assert_eq!(LogLevel::Warn.raised(2), LogLevel::Debug);
        assert_eq!(LogLevel::Info.raised(9), LogLevel::Trace);
    }

    #[test]
    fn render_has_no_secret_and_all_fields() {
        let c = parse(&full()).unwrap();
        let out = c.render(Path::new("/etc/x.toml"));
        for needle in [
            "vpn.example.com",
            "10443",
            "alice",
            "staff",
            FP,
            "fvpn0",
            "debug",
        ] {
            assert!(out.contains(needle), "{needle} absent de {out}");
        }
    }
}
