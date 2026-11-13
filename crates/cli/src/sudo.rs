//! Configuration sous `sudo` (story 4.7, Linux).
//!
//! Lancé par `sudo fortivpn`, le processus est root et `$HOME` vaut `/root` : la
//! configuration de l'utilisateur qui a invoqué `sudo` (`SUDO_USER`) est alors
//! utilisée, à condition que le fichier ne soit pas contrôlable par un tiers (un
//! fichier modifiable par un autre utilisateur ne doit pas piloter un processus
//! root). `--config` explicite garde la priorité et n'est pas soumis à ce contrôle.
//!
//! Le répertoire personnel est résolu par la base des comptes, jamais par `$HOME`.

use std::path::{Path, PathBuf};

use crate::config::{self, ConfigError};

/// Compte local résolu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub uid: u32,
    pub home: PathBuf,
}

/// Environnement du processus (injectable pour les tests).
pub trait Env {
    /// UID effectif du processus.
    fn euid(&self) -> u32;
    /// Valeur de `SUDO_USER`.
    fn sudo_user(&self) -> Option<String>;
    /// Compte `name` d'après la base des comptes.
    fn account(&self, name: &str) -> Option<Account>;
}

/// Environnement réel.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEnv;

#[cfg(target_os = "linux")]
impl Env for SystemEnv {
    fn euid(&self) -> u32 {
        nix::unistd::geteuid().as_raw()
    }
    fn sudo_user(&self) -> Option<String> {
        std::env::var("SUDO_USER").ok()
    }
    fn account(&self, name: &str) -> Option<Account> {
        let u = nix::unistd::User::from_name(name).ok().flatten()?;
        Some(Account {
            uid: u.uid.as_raw(),
            home: u.dir,
        })
    }
}

#[cfg(not(target_os = "linux"))]
impl Env for SystemEnv {
    fn euid(&self) -> u32 {
        // Pas de notion de root/sudo hors Linux : jamais de contexte sudo.
        u32::MAX
    }
    fn sudo_user(&self) -> Option<String> {
        None
    }
    fn account(&self, _name: &str) -> Option<Account> {
        None
    }
}

/// Chemin de configuration retenu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub path: PathBuf,
    /// Configuration d'un utilisateur `sudo` : (nom, uid) du propriétaire attendu.
    pub sudo: Option<(String, u32)>,
}

impl Resolved {
    /// Message d'information à afficher si la configuration est celle d'un autre compte.
    pub fn info(&self) -> Option<String> {
        self.sudo
            .as_ref()
            .map(|(name, _)| format!("configuration de l'utilisateur {name}"))
    }

    /// Vérifie le fichier avant lecture (sans effet hors contexte `sudo`).
    /// Fichier absent : message suggérant `-c`.
    pub fn verify(&self) -> Result<(), ConfigError> {
        let Some((name, uid)) = &self.sudo else {
            return Ok(());
        };
        if !self.path.exists() {
            return Err(ConfigError::SudoMissing {
                user: name.clone(),
                path: self.path.clone(),
            });
        }
        check_trusted(&self.path, *uid)
    }
}

/// Vrai si le processus tourne en root (Linux).
pub fn is_root(env: &dyn Env) -> bool {
    env.euid() == 0
}

/// Choisit le chemin : `--config`, sinon (root + `SUDO_USER`) la configuration de
/// cet utilisateur, sinon le chemin par défaut du compte courant.
pub fn resolve(explicit: Option<&Path>, env: &dyn Env) -> Result<Resolved, ConfigError> {
    if let Some(p) = explicit {
        return Ok(Resolved {
            path: p.to_path_buf(),
            sudo: None,
        });
    }
    if is_root(env) {
        if let Some(user) = env.sudo_user().filter(|u| !u.is_empty() && u != "root") {
            let account = env
                .account(&user)
                .ok_or_else(|| ConfigError::SudoUnknownUser { user: user.clone() })?;
            // Même disposition que `dirs::config_dir()` pour ce compte (sans XDG :
            // l'environnement de root n'est pas celui de l'utilisateur).
            let path = config::default_path_in(&account.home.join(".config"));
            return Ok(Resolved {
                path,
                sudo: Some((user, account.uid)),
            });
        }
    }
    Ok(Resolved {
        path: config::default_path()?,
        sudo: None,
    })
}

/// Le fichier appartient à `owner_uid` ou à root et n'est modifiable ni par le
/// groupe ni par les autres.
#[cfg(unix)]
pub fn check_trusted(path: &Path, owner_uid: u32) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;
    let unsafe_file = |reason: String| ConfigError::UnsafeFile {
        path: path.to_path_buf(),
        reason,
    };
    let md = std::fs::metadata(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !md.is_file() {
        return Err(unsafe_file("ce n'est pas un fichier régulier".into()));
    }
    if md.uid() != owner_uid && md.uid() != 0 {
        return Err(unsafe_file(format!(
            "appartient à l'uid {} (attendu : l'utilisateur {owner_uid} ou root)",
            md.uid()
        )));
    }
    let mode = md.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(unsafe_file(format!(
            "modifiable par d'autres utilisateurs (mode {mode:04o}) ; corrigez avec chmod go-w"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn check_trusted(_path: &Path, _owner_uid: u32) -> Result<(), ConfigError> {
    Ok(())
}

/// Avertissement pour l'interface lancée en root.
pub const GUI_ROOT_WARNING: &str = "inutile de lancer l'interface avec sudo (elle fonctionne \
                                    en mode proxy sans droits)";

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct Fake {
        euid: u32,
        sudo_user: Option<&'static str>,
        accounts: HashMap<&'static str, Account>,
    }

    impl Env for Fake {
        fn euid(&self) -> u32 {
            self.euid
        }
        fn sudo_user(&self) -> Option<String> {
            self.sudo_user.map(str::to_owned)
        }
        fn account(&self, name: &str) -> Option<Account> {
            self.accounts.get(name).cloned()
        }
    }

    fn fake(euid: u32, sudo_user: Option<&'static str>) -> Fake {
        let accounts = HashMap::from([(
            "alice",
            Account {
                uid: 1000,
                home: "/home/alice".into(),
            },
        )]);
        Fake {
            euid,
            sudo_user,
            accounts,
        }
    }

    #[test]
    fn root_with_sudo_user_uses_that_users_home() {
        let r = resolve(None, &fake(0, Some("alice"))).unwrap();
        assert_eq!(
            r.path,
            Path::new("/home/alice/.config/fortivpn-rs/config.toml")
        );
        assert_eq!(r.sudo, Some(("alice".into(), 1000)));
        assert_eq!(
            r.info().as_deref(),
            Some("configuration de l'utilisateur alice")
        );
    }

    #[test]
    fn explicit_config_wins() {
        let r = resolve(Some(Path::new("/x/c.toml")), &fake(0, Some("alice"))).unwrap();
        assert_eq!(r.path, Path::new("/x/c.toml"));
        assert_eq!(r.sudo, None);
        assert_eq!(r.info(), None);
        assert!(r.verify().is_ok());
    }

    #[test]
    fn non_root_or_no_sudo_user_uses_default_path() {
        for env in [
            fake(1000, Some("alice")),
            fake(0, None),
            fake(0, Some("")),
            fake(0, Some("root")),
        ] {
            let r = resolve(None, &env).unwrap();
            assert_eq!(r.sudo, None);
            if let Ok(p) = config::default_path() {
                assert_eq!(r.path, p);
            }
        }
    }

    #[test]
    fn unknown_sudo_user_is_an_error() {
        let e = resolve(None, &fake(0, Some("mallory"))).unwrap_err();
        assert!(matches!(e, ConfigError::SudoUnknownUser { .. }));
        assert!(e.to_string().contains("mallory"));
    }

    #[test]
    fn missing_file_suggests_dash_c() {
        let r = resolve(None, &fake(0, Some("alice"))).unwrap();
        let r = Resolved {
            path: std::env::temp_dir().join(format!("fortivpn-absent-{}", std::process::id())),
            ..r
        };
        let msg = r.verify().unwrap_err().to_string();
        assert!(msg.contains("alice") && msg.contains("-c"), "{msg}");
    }

    #[cfg(target_os = "linux")]
    mod perms {
        use std::os::unix::fs::PermissionsExt;

        use super::*;

        fn temp_file(tag: &str, mode: u32) -> PathBuf {
            let dir =
                std::env::temp_dir().join(format!("fortivpn-sudo-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let p = dir.join("config.toml");
            std::fs::write(&p, "host = \"h\"\nusername = \"u\"\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            p
        }

        fn my_uid() -> u32 {
            nix::unistd::geteuid().as_raw()
        }

        fn cleanup(p: &Path) {
            let _ = std::fs::remove_dir_all(p.parent().unwrap());
        }

        #[test]
        fn owner_and_private_mode_accepted() {
            let p = temp_file("ok", 0o600);
            assert!(check_trusted(&p, my_uid()).is_ok());
            cleanup(&p);
        }

        #[test]
        fn group_or_other_writable_refused() {
            for mode in [0o660, 0o606, 0o666, 0o620] {
                let p = temp_file(&format!("w{mode:o}"), mode);
                let e = check_trusted(&p, my_uid()).unwrap_err();
                assert!(matches!(e, ConfigError::UnsafeFile { .. }), "{mode:o}");
                assert!(e.to_string().contains("modifiable"), "{e}");
                cleanup(&p);
            }
        }

        #[test]
        fn foreign_owner_refused() {
            let p = temp_file("own", 0o600);
            // Propriétaire attendu différent (et ni lui ni root : on est non-root).
            let other = my_uid().wrapping_add(4242);
            if my_uid() != 0 {
                let e = check_trusted(&p, other).unwrap_err();
                assert!(matches!(e, ConfigError::UnsafeFile { .. }));
                assert!(e.to_string().contains("appartient"), "{e}");
            }
            cleanup(&p);
        }

        #[test]
        fn directory_refused() {
            let p = temp_file("dir", 0o600);
            let dir = p.parent().unwrap();
            assert!(matches!(
                check_trusted(dir, my_uid()),
                Err(ConfigError::UnsafeFile { .. })
            ));
            cleanup(&p);
        }

        #[test]
        fn verify_applies_to_sudo_context_only() {
            let p = temp_file("vf", 0o666);
            let sudo = Resolved {
                path: p.clone(),
                sudo: Some(("alice".into(), my_uid())),
            };
            assert!(sudo.verify().is_err());
            let plain = Resolved {
                path: p.clone(),
                sudo: None,
            };
            assert!(plain.verify().is_ok());
            cleanup(&p);
        }
    }
}
