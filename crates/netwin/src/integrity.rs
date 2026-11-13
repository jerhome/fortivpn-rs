//! Intégrité de l'installation (revue 5.3, M4) : décision pure sur le
//! propriétaire et la DACL d'un fichier / dossier, empreinte SHA-256.
//!
//! Les SID sont manipulés sous forme de chaîne (`S-1-5-18`…), produite côté
//! Windows par `ConvertSidToStringSidW`. Compilé et testé partout.

use std::io::Read;

use sha2::{Digest, Sha256};

/// `NT AUTHORITY\SYSTEM`.
const SID_SYSTEM: &str = "S-1-5-18";
/// `BUILTIN\Administrators`.
const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
/// `NT SERVICE\TrustedInstaller`.
const SID_TRUSTED_INSTALLER: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
/// `CREATOR OWNER` (substitué à l'héritage ; sans effet sur l'objet lui-même).
const SID_CREATOR_OWNER: &str = "S-1-3-0";
/// `OWNER RIGHTS` (s'applique au propriétaire, vérifié par ailleurs).
const SID_OWNER_RIGHTS: &str = "S-1-3-4";

/// Propriétaires acceptés.
const TRUSTED_OWNERS: [&str; 3] = [SID_SYSTEM, SID_ADMINISTRATORS, SID_TRUSTED_INSTALLER];

/// SID autorisés à disposer d'un droit d'écriture.
const TRUSTED_WRITERS: [&str; 5] = [
    SID_SYSTEM,
    SID_ADMINISTRATORS,
    SID_TRUSTED_INSTALLER,
    SID_CREATOR_OWNER,
    SID_OWNER_RIGHTS,
];

/// Droits permettant de remplacer / planter un fichier : `FILE_WRITE_DATA`
/// (`FILE_ADD_FILE`), `FILE_APPEND_DATA` (`FILE_ADD_SUBDIRECTORY`),
/// `FILE_DELETE_CHILD`, `DELETE`, `WRITE_DAC`, `WRITE_OWNER`, `GENERIC_ALL`,
/// `GENERIC_WRITE`, `MAXIMUM_ALLOWED`.
pub(crate) const WRITE_MASK: u32 = 0x0000_0002
    | 0x0000_0004
    | 0x0000_0040
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x1000_0000
    | 0x4000_0000
    | 0x0200_0000;

/// ACE de la DACL, telle que lue par le code Windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ace {
    /// ACE d'autorisation analysée (`ACCESS_ALLOWED_ACE`, `…_CALLBACK_ACE`).
    Allow {
        /// SID bénéficiaire.
        sid: String,
        /// Masque d'accès.
        mask: u32,
        /// `INHERIT_ONLY_ACE` : ne s'applique pas à l'objet lui-même.
        inherit_only: bool,
    },
    /// ACE de refus (ne fait que retirer des droits : ignorée).
    Deny,
    /// ACE d'autorisation d'un type non analysé (objet…) : refusée par prudence.
    UnknownAllow {
        /// Type d'ACE.
        ace_type: u8,
    },
}

/// Vérifie qu'un objet n'est modifiable que par SYSTEM / Administrateurs /
/// `TrustedInstaller` : propriétaire de confiance, DACL présente, aucune ACE
/// accordant un droit d'écriture à un autre SID. Les ACE de refus sont
/// ignorées (approche conservatrice : on ne crédite pas un refus qui pourrait
/// être ordonné après une autorisation).
///
/// `dacl` vaut `None` pour une DACL nulle (accès total à tous).
pub(crate) fn check_admin_only(owner: &str, dacl: Option<&[Ace]>) -> Result<(), String> {
    if !TRUSTED_OWNERS.contains(&owner) {
        return Err(format!(
            "propriétaire non administrateur ({owner}) ; attendu SYSTEM, Administrateurs ou TrustedInstaller"
        ));
    }
    let Some(dacl) = dacl else {
        return Err("DACL nulle : modifiable par tous".into());
    };
    for ace in dacl {
        match ace {
            Ace::Allow {
                sid,
                mask,
                inherit_only,
            } => {
                if !inherit_only
                    && mask & WRITE_MASK != 0
                    && !TRUSTED_WRITERS.contains(&sid.as_str())
                {
                    return Err(format!(
                        "droit d'écriture accordé à {sid} (masque {mask:#010x})"
                    ));
                }
            }
            Ace::Deny => {}
            Ace::UnknownAllow { ace_type } => {
                return Err(format!(
                    "ACE d'autorisation de type {ace_type} non analysée"
                ));
            }
        }
    }
    Ok(())
}

/// Empreinte SHA-256 officielle de `wintun.dll` (amd64), si épinglée.
///
/// TODO(3.W) : renseigner depuis l'archive officielle
/// <https://www.wintun.net/builds/wintun-0.14.1.zip> (fichier
/// `wintun/bin/amd64/wintun.dll`), après vérification de la signature
/// Authenticode (`WireGuard LLC`) et de l'empreinte de l'archive publiée sur
/// wintun.net. Ne jamais inscrire ici une valeur non vérifiée. Tant que la
/// valeur est `None`, l'empreinte calculée est seulement journalisée.
pub const WINTUN_DLL_SHA256: Option<[u8; 32]> = None;

/// SHA-256 d'un flux.
pub(crate) fn sha256_reader(mut r: impl Read) -> std::io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// Représentation hexadécimale (minuscules).
pub(crate) fn to_hex(digest: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    digest.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Compare l'empreinte calculée à l'empreinte attendue (si fournie).
pub(crate) fn check_digest(actual: &[u8; 32], expected: Option<&[u8; 32]>) -> Result<(), String> {
    match expected {
        Some(e) if e != actual => Err(format!(
            "empreinte SHA-256 inattendue : {} (attendu {})",
            to_hex(actual),
            to_hex(e)
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS: &str = "S-1-5-32-545";
    const AUTH_USERS: &str = "S-1-5-11";
    const EVERYONE: &str = "S-1-1-0";

    fn allow(sid: &str, mask: u32) -> Ace {
        Ace::Allow {
            sid: sid.into(),
            mask,
            inherit_only: false,
        }
    }

    /// DACL typique d'un sous-dossier de `C:\Program Files` créé par un admin.
    fn program_files() -> Vec<Ace> {
        vec![
            allow(SID_TRUSTED_INSTALLER, 0x001f_01ff),
            allow(SID_SYSTEM, 0x001f_01ff),
            allow(SID_ADMINISTRATORS, 0x001f_01ff),
            allow(USERS, 0x0012_00a9),
            Ace::Allow {
                sid: SID_CREATOR_OWNER.into(),
                mask: 0x1000_0000,
                inherit_only: true,
            },
            // ALL APPLICATION PACKAGES : lecture / exécution.
            allow("S-1-15-2-1", 0x0012_00a9),
        ]
    }

    #[test]
    fn program_files_layout_is_accepted() {
        assert_eq!(
            check_admin_only(SID_ADMINISTRATORS, Some(&program_files())),
            Ok(())
        );
        assert_eq!(
            check_admin_only(SID_TRUSTED_INSTALLER, Some(&program_files())),
            Ok(())
        );
        assert_eq!(check_admin_only(SID_SYSTEM, Some(&[])), Ok(()));
    }

    #[test]
    fn untrusted_owner_is_rejected() {
        let user = "S-1-5-21-1-2-3-1001";
        assert!(check_admin_only(user, Some(&program_files())).is_err());
    }

    #[test]
    fn null_dacl_is_rejected() {
        assert!(check_admin_only(SID_ADMINISTRATORS, None).is_err());
    }

    #[test]
    fn write_for_non_admin_is_rejected() {
        for sid in [
            USERS,
            AUTH_USERS,
            EVERYONE,
            "S-1-5-4",
            "S-1-5-21-1-2-3-1001",
        ] {
            for mask in [
                0x2,
                0x4,
                0x40,
                0x0001_0000,
                0x0004_0000,
                0x0008_0000,
                0x1000_0000,
                0x4000_0000,
            ] {
                let mut dacl = program_files();
                dacl.push(allow(sid, mask));
                assert!(
                    check_admin_only(SID_ADMINISTRATORS, Some(&dacl)).is_err(),
                    "{sid} {mask:#x}"
                );
            }
        }
    }

    #[test]
    fn inherit_only_and_deny_aces_are_ignored() {
        let mut dacl = program_files();
        dacl.push(Ace::Allow {
            sid: USERS.into(),
            mask: 0x1000_0000,
            inherit_only: true,
        });
        dacl.push(Ace::Deny);
        assert_eq!(check_admin_only(SID_ADMINISTRATORS, Some(&dacl)), Ok(()));
    }

    #[test]
    fn unknown_allow_ace_is_rejected() {
        let mut dacl = program_files();
        dacl.push(Ace::UnknownAllow { ace_type: 5 });
        assert!(check_admin_only(SID_ADMINISTRATORS, Some(&dacl)).is_err());
    }

    #[test]
    fn sha256_and_pinning() {
        let d = sha256_reader(&b"abc"[..]).unwrap();
        assert_eq!(
            to_hex(&d),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(check_digest(&d, None).is_ok());
        assert!(check_digest(&d, Some(&d)).is_ok());
        assert!(check_digest(&d, Some(&[0; 32])).is_err());
    }
}
