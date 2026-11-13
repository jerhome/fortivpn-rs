//! Durcissement du processus (revue 5.3) : instance unique (verrou fichier
//! exclusif), chemin de recherche DLL et vérification d'ACL de l'installation.
//!
//! Toute mémoire allouée par l'OS (`LocalAlloc`) est possédée par
//! [`LocalBox`] (libérée au `Drop`) ; le fichier verrou est un `std::fs::File`
//! (fermé au `Drop`).
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::ptr;

use fortivpn_core::NetError;
use windows_sys::Win32::Foundation::{LocalFree, NO_ERROR};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, INHERIT_ONLY_ACE,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
use windows_sys::Win32::System::LibraryLoader::{
    LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
};

use crate::integrity::{self, Ace};
use crate::plan;

// Types d'ACE (winnt.h ; constantes de `Win32_System_SystemServices`).
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 6;
const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;
const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 10;
const ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: u8 = 12;

/// Mémoire allouée par l'OS avec `LocalAlloc`, libérée par `LocalFree`.
#[derive(Debug)]
struct LocalBox(*mut c_void);

impl Drop for LocalBox {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: pointeur retourné par une API documentée « à libérer
            // avec LocalFree », possédé exclusivement par ce wrapper et libéré
            // une seule fois.
            unsafe { LocalFree(self.0) };
        }
    }
}

fn last_os_err(op: &'static str) -> NetError {
    NetError::Io {
        op,
        source: io::Error::last_os_error(),
    }
}

/// Descripteur de sécurité construit à partir d'une chaîne SDDL.
fn security_descriptor(sddl: &str) -> Result<LocalBox, NetError> {
    let wsddl = plan::to_wide(sddl);
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `wsddl` est terminé par NUL et vit pendant l'appel ; `sd` est
    // une sortie locale ; la taille facultative n'est pas demandée.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wsddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut sd,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_os_err("sddl"));
    }
    Ok(LocalBox(sd))
}

/// Sous-dossier de `%ProgramData%` (admin-only) contenant le verrou d'instance.
const LOCK_DIR_NAME: &str = "fortivpn-rs";
/// Nom du fichier verrou d'instance.
pub const INSTANCE_LOCK_FILE: &str = "instance.lock";

/// DACL d'un dossier créé par nous : SYSTEM et Administrateurs, héritée par les
/// fichiers et sous-dossiers, DACL protégée.
const ADMIN_DIR_SDDL: &str = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)";

/// Droits d'accès du fichier verrou : `GENERIC_WRITE | DELETE` (ce dernier est
/// requis par `FILE_FLAG_DELETE_ON_CLOSE`).
const LOCK_ACCESS: u32 = 0x4000_0000 | 0x0001_0000;
const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
const ERROR_SHARING_VIOLATION: i32 = 32;

/// Dossier du verrou : `%ProgramData%\fortivpn-rs`.
fn lock_dir() -> Result<PathBuf, NetError> {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .map(|p| p.join(LOCK_DIR_NAME))
        .ok_or_else(|| NetError::Os {
            op: "instance_lock",
            reason: "variable ProgramData absente ou invalide".into(),
        })
}

/// Crée `path` (parent existant) avec la DACL [`ADMIN_DIR_SDDL`].
fn create_admin_dir(path: &Path) -> Result<(), NetError> {
    let sd = security_descriptor(ADMIN_DIR_SDDL)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let wpath = plan::to_wide(&path.to_string_lossy());
    // SAFETY: `wpath` terminé par NUL ; `sa` et le descripteur `sd` qu'il pointe
    // vivent pendant l'appel (CreateDirectoryW en copie le contenu).
    let ok = unsafe { CreateDirectoryW(wpath.as_ptr(), &raw const sa) };
    if ok == 0 {
        return Err(last_os_err("instance_lock_dir"));
    }
    Ok(())
}

/// Verrou d'instance unique (revue 5.3, M4 passe 2) : fichier
/// `%ProgramData%\fortivpn-rs\instance.lock`, ouvert en **partage exclusif**
/// (`share_mode(0)`) avec `FILE_FLAG_DELETE_ON_CLOSE`. Le dossier est vérifié
/// admin-only ([`check_admin_only`]) : un utilisateur standard ne peut ni créer,
/// ni ouvrir, ni renommer le fichier (le mutex `Global\` de la passe 1 était
/// squattable). Le verrou disparaît avec le dernier handle, y compris à la mort
/// du processus (un fichier résiduel est simplement rouvert).
#[derive(Debug)]
pub(crate) struct InstanceLock {
    _file: File,
}

impl InstanceLock {
    /// Prend le verrou ; erreur s'il est déjà tenu (autre instance), si le dossier
    /// n'est pas réservé aux administrateurs, ou sans droits suffisants.
    pub(crate) fn acquire() -> Result<Self, NetError> {
        Self::acquire_in(&lock_dir()?)
    }

    fn acquire_in(dir: &Path) -> Result<Self, NetError> {
        if !dir.exists() {
            create_admin_dir(dir)?;
        }
        check_admin_only(dir)?;
        let path = dir.join(INSTANCE_LOCK_FILE);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .access_mode(LOCK_ACCESS)
            .share_mode(0)
            .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
            .open(&path)
            .map_err(|e| {
                if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) {
                    NetError::AlreadyRunning
                } else {
                    NetError::Os {
                        op: "instance_lock",
                        reason: format!(
                            "verrou d'instance {} indisponible ({e}) : droits administrateur requis",
                            path.display()
                        ),
                    }
                }
            })?;
        // Pas de contrôle d'ACL du fichier : il est ouvert sans partage, et le
        // dossier (vérifié) est seul à pouvoir y déposer ou y renommer un fichier.
        Ok(Self { _file: file })
    }
}

/// Restreint la recherche des DLL chargées dynamiquement à `System32`
/// (`SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`, revue 5.3 M4).
/// À appeler au tout début de `main`, avant tout chargement de DLL. Les DLL
/// chargées par chemin absolu (`wintun.dll`) ne sont pas concernées.
pub fn harden_dll_search() -> Result<(), NetError> {
    // SAFETY: drapeau documenté, sans pointeur.
    if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } == 0 {
        return Err(last_os_err("harden_dll_search"));
    }
    Ok(())
}

/// SID sous forme de chaîne (`S-1-5-18`…).
fn sid_string(sid: PSID) -> Result<String, NetError> {
    let mut out: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` pointe un SID valide (fourni par l'OS, dans un
    // descripteur encore vivant chez l'appelant) ; `out` est une sortie locale.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut out) } == 0 {
        return Err(last_os_err("sid_string"));
    }
    let owned = LocalBox(out.cast());
    let mut len = 0usize;
    // SAFETY: `out` est une chaîne UTF-16 terminée par NUL allouée par l'API ;
    // la lecture s'arrête au NUL.
    while unsafe { *out.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` unités lisibles avant le NUL ; `owned` garde la mémoire
    // vivante jusqu'à la fin de la copie.
    let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, len) });
    drop(owned);
    Ok(s)
}

/// ACE de la DACL `acl`, décodées pour [`integrity::check_admin_only`].
fn read_aces(acl: *const ACL) -> Result<Vec<Ace>, NetError> {
    // SAFETY: `acl` est non nul et pointe une ACL valide (descripteur vivant
    // chez l'appelant) ; lecture d'un champ entier de l'en-tête.
    let count = unsafe { (*acl).AceCount };
    let mut aces = Vec::with_capacity(usize::from(count));
    for index in 0..u32::from(count) {
        let mut ace: *mut c_void = ptr::null_mut();
        // SAFETY: `acl` valide, `index` < AceCount ; `ace` est une sortie locale.
        if unsafe { GetAce(acl, index, &raw mut ace) } == 0 {
            return Err(last_os_err("get_ace"));
        }
        // SAFETY: GetAce a retourné un pointeur sur une ACE de l'ACL,
        // alignée sur 4 octets, commençant par un ACE_HEADER.
        let header = unsafe { ace.cast::<ACE_HEADER>().read() };
        let inherit_only = u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0;
        aces.push(match header.AceType {
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {
                // ACCESS_ALLOWED_ACE et ACCESS_ALLOWED_CALLBACK_ACE ont la même
                // disposition : en-tête, masque, puis SID à partir de SidStart.
                let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
                // SAFETY: pour ces types, l'ACE contient au moins l'en-tête, le
                // masque et un SID complet (AceSize, structure validée par
                // l'OS) ; `allowed` est aligné (ACE alignées sur 4 octets).
                // Seule l'adresse de SidStart est prise (pas de lecture).
                let (mask, sid) = unsafe {
                    (
                        (*allowed).Mask,
                        (&raw mut (*allowed).SidStart).cast::<c_void>(),
                    )
                };
                Ace::Allow {
                    sid: sid_string(sid)?,
                    mask,
                    inherit_only,
                }
            }
            ACCESS_DENIED_ACE_TYPE
            | ACCESS_DENIED_OBJECT_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => Ace::Deny,
            other => Ace::UnknownAllow { ace_type: other },
        });
    }
    Ok(aces)
}

/// Vérifie que `path` (fichier ou dossier) appartient à SYSTEM /
/// Administrateurs / `TrustedInstaller` et n'est modifiable que par eux
/// (revue 5.3, M4). Les liens sont suivis : c'est la cible effective qui est
/// vérifiée.
pub(crate) fn check_admin_only(path: &Path) -> Result<(), NetError> {
    check_path(path, integrity::check_admin_only)
}

/// Vérifie `path` (comme [`check_admin_only`]) **et toute la chaîne de ses
/// ancêtres** jusqu'à la racine du volume (revue 5.3 passe 2, F1) : un ancêtre
/// modifiable (renommage / suppression d'un enfant) permettrait de remplacer
/// le dossier vérifié. Le chemin est d'abord canonicalisé (liens et jonctions
/// résolus : ce sont les ancêtres réels qui sont contrôlés).
pub(crate) fn check_admin_only_chain(path: &Path) -> Result<(), NetError> {
    let real = std::fs::canonicalize(path).map_err(|e| NetError::Io {
        op: "install_acl",
        source: e,
    })?;
    check_path(&real, integrity::check_admin_only)?;
    for ancestor in integrity::ancestors_of(&real) {
        check_path(&ancestor, integrity::check_ancestor)?;
    }
    Ok(())
}

/// Lit propriétaire et DACL de `path` et applique `decide`.
fn check_path(
    path: &Path,
    decide: fn(&str, Option<&[Ace]>) -> Result<(), String>,
) -> Result<(), NetError> {
    let wpath = plan::to_wide(&path.to_string_lossy());
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `wpath` terminé par NUL ; sorties locales ; `owner` et `dacl`
    // pointent dans `sd`, libéré par LocalFree (LocalBox) après usage.
    let code = unsafe {
        GetNamedSecurityInfoW(
            wpath.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            ptr::null_mut(),
            &raw mut dacl,
            ptr::null_mut(),
            &raw mut sd,
        )
    };
    if code != NO_ERROR {
        return Err(NetError::Io {
            op: "install_acl",
            source: io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX)),
        });
    }
    let sd = LocalBox(sd);
    let owner = if owner.is_null() {
        String::new()
    } else {
        sid_string(owner)?
    };
    let aces = if dacl.is_null() {
        None
    } else {
        Some(read_aces(dacl)?)
    };
    drop(sd);
    decide(&owner, aces.as_deref()).map_err(|reason| NetError::Os {
        op: "install_acl",
        reason: format!(
            "{} : {reason} (installer fortivpn-rs et wintun.dll dans un dossier réservé \
             aux administrateurs, ex. C:\\Program Files\\fortivpn-rs)",
            path.display()
        ),
    })
}
