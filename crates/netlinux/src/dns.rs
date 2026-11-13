//! Stratégie DNS du backend Linux.
//!
//! Le backend ne modifie **jamais** `/etc/resolv.conf` de lui-même : il ne sert
//! qu'aux tests e2e dans WSL, où le resolver du système doit rester intact.
//! Deux stratégies :
//!
//! - [`DnsStrategy::Ignore`] (défaut) : aucune action ; la configuration DNS
//!   du tunnel est seulement journalisée.
//! - [`DnsStrategy::ResolvFile`] : écrit un fichier au format `resolv.conf`
//!   (`nameserver` / `search`) au chemin fourni, puis, à l'annulation, restaure
//!   son contenu antérieur ou le supprime s'il n'existait pas. L'écriture se
//!   fait sur place (pas de renommage), ce qui fonctionne aussi sur un fichier
//!   monté par `bind`.
//!
//! Sûreté (revue 5.3, F1) : aucun lien symbolique n'est suivi (chaque
//! composant du chemin est ouvert avec `O_NOFOLLOW`), le dossier parent doit
//! appartenir à root (ou à l'uid effectif, cas d'un userns de test) sans être
//! inscriptible par le groupe ou les autres, le fichier doit être un fichier
//! ordinaire à lien unique distinct de `/etc/resolv.conf`, et la restauration
//! se fait sur les descripteurs ouverts à l'écriture (pas de réouverture par
//! chemin).
//!
//! Pour un netns créé par `ip netns add NOM`, pointer vers
//! `/etc/netns/NOM/resolv.conf` : `ip netns exec NOM …` le monte sur
//! `/etc/resolv.conf` pour les processus du netns uniquement. Le chemin
//! `/etc/resolv.conf` lui-même (et tout chemin qui s'y résout) est refusé.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use fortivpn_core::{DnsConfig, NetError};
use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, open, openat};
use nix::sys::stat::{Mode, fstatat};
use nix::unistd::{UnlinkatFlags, geteuid, unlinkat};

use crate::plan::{DnsWrite, Undo};

/// Chemin du resolver du système, jamais modifié.
const SYSTEM_RESOLV: &str = "/etc/resolv.conf";

/// Nombre de `nameserver` pris en compte par la glibc (`MAXNS`).
const GLIBC_MAXNS: usize = 3;

/// Stratégie d'application de la configuration DNS du tunnel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum DnsStrategy {
    /// Ne rien faire (défaut).
    #[default]
    Ignore,
    /// Écrire un fichier au format `resolv.conf` au chemin absolu donné
    /// (jamais `/etc/resolv.conf`), restauré à l'annulation.
    ResolvFile(PathBuf),
}

fn dns_error(reason: String) -> NetError {
    NetError::Os { op: "dns", reason }
}

/// Domaine de recherche acceptable dans un fichier resolv : lettres, chiffres,
/// `-`, `_`, `.` ; pas de label vide ; 253 octets max. Empêche notamment
/// l'injection de lignes (`\n`) ou d'options dans le fichier.
pub(crate) fn is_valid_search_domain(domain: &str) -> bool {
    let d = domain.strip_suffix('.').unwrap_or(domain);
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Contenu du fichier resolv, ou `None` s'il n'y a rien à écrire.
pub(crate) fn render(dns: &DnsConfig) -> Result<Option<String>, NetError> {
    if let Some(bad) = dns
        .search_domains
        .iter()
        .find(|d| !is_valid_search_domain(d))
    {
        return Err(dns_error(format!(
            "domaine de recherche invalide : {bad:?}"
        )));
    }
    if dns.servers.is_empty() && dns.search_domains.is_empty() {
        return Ok(None);
    }
    if dns.servers.len() > GLIBC_MAXNS {
        tracing::warn!(
            count = dns.servers.len(),
            "plus de {GLIBC_MAXNS} serveurs DNS : la glibc n'utilisera que les premiers"
        );
    }
    let mut out = String::from("# Généré par fortivpn-rs (netlinux), retiré à la déconnexion.\n");
    for server in &dns.servers {
        out.push_str("nameserver ");
        out.push_str(&server.to_string());
        out.push('\n');
    }
    if !dns.search_domains.is_empty() {
        out.push_str("search ");
        out.push_str(&dns.search_domains.join(" "));
        out.push('\n');
    }
    Ok(Some(out))
}

/// Forme canonique « au mieux » d'un chemin : canonicalisé s'il existe, sinon
/// parent canonicalisé + nom, sinon tel quel.
fn best_effort_canonical(path: &Path) -> PathBuf {
    if let Ok(p) = path.canonicalize() {
        return p;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => parent
            .canonicalize()
            .map_or_else(|_| path.to_path_buf(), |p| p.join(name)),
        _ => path.to_path_buf(),
    }
}

/// Refuse les chemins relatifs et tout chemin désignant le resolver du système.
pub(crate) fn check_path(path: &Path) -> Result<(), NetError> {
    if !path.is_absolute() {
        return Err(dns_error(format!(
            "chemin du fichier resolv non absolu : {}",
            path.display()
        )));
    }
    let system = Path::new(SYSTEM_RESOLV);
    let canonical = best_effort_canonical(path);
    if path == system || canonical == system || canonical == best_effort_canonical(system) {
        return Err(dns_error(format!(
            "refus de modifier le resolver du système ({SYSTEM_RESOLV}) : \
             utiliser un fichier dédié (ex. /etc/netns/NOM/resolv.conf)"
        )));
    }
    Ok(())
}

/// Calcule l'écriture DNS à effectuer selon la stratégie (sans I/O d'écriture).
pub(crate) fn plan(strategy: &DnsStrategy, dns: &DnsConfig) -> Result<Option<DnsWrite>, NetError> {
    match strategy {
        DnsStrategy::Ignore => {
            if !dns.servers.is_empty() || !dns.search_domains.is_empty() {
                tracing::info!(
                    servers = ?dns.servers,
                    search = ?dns.search_domains,
                    "DNS du tunnel non appliqué (stratégie Ignore)"
                );
            }
            Ok(None)
        }
        DnsStrategy::ResolvFile(path) => {
            check_path(path)?;
            Ok(render(dns)?.map(|content| DnsWrite {
                path: path.clone(),
                content,
            }))
        }
    }
}

/// Taille maximale du contenu antérieur conservé pour l'annulation.
const MAX_PREVIOUS: u64 = 1024 * 1024;

fn io_err(op: &'static str, e: impl Into<std::io::Error>) -> NetError {
    NetError::Io {
        op,
        source: e.into(),
    }
}

fn nix_err(op: &'static str, e: Errno) -> NetError {
    io_err(op, std::io::Error::from(e))
}

/// Vérifie qu'un dossier ne peut être modifié que par root (ou par l'uid
/// effectif courant, cas d'un userns de test) : propriétaire `0` ou `euid`,
/// sans droit d'écriture pour le groupe ni les autres.
pub(crate) fn check_dir_owner_mode(uid: u32, mode: u32, euid: u32) -> Result<(), String> {
    if uid != 0 && uid != euid {
        return Err(format!(
            "dossier appartenant à l'uid {uid} (attendu : root ou {euid})"
        ));
    }
    if mode & 0o022 != 0 {
        return Err(format!(
            "dossier inscriptible par le groupe ou les autres (mode {:o})",
            mode & 0o7777
        ));
    }
    Ok(())
}

/// Ouvre le dossier parent de `path` composant par composant depuis `/`, sans
/// jamais suivre de lien symbolique (`O_DIRECTORY | O_NOFOLLOW` à chaque
/// étape), puis vérifie son propriétaire et ses droits. Retourne le dossier et
/// le nom du fichier.
fn open_parent(path: &Path) -> Result<(File, OsString), NetError> {
    let mut names = Vec::new();
    for c in path.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(n) => names.push(n),
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(dns_error(format!(
                    "chemin du fichier resolv non normalisé : {}",
                    path.display()
                )));
            }
        }
    }
    let Some(name) = names.pop() else {
        return Err(dns_error(format!(
            "chemin du fichier resolv sans nom de fichier : {}",
            path.display()
        )));
    };
    let dir_flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut dir =
        File::from(open("/", dir_flags, Mode::empty()).map_err(|e| nix_err("dns_open_dir", e))?);
    for n in names {
        dir = File::from(openat(&dir, n, dir_flags, Mode::empty()).map_err(|e| {
            if matches!(e, Errno::ELOOP | Errno::ENOTDIR) {
                dns_error(format!(
                    "lien symbolique ou non-dossier dans le chemin du fichier resolv \
                     ({n:?}) : refusé"
                ))
            } else {
                nix_err("dns_open_dir", e)
            }
        })?);
    }
    let meta = dir.metadata().map_err(|e| io_err("dns_stat_dir", e))?;
    check_dir_owner_mode(meta.uid(), meta.mode(), geteuid().as_raw()).map_err(|reason| {
        dns_error(format!(
            "dossier du fichier resolv non sûr ({}) : {reason}",
            path.parent().unwrap_or(path).display()
        ))
    })?;
    Ok((dir, name.to_os_string()))
}

/// Fichier resolv ouvert par [`write`] : dossier parent et fichier gardés
/// ouverts jusqu'à l'annulation (aucune réouverture par chemin).
#[derive(Debug)]
struct OpenedResolv {
    /// Chemin (journalisation uniquement).
    path: PathBuf,
    dir: File,
    name: OsString,
    file: File,
}

/// Annulation d'une écriture resolv : restaure le contenu antérieur par
/// `pwrite` + `ftruncate` sur le descripteur ouvert à l'écriture, ou supprime
/// le fichier (`unlinkat` relatif au dossier ouvert) s'il a été créé, à
/// condition que le nom désigne toujours le même inode.
#[derive(Debug, Clone)]
pub(crate) struct DnsUndo {
    opened: Arc<OpenedResolv>,
    /// Contenu antérieur ; `None` : le fichier a été créé.
    previous: Option<Vec<u8>>,
}

impl PartialEq for DnsUndo {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.opened, &other.opened) && self.previous == other.previous
    }
}

impl Eq for DnsUndo {}

impl DnsUndo {
    /// Contenu antérieur (`None` : fichier créé par nous).
    #[cfg(test)]
    pub(crate) fn previous(&self) -> Option<&[u8]> {
        self.previous.as_deref()
    }

    /// Annulation factice (jamais rejouée sur l'OS) pour les `System` fictifs.
    #[cfg(test)]
    pub(crate) fn placeholder(path: &Path) -> Self {
        let null = || File::open("/dev/null").unwrap();
        Self {
            opened: Arc::new(OpenedResolv {
                path: path.to_path_buf(),
                dir: null(),
                name: OsString::from("null"),
                file: null(),
            }),
            previous: None,
        }
    }
}

/// `(st_dev, st_ino)` de `/etc/resolv.conf` (liens suivis), s'il existe.
fn system_resolv_id() -> Option<(u64, u64)> {
    std::fs::metadata(SYSTEM_RESOLV)
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

/// Ouvre (ou crée) le fichier relativement au dossier, sans suivre de lien.
/// Retourne le fichier et `true` s'il vient d'être créé.
fn open_file(dir: &File, name: &OsStr) -> Result<(File, bool), NetError> {
    let base = OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_NOCTTY | OFlag::O_CLOEXEC;
    let symlink = || dns_error("le fichier resolv est un lien symbolique : refusé".into());
    match openat(
        dir,
        name,
        base | OFlag::O_CREAT | OFlag::O_EXCL,
        Mode::from_bits_truncate(0o644),
    ) {
        Ok(fd) => Ok((File::from(fd), true)),
        Err(Errno::EEXIST) => match openat(dir, name, base | OFlag::O_NONBLOCK, Mode::empty()) {
            Ok(fd) => Ok((File::from(fd), false)),
            Err(Errno::ELOOP) => Err(symlink()),
            Err(e) => Err(nix_err("dns_open", e)),
        },
        Err(Errno::ELOOP) => Err(symlink()),
        Err(e) => Err(nix_err("dns_open", e)),
    }
}

/// Contrôles sur le fichier ouvert : fichier ordinaire, un seul lien, distinct
/// du resolver du système.
fn check_file(file: &File, created: bool) -> Result<(), NetError> {
    let meta = file.metadata().map_err(|e| io_err("dns_stat", e))?;
    if !meta.file_type().is_file() {
        return Err(dns_error(
            "le fichier resolv n'est pas un fichier ordinaire".into(),
        ));
    }
    if !created && meta.nlink() != 1 {
        return Err(dns_error(format!(
            "le fichier resolv a {} liens physiques : refusé",
            meta.nlink()
        )));
    }
    if system_resolv_id() == Some((meta.dev(), meta.ino())) {
        return Err(dns_error(format!(
            "le fichier resolv désigne le resolver du système ({SYSTEM_RESOLV}) : refusé"
        )));
    }
    if meta.len() > MAX_PREVIOUS {
        return Err(dns_error(format!(
            "fichier resolv existant trop volumineux ({} octets)",
            meta.len()
        )));
    }
    Ok(())
}

/// Remplace le contenu par `pwrite` à l'offset 0 puis `ftruncate` (pas
/// d'instant où le fichier est vide).
fn overwrite(file: &File, bytes: &[u8]) -> std::io::Result<()> {
    file.write_all_at(bytes, 0)?;
    file.set_len(bytes.len() as u64)
}

/// `st` (de `fstatat`) et `meta` désignent-ils le même inode ?
// `st_dev`/`st_ino` ne sont pas `u64` sur toutes les cibles Linux.
#[allow(clippy::useless_conversion)]
fn same_inode(st: &nix::sys::stat::FileStat, meta: &std::fs::Metadata) -> bool {
    u64::from(st.st_dev) == meta.dev() && u64::from(st.st_ino) == meta.ino()
}

/// Supprime `name` de `dir` s'il désigne toujours l'inode de `file`.
fn unlink_if_same(dir: &File, name: &OsStr, file: &File, path: &Path) -> Result<(), NetError> {
    let ours = file.metadata().map_err(|e| io_err("dns_restore", e))?;
    match fstatat(dir, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Err(Errno::ENOENT) => Ok(()),
        Err(e) => Err(nix_err("dns_restore", e)),
        Ok(st) if same_inode(&st, &ours) => match unlinkat(dir, name, UnlinkatFlags::NoRemoveDir) {
            Ok(()) | Err(Errno::ENOENT) => Ok(()),
            Err(e) => Err(nix_err("dns_restore", e)),
        },
        Ok(_) => {
            tracing::warn!(
                path = %path.display(),
                "le fichier resolv a été remplacé depuis son écriture : laissé en place, \
                 seul notre contenu est effacé"
            );
            file.set_len(0).map_err(|e| io_err("dns_restore", e))
        }
    }
}

/// Écrit le fichier en conservant son contenu antérieur pour l'annulation.
///
/// Revue 5.3, F1 : dossier parent ouvert sans suivre de lien et vérifié
/// (propriétaire root/euid, pas g+w/o+w), fichier ouvert par `openat` avec
/// `O_NOFOLLOW`, toutes les opérations ultérieures (lecture, écriture,
/// restauration) par descripteur.
pub(crate) fn write(w: &DnsWrite) -> Result<Undo, NetError> {
    check_path(&w.path)?;
    let (dir, name) = open_parent(&w.path)?;
    let (mut file, created) = open_file(&dir, &name)?;
    let checked = check_file(&file, created).and_then(|()| {
        if created {
            return Ok(None);
        }
        let mut previous = Vec::new();
        (&mut file)
            .take(MAX_PREVIOUS + 1)
            .read_to_end(&mut previous)
            .map_err(|e| io_err("dns_read", e))?;
        if previous.len() as u64 > MAX_PREVIOUS {
            return Err(dns_error("fichier resolv existant trop volumineux".into()));
        }
        Ok(Some(previous))
    });
    let previous = match checked {
        Ok(p) => p,
        Err(e) => {
            if created {
                let _ = unlink_if_same(&dir, &name, &file, &w.path);
            }
            return Err(e);
        }
    };
    if let Err(source) = overwrite(&file, w.content.as_bytes()) {
        let undo = match &previous {
            Some(bytes) => overwrite(&file, bytes).map_err(|e| io_err("dns_restore", e)),
            None => unlink_if_same(&dir, &name, &file, &w.path),
        };
        if let Err(e) = undo {
            tracing::error!(error = %e, path = %w.path.display(), "restauration du fichier resolv impossible");
        }
        return Err(io_err("dns_write", source));
    }
    Ok(Undo::Dns(DnsUndo {
        opened: Arc::new(OpenedResolv {
            path: w.path.clone(),
            dir,
            name,
            file,
        }),
        previous,
    }))
}

/// Restaure le contenu antérieur par le descripteur (ou supprime le fichier
/// créé, s'il est toujours le nôtre).
pub(crate) fn restore(undo: &DnsUndo) -> Result<(), NetError> {
    let o = &undo.opened;
    match &undo.previous {
        Some(bytes) => overwrite(&o.file, bytes).map_err(|e| io_err("dns_restore", e)),
        None => unlink_if_same(&o.dir, &o.name, &o.file, &o.path),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    fn temp_dir() -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "netlinux-dns-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        dir
    }

    fn cfg(servers: &[&str], search: &[&str]) -> DnsConfig {
        DnsConfig {
            servers: servers.iter().map(|s| s.parse().unwrap()).collect(),
            search_domains: search.iter().map(|&s| s.to_owned()).collect(),
        }
    }

    #[test]
    fn renders_nameservers_and_search() {
        let out = render(&cfg(
            &["10.0.0.53", "fd00::53"],
            &["corp.example", "lab.corp.example."],
        ))
        .unwrap()
        .unwrap();
        let lines: Vec<_> = out.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(
            lines,
            vec![
                "nameserver 10.0.0.53",
                "nameserver fd00::53",
                "search corp.example lab.corp.example."
            ]
        );
    }

    #[test]
    fn empty_config_renders_nothing() {
        assert_eq!(render(&DnsConfig::default()).unwrap(), None);
        let dir = temp_dir();
        let strategy = DnsStrategy::ResolvFile(dir.join("resolv.conf"));
        assert_eq!(plan(&strategy, &DnsConfig::default()).unwrap(), None);
    }

    #[test]
    fn rejects_injection_in_search_domains() {
        for bad in [
            "corp\nnameserver 6.6.6.6",
            "corp example",
            "",
            ".",
            "a..b",
            "options ndots:15",
            "évil.example",
        ] {
            assert!(!is_valid_search_domain(bad), "{bad:?}");
            assert!(render(&cfg(&["10.0.0.53"], &[bad])).is_err(), "{bad:?}");
        }
        for good in ["corp.example", "corp.example.", "a-b_c.d1", "localdomain"] {
            assert!(is_valid_search_domain(good), "{good:?}");
        }
        assert!(!is_valid_search_domain(&"a".repeat(64)));
    }

    #[test]
    fn ignore_strategy_plans_nothing() {
        assert_eq!(
            plan(
                &DnsStrategy::Ignore,
                &cfg(&["10.0.0.53"], &["corp.example"])
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn refuses_system_resolv_and_relative_paths() {
        let c = cfg(&["10.0.0.53"], &[]);
        for p in ["/etc/resolv.conf", "/etc/../etc/resolv.conf", "resolv.conf"] {
            assert!(plan(&DnsStrategy::ResolvFile(p.into()), &c).is_err(), "{p}");
        }
        assert!(check_path(Path::new("/etc/netns/fvpn-test/resolv.conf")).is_ok());
    }

    /// Écrit via `plan` + `write` et retourne l'annulation.
    fn write_resolv(path: &Path) -> (DnsWrite, DnsUndo) {
        let w = plan(
            &DnsStrategy::ResolvFile(path.to_path_buf()),
            &cfg(&["10.0.0.53"], &["corp.example"]),
        )
        .unwrap()
        .unwrap();
        let Undo::Dns(undo) = write(&w).unwrap() else {
            panic!("undo inattendu");
        };
        (w, undo)
    }

    fn assert_refused(path: &Path) -> String {
        let w = DnsWrite {
            path: path.to_path_buf(),
            content: "nameserver 10.0.0.53\n".into(),
        };
        match write(&w) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("écriture acceptée : {}", path.display()),
        }
    }

    #[test]
    fn write_then_restore_previous_content() {
        let dir = temp_dir();
        let path = dir.join("resolv.conf");
        std::fs::write(&path, b"nameserver 192.0.2.53\n").unwrap();
        let (w, undo) = write_resolv(&path);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), w.content);
        assert_eq!(undo.previous(), Some(&b"nameserver 192.0.2.53\n"[..]));
        restore(&undo).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"nameserver 192.0.2.53\n");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn restore_shrinks_or_grows_to_previous_length() {
        let dir = temp_dir();
        let path = dir.join("resolv.conf");
        let long = "# commentaire\n".repeat(50);
        std::fs::write(&path, &long).unwrap();
        let (_, undo) = write_resolv(&path);
        restore(&undo).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), long);

        std::fs::write(&path, b"x").unwrap();
        let (_, undo) = write_resolv(&path);
        restore(&undo).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn write_then_restore_removes_created_file() {
        let dir = temp_dir();
        let path = dir.join("resolv.conf");
        let (_, undo) = write_resolv(&path);
        assert_eq!(undo.previous(), None);
        assert!(path.exists());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        restore(&undo).unwrap();
        assert!(!path.exists());
        // Idempotent : fichier déjà absent.
        restore(&undo).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn write_into_missing_directory_fails() {
        let w = DnsWrite {
            path: temp_dir().join("absent").join("resolv.conf"),
            content: String::new(),
        };
        assert!(matches!(write(&w), Err(NetError::Io { .. })));
    }

    #[test]
    fn refuses_symlinked_file_and_leaves_target_intact() {
        let dir = temp_dir();
        let victim = dir.join("victim");
        std::fs::write(&victim, b"secret\n").unwrap();
        let link = dir.join("resolv.conf");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let err = assert_refused(&link);
        assert!(err.contains("lien symbolique"), "{err}");
        assert_eq!(std::fs::read(&victim).unwrap(), b"secret\n");
        // Lien pendant : pas de création de la cible non plus.
        let dangling = dir.join("dangling.conf");
        std::os::unix::fs::symlink(dir.join("created-by-link"), &dangling).unwrap();
        assert_refused(&dangling);
        assert!(!dir.join("created-by-link").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_symlinked_parent_or_ancestor() {
        let dir = temp_dir();
        let real = dir.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = assert_refused(&link.join("resolv.conf"));
        assert!(err.contains("lien symbolique"), "{err}");
        std::fs::create_dir(real.join("sub")).unwrap();
        assert_refused(&link.join("sub").join("resolv.conf"));
        assert!(!real.join("resolv.conf").exists());
        assert!(!real.join("sub").join("resolv.conf").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_group_or_world_writable_parent() {
        for mode in [0o775, 0o757, 0o777, 0o1777] {
            let dir = temp_dir();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = assert_refused(&dir.join("resolv.conf"));
            assert!(err.contains("inscriptible"), "{mode:o} : {err}");
            assert!(!dir.join("resolv.conf").exists());
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn dir_owner_and_mode_rules() {
        assert!(check_dir_owner_mode(0, 0o40755, 1000).is_ok());
        assert!(check_dir_owner_mode(1000, 0o40700, 1000).is_ok());
        assert!(check_dir_owner_mode(0, 0o40755, 0).is_ok());
        assert!(check_dir_owner_mode(1001, 0o40755, 1000).is_err());
        assert!(check_dir_owner_mode(1001, 0o40755, 0).is_err());
        assert!(check_dir_owner_mode(0, 0o40775, 1000).is_err());
        assert!(check_dir_owner_mode(0, 0o40757, 0).is_err());
    }

    #[test]
    fn refuses_hard_link_fifo_and_directory() {
        let dir = temp_dir();
        let other = dir.join("other");
        std::fs::write(&other, b"keep\n").unwrap();
        let hard = dir.join("hard.conf");
        std::fs::hard_link(&other, &hard).unwrap();
        let err = assert_refused(&hard);
        assert!(err.contains("liens physiques"), "{err}");
        assert_eq!(std::fs::read(&other).unwrap(), b"keep\n");

        let fifo = dir.join("fifo.conf");
        nix::unistd::mkfifo(&fifo, Mode::from_bits_truncate(0o600)).unwrap();
        let err = assert_refused(&fifo);
        assert!(err.contains("ordinaire"), "{err}");

        std::fs::create_dir(dir.join("d.conf")).unwrap();
        assert_refused(&dir.join("d.conf"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_unnormalized_path() {
        let dir = temp_dir();
        std::fs::create_dir(dir.join("a")).unwrap();
        let w = DnsWrite {
            path: dir.join("a").join("..").join("resolv.conf"),
            content: String::new(),
        };
        assert!(write(&w).is_err());
        assert!(!dir.join("resolv.conf").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// TOCTOU : le nom est remplacé par un lien vers une victime après
    /// l'écriture ; la restauration agit sur le descripteur, pas sur le chemin.
    #[test]
    fn restore_uses_fd_not_path_after_swap() {
        let dir = temp_dir();
        let path = dir.join("resolv.conf");
        let victim = dir.join("victim");
        std::fs::write(&victim, b"victim\n").unwrap();
        std::fs::write(&path, b"nameserver 192.0.2.53\n").unwrap();
        let (_, undo) = write_resolv(&path);
        let moved = dir.join("moved.conf");
        std::fs::rename(&path, &moved).unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        restore(&undo).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"victim\n");
        assert_eq!(std::fs::read(&moved).unwrap(), b"nameserver 192.0.2.53\n");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Fichier créé puis remplacé par un autre : il n'est pas supprimé.
    #[test]
    fn created_file_replaced_is_not_unlinked() {
        let dir = temp_dir();
        let path = dir.join("resolv.conf");
        let (_, undo) = write_resolv(&path);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"someone else\n").unwrap();
        restore(&undo).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"someone else\n");
        // Même cas, remplacé par un lien : ni le lien ni sa cible ne bougent.
        std::fs::remove_file(&path).unwrap();
        let (_, undo) = write_resolv(&path);
        let victim = dir.join("victim");
        std::fs::write(&victim, b"victim\n").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        restore(&undo).unwrap();
        assert!(path.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&victim).unwrap(), b"victim\n");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
