//! Répertoire de données réservé aux administrateurs.

use std::io;
use std::path::Path;

use windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS;
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

use super::sd::SecurityDescriptor;

/// DACL protégée, héritée par le contenu : SYSTEM et Administrateurs seulement.
const ADMIN_ONLY_DIR_SDDL: &str = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)";

/// Crée `path` (un seul niveau) avec une DACL SYSTEM + Administrateurs ; sans
/// erreur s'il existe déjà (son ACL est alors vérifiée par l'appelant, qui ne doit
/// pas lui faire confiance).
pub fn create_admin_only_dir(path: &Path) -> io::Result<()> {
    let sd = SecurityDescriptor::from_sddl(ADMIN_ONLY_DIR_SDDL)?;
    let sa = sd.attributes();
    let wide = to_wide(path);
    // SAFETY: `wide` est terminé par NUL ; `sa` (et le descripteur pointé, porté
    // par `sd`) vivent pendant l'appel.
    let ok = unsafe { CreateDirectoryW(wide.as_ptr(), &raw const sa) };
    if ok == 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == i32::try_from(ERROR_ALREADY_EXISTS).ok() {
            return Ok(());
        }
        return Err(err);
    }
    Ok(())
}

fn to_wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}
