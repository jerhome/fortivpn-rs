//! Descripteur de sécurité construit depuis une chaîne SDDL, libéré au `Drop`.

use std::ffi::c_void;
use std::io;
use std::ptr;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

/// Descripteur alloué par l'OS (`LocalAlloc`), libéré par `LocalFree`.
#[derive(Debug)]
pub(super) struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    /// Construit le descripteur décrit par `sddl`.
    pub(super) fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `wide` est terminé par NUL et vit pendant l'appel ; `sd` est
        // une sortie locale ; la taille facultative n'est pas demandée.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &raw mut sd,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(sd))
    }

    /// `SECURITY_ATTRIBUTES` non héritables pointant ce descripteur ; valables tant
    /// que `self` vit.
    pub(super) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: pointeur retourné par une API documentée « à libérer avec
            // LocalFree », possédé exclusivement par ce wrapper, libéré une fois.
            unsafe { LocalFree(self.0.cast::<c_void>()) };
        }
    }
}
