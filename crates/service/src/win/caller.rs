//! Identité du client d'un named pipe : SID de l'utilisateur et appartenance au
//! groupe Administrateurs, lus dans le jeton d'emprunt d'identité du client
//! (revue 5.3 passe 2, M3). Le pipe est ouvert par les clients en
//! `SECURITY_IDENTIFICATION` : on ne peut que *lire* l'identité, pas agir sous
//! son nom ; l'emprunt est annulé (`RevertToSelf`) avant tout `await`.

use std::ffi::c_void;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::ptr;

use tokio::net::windows::named_pipe::NamedPipeServer;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, PSID, RevertToSelf, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER, TokenGroups,
    TokenUser,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

use crate::access::Caller;

/// Handle de jeton fermé au `Drop`.
struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: handle de jeton valide retourné par OpenThreadToken, possédé
        // exclusivement par ce wrapper et fermé une seule fois.
        unsafe { CloseHandle(self.0) };
    }
}

/// Emprunt d'identité du client sur le thread courant, annulé au `Drop`.
struct Impersonation;

impl Impersonation {
    fn begin(pipe: &NamedPipeServer) -> io::Result<Self> {
        // SAFETY: le handle appartient à `pipe`, vivant pendant l'appel ; un
        // client est connecté (appelé après `connect()`).
        if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self)
    }
}

impl Drop for Impersonation {
    fn drop(&mut self) {
        // SAFETY: sans précondition ; met fin à l'emprunt d'identité du thread.
        if unsafe { RevertToSelf() } == 0 {
            // Un thread resté sous l'identité d'un client serait dangereux : on
            // préfère arrêter le service (le SCM le relance).
            tracing::error!("RevertToSelf a échoué : arrêt du processus");
            std::process::abort();
        }
    }
}

/// SID (chaîne) pointé par `sid`.
fn sid_string(sid: PSID) -> io::Result<String> {
    let mut out: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` pointe un SID valide (dans un tampon vivant chez l'appelant) ;
    // `out` est une sortie locale.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut out) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut len = 0usize;
    // SAFETY: chaîne UTF-16 terminée par NUL allouée par l'API ; arrêt au NUL.
    while unsafe { *out.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` unités lisibles avant le NUL, mémoire encore vivante.
    let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, len) });
    // SAFETY: `out` alloué par l'API avec LocalAlloc, libéré une seule fois.
    unsafe { LocalFree(out.cast::<c_void>()) };
    Ok(s)
}

/// Lit une classe d'information du jeton dans un tampon aligné sur 8 octets.
fn token_info(token: &Token, class: i32) -> io::Result<Vec<u64>> {
    let mut len = 0u32;
    // SAFETY: appel de dimensionnement : tampon nul de taille 0 ; `len` sortie locale.
    unsafe { GetTokenInformation(token.0, class, ptr::null_mut(), 0, &raw mut len) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` offre au moins `len` octets, alignés sur 8 ; `len` sortie locale.
    let ok =
        unsafe { GetTokenInformation(token.0, class, buf.as_mut_ptr().cast(), len, &raw mut len) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buf)
}

fn token_user(token: &Token) -> io::Result<String> {
    let buf = token_info(token, TokenUser)?;
    // SAFETY: le tampon contient une TOKEN_USER valide (écrite par l'API, alignée) ;
    // le SID pointé est dans le même tampon, vivant pendant `sid_string`.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    sid_string(sid)
}

fn token_groups(token: &Token) -> io::Result<Vec<(String, u32)>> {
    let buf = token_info(token, TokenGroups)?;
    let base = buf.as_ptr().cast::<TOKEN_GROUPS>();
    // SAFETY: le tampon contient une TOKEN_GROUPS valide écrite par l'API.
    let count = unsafe { (*base).GroupCount } as usize;
    // SAFETY: tableau de `count` SID_AND_ATTRIBUTES contigus dans le tampon ;
    // seule l'adresse du premier élément est prise ici.
    let first = unsafe {
        (&raw const (*base).Groups).cast::<windows_sys::Win32::Security::SID_AND_ATTRIBUTES>()
    };
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        // SAFETY: `i < count` : élément du tableau décrit par l'API, SID dans le tampon.
        let (sid, attrs) = unsafe {
            let e = first.add(i);
            ((*e).Sid, (*e).Attributes)
        };
        out.push((sid_string(sid)?, attrs));
    }
    Ok(out)
}

/// Identifie le client connecté à `pipe`.
pub(super) fn identify(pipe: &NamedPipeServer) -> io::Result<Caller> {
    let _impersonation = Impersonation::begin(pipe)?;
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: jeton du thread courant (sous emprunt) ; OpenAsSelf = 1 : contrôle
    // d'accès avec l'identité du service ; `raw` sortie locale.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Token(raw);
    let user = token_user(&token)?;
    let groups = token_groups(&token)?;
    Ok(Caller::from_token(&user, &groups))
}
