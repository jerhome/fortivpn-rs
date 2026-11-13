//! Connexion cliente au pipe, avec vérification de l'identité du serveur.

use std::fs::OpenOptions;
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, IntoRawHandle, OwnedHandle};
use std::time::Duration;

use tokio::net::windows::named_pipe::NamedPipeClient;
use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OVERLAPPED, SECURITY_IDENTIFICATION};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

use super::scm;
use crate::protocol::{PIPE_NAME, PIPE_USER_ACCESS_MASK};

/// Ouvre le pipe sans demander `FILE_CREATE_PIPE_INSTANCE` (absent de la DACL) ni
/// laisser le serveur usurper l'identité du client (`SECURITY_IDENTIFICATION`).
fn open() -> io::Result<NamedPipeClient> {
    let file = OpenOptions::new()
        .access_mode(PIPE_USER_ACCESS_MASK)
        .custom_flags(FILE_FLAG_OVERLAPPED)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(PIPE_NAME)?;
    let handle = OwnedHandle::from(file).into_raw_handle();
    // SAFETY: `handle` est un handle de pipe valide, ouvert avec
    // FILE_FLAG_OVERLAPPED, dont la propriété est transférée à tokio (qui le ferme).
    unsafe { NamedPipeClient::from_raw_handle(handle) }
}

/// PID du processus serveur du pipe.
fn server_pid(pipe: &NamedPipeClient) -> io::Result<u32> {
    let mut pid = 0u32;
    // SAFETY: le handle appartient à `pipe`, vivant pendant l'appel ; `pid` est
    // une sortie locale.
    let ok = unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &raw mut pid) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

/// Ouvre le pipe (attend s'il est occupé) et vérifie que son serveur est bien le
/// processus du service enregistré : sans cela, un processus quelconque ayant créé
/// le pipe avant le service recevrait le mot de passe.
pub async fn connect_pipe() -> io::Result<NamedPipeClient> {
    let mut attempts = 0;
    let pipe = loop {
        match open() {
            Ok(pipe) => break pipe,
            Err(e) if e.raw_os_error() == i32::try_from(ERROR_PIPE_BUSY).ok() && attempts < 50 => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "service fortivpn-rs injoignable (installé et démarré ? `fortivpn service start`)",
                ));
            }
            Err(e) => return Err(e),
        }
    };
    let expected = scm::service_process_id()?;
    let actual = server_pid(&pipe)?;
    if expected != actual {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "le serveur du pipe n'est pas le service fortivpn-rs : connexion refusée",
        ));
    }
    Ok(pipe)
}
