//! Sockets d'écoute exclusives (constat E1 : vol de port local).
//!
//! Windows : `SO_EXCLUSIVEADDRUSE` avant `bind`, pour qu'aucun autre processus (même avec
//! `SO_REUSEADDR`) ne puisse capter nos connexions. Ailleurs : pas de `SO_REUSEADDR`.

use std::io;
use std::net::{SocketAddr, TcpListener};

use socket2::{Domain, Protocol, Socket, Type};

use crate::backend::ProxyError;

#[cfg(windows)]
#[allow(unsafe_code, clippy::cast_possible_truncation)]
fn set_exclusive(sock: &Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        SO_EXCLUSIVEADDRUSE, SOCKET_ERROR, SOL_SOCKET, setsockopt,
    };
    let on: u32 = 1;
    // SAFETY: le SOCKET est valide (possédé par `sock`) ; `on` vit pendant l'appel, longueur = 4.
    let rc = unsafe {
        setsockopt(
            sock.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            std::ptr::from_ref(&on).cast::<u8>(),
            4,
        )
    };
    if rc == SOCKET_ERROR {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps)]
fn set_exclusive(_sock: &Socket) -> io::Result<()> {
    Ok(()) // pas de SO_REUSEADDR : bind refusé si le port est déjà lié/écouté.
}

fn open(addr: SocketAddr) -> io::Result<TcpListener> {
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    set_exclusive(&sock)?;
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    sock.set_nonblocking(true)?;
    Ok(sock.into())
}

/// Classe une erreur de bind (codes OS injectables pour les tests).
fn classify(addr: SocketAddr, source: io::Error, windows: bool) -> ProxyError {
    let raw = source.raw_os_error();
    let code = raw.unwrap_or(0);
    let in_use = if windows {
        raw == Some(10048)
    } else {
        source.kind() == io::ErrorKind::AddrInUse
    };
    let denied = if windows {
        raw == Some(10013)
    } else {
        raw == Some(13)
    };
    if in_use {
        ProxyError::AddrInUse { addr, code }
    } else if denied {
        ProxyError::PortReserved { addr, code }
    } else {
        ProxyError::Bind { addr, source }
    }
}

/// Ouvre un écouteur TCP exclusif, non bloquant.
pub(crate) fn bind_exclusive(addr: SocketAddr) -> Result<TcpListener, ProxyError> {
    open(addr).map_err(|source| classify(addr, source, cfg!(windows)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_bind_refused() {
        let first = bind_exclusive("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = first.local_addr().unwrap();
        let err = bind_exclusive(addr).unwrap_err();
        assert!(matches!(err, ProxyError::AddrInUse { .. }), "{err:?}");
        let msg = err.to_string();
        assert!(
            msg.contains(&addr.to_string()) && msg.contains("[proxy]"),
            "{msg}"
        );
    }

    #[test]
    fn mapping_codes() {
        let a: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let e = |c| io::Error::from_raw_os_error(c);
        assert!(matches!(
            classify(a, e(10048), true),
            ProxyError::AddrInUse { code: 10048, .. }
        ));
        let r = classify(a, e(10013), true);
        assert!(matches!(r, ProxyError::PortReserved { code: 10013, .. }));
        let m = r.to_string();
        assert!(
            m.contains("os error 10013") && m.contains("excludedportrange"),
            "{m}"
        );
        assert!(matches!(
            classify(a, e(13), false),
            ProxyError::PortReserved { code: 13, .. }
        ));
        assert!(matches!(
            classify(a, e(98), false),
            ProxyError::AddrInUse { code: 98, .. }
        ));
        assert!(matches!(
            classify(a, e(10049), true),
            ProxyError::Bind { .. }
        ));
    }
}
