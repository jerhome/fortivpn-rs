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

/// Ouvre un écouteur TCP exclusif, non bloquant.
pub(crate) fn bind_exclusive(addr: SocketAddr) -> Result<TcpListener, ProxyError> {
    open(addr).map_err(|source| {
        // WSAEACCES (10013) : conflit avec un écouteur exclusif sous Windows.
        if source.kind() == io::ErrorKind::AddrInUse
            || source.raw_os_error() == Some(10013) && cfg!(windows)
        {
            ProxyError::AddrInUse { addr }
        } else {
            ProxyError::Bind { addr, source }
        }
    })
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
}
