//! Contrôle du propriétaire du processus client (constat M1).
//!
//! Le proxy SOCKS5 n'a pas d'authentification : sur un poste partagé (autre
//! utilisateur, session RDP) ou face à un processus d'un autre compte, tout client
//! loopback accéderait au réseau d'entreprise. On n'accepte donc une connexion que
//! si le processus qui détient l'autre extrémité appartient à l'utilisateur qui a
//! lancé le proxy.
//!
//! - Linux : socket du pair retrouvé dans `/proc/net/tcp{,6}` (adresses locale et
//!   distante) → uid, comparé à l'uid effectif (`/proc/self/status`).
//! - Windows : `GetExtendedTcpTable` → PID du pair → jeton du processus → SID,
//!   comparé au SID du processus courant.
//!
//! Tout échec de vérification (pair introuvable, accès refusé, pair non local)
//! vaut refus. Plates-formes sans implémentation : refus.

use std::net::SocketAddr;
use std::sync::Arc;

/// Décide si le client dont le socket est `peer` (connecté à `local`) est autorisé.
/// Bloquant (lecture de tables système) : à appeler via `spawn_blocking`.
pub(crate) trait OwnerCheck: Send + Sync + std::fmt::Debug {
    fn allowed(&self, peer: SocketAddr, local: SocketAddr) -> bool;
}

/// Vérificateur du système (uid sous Linux, SID sous Windows).
#[derive(Debug, Default)]
pub(crate) struct SystemOwnerCheck;

impl OwnerCheck for SystemOwnerCheck {
    fn allowed(&self, peer: SocketAddr, local: SocketAddr) -> bool {
        match sys::peer_is_current_user(peer, local) {
            Ok(ok) => ok,
            Err(reason) => {
                tracing::debug!(%reason, "proxy : propriétaire du client non vérifiable, refus");
                false
            }
        }
    }
}

pub(crate) fn system_check() -> Arc<dyn OwnerCheck> {
    Arc::new(SystemOwnerCheck)
}

// --- Linux ------------------------------------------------------------------------

/// Analyse de `/proc/net/tcp{,6}` (indépendante de la plate-forme, testable).
#[cfg(any(target_os = "linux", test))]
mod procnet {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    /// Décode `HEXADDR:HEXPORT` (mots de 32 bits en ordre natif, port en hexa).
    pub(super) fn parse_addr(s: &str, little_endian: bool) -> Option<SocketAddr> {
        let (addr, port) = s.split_once(':')?;
        let port = u16::from_str_radix(port, 16).ok()?;
        let word = |h: &str| -> Option<[u8; 4]> {
            let w = u32::from_str_radix(h, 16).ok()?;
            Some(if little_endian {
                w.to_le_bytes()
            } else {
                w.to_be_bytes()
            })
        };
        // `/proc` écrit chaque mot (%08X) en ordre natif : `word` restitue l'ordre réseau.
        let ip = match addr.len() {
            8 => IpAddr::V4(Ipv4Addr::from(word(addr)?)),
            32 => {
                let mut out = [0u8; 16];
                for (i, chunk) in out.chunks_exact_mut(4).enumerate() {
                    chunk.copy_from_slice(&word(addr.get(i * 8..i * 8 + 8)?)?);
                }
                IpAddr::V6(Ipv6Addr::from(out))
            }
            _ => return None,
        };
        Some(SocketAddr::new(ip, port))
    }

    /// Normalise `::ffff:a.b.c.d` en IPv4 pour comparer v4 et v6 mappé.
    pub(super) fn canon(a: SocketAddr) -> SocketAddr {
        match a.ip() {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map_or(a, |v4| SocketAddr::new(IpAddr::V4(v4), a.port())),
            IpAddr::V4(_) => a,
        }
    }

    /// Trouve l'uid du socket dont l'adresse locale est `local` et la distante
    /// `remote`, dans le contenu d'un fichier `/proc/net/tcp{,6}`.
    pub(super) fn find_uid(
        table: &str,
        local: SocketAddr,
        remote: SocketAddr,
        little_endian: bool,
    ) -> Option<u32> {
        let (local, remote) = (canon(local), canon(remote));
        table.lines().skip(1).find_map(|line| {
            let mut f = line.split_whitespace();
            let l = canon(parse_addr(f.nth(1)?, little_endian)?);
            let r = canon(parse_addr(f.next()?, little_endian)?);
            if l != local || r != remote {
                return None;
            }
            // Après rem_address : st, tx:rx, tr:when, retrnsmt, uid.
            f.nth(4)?.parse().ok()
        })
    }
}

#[cfg(target_os = "linux")]
mod sys {
    use super::procnet;
    use std::net::SocketAddr;

    /// Uid effectif du processus (`Uid:` réel, effectif, … de `/proc/self/status`).
    pub(super) fn current_uid() -> Result<u32, String> {
        let status = std::fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
        parse_euid(&status).ok_or_else(|| "uid courant introuvable".to_owned())
    }

    pub(super) fn parse_euid(status: &str) -> Option<u32> {
        let line = status.lines().find(|l| l.starts_with("Uid:"))?;
        line.split_whitespace().nth(2)?.parse().ok()
    }

    pub(super) fn peer_is_current_user(
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Result<bool, String> {
        let me = current_uid()?;
        // Le socket du client : local = `peer`, distant = notre adresse d'écoute.
        for file in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let Ok(table) = std::fs::read_to_string(file) else {
                continue;
            };
            if let Some(uid) =
                procnet::find_uid(&table, peer, local, cfg!(target_endian = "little"))
            {
                return Ok(uid == me);
            }
        }
        Err("socket du pair introuvable dans /proc/net/tcp".to_owned())
    }
}

// --- Windows ----------------------------------------------------------------------

#[cfg(windows)]
#[allow(unsafe_code)]
mod sys {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE, NO_ERROR,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// Handle fermé à la destruction.
    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: handle valide, obtenu par OpenProcess/OpenProcessToken, fermé une seule fois.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// `TOKEN_USER` d'un jeton, dans un tampon aligné (le SID pointe dans le tampon).
    struct UserSid(Vec<u64>);

    impl UserSid {
        fn sid(&self) -> *mut core::ffi::c_void {
            // SAFETY: le tampon a été rempli par GetTokenInformation(TokenUser) ; il est
            // aligné sur 8 octets et vit autant que `self`.
            unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
        }
    }

    fn token_user(token: &Handle) -> Result<UserSid, String> {
        let mut len = 0u32;
        // SAFETY: première requête de taille (tampon nul, longueur 0) ; `len` est valide.
        unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &raw mut len) };
        if len == 0 {
            return Err("taille TokenUser nulle".to_owned());
        }
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: `buf` offre au moins `len` octets ; `len` est valide.
        let ok = unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buf.as_mut_ptr().cast(),
                len,
                &raw mut len,
            )
        };
        if ok == 0 {
            return Err("GetTokenInformation a échoué".to_owned());
        }
        Ok(UserSid(buf))
    }

    fn process_user(process: HANDLE) -> Result<UserSid, String> {
        let mut tok: HANDLE = std::ptr::null_mut();
        // SAFETY: `process` valide ; `tok` reçoit un handle que `Handle` fermera.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut tok) } == 0 {
            return Err("OpenProcessToken a échoué".to_owned());
        }
        token_user(&Handle(tok))
    }

    fn pid_is_current_user(pid: u32) -> Result<bool, String> {
        // SAFETY: GetCurrentProcess renvoie un pseudo-handle, sans fermeture requise.
        let me = process_user(unsafe { GetCurrentProcess() })?;
        // SAFETY: appel simple ; le handle résultat est géré par `Handle`.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            return Err("OpenProcess refusé".to_owned());
        }
        let h = Handle(h);
        let other = process_user(h.0)?;
        // SAFETY: les deux SID sont valides (tampons vivants).
        Ok(unsafe { EqualSid(me.sid(), other.sid()) } != 0)
    }

    /// Récupère la table TCP (`family` : IPv4 ou IPv6) dans un tampon aligné.
    fn tcp_table(family: u32) -> Result<Vec<u64>, String> {
        let mut size = 0u32;
        for _ in 0..8 {
            let mut buf = vec![0u64; (size as usize).div_ceil(8).max(1)];
            // SAFETY: `buf` offre `size` octets (ou 8 pour la requête initiale, size = 0) ;
            // `size` est valide en lecture/écriture.
            let rc = unsafe {
                GetExtendedTcpTable(
                    buf.as_mut_ptr().cast(),
                    &raw mut size,
                    0,
                    family,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };
            match rc {
                NO_ERROR => return Ok(buf),
                ERROR_INSUFFICIENT_BUFFER => {}
                e => return Err(format!("GetExtendedTcpTable : code {e}")),
            }
        }
        Err("GetExtendedTcpTable : table instable".to_owned())
    }

    fn port(dw: u32) -> u16 {
        // Octets réseau dans les 16 bits de poids faible.
        u16::from_be((dw & 0xFFFF) as u16)
    }

    fn find_pid(peer: SocketAddr, local: SocketAddr) -> Result<Option<u32>, String> {
        let v6 = peer.is_ipv6() || local.is_ipv6();
        let buf = tcp_table(u32::from(if v6 { AF_INET6 } else { AF_INET }))?;
        if v6 {
            let t = buf.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>();
            // SAFETY: tampon rempli par GetExtendedTcpTable ; dwNumEntries lignes contiguës.
            let rows = unsafe {
                std::slice::from_raw_parts((*t).table.as_ptr(), (*t).dwNumEntries as usize)
            };
            Ok(rows.iter().find_map(|r| {
                let l = SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                    port(r.dwLocalPort),
                );
                let d = SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)),
                    port(r.dwRemotePort),
                );
                (l == peer && d == local).then_some(r.dwOwningPid)
            }))
        } else {
            let t = buf.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
            // SAFETY: idem, version IPv4.
            let rows = unsafe {
                std::slice::from_raw_parts((*t).table.as_ptr(), (*t).dwNumEntries as usize)
            };
            Ok(rows.iter().find_map(|r| {
                let l = SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())),
                    port(r.dwLocalPort),
                );
                let d = SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes())),
                    port(r.dwRemotePort),
                );
                (l == peer && d == local).then_some(r.dwOwningPid)
            }))
        }
    }

    pub(super) fn peer_is_current_user(
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Result<bool, String> {
        let pid = find_pid(peer, local)?.ok_or_else(|| "socket du pair introuvable".to_owned())?;
        pid_is_current_user(pid)
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod sys {
    use std::net::SocketAddr;

    pub(super) fn peer_is_current_user(_: SocketAddr, _: SocketAddr) -> Result<bool, String> {
        Err("contrôle du propriétaire non pris en charge sur cette plate-forme".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:0438 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0 100 0 0 10 0\n\
   1: 0100007F:C350 0100007F:0438 01 00000000:00000000 00:00000000 00000000  1234        0 22222 1 0 100 0 0 10 0\n";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000000000000000000001000000:C351 00000000000000000000000001000000:0438 01 00000000:00000000 00:00000000 00000000  4321        0 33333 1 0 100 0 0 10 0\n";

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parse_proc_samples() {
        assert_eq!(
            procnet::parse_addr("0100007F:0438", true),
            Some(sa("127.0.0.1:1080"))
        );
        assert_eq!(
            procnet::parse_addr("00000000000000000000000001000000:C351", true),
            Some(sa("[::1]:50001"))
        );
        assert_eq!(procnet::parse_addr("zz:1", true), None);
        assert_eq!(procnet::parse_addr("0100007F", true), None);
    }

    #[test]
    fn find_uid_in_tables() {
        let (cli, srv) = (sa("127.0.0.1:50000"), sa("127.0.0.1:1080"));
        assert_eq!(procnet::find_uid(TCP, cli, srv, true), Some(1234));
        // Mauvais port ou socket d'écoute seul : introuvable.
        assert_eq!(
            procnet::find_uid(TCP, sa("127.0.0.1:50001"), srv, true),
            None
        );
        let (cli6, srv6) = (sa("[::1]:50001"), sa("[::1]:1080"));
        assert_eq!(procnet::find_uid(TCP6, cli6, srv6, true), Some(4321));
        // Ligne tronquée : ignorée sans panique.
        assert_eq!(
            procnet::find_uid("hdr\n 0: 0100007F:0438", cli, srv, true),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn euid_parsing() {
        assert_eq!(
            sys::parse_euid("Name:\tx\nUid:\t1000\t1001\t1000\t1000\n"),
            Some(1001)
        );
        assert_eq!(sys::parse_euid("Name:\tx\n"), None);
        assert!(sys::current_uid().is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_local_connection_is_allowed() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, peer) = l.accept().unwrap();
        assert!(SystemOwnerCheck.allowed(peer, s.local_addr().unwrap()));
        // Pair inexistant : refus.
        assert!(!SystemOwnerCheck.allowed(sa("127.0.0.1:1"), c.peer_addr().unwrap()));
    }
}
