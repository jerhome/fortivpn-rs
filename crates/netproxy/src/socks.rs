//! Protocole SOCKS5 (RFC 1928), côté serveur, réduit au strict nécessaire.
//!
//! - Méthode d'authentification : « aucune » (0x00) seulement. Le proxy n'écoute
//!   que sur loopback par défaut ; une écoute réseau doit être autorisée
//!   explicitement ([`ProxyConfig::allow_non_loopback`](crate::ProxyConfig)).
//! - Commande : `CONNECT` uniquement. `BIND` et `UDP ASSOCIATE` sont refusés
//!   (réponse 0x07 « commande non prise en charge ») : le premier exigerait une
//!   écoute dans le tunnel, le second un relais UDP, hors périmètre.
//! - Adresses : IPv4 et nom de domaine (résolu par les DNS du tunnel). IPv6 est
//!   refusé (0x08) : le tunnel n'en porte pas.

use std::net::{Ipv4Addr, SocketAddrV4};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::{Host, Target};

const VERSION: u8 = 5;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Code de réponse SOCKS5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reply {
    /// Succès.
    Succeeded = 0x00,
    /// Échec général (ex. tunnel non établi).
    GeneralFailure = 0x01,
    /// Réseau inaccessible (tunnel coupé).
    NetworkUnreachable = 0x03,
    /// Hôte inaccessible (résolution échouée, délai dépassé).
    HostUnreachable = 0x04,
    /// Connexion refusée (RST).
    ConnectionRefused = 0x05,
    /// Commande non prise en charge (BIND, UDP ASSOCIATE).
    CommandNotSupported = 0x07,
    /// Type d'adresse non pris en charge (IPv6).
    AddressTypeNotSupported = 0x08,
}

/// Erreur de négociation SOCKS5.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SocksError {
    /// Erreur d'entrée/sortie (dont fin de flux prématurée).
    #[error("entrée/sortie : {0}")]
    Io(#[from] std::io::Error),
    /// Version de protocole autre que 5.
    #[error("version SOCKS {0} non prise en charge")]
    Version(u8),
    /// Le client ne propose pas la méthode « sans authentification ».
    #[error("aucune méthode d'authentification acceptable")]
    NoAcceptableMethod,
    /// Requête refusée ; la réponse a été (ou doit être) envoyée avec ce code.
    #[error("requête refusée ({0:?})")]
    Refused(Reply),
    /// Champ réservé non nul ou nom de domaine invalide.
    #[error("requête mal formée")]
    Malformed,
}

/// Lit le message de salutation et répond : méthode « sans authentification »
/// si proposée, sinon 0xFF (et erreur).
pub(crate) async fn negotiate_method<S>(stream: &mut S) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(SocksError::Version(head[0]));
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    stream.read_exact(&mut methods).await?;
    if methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&[VERSION, METHOD_NO_AUTH]).await?;
        Ok(())
    } else {
        stream.write_all(&[VERSION, METHOD_NONE_ACCEPTABLE]).await?;
        Err(SocksError::NoAcceptableMethod)
    }
}

/// Lit la requête. Une commande ou un type d'adresse non pris en charge donne
/// `Err(Refused(code))` : l'appelant envoie alors la réponse avec [`write_reply`].
pub(crate) async fn read_request<R>(stream: &mut R) -> Result<Target, SocksError>
where
    R: AsyncRead + Unpin,
{
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    let [version, cmd, reserved, atyp] = head;
    if version != VERSION {
        return Err(SocksError::Version(version));
    }
    if reserved != 0 {
        return Err(SocksError::Malformed);
    }
    let host = match atyp {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            Host::Ip(Ipv4Addr::from(ip))
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await?;
            let mut name = vec![0u8; usize::from(len)];
            stream.read_exact(&mut name).await?;
            let name = String::from_utf8(name).map_err(|_| SocksError::Malformed)?;
            Host::parse(&name).ok_or(SocksError::Malformed)?
        }
        ATYP_IPV6 => {
            // Consomme l'adresse et le port pour pouvoir répondre proprement.
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).await?;
            return Err(SocksError::Refused(Reply::AddressTypeNotSupported));
        }
        _ => return Err(SocksError::Refused(Reply::AddressTypeNotSupported)),
    };
    let port = stream.read_u16().await?;
    if cmd != CMD_CONNECT {
        return Err(SocksError::Refused(Reply::CommandNotSupported));
    }
    if port == 0 {
        return Err(SocksError::Refused(Reply::HostUnreachable));
    }
    Ok(Target { host, port })
}

/// Encode une réponse (adresse liée IPv4).
pub(crate) fn encode_reply(reply: Reply, bound: SocketAddrV4) -> [u8; 10] {
    let ip = bound.ip().octets();
    let port = bound.port().to_be_bytes();
    [
        VERSION,
        reply as u8,
        0,
        ATYP_IPV4,
        ip[0],
        ip[1],
        ip[2],
        ip[3],
        port[0],
        port[1],
    ]
}

/// Envoie une réponse.
pub(crate) async fn write_reply<W>(
    stream: &mut W,
    reply: Reply,
    bound: SocketAddrV4,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    stream.write_all(&encode_reply(reply, bound)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn request(bytes: &[u8]) -> Result<Target, SocksError> {
        let mut r = bytes;
        read_request(&mut r).await
    }

    #[tokio::test]
    async fn method_negotiation() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&[5, 2, 0x02, 0x00]).await.unwrap();
        negotiate_method(&mut server).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [5, 0]);

        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&[5, 1, 0x02]).await.unwrap();
        assert!(matches!(
            negotiate_method(&mut server).await,
            Err(SocksError::NoAcceptableMethod)
        ));
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [5, 0xFF]);

        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&[4, 1, 0]).await.unwrap();
        assert!(matches!(
            negotiate_method(&mut server).await,
            Err(SocksError::Version(4))
        ));
    }

    #[tokio::test]
    async fn connect_ipv4_and_domain() {
        let t = request(&[5, 1, 0, 1, 10, 0, 0, 7, 0x0D, 0x3D])
            .await
            .unwrap();
        assert_eq!(t.host, Host::Ip(Ipv4Addr::new(10, 0, 0, 7)));
        assert_eq!(t.port, 3389);

        let mut req = vec![5, 1, 0, 3, 8];
        req.extend_from_slice(b"Srv.Corp");
        req.extend_from_slice(&[0, 22]);
        let t = request(&req).await.unwrap();
        assert_eq!(t.host, Host::Domain("srv.corp".into()));
        assert_eq!(t.port, 22);

        // Nom de domaine contenant une IPv4 littérale.
        let mut req = vec![5, 1, 0, 3, 8];
        req.extend_from_slice(b"10.1.2.3");
        req.extend_from_slice(&[0, 80]);
        assert_eq!(
            request(&req).await.unwrap().host,
            Host::Ip(Ipv4Addr::new(10, 1, 2, 3))
        );
    }

    #[tokio::test]
    async fn refused_requests() {
        // BIND, UDP ASSOCIATE.
        for cmd in [2, 3] {
            assert!(matches!(
                request(&[5, cmd, 0, 1, 10, 0, 0, 7, 0, 80]).await,
                Err(SocksError::Refused(Reply::CommandNotSupported))
            ));
        }
        let mut v6 = vec![5, 1, 0, 4];
        v6.extend_from_slice(&[0; 16]);
        v6.extend_from_slice(&[0, 80]);
        assert!(matches!(
            request(&v6).await,
            Err(SocksError::Refused(Reply::AddressTypeNotSupported))
        ));
        assert!(matches!(
            request(&[5, 1, 0, 9, 0, 0]).await,
            Err(SocksError::Refused(Reply::AddressTypeNotSupported))
        ));
        assert!(matches!(
            request(&[5, 1, 0, 1, 10, 0, 0, 7, 0, 0]).await,
            Err(SocksError::Refused(Reply::HostUnreachable))
        ));
    }

    #[tokio::test]
    async fn malformed_requests() {
        assert!(matches!(
            request(&[5, 1, 1, 1, 10, 0, 0, 7, 0, 80]).await,
            Err(SocksError::Malformed)
        ));
        assert!(matches!(
            request(&[4, 1, 0, 1, 10, 0, 0, 7, 0, 80]).await,
            Err(SocksError::Version(4))
        ));
        let mut bad = vec![5, 1, 0, 3, 5];
        bad.extend_from_slice(b"a b c");
        bad.extend_from_slice(&[0, 80]);
        assert!(matches!(request(&bad).await, Err(SocksError::Malformed)));
        let mut empty = vec![5, 1, 0, 3, 0];
        empty.extend_from_slice(&[0, 80]);
        assert!(matches!(request(&empty).await, Err(SocksError::Malformed)));
        // Tronquée.
        assert!(matches!(
            request(&[5, 1, 0, 1, 10, 0]).await,
            Err(SocksError::Io(_))
        ));
    }

    #[test]
    fn reply_encoding() {
        let r = encode_reply(
            Reply::Succeeded,
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 49152),
        );
        assert_eq!(r, [5, 0, 0, 1, 10, 0, 0, 2, 0xC0, 0x00]);
        assert_eq!(
            encode_reply(
                Reply::CommandNotSupported,
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)
            )[1],
            7
        );
    }
}
