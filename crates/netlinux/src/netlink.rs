//! [`System`] réel : rtnetlink (adresses, liens, routes, `RTM_GETROUTE`) et
//! fichier resolv.
//!
//! Chaque appel ouvre sa propre connexion netlink, pilotée dans la même tâche
//! que la requête (`select!`) : aucune tâche n'est lancée en arrière-plan et
//! l'appel fonctionne dans n'importe quel runtime tokio (y compris le runtime
//! `current_thread` du thread de nettoyage bloquant).

use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};

use fortivpn_core::NetError;
use futures_util::TryStreamExt;
use ipnet::Ipv6Net;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::address::{AddressAttribute, AddressMessage};
use rtnetlink::packet_route::route::{
    RouteAddress, RouteAttribute, RouteMessage, RouteScope, RouteType,
};
use rtnetlink::{Handle, LinkUnspec, RouteMessageBuilder};

use crate::dns;
use crate::plan::{AddrSpec, Op, OriginRoute, RouteSpec, Undo};
use crate::system::{Outcome, System};

// errno Linux (asm-generic, identiques sur x86_64 et aarch64).
const ENOENT: i32 = 2;
const ESRCH: i32 = 3;
const EEXIST: i32 = 17;
const ENODEV: i32 = 19;
const EOPNOTSUPP: i32 = 95;
const EAFNOSUPPORT: i32 = 97;
const EADDRNOTAVAIL: i32 = 99;
const ENETUNREACH: i32 = 101;
const EHOSTUNREACH: i32 = 113;

/// Code errno (positif) d'une erreur netlink, s'il y en a un.
pub(crate) fn errno(e: &rtnetlink::Error) -> Option<i32> {
    match e {
        rtnetlink::Error::NetlinkError(m) => Some(m.raw_code().abs()),
        _ => None,
    }
}

/// Erreur d'ajout signifiant « déjà présent ».
pub(crate) fn is_already_present(e: &rtnetlink::Error) -> bool {
    errno(e) == Some(EEXIST)
}

/// Erreur de suppression signifiant « déjà absent » (route/adresse retirée par
/// ailleurs, ou interface TUN déjà détruite avec ses routes).
pub(crate) fn is_already_gone(e: &rtnetlink::Error) -> bool {
    matches!(errno(e), Some(ENOENT | ESRCH | ENODEV | EADDRNOTAVAIL))
}

/// Erreur de `RTM_GETROUTE` signifiant « pas de route ».
pub(crate) fn is_unreachable(e: &rtnetlink::Error) -> bool {
    matches!(errno(e), Some(ENETUNREACH | EHOSTUNREACH))
}

/// Erreur signifiant « pas d'IPv6 sur cet hôte » (`ipv6.disable=1`, module
/// absent…).
pub(crate) fn is_ipv6_unavailable(e: &rtnetlink::Error) -> bool {
    matches!(errno(e), Some(EAFNOSUPPORT | EOPNOTSUPP))
}

pub(crate) fn map_err(op: &'static str, e: rtnetlink::Error) -> NetError {
    match e {
        rtnetlink::Error::NetlinkError(m) => NetError::Io {
            op,
            source: m.to_io(),
        },
        other => NetError::Os {
            op,
            reason: other.to_string(),
        },
    }
}

/// Message de route (ajout et suppression utilisent le même message, ce qui
/// cible exactement la route installée).
pub(crate) fn route_message(spec: &RouteSpec) -> RouteMessage {
    let b = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(spec.dest.network(), spec.dest.prefix_len())
        .output_interface(spec.oif);
    match spec.gateway {
        Some(gw) => b.gateway(gw),
        // Comme `ip route add … dev X` : route directe, scope link.
        None => b.scope(RouteScope::Link),
    }
    .build()
}

/// Message de route IPv6 `blackhole` (table `main`, ajout et suppression).
pub(crate) fn blackhole6_message(net: Ipv6Net) -> RouteMessage {
    RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(net.network(), net.prefix_len())
        .kind(RouteType::BlackHole)
        .build()
}

/// Message d'adresse : `IFA_LOCAL` = adresse locale, `IFA_ADDRESS` = pair
/// point-à-point s'il est connu (équivalent `ip addr add A/N peer P dev X`).
pub(crate) fn address_message(spec: &AddrSpec) -> AddressMessage {
    let mut msg = rtnetlink::AddressMessageBuilder::<Ipv4Addr>::new()
        .index(spec.index)
        .address(spec.address.addr(), spec.address.prefix_len())
        .build();
    if let Some(peer) = spec.peer {
        msg.attributes.retain(|a| {
            !matches!(
                a,
                AddressAttribute::Address(_) | AddressAttribute::Broadcast(_)
            )
        });
        msg.attributes.push(AddressAttribute::Address(peer.into()));
    }
    debug_assert_eq!(msg.header.family, AddressFamily::Inet);
    msg
}

/// Interprète la réponse à `RTM_GETROUTE`.
pub(crate) fn parse_origin(msg: &RouteMessage) -> Option<OriginRoute> {
    let local = match msg.header.kind {
        RouteType::Unicast => false,
        RouteType::Local => true,
        other => {
            tracing::debug!(kind = ?other, "route d'origine non unicast");
            return None;
        }
    };
    let mut gateway = None;
    let mut oif = None;
    for attr in &msg.attributes {
        match attr {
            RouteAttribute::Gateway(RouteAddress::Inet(gw)) => gateway = Some(*gw),
            RouteAttribute::Oif(i) => oif = Some(*i),
            _ => {}
        }
    }
    Some(OriginRoute {
        gateway,
        oif: oif?,
        local,
    })
}

/// Ouvre une connexion netlink et exécute `f` en pilotant la connexion dans
/// la même tâche.
async fn with_handle<T, F, Fut>(op: &'static str, f: F) -> Result<T, NetError>
where
    F: FnOnce(Handle) -> Fut,
    Fut: Future<Output = Result<T, NetError>>,
{
    let (conn, handle, _messages) =
        rtnetlink::new_connection().map_err(|source| NetError::Io { op, source })?;
    tokio::select! {
        r = f(handle) => r,
        () = conn => Err(NetError::Os {
            op,
            reason: "connexion netlink fermée".into(),
        }),
    }
}

/// Backend système réel.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct LinuxSystem;

impl System for LinuxSystem {
    fn link_index(&self, name: &str) -> impl Future<Output = Result<u32, NetError>> + Send {
        let name = name.to_owned();
        with_handle("link_index", |h| async move {
            let link = h
                .link()
                .get()
                .match_name(name)
                .execute()
                .try_next()
                .await
                .map_err(|e| map_err("link_index", e))?;
            link.map(|l| l.header.index).ok_or(NetError::Os {
                op: "link_index",
                reason: "interface introuvable".into(),
            })
        })
    }

    fn lookup_route(
        &self,
        dst: Ipv4Addr,
    ) -> impl Future<Output = Result<Option<OriginRoute>, NetError>> + Send {
        with_handle("lookup_route", move |h| async move {
            let query = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(dst, 32)
                .build();
            match h.route().get(query).execute().try_next().await {
                Ok(Some(msg)) => Ok(parse_origin(&msg)),
                Ok(None) => Ok(None),
                Err(e) if is_unreachable(&e) => Ok(None),
                Err(e) => Err(map_err("lookup_route", e)),
            }
        })
    }

    fn execute(&self, op: &Op) -> impl Future<Output = Result<Outcome, NetError>> + Send {
        let op = op.clone();
        async move {
            match op {
                Op::Dns(w) => dns::write(&w).map(Outcome::Installed),
                Op::Link { index, mtu } => {
                    with_handle("set_link", |h| async move {
                        let msg = LinkUnspec::new_with_index(index)
                            .mtu(u32::from(mtu))
                            .up()
                            .build();
                        h.link()
                            .set(msg)
                            .execute()
                            .await
                            .map_err(|e| map_err("set_link", e))?;
                        Ok(Outcome::Unchanged)
                    })
                    .await
                }
                Op::Address(spec) => {
                    with_handle("add_address", |h| async move {
                        let mut req =
                            h.address()
                                .add(spec.index, spec.address.addr().into(), spec.address.prefix_len());
                        *req.message_mut() = address_message(&spec);
                        match req.execute().await {
                            Ok(()) => Ok(Outcome::Installed(Undo::Address(spec))),
                            Err(e) if is_already_present(&e) => {
                                tracing::warn!(address = %spec.address, "adresse déjà présente : laissée en place");
                                Ok(Outcome::Unchanged)
                            }
                            Err(e) => Err(map_err("add_address", e)),
                        }
                    })
                    .await
                }
                Op::Blackhole6(net) => {
                    with_handle("add_blackhole6", |h| async move {
                        match h.route().add(blackhole6_message(net)).execute().await {
                            Ok(()) => Ok(Outcome::Installed(Undo::Blackhole6(net))),
                            Err(e) if is_already_present(&e) => {
                                tracing::warn!(dest = %net, "route IPv6 déjà présente : laissée en place, l'IPv6 peut fuir hors tunnel");
                                Ok(Outcome::Unchanged)
                            }
                            Err(e) if is_ipv6_unavailable(&e) => {
                                tracing::warn!(dest = %net, error = %e, "IPv6 indisponible sur l'hôte : blackhole non installé");
                                Ok(Outcome::Unchanged)
                            }
                            Err(e) => Err(map_err("add_blackhole6", e)),
                        }
                    })
                    .await
                }
                Op::Route(spec) => {
                    with_handle("add_route", |h| async move {
                        match h.route().add(route_message(&spec)).execute().await {
                            Ok(()) => Ok(Outcome::Installed(Undo::Route(spec))),
                            Err(e) if is_already_present(&e) => {
                                tracing::warn!(dest = %spec.dest, "route déjà présente : laissée en place");
                                Ok(Outcome::Unchanged)
                            }
                            Err(e) => Err(map_err("add_route", e)),
                        }
                    })
                    .await
                }
            }
        }
    }

    fn revert(&self, undo: &Undo) -> impl Future<Output = Result<(), NetError>> + Send {
        let undo = undo.clone();
        async move {
            match undo {
                Undo::Dns(d) => dns::restore(&d),
                Undo::Blackhole6(net) => {
                    with_handle("del_blackhole6", |h| async move {
                        match h.route().del(blackhole6_message(net)).execute().await {
                            Err(e) if !is_already_gone(&e) && !is_ipv6_unavailable(&e) => {
                                Err(map_err("del_blackhole6", e))
                            }
                            _ => Ok(()),
                        }
                    })
                    .await
                }
                Undo::Address(spec) => {
                    with_handle("del_address", |h| async move {
                        match h.address().del(address_message(&spec)).execute().await {
                            Err(e) if !is_already_gone(&e) => Err(map_err("del_address", e)),
                            _ => Ok(()),
                        }
                    })
                    .await
                }
                Undo::Route(spec) => {
                    with_handle("del_route", |h| async move {
                        match h.route().del(route_message(&spec)).execute().await {
                            Err(e) if !is_already_gone(&e) => Err(map_err("del_route", e)),
                            _ => Ok(()),
                        }
                    })
                    .await
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroI32;

    use rtnetlink::packet_core::ErrorMessage;

    use super::*;

    fn nl_error(errno: i32) -> rtnetlink::Error {
        let mut m = ErrorMessage::default();
        m.code = NonZeroI32::new(-errno);
        rtnetlink::Error::NetlinkError(m)
    }

    #[test]
    fn errno_classification() {
        assert!(is_already_present(&nl_error(EEXIST)));
        assert!(!is_already_present(&nl_error(ENOENT)));
        for e in [ENOENT, ESRCH, ENODEV, EADDRNOTAVAIL] {
            assert!(is_already_gone(&nl_error(e)), "{e}");
        }
        assert!(!is_already_gone(&nl_error(1))); // EPERM
        assert!(is_ipv6_unavailable(&nl_error(EAFNOSUPPORT)));
        assert!(is_ipv6_unavailable(&nl_error(EOPNOTSUPP)));
        assert!(!is_ipv6_unavailable(&nl_error(EEXIST)));
        assert!(is_unreachable(&nl_error(ENETUNREACH)));
        assert!(is_unreachable(&nl_error(EHOSTUNREACH)));
        assert!(!is_unreachable(&rtnetlink::Error::RequestFailed));
        assert!(matches!(
            map_err("x", nl_error(1)),
            NetError::Io { op: "x", .. }
        ));
        assert!(matches!(
            map_err("x", rtnetlink::Error::RequestFailed),
            NetError::Os { op: "x", .. }
        ));
    }

    #[test]
    fn underlay_route_message() {
        let spec = RouteSpec {
            dest: "203.0.113.10/32".parse().unwrap(),
            oif: 2,
            gateway: Some(Ipv4Addr::new(192, 0, 2, 1)),
        };
        let m = route_message(&spec);
        assert_eq!(m.header.destination_prefix_length, 32);
        assert_eq!(m.header.scope, RouteScope::Universe);
        assert_eq!(m.header.kind, RouteType::Unicast);
        assert_eq!(m.header.table, 254, "table main");
        assert!(
            m.attributes
                .contains(&RouteAttribute::Destination(RouteAddress::Inet(
                    Ipv4Addr::new(203, 0, 113, 10)
                )))
        );
        assert!(m.attributes.contains(&RouteAttribute::Oif(2)));
        assert!(
            m.attributes
                .contains(&RouteAttribute::Gateway(RouteAddress::Inet(Ipv4Addr::new(
                    192, 0, 2, 1
                ))))
        );
    }

    #[test]
    fn tunnel_route_message_is_scope_link_without_gateway() {
        let spec = RouteSpec {
            dest: "128.0.0.0/1".parse().unwrap(),
            oif: 7,
            gateway: None,
        };
        let m = route_message(&spec);
        assert_eq!(m.header.destination_prefix_length, 1);
        assert_eq!(m.header.scope, RouteScope::Link);
        assert!(m.attributes.contains(&RouteAttribute::Oif(7)));
        assert!(
            !m.attributes
                .iter()
                .any(|a| matches!(a, RouteAttribute::Gateway(_)))
        );
    }

    #[test]
    fn blackhole6_message_is_blackhole_in_main_without_oif() {
        let m = blackhole6_message("8000::/1".parse().unwrap());
        assert_eq!(m.header.address_family, AddressFamily::Inet6);
        assert_eq!(m.header.kind, RouteType::BlackHole);
        assert_eq!(m.header.destination_prefix_length, 1);
        assert_eq!(m.header.table, 254, "table main");
        assert_eq!(m.header.scope, RouteScope::Universe);
        assert_eq!(
            m.attributes,
            vec![RouteAttribute::Destination(RouteAddress::Inet6(
                "8000::".parse().unwrap()
            ))]
        );
    }

    #[test]
    fn address_message_with_and_without_peer() {
        let local = Ipv4Addr::new(10, 212, 134, 200);
        let peer = Ipv4Addr::new(169, 254, 2, 1);
        let with_peer = address_message(&AddrSpec {
            index: 7,
            address: "10.212.134.200/32".parse().unwrap(),
            peer: Some(peer),
        });
        assert_eq!(with_peer.header.index, 7);
        assert_eq!(with_peer.header.prefix_len, 32);
        assert_eq!(
            with_peer.attributes,
            vec![
                AddressAttribute::Local(local.into()),
                AddressAttribute::Address(peer.into())
            ]
        );

        let plain = address_message(&AddrSpec {
            index: 7,
            address: "10.0.0.2/24".parse().unwrap(),
            peer: None,
        });
        assert!(
            plain
                .attributes
                .contains(&AddressAttribute::Local(Ipv4Addr::new(10, 0, 0, 2).into()))
        );
        assert!(plain.attributes.contains(&AddressAttribute::Address(
            Ipv4Addr::new(10, 0, 0, 2).into()
        )));
    }

    fn reply(kind: RouteType, attrs: Vec<RouteAttribute>) -> RouteMessage {
        let mut m = RouteMessage::default();
        m.header.kind = kind;
        m.attributes = attrs;
        m
    }

    #[test]
    fn parse_route_replies() {
        let gw = Ipv4Addr::new(192, 0, 2, 1);
        assert_eq!(
            parse_origin(&reply(
                RouteType::Unicast,
                vec![
                    RouteAttribute::Gateway(RouteAddress::Inet(gw)),
                    RouteAttribute::Oif(2),
                    RouteAttribute::Table(254),
                ]
            )),
            Some(OriginRoute {
                gateway: Some(gw),
                oif: 2,
                local: false
            })
        );
        assert_eq!(
            parse_origin(&reply(RouteType::Unicast, vec![RouteAttribute::Oif(3)])),
            Some(OriginRoute {
                gateway: None,
                oif: 3,
                local: false
            })
        );
        assert_eq!(
            parse_origin(&reply(RouteType::Local, vec![RouteAttribute::Oif(1)])),
            Some(OriginRoute {
                gateway: None,
                oif: 1,
                local: true
            })
        );
        assert_eq!(parse_origin(&reply(RouteType::Unicast, vec![])), None);
        assert_eq!(
            parse_origin(&reply(RouteType::Unreachable, vec![RouteAttribute::Oif(2)])),
            None
        );
    }
}
