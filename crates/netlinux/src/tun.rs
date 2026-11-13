//! Création de l'interface TUN (`tokio-tun`) et relais fd ↔ [`PacketChannel`].
//!
//! Deux tâches tokio partagent la TUN :
//!
//! - **montante** (OS → tunnel) : lit les paquets émis par l'OS et les pousse
//!   dans le canal ; si le consommateur a lâché sa moitié réceptrice, les
//!   paquets sont jetés ;
//! - **descendante** (tunnel → OS) : écrit dans la TUN les paquets reçus du
//!   canal. Quand toutes les moitiés émettrices côté client sont lâchées, elle
//!   s'arrête, arrête la tâche montante, et la TUN (donc l'interface, avec ses
//!   adresses et routes directes) est détruite par le noyau.

use std::sync::Arc;

use bytes::Bytes;
use fortivpn_core::{
    NetError, PacketChannel, PacketReceiver, PacketSender, TunDevice, TunInfo, TunOptions,
};
use tokio::sync::oneshot;
use tokio_tun::Tun;

use crate::system::System;

/// Taille du tampon de lecture : un datagramme IPv4 complet au maximum.
const READ_BUF: usize = 65_536;

/// `IFNAMSIZ` - 1.
const MAX_IFNAME: usize = 15;

/// Nom d'interface acceptable par le noyau : vide (nom choisi par le noyau,
/// `tunN`) ou 1 à 15 caractères ASCII imprimables, sans `/`, `:` ni espace,
/// différent de `.` et `..`. Un motif `%d` est autorisé (ex. `fvpn%d`).
pub(crate) fn validate_ifname(name: &str) -> Result<(), NetError> {
    let ok = name.is_empty()
        || (name.len() <= MAX_IFNAME
            && name != "."
            && name != ".."
            && name
                .bytes()
                .all(|b| b.is_ascii_graphic() && b != b'/' && b != b':'));
    if ok {
        Ok(())
    } else {
        Err(NetError::Os {
            op: "create_tun",
            reason: format!("nom d'interface invalide : {name:?}"),
        })
    }
}

/// Crée la TUN (sans en-tête `packet_info`) et lance le relais.
pub(crate) async fn create<S: System>(
    sys: &S,
    options: &TunOptions,
) -> Result<TunDevice, NetError> {
    validate_ifname(&options.name)?;
    let tun = Tun::builder()
        .name(&options.name)
        .build()
        .map_err(|e| match e {
            tokio_tun::Error::IoError(source) => NetError::Io {
                op: "create_tun",
                source,
            },
            tokio_tun::Error::NixError(e) => NetError::Os {
                op: "create_tun",
                reason: e.to_string(),
            },
        })?
        .pop()
        .ok_or(NetError::Os {
            op: "create_tun",
            reason: "aucune file TUN créée".into(),
        })?;
    let name = tun.name().to_owned();
    // En cas d'échec ici, `tun` est lâchée et l'interface disparaît.
    let index = sys.link_index(&name).await?;
    tracing::debug!(%name, index, "interface TUN créée");

    let (ours, peer) = PacketChannel::pair(options.queue_capacity);
    spawn_relay(tun, peer);
    Ok(TunDevice {
        info: TunInfo {
            name,
            index: Some(index),
        },
        packets: ours,
    })
}

fn spawn_relay(tun: Tun, peer: PacketChannel) {
    let tun = Arc::new(tun);
    let (to_client, from_client) = peer.split();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    tokio::spawn(os_to_tunnel(Arc::clone(&tun), to_client, stop_rx));
    tokio::spawn(tunnel_to_os(tun, from_client, stop_tx));
}

async fn os_to_tunnel(tun: Arc<Tun>, to_client: PacketSender, mut stop: oneshot::Receiver<()>) {
    let mut buf = vec![0u8; READ_BUF];
    loop {
        tokio::select! {
            biased;
            _ = &mut stop => break,
            r = tun.recv(&mut buf) => match r {
                Ok(0) => {}
                Ok(n) => {
                    if to_client.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                        tracing::trace!("consommateur TUN absent : paquet jeté");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "lecture TUN : arrêt du relais montant");
                    break;
                }
            },
        }
    }
}

async fn tunnel_to_os(tun: Arc<Tun>, mut from_client: PacketReceiver, stop: oneshot::Sender<()>) {
    while let Some(packet) = from_client.recv().await {
        if let Err(e) = tun.send_all(&packet).await {
            tracing::debug!(error = %e, len = packet.len(), "écriture TUN : paquet jeté");
        }
    }
    tracing::debug!("canal TUN libéré : fermeture de l'interface");
    drop(stop);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_names() {
        for ok in ["", "fvpn0", "fvpn%d", "tun-test_1", "a23456789012345"] {
            assert!(validate_ifname(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "a234567890123456",
            "a/b",
            "a:b",
            "a b",
            "fvpn\n",
            ".",
            "..",
            "évpn",
        ] {
            assert!(validate_ifname(bad).is_err(), "{bad:?}");
        }
    }
}
