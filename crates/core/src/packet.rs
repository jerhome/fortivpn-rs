//! Canal bidirectionnel de paquets IP.
//!
//! Type commun à la TUN ([`NetBackend`](crate::NetBackend)) et au tunnel
//! ([`Transport`](crate::Transport)) : chaque côté reçoit une extrémité d'une paire
//! créée par [`PacketChannel::pair`]. Un paquet = un datagramme IP complet
//! (sans en-tête PPP ni ESP). Les deux moitiés sont séparables
//! ([`PacketChannel::split`]) pour lire et écrire depuis des tâches distinctes.

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::error::ChannelClosed;

/// Extrémité d'un canal bidirectionnel de paquets IP.
#[derive(Debug)]
pub struct PacketChannel {
    tx: PacketSender,
    rx: PacketReceiver,
}

/// Moitié émettrice (clonable).
#[derive(Debug, Clone)]
pub struct PacketSender(mpsc::Sender<Bytes>);

/// Moitié réceptrice.
#[derive(Debug)]
pub struct PacketReceiver(mpsc::Receiver<Bytes>);

impl PacketChannel {
    /// Crée deux extrémités connectées : ce qui est envoyé sur l'une est reçu sur
    /// l'autre. `capacity` (au moins 1) borne le nombre de paquets en attente par
    /// direction (contre-pression).
    pub fn pair(capacity: usize) -> (Self, Self) {
        let capacity = capacity.max(1);
        let (a_tx, b_rx) = mpsc::channel(capacity);
        let (b_tx, a_rx) = mpsc::channel(capacity);
        (
            Self {
                tx: PacketSender(a_tx),
                rx: PacketReceiver(a_rx),
            },
            Self {
                tx: PacketSender(b_tx),
                rx: PacketReceiver(b_rx),
            },
        )
    }

    /// Envoie un paquet vers l'autre extrémité (attend s'il n'y a plus de place).
    pub async fn send(&self, packet: Bytes) -> Result<(), ChannelClosed> {
        self.tx.send(packet).await
    }

    /// Reçoit le prochain paquet ; `None` quand l'autre extrémité est fermée.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.rx.recv().await
    }

    /// Sépare l'extrémité en moitiés émettrice et réceptrice.
    pub fn split(self) -> (PacketSender, PacketReceiver) {
        (self.tx, self.rx)
    }
}

impl PacketSender {
    /// Envoie un paquet (attend s'il n'y a plus de place).
    pub async fn send(&self, packet: Bytes) -> Result<(), ChannelClosed> {
        self.0.send(packet).await.map_err(|_| ChannelClosed)
    }

    /// Vrai si l'extrémité réceptrice a été fermée.
    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }

    /// Attend une place libre et la réserve : l'envoi via le [`PacketPermit`]
    /// obtenu ne peut plus attendre (utile dans un `select!` sans perdre de paquet).
    pub async fn reserve(&self) -> Result<PacketPermit<'_>, ChannelClosed> {
        self.0
            .reserve()
            .await
            .map(PacketPermit)
            .map_err(|_| ChannelClosed)
    }

    /// Réserve une place si elle est disponible tout de suite : `Ok(None)` si le
    /// canal est plein.
    pub fn try_reserve(&self) -> Result<Option<PacketPermit<'_>>, ChannelClosed> {
        match self.0.try_reserve() {
            Ok(p) => Ok(Some(PacketPermit(p))),
            Err(mpsc::error::TrySendError::Full(())) => Ok(None),
            Err(mpsc::error::TrySendError::Closed(())) => Err(ChannelClosed),
        }
    }
}

/// Place réservée dans un [`PacketSender`] (voir [`PacketSender::reserve`]).
#[derive(Debug)]
pub struct PacketPermit<'a>(mpsc::Permit<'a, Bytes>);

impl PacketPermit<'_> {
    /// Envoie le paquet dans la place réservée (sans attente).
    pub fn send(self, packet: Bytes) {
        self.0.send(packet);
    }
}

impl PacketReceiver {
    /// Reçoit le prochain paquet ; `None` quand tous les émetteurs sont fermés.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.0.recv().await
    }

    /// Paquet déjà disponible, sans attendre : `Ok(None)` si aucun n'est en
    /// attente, `Err` quand tous les émetteurs sont fermés et la file vide.
    pub fn try_recv(&mut self) -> Result<Option<Bytes>, ChannelClosed> {
        match self.0.try_recv() {
            Ok(p) => Ok(Some(p)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(ChannelClosed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pair_is_bidirectional() {
        let (mut a, mut b) = PacketChannel::pair(4);
        a.send(Bytes::from_static(b"ping")).await.unwrap();
        assert_eq!(b.recv().await.unwrap(), Bytes::from_static(b"ping"));
        b.send(Bytes::from_static(b"pong")).await.unwrap();
        assert_eq!(a.recv().await.unwrap(), Bytes::from_static(b"pong"));
    }

    #[tokio::test]
    async fn closed_peer_is_reported() {
        let (mut a, b) = PacketChannel::pair(0);
        drop(b);
        assert_eq!(a.send(Bytes::new()).await, Err(ChannelClosed));
        assert!(a.recv().await.is_none());
    }

    #[tokio::test]
    async fn split_halves_work() {
        let (a, mut b) = PacketChannel::pair(1);
        let (tx, mut rx) = a.split();
        tx.send(Bytes::from_static(b"x")).await.unwrap();
        assert_eq!(b.recv().await.unwrap(), Bytes::from_static(b"x"));
        b.send(Bytes::from_static(b"y")).await.unwrap();
        assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"y"));
    }

    #[tokio::test]
    async fn reserve_and_try_recv() {
        let (a, b) = PacketChannel::pair(1);
        let (tx, _rx) = a.split();
        let (_btx, mut brx) = b.split();
        assert_eq!(brx.try_recv(), Ok(None));
        tx.reserve().await.unwrap().send(Bytes::from_static(b"z"));
        assert!(matches!(tx.try_reserve(), Ok(None)));
        assert_eq!(brx.try_recv(), Ok(Some(Bytes::from_static(b"z"))));
        tx.try_reserve()
            .unwrap()
            .unwrap()
            .send(Bytes::from_static(b"w"));
        assert_eq!(brx.try_recv(), Ok(Some(Bytes::from_static(b"w"))));
        drop(tx);
        assert_eq!(brx.try_recv(), Err(ChannelClosed));
    }
}
