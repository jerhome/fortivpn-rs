//! Régressions issues du fuzzing (story 5.2).
//!
//! Bug « Code-Reject / Protocol-Reject non bornés par `MAX_PPP_LEN` » corrigé dans
//! `PppSession::reject_room`.

use std::num::NonZeroU32;
use std::time::Instant;

use bytes::{BufMut, Bytes, BytesMut};
use proto::frame::{MAX_PPP_LEN, encode_frame};
use proto::ppp::{Code, ControlPacket, Packet, PppConfig, PppSession, Protocol};

const CLIENT_MAGIC: u32 = 0x1a2b_3c4d;

/// LCP ouvert avec une passerelle annonçant MRU = 65535.
fn lcp_open_with_peer_mru_65535() -> (PppSession, Instant) {
    let now = Instant::now();
    let mut s = PppSession::new(PppConfig::new(NonZeroU32::new(CLIENT_MAGIC).unwrap()));
    s.open(now);
    let req = s.poll_transmit().unwrap();
    let Ok(Packet::Lcp(req)) = Packet::parse(req) else {
        panic!("Configure-Request LCP attendu")
    };
    // Configure-Request de la passerelle : MRU 65535, magic 0x5e6f7081.
    let peer = ControlPacket::new(
        Code::ConfigureRequest,
        1,
        Bytes::from_static(&[1, 4, 0xff, 0xff, 5, 6, 0x5e, 0x6f, 0x70, 0x81]),
    )
    .unwrap();
    s.handle_frame(now, peer.to_frame(Protocol::LCP));
    let ack = ControlPacket::new(Code::ConfigureAck, req.id(), req.data().clone()).unwrap();
    s.handle_frame(now, ack.to_frame(Protocol::LCP));
    while s.poll_transmit().is_some() {}
    while s.poll_event().is_some() {}
    assert_eq!(s.mtu(), proto::ppp::DEFAULT_MRU);
    (s, now)
}

fn assert_all_transmits_fit(s: &mut PppSession) {
    let mut n = 0;
    while let Some(f) = s.poll_transmit() {
        n += 1;
        let mut w = BytesMut::new();
        assert!(
            encode_frame(&f, &mut w).is_ok(),
            "trame émise de {} octets > MAX_PPP_LEN ({MAX_PPP_LEN}) : non encapsulable",
            f.len()
        );
    }
    assert!(n > 0, "une réponse était attendue");
}

/// BUG : un Code-Reject n'est tronqué qu'au MRU du pair (≤ 65535), pas à la limite du
/// framing 0x5050 (`MAX_PPP_LEN` = 65529 octets protocole compris). Avec un MRU pair
/// ≥ 65532 et un paquet LCP de code inconnu de taille maximale, la trame émise fait
/// 65533 octets et `encode_frame` la refuse (`EncodeError::TooLong`).
#[test]
fn code_reject_fits_in_0x5050_frame() {
    let (mut s, now) = lcp_open_with_peer_mru_65535();
    // Trame LCP maximale reçue : 2 (proto) + 65527 (paquet LCP, code 0x0c inconnu).
    let lcp_len = MAX_PPP_LEN - 2;
    let mut f = BytesMut::with_capacity(MAX_PPP_LEN);
    f.put_u16(Protocol::LCP.0);
    f.put_u8(0x0c);
    f.put_u8(0x42);
    f.put_u16(u16::try_from(lcp_len).unwrap());
    f.put_bytes(0xa5, lcp_len - 4);
    assert_eq!(f.len(), MAX_PPP_LEN);
    s.handle_frame(now, f.freeze());
    assert_all_transmits_fit(&mut s);
}

/// BUG : même défaut pour Protocol-Reject (troncature à `peer_mru - 6` seulement). Avec
/// un protocole compressé sur 1 octet, la trame émise atteint 65536 octets.
#[test]
fn protocol_reject_fits_in_0x5050_frame() {
    let (mut s, now) = lcp_open_with_peer_mru_65535();
    let mut f = BytesMut::with_capacity(MAX_PPP_LEN);
    f.put_u8(0xfd); // protocole 0x00fd compressé (octet impair)
    f.put_bytes(0x5a, MAX_PPP_LEN - 1);
    s.handle_frame(now, f.freeze());
    assert_all_transmits_fit(&mut s);
}

/// Même chose sans compression du protocole (protocole 0x8057 sur 2 octets).
#[test]
fn protocol_reject_fits_in_0x5050_frame_uncompressed() {
    let (mut s, now) = lcp_open_with_peer_mru_65535();
    let mut f = BytesMut::with_capacity(MAX_PPP_LEN);
    f.put_u16(Protocol::IPV6CP.0);
    f.put_bytes(0x5a, MAX_PPP_LEN - 2);
    s.handle_frame(now, f.freeze());
    assert_all_transmits_fit(&mut s);
}
