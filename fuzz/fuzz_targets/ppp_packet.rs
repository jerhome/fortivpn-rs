//! Trame PPP arbitraire (sortie de `decode_frame`).
//!
//! Invariants :
//! - `Packet::parse` / `PppFrame::parse` / `ControlPacket::parse` ne paniquent jamais ;
//! - parse → encode → parse idempotent, et l'encodage est un point fixe ;
//! - encodage ≤ entrée + 1 octet (seule l'expansion du protocole compressé est permise) ;
//! - `ControlPacket::encode` == `info[..length]` ;
//! - `code_reject` / `protocol_reject` respectent `max_len` et se ré-analysent.
#![no_main]

use bytes::{Bytes, BytesMut};
use libfuzzer_sys::fuzz_target;
use proto::ppp::{Code, ControlPacket, Packet, PppFrame, Protocol};

fn check_control(p: &ControlPacket, max_len: usize) {
    let mut enc = BytesMut::new();
    p.encode(&mut enc);
    assert_eq!(enc.len(), p.len());
    let back = ControlPacket::parse(&enc.clone().freeze()).expect("paquet encodé illisible");
    assert_eq!(&back, p);

    let _ = p.options();
    if let Some((_, d)) = p.magic_and_data() {
        assert_eq!(d.len() + 4, p.data().len());
    }
    if let Some((_, d)) = p.rejected_protocol() {
        assert_eq!(d.len() + 2, p.data().len());
    }

    let cr = ControlPacket::code_reject(7, p, max_len);
    assert_eq!(cr.code(), Code::CodeReject);
    assert!(cr.len() <= max_len.clamp(4, 65535), "code_reject > max_len");
    let mut e = BytesMut::new();
    cr.encode(&mut e);
    assert_eq!(ControlPacket::parse(&e.freeze()).as_ref(), Ok(&cr));
    // Le contenu rejeté est un préfixe du paquet d'origine.
    assert!(enc.starts_with(cr.data()));

    let pr = ControlPacket::protocol_reject(8, Protocol(0x8057), p.data(), max_len);
    assert!(
        pr.len() <= max_len.clamp(6, 65535),
        "protocol_reject > max_len"
    );
    let mut e = BytesMut::new();
    pr.encode(&mut e);
    assert_eq!(ControlPacket::parse(&e.freeze()).as_ref(), Ok(&pr));
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let max_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    let input = Bytes::copy_from_slice(&data[2..]);

    if let Ok(f) = PppFrame::parse(input.clone()) {
        let enc = f.to_bytes();
        assert!(enc.len() <= input.len() + 1);
        assert!(!enc.starts_with(&[0xff, 0x03]), "ff 03 émis");
        let f2 = PppFrame::parse(enc.clone()).expect("PppFrame encodée illisible");
        assert_eq!(f2, f, "PppFrame parse∘encode != id");
        assert_eq!(f2.to_bytes(), enc);
    }

    let _ = ControlPacket::parse(&input).map(|p| check_control(&p, max_len));

    match Packet::parse(input.clone()) {
        Ok(p) => {
            let enc = p.to_bytes();
            assert!(enc.len() <= input.len() + 1);
            let p2 = Packet::parse(enc.clone()).expect("Packet encodé illisible");
            assert_eq!(p2, p, "Packet parse∘encode != id");
            assert_eq!(p2.to_bytes(), enc, "encodage non point fixe");
            if let Packet::Lcp(c) | Packet::Ipcp(c) = &p {
                check_control(c, max_len);
            }
            if let Packet::Other(f) = &p {
                assert!(!matches!(
                    f.protocol,
                    Protocol::LCP | Protocol::IPCP | Protocol::IPV4
                ));
            }
        }
        Err(_) => {
            // Une erreur Packet n'est possible que si la trame est tronquée ou si le
            // paquet de contrôle LCP/IPCP est invalide.
            if let Ok(f) = PppFrame::parse(input) {
                assert!(matches!(f.protocol, Protocol::LCP | Protocol::IPCP));
                assert!(ControlPacket::parse(&f.payload).is_err());
            }
        }
    }
});
