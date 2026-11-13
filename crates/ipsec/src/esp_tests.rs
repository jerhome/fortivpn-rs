use super::*;
use crate::crypto::Prf;
use crate::ike::{EspProposal, derive_child_keys};
use zeroize::Zeroizing;

const SUITES: [(Encr, Option<Integ>); 6] = [
    (Encr::AesGcm16_128, None),
    (Encr::AesGcm16_256, None),
    (Encr::AesCbc128, Some(Integ::HmacSha256_128)),
    (Encr::AesCbc256, Some(Integ::HmacSha256_128)),
    (Encr::AesCbc128, Some(Integ::HmacSha1_96)),
    (Encr::AesCbc256, Some(Integ::HmacSha1_96)),
];

fn keys(encr: Encr, integ: Option<Integ>) -> ChildSaKeys {
    derive_child_keys(
        Prf::HmacSha256,
        &[7u8; 32],
        &[1u8; 32],
        &[2u8; 32],
        EspProposal { encr, integ },
        0x1111_2222,
        0x3333_4444,
    )
    .unwrap()
}

/// Vue passerelle : directions et SPI inversés.
fn mirror(k: &ChildSaKeys) -> ChildSaKeys {
    ChildSaKeys {
        spi_in: k.spi_out,
        spi_out: k.spi_in,
        encr: k.encr,
        integ: k.integ,
        encr_key_out: Zeroizing::new(k.encr_key_in.to_vec()),
        integ_key_out: Zeroizing::new(k.integ_key_in.to_vec()),
        encr_key_in: Zeroizing::new(k.encr_key_out.to_vec()),
        integ_key_in: Zeroizing::new(k.integ_key_out.to_vec()),
    }
}

fn pair(encr: Encr, integ: Option<Integ>, esn: bool) -> (EspTunnel, EspTunnel) {
    let k = keys(encr, integ);
    (
        EspTunnel::new(&k, esn).unwrap(),
        EspTunnel::new(&mirror(&k), esn).unwrap(),
    )
}

#[allow(clippy::unnecessary_wraps)]
fn iv(n: u8) -> Option<[u8; 16]> {
    Some([n; 16])
}

/// Paquet IPv4 valide de `max(len, 20)` octets (en-tête minimal, charge pseudo-aléatoire).
fn pkt(len: usize) -> Vec<u8> {
    let len = len.max(20);
    let mut p: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    p
}

#[test]
fn roundtrip_all_suites_and_sizes() {
    for (e, i) in SUITES {
        for esn in [false, true] {
            let (mut c, mut g) = pair(e, i, esn);
            for len in [0usize, 1, 2, 3, 4, 15, 16, 17, 60, 1400] {
                let p = pkt(len);
                let w = c.seal(&p, iv(len as u8).as_ref()).unwrap();
                let align = if e.is_aead() { 4 } else { 16 };
                let overhead = 8 + e.iv_len() + 2 + i.map_or(16, Integ::icv_len);
                assert_eq!((w.len() - overhead + 2) % align, 0, "{e:?} len {len}");
                assert_eq!(
                    g.open(&w).unwrap(),
                    Inbound::Packet(p.clone()),
                    "{e:?} {i:?} {len}"
                );
                // sens inverse
                let w2 = g.seal(&p, iv(9).as_ref()).unwrap();
                assert_eq!(c.open(&w2).unwrap(), Inbound::Packet(p));
            }
        }
    }
}

#[test]
fn header_layout_and_gcm_iv_from_counter() {
    let (mut c, _) = pair(Encr::AesGcm16_128, None, false);
    let w = c.seal(&pkt(10), None).unwrap();
    assert_eq!(&w[..4], &0x3333_4444u32.to_be_bytes());
    assert_eq!(&w[4..8], &1u32.to_be_bytes());
    assert_eq!(&w[8..16], &1u64.to_be_bytes());
    let w = c.seal(&pkt(10), None).unwrap();
    assert_eq!(&w[4..8], &2u32.to_be_bytes());
    assert_eq!(&w[8..16], &2u64.to_be_bytes());
    // 8 + 8 + (20 + 2 + 2 pad => 24) + 16
    assert_eq!(w.len(), 8 + 8 + 24 + 16);
}

#[test]
fn gcm_matches_independent_aes_gcm_computation() {
    let k = keys(Encr::AesGcm16_128, None);
    let mut c = EspTunnel::new(&k, false).unwrap();
    let p = pkt(21);
    let w = c.seal(&p, Some(&[0xAB; 16])).unwrap();
    // Reconstruction indépendante : nonce = sel | IV, AAD = SPI | Seq.
    let (key, salt) = k.encr_key_out.split_at(16);
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(salt);
    nonce[4..].copy_from_slice(&[0xAB; 8]);
    let mut expect = p.clone();
    expect.extend_from_slice(&[1, 1, 4]); // 21 + 2 = 23 -> 1 octet de padding
    let mut aad = Vec::new();
    aad.extend_from_slice(&k.spi_out.to_be_bytes());
    aad.extend_from_slice(&1u32.to_be_bytes());
    let tag = Aes128Gcm::new_from_slice(key)
        .unwrap()
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut expect)
        .unwrap();
    assert_eq!(&w[16..16 + expect.len()], &expect[..]);
    assert_eq!(&w[16 + expect.len()..], tag.as_slice());
}

#[test]
fn replay_out_of_order_and_window() {
    for (e, i) in SUITES {
        let (mut c, mut g) = pair(e, i, false);
        let w: Vec<Vec<u8>> = (0..300)
            .map(|n| c.seal(&pkt(20), iv(n as u8).as_ref()).unwrap())
            .collect();
        // Désordre dans la fenêtre.
        for n in [5usize, 3, 4, 1, 2] {
            g.open(&w[n]).unwrap();
        }
        // Rejeu.
        for n in [5usize, 3, 1] {
            assert_eq!(g.open(&w[n]), Err(EspError::Replay));
        }
        // Saut en avant puis ancien paquet hors fenêtre.
        g.open(&w[299]).unwrap();
        assert_eq!(g.open(&w[0]), Err(EspError::Replay)); // seq 1 vs top 300 : hors fenêtre
        // Dans la fenêtre (300 - 128 < seq), jamais vu : accepté ; puis rejeu.
        g.open(&w[250]).unwrap();
        assert_eq!(g.open(&w[250]), Err(EspError::Replay));
        assert_eq!(g.open(&w[299]), Err(EspError::Replay));
    }
}

#[test]
fn replay_not_updated_by_forged_packet() {
    let (mut c, mut g) = pair(Encr::AesGcm16_128, None, false);
    let w1 = c.seal(&pkt(8), None).unwrap();
    let mut bad = w1.clone();
    bad[7] = 200; // seq 200, ICV invalide
    assert_eq!(g.open(&bad), Err(EspError::Integrity));
    g.open(&w1).unwrap();
}

#[test]
fn any_byte_flip_is_rejected_for_every_suite() {
    for (e, i) in SUITES {
        for esn in [false, true] {
            let (mut c, mut g) = pair(e, i, esn);
            let w = c.seal(&pkt(33), iv(5).as_ref()).unwrap();
            for pos in 0..w.len() {
                let mut t = w.clone();
                t[pos] ^= 0x01;
                assert!(g.open(&t).is_err(), "{e:?} {i:?} esn={esn} octet {pos}");
            }
            // L'original reste acceptable (rien n'a été consommé).
            g.open(&w).unwrap();
        }
    }
}

#[test]
fn truncated_and_hostile_inputs_do_not_panic() {
    for (e, i) in SUITES {
        let (mut c, mut g) = pair(e, i, true);
        let w = c.seal(&pkt(40), iv(1).as_ref()).unwrap();
        for n in 0..w.len() {
            assert!(g.open(&w[..n]).is_err());
        }
        assert!(g.open(&[0xff; 200]).is_err());
        let mut z = vec![0u8; 100];
        z[..4].copy_from_slice(&0x1111_2222u32.to_be_bytes());
        assert!(g.open(&z).is_err());
    }
}

#[test]
fn wrong_spi_and_wrong_direction() {
    let (mut c, _) = pair(Encr::AesCbc128, Some(Integ::HmacSha1_96), false);
    let w = c.seal(&pkt(10), iv(1).as_ref()).unwrap();
    // Le client ne peut pas relire son propre trafic sortant (SPI sortant != SPI entrant).
    assert_eq!(c.open(&w), Err(EspError::BadSpi));
}

#[test]
fn cbc_requires_iv() {
    let (mut c, _) = pair(Encr::AesCbc128, Some(Integ::HmacSha256_128), false);
    assert_eq!(c.seal(&pkt(4), None), Err(EspError::MissingIv));
}

#[test]
fn padding_bytes_are_1_2_3_and_checked() {
    // Suite GCM : fabriquer un paquet authentique avec un padding faux.
    let k = keys(Encr::AesGcm16_128, None);
    let mut g = EspTunnel::new(&mirror(&k), false).unwrap();
    let forge = |trailer: &[u8]| {
        let mut ct = pkt(20);
        ct.extend_from_slice(trailer);
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&k.encr_key_out[16..]);
        let mut aad = k.spi_out.to_be_bytes().to_vec();
        aad.extend_from_slice(&1u32.to_be_bytes());
        let tag = Aes128Gcm::new_from_slice(&k.encr_key_out[..16])
            .unwrap()
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut ct)
            .unwrap();
        let mut w = k.spi_out.to_be_bytes().to_vec();
        w.extend_from_slice(&1u32.to_be_bytes());
        w.extend_from_slice(&[0; 8]);
        w.extend_from_slice(&ct);
        w.extend_from_slice(&tag);
        w
    };
    // Valide : 20 + 2 pad + padlen + nh = 12.
    assert!(matches!(g.open(&forge(&[1, 2, 2, 4])), Ok(Inbound::Packet(p)) if p.len() == 20));
    let mut g = EspTunnel::new(&mirror(&k), false).unwrap();
    assert!(matches!(
        g.open(&forge(&[1, 9, 2, 4])),
        Err(EspError::BadPadding(_))
    ));
    let mut g = EspTunnel::new(&mirror(&k), false).unwrap();
    assert!(matches!(
        g.open(&forge(&[0, 0, 200, 4])),
        Err(EspError::BadPadding(_))
    ));
    let mut g = EspTunnel::new(&mirror(&k), false).unwrap();
    assert_eq!(
        g.open(&forge(&[0, 0, 0, 41])),
        Err(EspError::UnsupportedNextHeader(41))
    );
}

#[test]
fn dummy_packet_is_reported() {
    for (e, i) in SUITES {
        let (mut c, mut g) = pair(e, i, false);
        let w = c.seal_dummy(13, iv(3).as_ref()).unwrap();
        assert_eq!(g.open(&w), Ok(Inbound::Dummy));
    }
}

#[test]
fn esn_sequence_recovery_across_32_bit_boundary() {
    let (mut c, mut g) = pair(Encr::AesGcm16_256, None, true);
    let start = u64::from(u32::MAX) - 3;
    c.out.next_seq = start;
    g.inn.window = ReplayWindow {
        top: start - 1,
        bitmap: 1,
    };
    let w: Vec<Vec<u8>> = (0..10).map(|_| c.seal(&pkt(16), None).unwrap()).collect();
    // Désordre autour du franchissement de 2^32.
    for n in [0usize, 5, 4, 3, 2, 1, 9, 8, 7, 6] {
        assert!(g.open(&w[n]).is_ok(), "paquet {n}");
    }
    assert_eq!(g.inn.window.top, start + 9);
    assert_eq!(g.open(&w[5]), Err(EspError::Replay));
}

#[test]
fn sequence_exhaustion_without_esn() {
    let (mut c, _) = pair(Encr::AesGcm16_128, None, false);
    c.out.next_seq = u64::from(u32::MAX);
    assert!(c.seal(&pkt(4), None).is_ok());
    assert_eq!(c.seal(&pkt(4), None), Err(EspError::SeqExhausted));
}

#[test]
fn esn_and_non_esn_are_not_interchangeable_after_wrap_of_hi() {
    // Avec ESN, SeqHi entre dans l'ICV : un récepteur qui reconstruit Hi différemment rejette.
    let (mut c, _) = pair(Encr::AesCbc128, Some(Integ::HmacSha256_128), true);
    let (_, mut g) = pair(Encr::AesCbc128, Some(Integ::HmacSha256_128), true);
    c.out.next_seq = (1u64 << 32) + 5;
    let w = c.seal(&pkt(8), iv(1).as_ref()).unwrap();
    assert_eq!(g.open(&w), Err(EspError::Integrity)); // récepteur attend Hi = 0
}

#[test]
fn demux() {
    assert_eq!(classify(&[0xff]), Ok(Datagram::Keepalive));
    assert_eq!(classify(&[0, 0, 0, 0, 9, 8]), Ok(Datagram::Ike(&[9, 8])));
    assert_eq!(
        classify(&[0, 0, 0, 1, 2]),
        Ok(Datagram::Esp(&[0, 0, 0, 1, 2]))
    );
    assert_eq!(classify(&[]), Err(EspError::Truncated));
    assert_eq!(classify(&[1, 2, 3]), Err(EspError::Truncated));
    assert_eq!(wrap_ike(&[1, 2]), vec![0, 0, 0, 0, 1, 2]);
    assert_eq!(classify(&wrap_ike(&[7; 28])), Ok(Datagram::Ike(&[7; 28])));
}

#[test]
fn bad_key_lengths_rejected_and_debug_hides_keys() {
    let mut k = keys(Encr::AesGcm16_128, None);
    let t = EspTunnel::new(&k, false).unwrap();
    let dbg = format!("{t:?}");
    assert!(!dbg.contains("key"));
    k.encr_key_in = Zeroizing::new(vec![0; 5]);
    assert!(matches!(
        EspTunnel::new(&k, false),
        Err(EspError::BadKeys(_))
    ));
}

#[test]
fn prf_plus_keys_are_used_per_direction() {
    let (mut c, _) = pair(Encr::AesGcm16_128, None, false);
    let k = keys(Encr::AesGcm16_128, None);
    // Un tunnel dont les clés entrantes = clés sortantes du client ne peut pas lire (sens différent).
    let mut same = EspTunnel::new(&k, false).unwrap();
    let w = c.seal(&pkt(8), None).unwrap();
    assert!(same.open(&w).is_err());
}

#[test]
fn invalid_inner_ipv4_is_rejected() {
    let (mut cli, mut gw) = pair(Encr::AesGcm16_128, None, false);
    let good = pkt(40);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("version", {
            let mut p = good.clone();
            p[0] = 0x65;
            p
        }),
        ("ihl", {
            let mut p = good.clone();
            p[0] = 0x44;
            p
        }),
        ("total length > data", {
            let mut p = good.clone();
            p[2..4].copy_from_slice(&41u16.to_be_bytes());
            p
        }),
        ("total length < ihl", {
            let mut p = good.clone();
            p[2..4].copy_from_slice(&19u16.to_be_bytes());
            p
        }),
        ("trop court", vec![0x45; 10]),
    ];
    for (name, p) in cases {
        let w = cli.seal(&p, None).unwrap();
        assert!(
            matches!(gw.open(&w), Err(EspError::BadInner(_))),
            "cas {name}"
        );
    }
    // Excédent au-delà de la longueur totale : tronqué.
    let mut big = good.clone();
    big[2..4].copy_from_slice(&30u16.to_be_bytes());
    let w = cli.seal(&big, None).unwrap();
    assert!(matches!(gw.open(&w), Ok(Inbound::Packet(pk)) if pk.len() == 30));
}

#[test]
fn replayed_and_stale_packets_are_rejected_for_all_suites() {
    for (e, i) in SUITES {
        let (mut c, mut g) = pair(e, i, false);
        let w: Vec<Vec<u8>> = (0..200)
            .map(|n| c.seal(&pkt(20), iv(n as u8).as_ref()).unwrap())
            .collect();
        g.open(&w[0]).unwrap();
        assert_eq!(g.open(&w[0]), Err(EspError::Replay), "rejeu {e:?}");
        g.open(&w[199]).unwrap();
        // Hors fenêtre (199 - 128 = 71 -> seq 1..=71 rejetés).
        assert_eq!(g.open(&w[10]), Err(EspError::Replay), "hors fenêtre {e:?}");
        // Dans la fenêtre, jamais vu : accepté.
        g.open(&w[150]).unwrap();
        // ICV/tag altéré : Integrity, et la fenêtre n'est pas consommée.
        let mut bad = w[160].clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert_eq!(g.open(&bad), Err(EspError::Integrity));
        g.open(&w[160]).unwrap();
    }
}
