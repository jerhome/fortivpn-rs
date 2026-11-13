use secrecy::SecretString;

use crate::crypto::*;
use crate::mschapv2::*;
use crate::sk;
use crate::wire::*;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}
fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().unwrap()
}

// ---------- HMAC / prf+ ----------

#[test]
fn hmac_rfc4231_case2_and_rfc2202_case2() {
    let m = b"what do ya want for nothing?";
    assert_eq!(
        Prf::HmacSha256.compute(b"Jefe", &[m]).to_vec(),
        hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    );
    assert_eq!(
        Prf::HmacSha1.compute(b"Jefe", &[m]).to_vec(),
        hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
    );
}

#[test]
fn prf_plus_matches_definition() {
    for prf in [Prf::HmacSha1, Prf::HmacSha256] {
        let (k, s) = (b"key".as_slice(), b"seed".as_slice());
        let t1 = prf.compute(k, &[s, &[1]]);
        let t2 = prf.compute(k, &[&t1, s, &[2]]);
        let t3 = prf.compute(k, &[&t2, s, &[3]]);
        let mut want = t1.to_vec();
        want.extend_from_slice(&t2);
        want.extend_from_slice(&t3);
        want.truncate(2 * prf.output_len() + 5);
        assert_eq!(prf_plus(prf, k, s, want.len()).unwrap().to_vec(), want);
    }
    assert!(prf_plus(Prf::HmacSha1, b"k", b"s", 255 * 20 + 1).is_err());
}

fn suites() -> Vec<IkeSuite> {
    vec![
        IkeSuite::new(
            Encr::AesCbc128,
            Prf::HmacSha256,
            Some(Integ::HmacSha256_128),
        )
        .unwrap(),
        IkeSuite::new(Encr::AesCbc256, Prf::HmacSha1, Some(Integ::HmacSha1_96)).unwrap(),
        IkeSuite::new(Encr::AesGcm16_128, Prf::HmacSha256, None).unwrap(),
        IkeSuite::new(Encr::AesGcm16_256, Prf::HmacSha256, None).unwrap(),
    ]
}

#[test]
fn suite_validation_and_key_layout() {
    assert!(
        IkeSuite::new(
            Encr::AesGcm16_128,
            Prf::HmacSha256,
            Some(Integ::HmacSha1_96)
        )
        .is_err()
    );
    assert!(IkeSuite::new(Encr::AesCbc128, Prf::HmacSha256, None).is_err());
    let s = suites();
    let k = derive_sk_keys(&s[0], &[1; 32], &[2; 32], &[3; 8], &[4; 8], &[5; 256]).unwrap();
    assert_eq!(
        (k.sk_d.len(), k.sk_ai.len(), k.sk_ei.len(), k.sk_pr.len()),
        (32, 32, 16, 32)
    );
    let k = derive_sk_keys(&s[2], &[1; 32], &[2; 32], &[3; 8], &[4; 8], &[5; 256]).unwrap();
    assert_eq!((k.sk_ai.len(), k.sk_ei.len()), (0, 20));
    // Concordance avec la définition : SK_d est le début de prf+.
    let seed: Vec<u8> = [[1u8; 32].as_slice(), &[2; 32], &[3; 8], &[4; 8]].concat();
    let skeyseed = Prf::HmacSha256.compute(&[[1u8; 32], [2; 32]].concat(), &[&[5; 256]]);
    let pp = prf_plus(Prf::HmacSha256, &skeyseed, &seed, 32).unwrap();
    assert_eq!(*k.sk_d, *pp);
    assert_eq!(format!("{k:?}"), "SkKeys(<masqué>)");
}

#[test]
fn auth_value_composition() {
    let prf = Prf::HmacSha256;
    let id = id_body(2, b"client.example.test");
    let a = auth_value(prf, b"psk", b"msg1", b"nr", b"skpi", &id);
    let want = prf.compute(
        &prf.compute(b"psk", &[b"Key Pad for IKEv2"]),
        &[b"msg1", b"nr", &prf.compute(b"skpi", &[&id])],
    );
    assert_eq!(*a, *want);
    assert_ne!(*a, *auth_value(prf, b"psk2", b"msg1", b"nr", b"skpi", &id));
}

// ---------- DH ----------

#[test]
fn dh_agreement_both_groups() {
    for g in [DhGroup::Modp2048, DhGroup::Ecp256] {
        let a = DhKeypair::new(g, &[0x11; 32]).unwrap();
        let b = DhKeypair::new(g, &[0x22; 32]).unwrap();
        assert_eq!(a.public().len(), g.public_len());
        assert_eq!(
            *a.shared_secret(b.public()).unwrap(),
            *b.shared_secret(a.public()).unwrap()
        );
        assert!(a.shared_secret(&[0; 3]).is_err());
    }
}

#[test]
fn dh_rejects_bad_peer_values() {
    let a = DhKeypair::new(DhGroup::Modp2048, &[0x11; 32]).unwrap();
    let mut one = vec![0u8; 256];
    one[255] = 1;
    assert!(a.shared_secret(&one).is_err());
    assert!(a.shared_secret(&[0; 256]).is_err());
    assert!(a.shared_secret(&[0xff; 256]).is_err());
    let e = DhKeypair::new(DhGroup::Ecp256, &[0x11; 32]).unwrap();
    assert!(e.shared_secret(&[1; 64]).is_err()); // hors courbe
    assert!(DhKeypair::new(DhGroup::Ecp256, &[0; 32]).is_err());
    assert!(DhKeypair::new(DhGroup::Modp2048, &[0; 31]).is_err());
    // p - 1 (p = 2^2048 - 2^1984 - 1 + 2^64 * (...) : seul le dernier mot diffère de p).
    let mut pm1 = hex(MODP2048_P_HEX);
    assert_eq!(pm1.len(), 256);
    // p lui-même et p - 1 sont refusés ; p - 2 est accepté.
    assert!(a.shared_secret(&pm1).is_err());
    pm1[255] -= 1;
    assert!(a.shared_secret(&pm1).is_err());
    pm1[255] -= 1;
    assert!(a.shared_secret(&pm1).is_ok());
    // Exposant 0 / 1 refusés.
    let mut k1 = [0u8; 32];
    k1[31] = 1;
    assert!(DhKeypair::new(DhGroup::Modp2048, &k1).is_err());
    // Taille de KE incorrecte.
    assert!(a.shared_secret(&[2; 255]).is_err());
    assert!(a.shared_secret(&[2; 257]).is_err());
}

const MODP2048_P_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

#[test]
fn modp_modpow_matches_reference_and_agrees() {
    // g^(ab) identique des deux côtés avec la nouvelle exponentiation.
    let a = DhKeypair::new(DhGroup::Modp2048, &[0x11; 32]).unwrap();
    let b = DhKeypair::new(DhGroup::Modp2048, &[0x7e; 32]).unwrap();
    assert_eq!(
        *a.shared_secret(b.public()).unwrap(),
        *b.shared_secret(a.public()).unwrap()
    );
    // Exposant 2 : 2^2 = 4.
    let mut k = [0u8; 32];
    k[31] = 2;
    let c = DhKeypair::new(DhGroup::Modp2048, &k).unwrap();
    let mut four = vec![0u8; 256];
    four[255] = 4;
    assert_eq!(c.public(), &four[..]);
}

// ---------- NAT-D (docs/vectors/ipsec/nat-d.txt) ----------

#[test]
fn nat_detection_vectors() {
    let spi_i = arr::<8>("0102030405060708");
    let spi_r = [0u8; 8];
    assert_eq!(
        nat_detection_hash(&spi_i, &spi_r, [192, 0, 2, 10], 500).to_vec(),
        hex("9cdaf8713cea81e287d3c0bacb7db468691dfe58")
    );
    assert_eq!(
        nat_detection_hash(&spi_i, &spi_r, [198, 51, 100, 1], 500).to_vec(),
        hex("3a02de24d181fd88168057d5ab63bd418473444a")
    );
}

// ---------- Messages IKE ----------

fn hdr(exch: u8, flags: u8, mid: u32) -> Header {
    Header {
        spi_i: [1, 2, 3, 4, 5, 6, 7, 8],
        spi_r: [0; 8],
        next_payload: 0,
        exchange_type: exch,
        flags,
        message_id: mid,
        length: 0,
    }
}

fn sa_init_payloads() -> Vec<Payload> {
    let t = |ty, id, key_len| Transform { ty, id, key_len };
    vec![
        Payload::Sa(vec![
            Proposal {
                number: 1,
                protocol: 1,
                spi: vec![],
                transforms: vec![
                    t(1, 12, Some(128)),
                    t(1, 12, Some(256)),
                    t(2, 5, None),
                    t(3, 12, None),
                    t(4, 14, None),
                ],
            },
            Proposal {
                number: 2,
                protocol: 1,
                spi: vec![],
                transforms: vec![t(1, 20, Some(128)), t(2, 5, None), t(4, 19, None)],
            },
        ]),
        Payload::Ke {
            group: 14,
            data: vec![7; 256],
        },
        Payload::Nonce(vec![9; 32]),
        Payload::Notify(Notify::new(notify::NAT_DETECTION_SOURCE_IP, vec![0xaa; 20])),
        Payload::Notify(Notify::new(
            notify::NAT_DETECTION_DESTINATION_IP,
            vec![0xbb; 20],
        )),
        Payload::Notify(Notify::new(notify::IKEV2_FRAGMENTATION_SUPPORTED, vec![])),
        Payload::Vendor(hex("1d6e178f6c2c0be284985465450fe9d4")),
    ]
}

#[test]
fn sa_init_roundtrip() {
    let raw = Message::encode(
        &hdr(exchange::IKE_SA_INIT, flags::INITIATOR, 0),
        &sa_init_payloads(),
    )
    .unwrap();
    assert_eq!(raw[17], 0x20);
    assert_eq!(
        u32::from_be_bytes(raw[24..28].try_into().unwrap()) as usize,
        raw.len()
    );
    let m = Message::decode(&raw).unwrap();
    assert_eq!(m.payloads, sa_init_payloads());
    assert_eq!(m.header.next_payload, ptype::SA);
    assert_eq!(m.notifies().count(), 3);
    // Ré-encodage identique.
    assert_eq!(Message::encode(&m.header, &m.payloads).unwrap(), raw);
}

#[test]
fn key_length_attribute_wire_format() {
    let p = Payload::Sa(vec![Proposal {
        number: 1,
        protocol: 1,
        spi: vec![],
        transforms: vec![Transform {
            ty: 1,
            id: 12,
            key_len: Some(128),
        }],
    }]);
    let (_, b) = encode_chain(&[p]).unwrap();
    assert_eq!(
        &b[b.len() - 12..],
        hex("0000000c0100000c800e0080").as_slice()
    );
}

fn auth_payloads() -> Vec<Payload> {
    vec![
        Payload::Id {
            responder: false,
            id_type: 2,
            data: b"fortivpn-client".to_vec(),
        },
        Payload::Notify(Notify::new(notify::INITIAL_CONTACT, vec![])),
        Payload::Cp(Cp::request()),
        Payload::Sa(vec![Proposal {
            number: 1,
            protocol: 3,
            spi: vec![0xde, 0xad, 0xbe, 0xef],
            transforms: vec![
                Transform {
                    ty: 1,
                    id: 20,
                    key_len: Some(256),
                },
                Transform {
                    ty: 5,
                    id: 0,
                    key_len: None,
                },
            ],
        }]),
        Payload::Ts {
            responder: false,
            selectors: vec![TrafficSelector::any()],
        },
        Payload::Ts {
            responder: true,
            selectors: vec![TrafficSelector::any()],
        },
        Payload::Eap(EapPacket::identity_response(1, "user").encode().unwrap()),
        Payload::Auth {
            method: 2,
            data: vec![5; 32],
        },
    ]
}

#[test]
fn auth_payloads_roundtrip() {
    let raw = Message::encode(
        &hdr(exchange::IKE_AUTH, flags::INITIATOR, 1),
        &auth_payloads(),
    )
    .unwrap();
    assert_eq!(Message::decode(&raw).unwrap().payloads, auth_payloads());
}

#[test]
fn cp_reply_accessors_with_25_domains() {
    let mut attrs = vec![
        CpAttr {
            ty: cp_attr::INTERNAL_IP4_ADDRESS,
            value: vec![10, 10, 2, 7],
        },
        CpAttr {
            ty: cp_attr::INTERNAL_IP4_NETMASK,
            value: vec![255; 4],
        },
        CpAttr {
            ty: cp_attr::INTERNAL_IP4_DNS,
            value: vec![10, 20, 0, 53],
        },
        CpAttr {
            ty: cp_attr::INTERNAL_IP4_DNS,
            value: vec![10, 20, 0, 54],
        },
        CpAttr {
            ty: cp_attr::INTERNAL_IP4_SUBNET,
            value: vec![10, 20, 0, 0, 255, 255, 255, 0],
        },
        CpAttr {
            ty: 16400,
            value: vec![1, 2, 3],
        }, // privé : conservé, ignoré
        CpAttr {
            ty: cp_attr::INTERNAL_IP4_DNS,
            value: vec![1, 2],
        }, // longueur invalide : ignoré
    ];
    for i in 0..25 {
        attrs.push(CpAttr {
            ty: cp_attr::INTERNAL_DNS_DOMAIN,
            value: format!("d{i}.example.test").into_bytes(),
        });
    }
    let cp = Cp { cfg_type: 2, attrs };
    let raw = Message::encode(
        &hdr(exchange::IKE_AUTH, flags::RESPONSE, 1),
        &[Payload::Cp(cp.clone())],
    )
    .unwrap();
    let Payload::Cp(d) = Message::decode(&raw).unwrap().payloads.remove(0) else {
        panic!()
    };
    assert_eq!(d, cp);
    assert_eq!(d.ip4_address(), Some([10, 10, 2, 7]));
    assert_eq!(d.ip4_netmask(), Some([255; 4]));
    assert_eq!(d.ip4_dns(), vec![[10, 20, 0, 53], [10, 20, 0, 54]]);
    assert_eq!(d.ip4_subnets(), vec![([10, 20, 0, 0], [255, 255, 255, 0])]);
    // Borné à 8 domaines (F7).
    assert_eq!(d.dns_domains().len(), 8);
    assert_eq!(d.dns_domains()[7], "d7.example.test");
}

#[test]
fn hostile_inputs_do_not_panic() {
    let raws = [
        Message::encode(
            &hdr(exchange::IKE_SA_INIT, flags::INITIATOR, 0),
            &sa_init_payloads(),
        )
        .unwrap(),
        Message::encode(
            &hdr(exchange::IKE_AUTH, flags::INITIATOR, 1),
            &auth_payloads(),
        )
        .unwrap(),
    ];
    for raw in &raws {
        // Troncatures (avec en-tête réajusté) et inversions d'octets.
        for n in 0..raw.len() {
            let mut t = raw[..n].to_vec();
            if n >= HEADER_LEN {
                t[24..28].copy_from_slice(&u32::try_from(n).unwrap().to_be_bytes());
            }
            let _ = Message::decode(&t);
        }
        for i in HEADER_LEN..raw.len() {
            for v in [0x00, 0xff, 0x80] {
                let mut t = raw.clone();
                t[i] = v;
                let _ = Message::decode(&t);
            }
        }
    }
    // Longueur déclarée absurde, version, payload critique inconnu.
    let mut r = raws[0].clone();
    r[24..28].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
    assert!(Message::decode(&r).is_err());
    let mut r = raws[0].clone();
    r[17] = 0x10;
    assert!(Message::decode(&r).is_err());
    let mut r = Message::encode(&hdr(34, 8, 0), &[Payload::Nonce(vec![0; 16])]).unwrap();
    r[16] = 200; // type inconnu
    r[29] = 0x80; // critique
    assert_eq!(
        Message::decode(&r),
        Err(crate::Error::UnsupportedCritical(200))
    );
    // Non critique : conservé.
    r[29] = 0;
    assert!(matches!(
        Message::decode(&r).unwrap().payloads[0],
        Payload::Unknown { ty: 200, .. }
    ));
    // Trop de payloads (chaîne de Vendor).
    let many: Vec<Payload> = (0..40).map(|_| Payload::Vendor(vec![1])).collect();
    let raw = Message::encode(&hdr(34, 8, 0), &many).unwrap();
    assert!(Message::decode(&raw).is_err());
}

// ---------- SK ----------

#[test]
fn sk_roundtrip_all_suites_and_tamper() {
    for suite in suites() {
        let keys = derive_sk_keys(&suite, &[1; 32], &[2; 32], &[3; 8], &[4; 8], &[5; 256]).unwrap();
        let iv = vec![0x42; suite.encr.iv_len()];
        let hd = hdr(exchange::IKE_AUTH, flags::INITIATOR, 1);
        let raw = sk::seal(&suite, &keys, true, &hd, &auth_payloads(), &iv).unwrap();
        let m = Message::decode(&raw).unwrap();
        assert_eq!(m.header.next_payload, ptype::SK);
        assert!(matches!(
            m.payloads.last(),
            Some(Payload::Sk {
                next: ptype::IDI,
                ..
            })
        ));
        let (hh, p) = sk::open(&suite, &keys, true, &raw).unwrap();
        assert_eq!(p, auth_payloads());
        assert_eq!(hh.message_id, 1);
        // Mauvaise direction.
        assert!(sk::open(&suite, &keys, false, &raw).is_err());
        // Altération de chaque octet après l'en-tête IKE : toujours rejeté, sans panique.
        for i in 24..raw.len() {
            if i < 28 {
                continue; // le champ Length est validé par decode
            }
            let mut t = raw.clone();
            t[i] ^= 1;
            assert!(
                sk::open(&suite, &keys, true, &t).is_err(),
                "octet {i} modifié accepté ({suite:?})"
            );
        }
        // Altération de l'en-tête IKE (AAD / MAC), hors Length.
        let mut t = raw.clone();
        t[20] ^= 1;
        assert!(sk::open(&suite, &keys, true, &t).is_err());
        // Payload interne vide (INFORMATIONAL vide).
        let e = sk::seal(&suite, &keys, false, &hdr(37, flags::RESPONSE, 2), &[], &iv).unwrap();
        assert_eq!(sk::open(&suite, &keys, false, &e).unwrap().1, vec![]);
        // IV de mauvaise taille.
        assert!(sk::seal(&suite, &keys, true, &hd, &[], &[0; 3]).is_err());
    }
}

#[test]
fn gcm_layout_matches_rfc5282() {
    let suite = suites()[2];
    let keys = derive_sk_keys(&suite, &[1; 32], &[2; 32], &[3; 8], &[4; 8], &[5; 256]).unwrap();
    let raw = sk::seal(
        &suite,
        &keys,
        true,
        &hdr(37, 8, 3),
        &[Payload::Notify(Notify::new(1, vec![]))],
        &[9; 8],
    )
    .unwrap();
    // 28 (IKE) + 4 (SK) + 8 (IV) + 8 (notify 8 + pad len 1 -> 12) ... + 16 ICV
    let inner: usize = 8 + 1;
    let ct = inner.div_ceil(4) * 4;
    assert_eq!(raw.len(), 28 + 4 + 8 + ct + 16);
    assert_eq!(&raw[32..40], &[9; 8]);
}

// ---------- MS-CHAPv2 (RFC 2759 §9.2, RFC 3079 §3.5.1) ----------

#[test]
fn rfc2759_vectors() {
    let pw = SecretString::from("clientPass".to_owned());
    let auth = arr::<16>("5B5D7C7D7B3F2F3E3C2C602132262628");
    let peer = arr::<16>("21402324255E262A28295F2B3A337C7E");
    assert_eq!(
        challenge_hash(&peer, &auth, "User"),
        arr::<8>("D02E4386BCE91226")
    );
    assert_eq!(
        challenge_hash(&peer, &auth, "DOM\\User"),
        arr::<8>("D02E4386BCE91226")
    );
    assert_eq!(
        nt_password_hash(&pw)[..],
        hex("44EBBA8D5312B8D611474411F56989AE")[..]
    );
    let nt = generate_nt_response(&auth, &peer, "User", &pw);
    assert_eq!(
        nt.to_vec(),
        hex("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")
    );
    assert_eq!(
        generate_authenticator_response(&pw, &nt, &peer, &auth, "User"),
        "S=407A5589115FD0D6209F510FE9C04566932CDA56"
    );
    // RFC 3079 §3.5.1
    assert_eq!(
        mppe_master_key(&pw, &nt)[..],
        hex("FDECE3717A8C838CB388E527AE3CDD31")[..]
    );
}

#[test]
fn msk_layout() {
    let pw = SecretString::from("clientPass".to_owned());
    let nt = arr::<24>("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF");
    let msk = eap_msk(&pw, &nt);
    assert_eq!(msk.len(), 64);
    assert!(msk[32..].iter().all(|&b| b == 0));
    assert_ne!(msk[..16], msk[16..32]);
    assert!(msk[..32].iter().any(|&b| b != 0));
}

#[test]
fn mschapv2_codec_and_client_flow() {
    let auth = arr::<16>("5B5D7C7D7B3F2F3E3C2C602132262628");
    let peer = arr::<16>("21402324255E262A28295F2B3A337C7E");
    let pw = SecretString::from("clientPass".to_owned());

    let ch = MsChapV2::Challenge {
        id: 7,
        challenge: auth,
        name: b"gw".to_vec(),
    };
    let eap = EapPacket {
        code: 1,
        id: 3,
        data: ch.encode().unwrap(),
    };
    let parsed = EapPacket::parse(&eap.encode().unwrap()).unwrap();
    assert_eq!(parsed, eap);
    let MsChapV2::Challenge { id, challenge, .. } = MsChapV2::parse(&parsed.data).unwrap() else {
        panic!()
    };

    let r = respond(id, &challenge, &peer, "User", &pw).unwrap();
    assert_eq!(r.eap_data.len(), 1 + 4 + 1 + 49 + 4);
    assert!(
        matches!(MsChapV2::parse(&r.eap_data).unwrap(), MsChapV2::Response { nt_response, .. } if nt_response == r.nt_response)
    );

    let ok = b"S=407A5589115FD0D6209F510FE9C04566932CDA56 M=Welcome";
    assert!(verify_success(ok, &pw, &r, "User"));
    assert!(!verify_success(
        b"S=407A5589115FD0D6209F510FE9C04566932CDA57 M=x",
        &pw,
        &r,
        "User"
    ));
    assert!(!verify_success(b"S=40", &pw, &r, "User"));

    let ack = MsChapV2::Success {
        id: 7,
        message: vec![],
    };
    assert_eq!(MsChapV2::parse(&ack.encode().unwrap()).unwrap(), ack);
    for bad in [
        &[][..],
        &[26],
        &[26, 1, 0, 0, 3],
        &[26, 1, 0, 0, 200],
        &[25, 1, 0, 0, 4],
    ] {
        assert!(MsChapV2::parse(bad).is_err());
    }
    assert!(EapPacket::parse(&[1, 1, 0, 200, 0]).is_err());
}

#[test]
fn short_or_long_nonce_is_rejected_on_decode() {
    for len in [0usize, 1, 15, 257] {
        let raw = Message::encode(
            &hdr(exchange::IKE_SA_INIT, flags::RESPONSE, 0),
            &[Payload::Nonce(vec![7; len])],
        )
        .unwrap();
        assert!(Message::decode(&raw).is_err(), "nonce de {len} octets");
    }
    for len in [16usize, 256] {
        let raw = Message::encode(
            &hdr(exchange::IKE_SA_INIT, flags::RESPONSE, 0),
            &[Payload::Nonce(vec![7; len])],
        )
        .unwrap();
        assert!(Message::decode(&raw).is_ok());
    }
}

#[test]
fn gcm_tag_tamper_is_rejected_and_plaintext_untouched() {
    for suite in suites().into_iter().filter(|s| s.encr.is_aead()) {
        let keys = derive_sk_keys(&suite, &[1; 32], &[2; 32], &[3; 8], &[4; 8], &[5; 256]).unwrap();
        let hd = hdr(exchange::IKE_AUTH, flags::INITIATOR, 1);
        let iv = vec![0x42; suite.encr.iv_len()];
        let raw = sk::seal(&suite, &keys, true, &hd, &auth_payloads(), &iv).unwrap();
        for bit in 0..8 {
            let mut t = raw.clone();
            let n = t.len();
            t[n - 1] ^= 1 << bit; // dernier octet du tag
            assert!(sk::open(&suite, &keys, true, &t).is_err());
            let mut t = raw.clone();
            t[n - 16] ^= 1 << bit; // premier octet du tag
            assert!(sk::open(&suite, &keys, true, &t).is_err());
        }
        assert!(sk::open(&suite, &keys, true, &raw).is_ok());
    }
}

#[test]
fn cp_domains_are_filtered_and_bounded() {
    let mk = |v: &[u8]| CpAttr {
        ty: cp_attr::INTERNAL_DNS_DOMAIN,
        value: v.to_vec(),
    };
    let cp = Cp {
        cfg_type: 2,
        attrs: vec![
            mk(b"corp.example.test"),
            mk(b""),
            mk(b"bad domain"),
            mk(b"evil\nnameserver 1.2.3.4"),
            mk(&[b'a'; 254]),
            mk(b"ok-2.example"),
        ],
    };
    assert_eq!(cp.dns_domains(), vec!["corp.example.test", "ok-2.example"]);
}

#[test]
fn traffic_selector_validity() {
    assert!(TrafficSelector::any().is_valid());
    let mut t = TrafficSelector::any();
    t.start = [10, 0, 0, 2];
    t.end = [10, 0, 0, 1];
    assert!(!t.is_valid());
    let mut t = TrafficSelector::any();
    t.start_port = 10;
    t.end_port = 5;
    assert!(!t.is_valid());
}
