//! Tests de l'initiateur IKEv2 face à un répondeur simulé (PSK + EAP-MSCHAPv2).

use std::time::{Duration, Instant};

use secrecy::ExposeSecret;

use crate::crypto::*;
use crate::ike::*;
use crate::sk;
use crate::testutil::*;
use crate::wire::*;

struct Run {
    events: Vec<Event>,
    /// Message IDs (déchiffrés) des IKE_AUTH envoyés par le client.
    sent_auth_mids: Vec<u32>,
    sent_init: u32,
}

/// Fait dialoguer l'initiateur et le répondeur jusqu'à la fin.
fn run(ini: &mut IkeInitiator, resp: &mut Responder) -> Run {
    let now = Instant::now();
    let mut r = Run {
        events: vec![],
        sent_auth_mids: vec![],
        sent_init: 0,
    };
    let mut queue = ini.start(now);
    let mut guard = 0;
    while !queue.is_empty() {
        guard += 1;
        assert!(guard < 50, "boucle infinie");
        let mut next = vec![];
        for o in queue {
            match o {
                Output::Send { port, data } => {
                    if port == IKE_PORT {
                        r.sent_init += 1;
                    } else {
                        assert_eq!(port, NATT_PORT);
                        assert_eq!(data[..4], [0; 4], "marqueur non-ESP");
                        r.sent_auth_mids
                            .push(Header::parse(&data[4..]).unwrap().message_id);
                    }
                    for reply in resp.handle(&data) {
                        next.extend(ini.handle_datagram(now, &reply));
                    }
                }
                Output::Event(e) => r.events.push(e),
            }
        }
        queue = next;
    }
    r
}

fn new_ini() -> IkeInitiator {
    IkeInitiator::new(cfg(), det_rng()).unwrap()
}

#[test]
fn full_exchange_established() {
    let mut ini = new_ini();
    let mut resp = Responder::new(Quirk::None);
    let r = run(&mut ini, &mut resp);
    assert_eq!(r.sent_auth_mids, vec![1, 2, 3, 4, 5]);
    assert_eq!(r.sent_init, 1);
    assert_eq!(resp.seen_user.as_deref(), Some(USER));
    let [
        Event::Established {
            config,
            child_sa_keys,
        },
    ] = r.events.as_slice()
    else {
        panic!("Established attendu : {:?}", r.events);
    };
    assert_eq!(config.ip, [10, 10, 2, 7]);
    assert_eq!(config.netmask, Some([255; 4]));
    assert_eq!(config.dns, vec![[10, 20, 0, 53]]);
    assert_eq!(config.subnets, vec![([10, 20, 0, 0], [255, 255, 255, 0])]);
    assert_eq!(config.dns_domains, vec!["corp.example.test".to_owned()]);
    assert_eq!(config.ts_remote[0].end, [10, 20, 0, 255]);
    assert_eq!(config.ts_local[0].start, [10, 10, 2, 7]);
    assert_eq!(child_sa_keys.spi_out, SPI_CHILD_R);
    assert_eq!(child_sa_keys.spi_in, resp.child_spi_i);
    assert_eq!(child_sa_keys.encr, Encr::AesGcm16_128);

    // KEYMAT recalculé indépendamment côté répondeur.
    let suite = resp.suite.unwrap();
    let keys = resp.keys.as_ref().unwrap();
    let mut seed = resp.ni.clone();
    seed.extend_from_slice(&NR);
    let e = child_sa_keys.encr.key_len() + child_sa_keys.encr.salt_len();
    let a = child_sa_keys.integ.map_or(0, Integ::key_len);
    let km = prf_plus(suite.prf, &keys.sk_d, &seed, 2 * (e + a)).unwrap();
    assert_eq!(child_sa_keys.encr_key_out[..], km[..e]);
    assert_eq!(child_sa_keys.integ_key_out[..], km[e..e + a]);
    assert_eq!(child_sa_keys.encr_key_in[..], km[e + a..2 * e + a]);
    assert_eq!(child_sa_keys.integ_key_in[..], km[2 * e + a..]);
    assert!(ini.is_finished());
}

#[test]
fn established_with_cbc_suite_and_ecp() {
    let mut c = cfg();
    c.dh_groups = vec![DhGroup::Ecp256];
    c.ike_suites =
        vec![IkeSuite::new(Encr::AesCbc256, Prf::HmacSha1, Some(Integ::HmacSha1_96)).unwrap()];
    c.esp_proposals = vec![EspProposal {
        encr: Encr::AesCbc128,
        integ: Some(Integ::HmacSha256_128),
    }];
    let mut ini = IkeInitiator::new(c, det_rng()).unwrap();
    let r = run(&mut ini, &mut Responder::new(Quirk::None));
    let [Event::Established { child_sa_keys, .. }] = r.events.as_slice() else {
        panic!("Established attendu : {:?}", r.events);
    };
    assert_eq!(child_sa_keys.encr, Encr::AesCbc128);
    assert_eq!(child_sa_keys.integ, Some(Integ::HmacSha256_128));
    assert_eq!(child_sa_keys.encr_key_out.len(), 16);
    assert_eq!(child_sa_keys.integ_key_in.len(), 32);
}

#[test]
fn nat_detection_source_is_wrong_destination_is_right() {
    let mut ini = new_ini();
    let Some(Output::Send { port, data }) = ini.start(Instant::now()).into_iter().next() else {
        panic!()
    };
    assert_eq!(port, IKE_PORT);
    let m = Message::decode(&data).unwrap();
    let spi_i = m.header.spi_i;
    let src = m
        .notifies()
        .find(|n| n.ty == notify::NAT_DETECTION_SOURCE_IP)
        .unwrap();
    let dst = m
        .notifies()
        .find(|n| n.ty == notify::NAT_DETECTION_DESTINATION_IP)
        .unwrap();
    assert_eq!(
        dst.data,
        nat_detection_hash(&spi_i, &[0; 8], GW_IP, 500).to_vec()
    );
    assert_ne!(
        src.data,
        nat_detection_hash(&spi_i, &[0; 8], [192, 0, 2, 10], 500).to_vec()
    );
    assert_eq!(m.header.message_id, 0);
}

#[test]
fn wrong_password_fails_without_further_requests() {
    let mut ini = new_ini();
    let r = run(&mut ini, &mut Responder::new(Quirk::WrongPassword));
    assert!(matches!(
        r.events.as_slice(),
        [Event::Failed(FailReason::CredentialsRejected)]
    ));
    assert_eq!(r.sent_auth_mids, vec![1, 2, 3]);
}

#[test]
fn wrong_responder_psk_fails_before_eap_identity() {
    let mut ini = new_ini();
    let r = run(&mut ini, &mut Responder::new(Quirk::WrongPsk));
    assert!(matches!(
        r.events.as_slice(),
        [Event::Failed(FailReason::GatewayAuthFailed)]
    ));
    // Seul IKE_AUTH #1 est parti : l'identité EAP (MID 2) n'a jamais été envoyée.
    assert_eq!(r.sent_auth_mids, vec![1]);
}

#[test]
fn unexpected_idr_fails() {
    let mut c = cfg();
    c.expected_idr = Some((2, b"autre.example.test".to_vec()));
    let mut ini = IkeInitiator::new(c, det_rng()).unwrap();
    let r = run(&mut ini, &mut Responder::new(Quirk::None));
    assert!(matches!(
        r.events.as_slice(),
        [Event::Failed(FailReason::IdrMismatch)]
    ));
    assert_eq!(r.sent_auth_mids, vec![1]);
}

#[test]
fn bad_server_mschapv2_success_is_rejected_before_reply() {
    let mut ini = new_ini();
    let r = run(&mut ini, &mut Responder::new(Quirk::BadServerSuccess));
    assert!(matches!(
        r.events.as_slice(),
        [Event::Failed(FailReason::ServerAuthFailed)]
    ));
    assert_eq!(r.sent_auth_mids, vec![1, 2, 3]);
}

#[test]
fn invalid_ke_payload_triggers_retry_with_new_group() {
    let mut ini = new_ini();
    let mut resp = Responder::new(Quirk::RequireGroup(DhGroup::Ecp256));
    let r = run(&mut ini, &mut resp);
    assert_eq!(r.sent_init, 2);
    assert_eq!(resp.init_count, 2);
    assert!(matches!(r.events.as_slice(), [Event::Established { .. }]));
    // Les AUTH sont calculés sur le DERNIER IKE_SA_INIT (le répondeur a vérifié via assert_eq).
}

#[test]
fn invalid_ke_unknown_group_is_ignored_until_timeout() {
    let mut c = cfg();
    c.dh_groups = vec![DhGroup::Modp2048];
    let mut ini = IkeInitiator::new(c, det_rng()).unwrap();
    let r = run(
        &mut ini,
        &mut Responder::new(Quirk::RequireGroup(DhGroup::Ecp256)),
    );
    // Erreur non authentifiée : ni échec immédiat ni relance.
    assert!(r.events.is_empty());
    assert!(!ini.is_finished());
    assert_eq!(timeout_reason(&mut ini), FailReason::Timeout);
}

/// Pousse les échéances jusqu'à l'échec et renvoie la raison.
fn timeout_reason(ini: &mut IkeInitiator) -> FailReason {
    let mut now = Instant::now();
    for _ in 0..20 {
        let Some(d) = ini.next_deadline() else { break };
        now = now.max(d);
        for o in ini.handle_timeout(now) {
            if let Output::Event(Event::Failed(r)) = o {
                return r;
            }
        }
    }
    panic!("pas d'échec par timeout");
}

/// Réponse IKE_SA_INIT forgée (non authentifiée) à la requête `req`.
fn forged_init_response(req: &[u8], payloads: &[Payload]) -> Vec<u8> {
    let h = Header::parse(req).unwrap();
    let hdr = Header {
        spi_i: h.spi_i,
        spi_r: [9; 8],
        next_payload: 0,
        exchange_type: exchange::IKE_SA_INIT,
        flags: flags::RESPONSE,
        message_id: 0,
        length: 0,
    };
    Message::encode(&hdr, payloads).unwrap()
}

fn first_send(out: &[Output]) -> Vec<u8> {
    out.iter()
        .find_map(|o| match o {
            Output::Send { data, .. } => Some(data.clone()),
            Output::Event(_) => None,
        })
        .unwrap()
}

#[test]
fn unauthenticated_init_errors_are_ignored() {
    for ty in [14u16, 24, 7, 1] {
        let mut ini = new_ini();
        let req = first_send(&ini.start(Instant::now()));
        let forged = forged_init_response(&req, &[Payload::Notify(Notify::new(ty, vec![]))]);
        let out = ini.handle_datagram(Instant::now(), &forged);
        assert!(out.is_empty(), "notify {ty}");
        assert!(!ini.is_finished());
        // Message sans SA/KE/Nonce ni notify : ignoré aussi.
        let out = ini.handle_datagram(Instant::now(), &forged_init_response(&req, &[]));
        assert!(out.is_empty());
        assert_eq!(timeout_reason(&mut ini), FailReason::Timeout);
    }
}

#[test]
fn oversized_or_empty_cookie_is_ignored() {
    for len in [0usize, 65, 4000] {
        let mut ini = new_ini();
        let req = first_send(&ini.start(Instant::now()));
        let forged = forged_init_response(
            &req,
            &[Payload::Notify(Notify::new(notify::COOKIE, vec![7; len]))],
        );
        assert!(ini.handle_datagram(Instant::now(), &forged).is_empty());
        assert!(!ini.is_finished());
    }
    // 64 octets : accepté (relance avec cookie).
    let mut ini = new_ini();
    let req = first_send(&ini.start(Instant::now()));
    let forged = forged_init_response(
        &req,
        &[Payload::Notify(Notify::new(notify::COOKIE, vec![7; 64]))],
    );
    assert!(!ini.handle_datagram(Instant::now(), &forged).is_empty());
}

#[test]
fn init_restarts_are_bounded_then_ignored() {
    let mut ini = new_ini();
    let mut req = first_send(&ini.start(Instant::now()));
    let mut restarts = 0;
    loop {
        let forged = forged_init_response(
            &req,
            &[Payload::Notify(Notify::new(notify::COOKIE, vec![7; 8]))],
        );
        let out = ini.handle_datagram(Instant::now(), &forged);
        if out.is_empty() {
            break;
        }
        req = first_send(&out);
        restarts += 1;
        assert!(restarts <= 4);
    }
    assert!(!ini.is_finished());
}

#[test]
fn invalid_ke_response_with_bad_public_value_is_ignored() {
    // Réponse structurellement correcte mais KE nul (y = 0) : ignorée, état init conservé.
    let mut ini = new_ini();
    let req = first_send(&ini.start(Instant::now()));
    let msg = Message::decode(&req).unwrap();
    let mut sa = None;
    for p in &msg.payloads {
        if let Payload::Sa(v) = p {
            sa = Some(v.clone());
        }
    }
    let mut prop = sa.unwrap().remove(0);
    prop.transforms.retain(|t| t.ty != 4 || t.id == 19);
    let forged = forged_init_response(
        &req,
        &[
            Payload::Sa(vec![prop]),
            Payload::Ke {
                group: 19,
                data: vec![0; 64],
            },
            Payload::Nonce(vec![5; 32]),
        ],
    );
    assert!(ini.handle_datagram(Instant::now(), &forged).is_empty());
    assert!(!ini.is_finished());
}

#[test]
fn short_or_empty_psk_is_refused() {
    for psk in ["", "1234567"] {
        let mut c = cfg();
        c.psk = secrecy::SecretString::from(psk);
        assert!(IkeInitiator::new(c, det_rng()).is_err(), "{psk:?}");
    }
    let mut c = cfg();
    c.psk = secrecy::SecretString::from("12345678");
    assert!(IkeInitiator::new(c, det_rng()).is_ok());
}

#[test]
fn default_dh_order_prefers_ecp256() {
    let c = IkeConfig::new(
        GW_IP,
        [192, 0, 2, 10],
        500,
        secrecy::SecretString::from(PSK),
        USER.to_owned(),
        secrecy::SecretString::from(PASS),
    );
    assert_eq!(c.dh_groups[0], DhGroup::Ecp256);
}

#[test]
fn cookie_is_echoed() {
    let mut ini = new_ini();
    let mut resp = Responder::new(Quirk::RequireCookie);
    let r = run(&mut ini, &mut resp);
    assert_eq!(r.sent_init, 2);
    assert!(matches!(r.events.as_slice(), [Event::Established { .. }]));
}

#[test]
fn retransmission_then_progress_and_timeout() {
    let t0 = Instant::now();
    let mut ini = new_ini();
    let mut resp = Responder::new(Quirk::None);
    let first = ini.start(t0);
    let Some(Output::Send { data: d1, .. }) = first.into_iter().next() else {
        panic!()
    };
    assert_eq!(ini.next_deadline(), Some(t0 + Duration::from_secs(2)));
    // Avant l'échéance : rien.
    assert!(ini.handle_timeout(t0 + Duration::from_secs(1)).is_empty());
    // Échéance : même datagramme, délai doublé.
    let t1 = t0 + Duration::from_secs(2);
    let o = ini.handle_timeout(t1);
    let [Output::Send { data: d2, .. }] = o.as_slice() else {
        panic!()
    };
    assert_eq!(&d1, d2);
    assert_eq!(ini.next_deadline(), Some(t1 + Duration::from_secs(4)));
    // La réponse arrive : l'échange progresse.
    let reply = resp.handle(&d1).remove(0);
    let o = ini.handle_datagram(t1, &reply);
    assert!(matches!(
        o.as_slice(),
        [Output::Send {
            port: NATT_PORT,
            ..
        }]
    ));
    // Rejeu de la même réponse : ignoré.
    assert!(ini.handle_datagram(t1, &reply).is_empty());

    // Timeout complet sur un autre initiateur : 5 envois puis Failed(Timeout).
    let mut ini = new_ini();
    let mut t = t0;
    let mut sends = 1;
    ini.start(t);
    let ev = loop {
        t = ini.next_deadline().unwrap();
        let o = ini.handle_timeout(t);
        match o.into_iter().next() {
            Some(Output::Send { .. }) => sends += 1,
            Some(Output::Event(e)) => break e,
            None => panic!(),
        }
    };
    assert_eq!(sends, 5);
    assert!(matches!(ev, Event::Failed(FailReason::Timeout)));
    assert!(ini.is_finished());
    assert!(ini.handle_timeout(t + Duration::from_secs(999)).is_empty());
}

#[test]
fn garbage_and_foreign_datagrams_are_ignored() {
    let mut ini = new_ini();
    ini.start(Instant::now());
    let now = Instant::now();
    assert!(ini.handle_datagram(now, &[1, 2, 3]).is_empty());
    assert!(ini.handle_datagram(now, &[0xAB; 64]).is_empty());
    assert!(!ini.is_finished());
}

#[test]
fn debug_does_not_leak_secrets() {
    let c = cfg();
    let s = format!("{c:?}");
    assert!(!s.contains(PSK) && !s.contains(PASS));
    assert_eq!(c.psk.expose_secret(), PSK);
}

#[path = "ike_est_tests.rs"]
mod est;
