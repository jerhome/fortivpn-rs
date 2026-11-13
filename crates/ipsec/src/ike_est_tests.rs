//! Phase Established : DPD, Delete, rekey CHILD/IKE (deux sens), collision, transition ESP.

#![allow(clippy::many_single_char_names, clippy::cast_possible_truncation)]

use super::*;
use crate::esp::{EspTunnel, Inbound};

const OVERLAP: Duration = Duration::from_secs(10);

/// IKE SA vue de la passerelle simulée.
struct PSa {
    suite: IkeSuite,
    keys: SkKeys,
    spi_i: [u8; 8],
    spi_r: [u8; 8],
    gw_init: bool,
    next_mid: u32,
}

struct Peer {
    cur: PSa,
    old: Option<PSa>,
    gcm: u64,
    esp: EspProposal,
}

fn dh() -> DhKeypair {
    DhKeypair::new(DhGroup::Modp2048, &[0x2Du8; 32]).unwrap()
}

fn tsany() -> Vec<Payload> {
    vec![
        Payload::Ts {
            responder: false,
            selectors: vec![TrafficSelector::any()],
        },
        Payload::Ts {
            responder: true,
            selectors: vec![TrafficSelector::any()],
        },
    ]
}

fn esp_prop(spi: u32) -> Proposal {
    Proposal {
        number: 1,
        protocol: 3,
        spi: spi.to_be_bytes().to_vec(),
        transforms: vec![
            Transform {
                ty: 1,
                id: 20,
                key_len: Some(128),
            },
            Transform {
                ty: 4,
                id: 14,
                key_len: None,
            },
            Transform {
                ty: 5,
                id: 0,
                key_len: None,
            },
        ],
    }
}

fn sends(out: &[Output]) -> Vec<Vec<u8>> {
    out.iter()
        .filter_map(|o| match o {
            Output::Send { data, .. } => Some(data.clone()),
            Output::Event(_) => None,
        })
        .collect()
}

fn events(out: &[Output]) -> Vec<&Event> {
    out.iter()
        .filter_map(|o| match o {
            Output::Event(e) => Some(e),
            Output::Send { .. } => None,
        })
        .collect()
}

fn mirror(k: &ChildSaKeys) -> ChildSaKeys {
    ChildSaKeys {
        spi_in: k.spi_out,
        spi_out: k.spi_in,
        encr: k.encr,
        integ: k.integ,
        encr_key_out: k.encr_key_in.clone(),
        integ_key_out: k.integ_key_in.clone(),
        encr_key_in: k.encr_key_out.clone(),
        integ_key_in: k.integ_key_out.clone(),
    }
}

impl Peer {
    fn sa(&self, old: bool) -> &PSa {
        if old {
            self.old.as_ref().unwrap()
        } else {
            &self.cur
        }
    }

    fn seal(
        &mut self,
        old: bool,
        response: bool,
        exch: u8,
        mid: u32,
        inner: &[Payload],
    ) -> Vec<u8> {
        self.gcm += 1;
        let sa = self.sa(old);
        let iv = if sa.suite.encr.is_aead() {
            self.gcm.to_be_bytes().to_vec()
        } else {
            vec![self.gcm as u8; 16]
        };
        let h = Header {
            spi_i: sa.spi_i,
            spi_r: sa.spi_r,
            next_payload: 0,
            exchange_type: exch,
            flags: if sa.gw_init { flags::INITIATOR } else { 0 }
                | if response { flags::RESPONSE } else { 0 },
            message_id: mid,
            length: 0,
        };
        let m = sk::seal(&sa.suite, &sa.keys, sa.gw_init, &h, inner, &iv).unwrap();
        let mut d = vec![0u8; 4];
        d.extend_from_slice(&m);
        d
    }

    fn request(&mut self, old: bool, exch: u8, inner: &[Payload]) -> Vec<u8> {
        let sa = if old {
            self.old.as_mut().unwrap()
        } else {
            &mut self.cur
        };
        let mid = sa.next_mid;
        sa.next_mid += 1;
        self.seal(old, false, exch, mid, inner)
    }

    /// Déchiffre un datagramme du client : (en-tête, payloads, sur l'ancienne SA ?).
    fn open(&self, data: &[u8]) -> (Header, Vec<Payload>, bool) {
        let raw = &data[4..];
        let h = Header::parse(raw).unwrap();
        let old = !(h.spi_i == self.cur.spi_i && h.spi_r == self.cur.spi_r);
        let sa = self.sa(old);
        assert_eq!((sa.spi_i, sa.spi_r), (h.spi_i, h.spi_r));
        let (_, p) = sk::open(&sa.suite, &sa.keys, !sa.gw_init, raw).unwrap();
        (h, p, old)
    }

    fn respond(&mut self, h: &Header, old: bool, inner: &[Payload]) -> Vec<u8> {
        self.seal(old, true, h.exchange_type, h.message_id, inner)
    }

    /// Dérive la CHILD SA vue de la passerelle ; `gw_initiator` : la passerelle a initié.
    fn child_keys(
        &self,
        shared: &[u8],
        ni: &[u8],
        nr: &[u8],
        spi_gw: u32,
        spi_cl: u32,
        gw_initiator: bool,
    ) -> ChildSaKeys {
        derive_child_keys_ex(
            self.cur.suite.prf,
            &self.cur.keys.sk_d,
            Some(shared),
            ni,
            nr,
            self.esp,
            spi_gw,
            spi_cl,
            gw_initiator,
        )
        .unwrap()
    }
}

struct Ctx {
    ini: IkeInitiator,
    peer: Peer,
    keys: ChildSaKeys,
    t0: Instant,
    spi_gw_in: u32,
}

fn established() -> Ctx {
    established_with(cfg())
}

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

fn is_delete_esp(p: &[Payload], spi: u32) -> bool {
    p.iter()
        .filter_map(parse_delete)
        .any(|(pr, v)| pr == 3 && v == [spi])
}

// ---------- DPD / Delete ----------

#[test]
fn dpd_request_is_answered_and_retransmission_replayed() {
    let mut c = established();
    let req = c.peer.request(false, exchange::INFORMATIONAL, &[]);
    let out = c.ini.handle_datagram(c.t0, &req);
    let s = sends(&out);
    assert_eq!(s.len(), 1);
    let h = Header::parse(&s[0][4..]).unwrap();
    assert_eq!(
        (h.message_id, h.exchange_type),
        (0, exchange::INFORMATIONAL)
    );
    assert_ne!(h.flags & flags::RESPONSE, 0);
    let sa = &c.peer.cur;
    let (_, p) = sk::open(&sa.suite, &sa.keys, true, &s[0][4..]).unwrap();
    assert!(p.is_empty());
    assert!(events(&out).is_empty());
    // Retransmission de la requête : même réponse, aucun nouvel effet.
    let again = sends(&c.ini.handle_datagram(c.t0, &req));
    assert_eq!(again, s);
    // Requête suivante (MID 1) : traitée.
    let req2 = c.peer.request(false, exchange::INFORMATIONAL, &[]);
    assert_eq!(sends(&c.ini.handle_datagram(c.t0, &req2)).len(), 1);
}

#[test]
fn client_dpd_after_idle_then_ack() {
    let mut c = established();
    assert!(c.ini.handle_timeout(c.t0 + secs(20)).is_empty());
    let out = c.ini.handle_timeout(c.t0 + secs(31));
    let s = sends(&out);
    assert_eq!(s.len(), 1);
    let (h, p, old) = c.peer.open(&s[0]);
    assert!(p.is_empty() && !old);
    assert_eq!(
        (h.exchange_type, h.message_id),
        (exchange::INFORMATIONAL, 6)
    );
    let ack = c.peer.respond(&h, false, &[]);
    let out = c.ini.handle_datagram(c.t0 + secs(32), &ack);
    assert!(out.is_empty());
    // Plus de retransmission ; prochain DPD 30 s après le dernier trafic entrant.
    assert!(c.ini.handle_timeout(c.t0 + secs(60)).is_empty());
    assert_eq!(sends(&c.ini.handle_timeout(c.t0 + secs(63))).len(), 1);
}

#[test]
fn inbound_traffic_defers_dpd() {
    let mut c = established();
    c.ini.note_inbound_traffic(c.t0 + secs(25));
    assert!(c.ini.handle_timeout(c.t0 + secs(31)).is_empty());
    assert_eq!(sends(&c.ini.handle_timeout(c.t0 + secs(56))).len(), 1);
}

#[test]
fn silent_peer_is_dead_after_retransmissions() {
    let mut c = established();
    let mut now = c.t0 + secs(31);
    let mut nsend = sends(&c.ini.handle_timeout(now)).len();
    assert_eq!(nsend, 1);
    let mut failed = None;
    for _ in 0..20 {
        now = c.ini.next_deadline().unwrap().max(now);
        let out = c.ini.handle_timeout(now);
        nsend += sends(&out).len();
        if let Some(Event::Failed(r)) = events(&out).first() {
            failed = Some(r.clone());
            break;
        }
    }
    assert_eq!(failed, Some(FailReason::DeadPeer));
    assert_eq!(nsend, 5, "max_sends envois au total");
    assert!(c.ini.is_finished());
}

#[test]
fn peer_delete_ike_closes() {
    let mut c = established();
    let req = c
        .peer
        .request(false, exchange::INFORMATIONAL, &[delete_payload(1, &[])]);
    let out = c.ini.handle_datagram(c.t0, &req);
    assert_eq!(sends(&out).len(), 1, "réponse vide");
    assert!(matches!(
        events(&out).as_slice(),
        [Event::Closed(CloseReason::PeerDeletedIke)]
    ));
    assert!(c.ini.is_finished());
    assert!(c.ini.handle_datagram(c.t0, &req).is_empty());
}

#[test]
fn peer_delete_child_closes_and_acks_with_our_spi() {
    let mut c = established();
    let req = c.peer.request(
        false,
        exchange::INFORMATIONAL,
        &[delete_payload(3, &[c.spi_gw_in])],
    );
    let out = c.ini.handle_datagram(c.t0, &req);
    let s = sends(&out);
    let sa = &c.peer.cur;
    let (_, p) = sk::open(&sa.suite, &sa.keys, true, &s[0][4..]).unwrap();
    assert!(is_delete_esp(&p, c.keys.spi_in));
    assert!(matches!(
        events(&out).as_slice(),
        [Event::Closed(CloseReason::PeerDeletedChild)]
    ));
}

#[test]
fn local_close_sends_delete_ike() {
    let mut c = established();
    let out = c.ini.close();
    let s = sends(&out);
    let (_, p, _) = c.peer.open(&s[0]);
    assert!(p.iter().filter_map(parse_delete).any(|(pr, _)| pr == 1));
    assert!(matches!(
        events(&out).as_slice(),
        [Event::Closed(CloseReason::Local)]
    ));
}

#[test]
fn hard_lifetime_expires() {
    let mut c = established();
    let out = c.ini.handle_timeout(c.t0 + secs(28_801));
    assert!(matches!(
        events(&out).as_slice(),
        [Event::Failed(FailReason::Expired)]
    ));
}

// ---------- rekey CHILD ----------

#[test]
fn child_rekey_initiated_by_client_with_pfs() {
    let mut c = established();
    c.ini.note_inbound_traffic(c.t0 + secs(24_990));
    assert!(sends(&c.ini.handle_timeout(c.t0 + secs(25_000))).is_empty());
    let out = c.ini.handle_timeout(c.t0 + secs(26_000));
    let s = sends(&out);
    assert_eq!(s.len(), 1);
    let (h, p, _) = c.peer.open(&s[0]);
    assert_eq!(h.exchange_type, exchange::CREATE_CHILD_SA);
    let n = p
        .iter()
        .find_map(|x| match x {
            Payload::Notify(n) if n.ty == notify::REKEY_SA => Some(n),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        (n.protocol, n.spi.clone()),
        (3, c.keys.spi_in.to_be_bytes().to_vec())
    );
    let ni = find_nonce_t(&p);
    let (kg, kd) = find_ke_t(&p);
    assert_eq!(kg, 14);
    let kp = dh();
    let shared = kp.shared_secret(&kd).unwrap();
    let (gw_spi, nr) = (0x5555_0001u32, vec![0x66u8; 32]);
    let gw_keys = c
        .peer
        .child_keys(&shared, &ni, &nr, gw_spi, spi_of_req(&p), false);
    let mut resp = vec![
        Payload::Sa(vec![esp_prop(gw_spi)]),
        Payload::Nonce(nr),
        Payload::Ke {
            group: 14,
            data: kp.public().to_vec(),
        },
    ];
    resp.extend(tsany());
    let r = c.peer.respond(&h, false, &resp);
    let out = c.ini.handle_datagram(c.t0 + secs(26_001), &r);
    let evs = events(&out);
    let [Event::ChildRekeyed { keys, old_spi }] = evs.as_slice() else {
        panic!("ChildRekeyed attendu : {evs:?}");
    };
    assert_eq!(*old_spi, c.keys.spi_in);
    assert_eq!((keys.spi_out, keys.spi_in), (gw_spi, spi_of_req(&p)));
    assert_eq!(keys.encr_key_out[..], gw_keys.encr_key_in[..]);
    assert_eq!(keys.encr_key_in[..], gw_keys.encr_key_out[..]);
    assert_ne!(
        keys.encr_key_out[..],
        c.keys.encr_key_out[..],
        "clés neuves (PFS)"
    );
    // Delete(ESP, ancien SPI entrant) suit.
    let s = sends(&out);
    assert_eq!(s.len(), 1);
    let (dh_, dp, _) = c.peer.open(&s[0]);
    assert_eq!(dh_.exchange_type, exchange::INFORMATIONAL);
    assert!(is_delete_esp(&dp, c.keys.spi_in));
    // Fin de la fenêtre de transition.
    let ack = c
        .peer
        .respond(&dh_, false, &[delete_payload(3, &[c.spi_gw_in])]);
    assert!(c.ini.handle_datagram(c.t0 + secs(26_002), &ack).is_empty());
    let out = c
        .ini
        .handle_timeout(c.t0 + secs(26_001) + OVERLAP + secs(1));
    assert!(matches!(
        events(&out).as_slice(),
        [Event::OldChildExpired { spi }] if *spi == c.keys.spi_in
    ));
}

#[test]
fn gateway_child_rekey_without_pfs_is_refused() {
    let mut c = established();
    let mut prop = esp_prop(0x7777_0003);
    prop.transforms.retain(|t| t.ty != 4);
    let mut p = vec![
        Payload::Notify(Notify {
            protocol: 3,
            spi: SPI_CHILD_R.to_be_bytes().to_vec(),
            ty: notify::REKEY_SA,
            data: vec![],
        }),
        Payload::Sa(vec![prop]),
        Payload::Nonce(vec![0x21; 32]),
    ];
    p.extend(tsany());
    let req = c.peer.request(false, exchange::CREATE_CHILD_SA, &p);
    let out = c.ini.handle_datagram(c.t0 + secs(100), &req);
    assert!(events(&out).is_empty());
    let (_, p, _) = c.peer.open(&sends(&out)[0]);
    assert!(matches!(
        p.as_slice(),
        [Payload::Notify(n)] if n.ty == 14
    ));
}

#[test]
fn client_child_rekey_response_without_pfs_is_rejected() {
    let mut c = established();
    c.ini.note_inbound_traffic(c.t0 + secs(24_990));
    let out = c.ini.handle_timeout(c.t0 + secs(26_000));
    let s = sends(&out);
    let (h, p, _) = c.peer.open(&s[0]);
    let ni = find_nonce_t(&p);
    assert_eq!(ni.len(), 32);
    let mut prop = esp_prop(0x5555_0001);
    prop.transforms.retain(|t| t.ty != 4);
    let mut resp = vec![Payload::Sa(vec![prop]), Payload::Nonce(vec![0x66; 32])];
    resp.extend(tsany());
    let r = c.peer.respond(&h, false, &resp);
    let out = c.ini.handle_datagram(c.t0 + secs(26_001), &r);
    assert!(
        events(&out)
            .iter()
            .all(|e| !matches!(e, Event::ChildRekeyed { .. }))
    );
}

#[test]
fn gateway_child_rekey_with_inverted_ts_is_refused() {
    let mut c = established();
    let mut p = vec![
        Payload::Notify(Notify {
            protocol: 3,
            spi: SPI_CHILD_R.to_be_bytes().to_vec(),
            ty: notify::REKEY_SA,
            data: vec![],
        }),
        Payload::Sa(vec![esp_prop(0x7777_0004)]),
        Payload::Nonce(vec![0x21; 32]),
        Payload::Ke {
            group: 14,
            data: dh().public().to_vec(),
        },
    ];
    let bad = TrafficSelector {
        protocol: 0,
        start_port: 0,
        end_port: 65535,
        start: [10, 0, 0, 9],
        end: [10, 0, 0, 1],
    };
    p.push(Payload::Ts {
        responder: false,
        selectors: vec![bad],
    });
    p.push(Payload::Ts {
        responder: true,
        selectors: vec![TrafficSelector::any()],
    });
    let req = c.peer.request(false, exchange::CREATE_CHILD_SA, &p);
    let out = c.ini.handle_datagram(c.t0 + secs(100), &req);
    assert!(events(&out).is_empty());
    let (_, p, _) = c.peer.open(&sends(&out)[0]);
    assert!(matches!(
        p.as_slice(),
        [Payload::Notify(n)] if n.ty == notify::TS_UNACCEPTABLE
    ));
}

fn find_nonce_t(p: &[Payload]) -> Vec<u8> {
    p.iter()
        .find_map(|x| match x {
            Payload::Nonce(n) => Some(n.clone()),
            _ => None,
        })
        .unwrap()
}

fn find_ke_t(p: &[Payload]) -> (u16, Vec<u8>) {
    p.iter()
        .find_map(|x| match x {
            Payload::Ke { group, data } => Some((*group, data.clone())),
            _ => None,
        })
        .unwrap()
}

/// SPI entrant proposé par le client dans la requête de rekey.
fn spi_of_req(p: &[Payload]) -> u32 {
    p.iter()
        .find_map(|x| match x {
            Payload::Sa(v) => Some(u32::from_be_bytes(v[0].spi[..4].try_into().unwrap())),
            _ => None,
        })
        .unwrap()
}

/// Requête de rekey CHILD émise par la passerelle ; renvoie (datagramme, KE privé, Ni, SPI gw).
fn gw_child_rekey(c: &mut Ctx, ni: &[u8], gw_spi: u32, target: u32) -> Vec<u8> {
    let mut p = vec![
        Payload::Notify(Notify {
            protocol: 3,
            spi: target.to_be_bytes().to_vec(),
            ty: notify::REKEY_SA,
            data: vec![],
        }),
        Payload::Sa(vec![esp_prop(gw_spi)]),
        Payload::Nonce(ni.to_vec()),
        Payload::Ke {
            group: 14,
            data: dh().public().to_vec(),
        },
    ];
    p.extend(tsany());
    c.peer.request(false, exchange::CREATE_CHILD_SA, &p)
}

#[test]
fn child_rekey_initiated_by_gateway_and_esp_transition() {
    let mut c = established();
    let mut old_tunnel = EspTunnel::new(&c.keys, false).unwrap();
    let mut gw_old = EspTunnel::new(&mirror(&c.keys), false).unwrap();
    let (ni, gw_spi) = (vec![0x21u8; 32], 0x7777_0002u32);
    let req = gw_child_rekey(&mut c, &ni, gw_spi, SPI_CHILD_R);
    let out = c.ini.handle_datagram(c.t0 + secs(100), &req);
    let evs = events(&out);
    let [Event::ChildRekeyed { keys, old_spi }] = evs.as_slice() else {
        panic!("ChildRekeyed attendu : {evs:?}");
    };
    assert_eq!(*old_spi, c.keys.spi_in);
    assert_eq!(keys.spi_out, gw_spi);
    let s = sends(&out);
    let (h, p, _) = c.peer.open(&s[0]);
    assert_ne!(h.flags & flags::RESPONSE, 0);
    // Reproduit la dérivation côté passerelle (elle est initiatrice).
    let nr = find_nonce_t(&p);
    let (_, kd) = find_ke_t(&p);
    let shared = dh().shared_secret(&kd).unwrap();
    let gw_keys = c
        .peer
        .child_keys(&shared, &ni, &nr, gw_spi, keys.spi_in, true);
    assert_eq!(keys.encr_key_out[..], gw_keys.encr_key_in[..]);
    assert_eq!(keys.encr_key_in[..], gw_keys.encr_key_out[..]);

    // ESP : émission sur la nouvelle SA, réception des deux SPI pendant la transition.
    old_tunnel.rekey(keys).unwrap();
    let mut gw_new = EspTunnel::new(&gw_keys, false).unwrap();
    let pkt = [
        0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
    ];
    let from_old = gw_old.seal(&pkt, Some(&[1u8; 16])).unwrap();
    let from_new = gw_new.seal(&pkt, Some(&[2u8; 16])).unwrap();
    assert_eq!(
        old_tunnel.open(&from_old).unwrap(),
        Inbound::Packet(pkt.to_vec())
    );
    assert_eq!(
        old_tunnel.open(&from_new).unwrap(),
        Inbound::Packet(pkt.to_vec())
    );
    let out_pkt = old_tunnel.seal(&pkt, Some(&[3u8; 16])).unwrap();
    assert_eq!(u32::from_be_bytes(out_pkt[..4].try_into().unwrap()), gw_spi);
    assert_eq!(
        gw_new.open(&out_pkt).unwrap(),
        Inbound::Packet(pkt.to_vec())
    );
    old_tunnel.drop_old(*old_spi);
    let from_old = gw_old.seal(&pkt, Some(&[4u8; 16])).unwrap();
    assert!(old_tunnel.open(&from_old).is_err());

    // La passerelle supprime l'ancienne SA : acquittement, pas de fermeture.
    let del = c.peer.request(
        false,
        exchange::INFORMATIONAL,
        &[delete_payload(3, &[c.spi_gw_in])],
    );
    let out = c.ini.handle_datagram(c.t0 + secs(101), &del);
    assert!(events(&out).is_empty());
    let (_, p, _) = c.peer.open(&sends(&out)[0]);
    assert!(is_delete_esp(&p, c.keys.spi_in));
}

#[test]
fn child_rekey_for_unknown_spi_is_refused() {
    let mut c = established();
    let req = gw_child_rekey(&mut c, &[1u8; 32], 0x1234_5678, 0xdead_beef);
    let out = c.ini.handle_datagram(c.t0, &req);
    assert!(events(&out).is_empty());
    let (_, p, _) = c.peer.open(&sends(&out)[0]);
    assert!(matches!(
        p.as_slice(),
        [Payload::Notify(n)] if n.ty == notify::CHILD_SA_NOT_FOUND
    ));
}

#[test]
fn refused_rekey_is_not_fatal_and_is_retried() {
    let mut c = established();
    let s = sends(&c.ini.handle_timeout(c.t0 + secs(26_000)));
    let (h, _, _) = c.peer.open(&s[0]);
    let r = c.peer.respond(
        &h,
        false,
        &[Payload::Notify(Notify::new(
            notify::NO_ADDITIONAL_SAS,
            vec![],
        ))],
    );
    let out = c.ini.handle_datagram(c.t0 + secs(26_001), &r);
    assert!(out.is_empty());
    c.ini.note_inbound_traffic(c.t0 + secs(26_040));
    assert!(sends(&c.ini.handle_timeout(c.t0 + secs(26_050))).is_empty());
    let out = c.ini.handle_timeout(c.t0 + secs(26_062));
    let rekeys = sends(&out)
        .iter()
        .filter(|d| c.peer.open(d).0.exchange_type == exchange::CREATE_CHILD_SA)
        .count();
    assert_eq!(rekeys, 1);
}

/// Collision de rekeys CHILD : `a_loses` = notre SA (A) porte le plus petit nonce.
fn collision(a_loses: bool) {
    let mut c = established();
    // A : rekey du client, en vol.
    let s = sends(&c.ini.handle_timeout(c.t0 + secs(26_000)));
    let (ha, pa, _) = c.peer.open(&s[0]);
    let ni_a = find_nonce_t(&pa);
    let spi_cl_a = spi_of_req(&pa);
    // B : rekey de la passerelle, simultané.
    let (lo, hi) = (vec![0x00u8; 32], vec![0xFFu8; 32]);
    let (ni_b, nr_a) = if a_loses { (hi, lo) } else { (lo, hi) };
    let gw_spi_b = 0x4242_0003u32;
    let req_b = gw_child_rekey(&mut c, &ni_b, gw_spi_b, SPI_CHILD_R);
    let out = c.ini.handle_datagram(c.t0 + secs(26_001), &req_b);
    assert!(
        events(&out).is_empty(),
        "SA du pair retenue jusqu'à la résolution"
    );
    let (_, pb, _) = c.peer.open(&sends(&out)[0]);
    let nr_b = find_nonce_t(&pb);
    let spi_cl_b = spi_of_req(&pb);
    // Réponse de la passerelle à A.
    let kp = dh();
    let gw_spi_a = 0x4242_0004u32;
    let mut resp = vec![
        Payload::Sa(vec![esp_prop(gw_spi_a)]),
        Payload::Nonce(nr_a.clone()),
        Payload::Ke {
            group: 14,
            data: kp.public().to_vec(),
        },
    ];
    resp.extend(tsany());
    let r = c.peer.respond(&ha, false, &resp);
    let out = c.ini.handle_datagram(c.t0 + secs(26_002), &r);
    let evs = events(&out);
    let [Event::ChildRekeyed { keys, old_spi }] = evs.as_slice() else {
        panic!("un seul ChildRekeyed attendu : {evs:?}");
    };
    assert_eq!(*old_spi, c.keys.spi_in);
    let s = sends(&out);
    assert_eq!(s.len(), 1);
    let (_, dp, _) = c.peer.open(&s[0]);
    let _ = (ni_a, nr_b);
    if a_loses {
        // B gagne ; A (SPI client spi_cl_a) est supprimée par nous.
        assert_eq!((keys.spi_out, keys.spi_in), (gw_spi_b, spi_cl_b));
        assert!(is_delete_esp(&dp, spi_cl_a));
    } else {
        // A gagne ; nous supprimons l'ancienne SA ; la passerelle supprimera B.
        assert_eq!((keys.spi_out, keys.spi_in), (gw_spi_a, spi_cl_a));
        assert!(is_delete_esp(&dp, c.keys.spi_in));
    }
}

#[test]
fn child_rekey_collision_lowest_nonce_ours_is_deleted() {
    collision(true);
}

#[test]
fn child_rekey_collision_lowest_nonce_peers_is_deleted() {
    collision(false);
}

// ---------- rekey IKE ----------

fn ike_prop(spi: [u8; 8]) -> Proposal {
    Proposal {
        number: 1,
        protocol: 1,
        spi: spi.to_vec(),
        transforms: vec![
            Transform {
                ty: 1,
                id: 12,
                key_len: Some(128),
            },
            Transform {
                ty: 2,
                id: 5,
                key_len: None,
            },
            Transform {
                ty: 3,
                id: 12,
                key_len: None,
            },
            Transform {
                ty: 4,
                id: 14,
                key_len: None,
            },
        ],
    }
}

/// Vérifie qu'un DPD de la passerelle sur la nouvelle SA est répondu.
fn dpd_on_cur(c: &mut Ctx, now: Instant) {
    let req = c.peer.request(false, exchange::INFORMATIONAL, &[]);
    let s = sends(&c.ini.handle_datagram(now, &req));
    assert_eq!(s.len(), 1, "DPD répondu sur la nouvelle IKE SA");
    let (h, p, old) = c.peer.open(&s[0]);
    assert!(p.is_empty() && !old);
    assert_ne!(h.flags & flags::RESPONSE, 0);
}

#[test]
fn ike_rekey_initiated_by_client() {
    let mut cfg = cfg();
    cfg.lifetimes.ike_soft = secs(1_000);
    cfg.lifetimes.ike_hard = secs(2_000);
    let mut c = established_with(cfg);
    let s = sends(&c.ini.handle_timeout(c.t0 + secs(1_001)));
    assert_eq!(s.len(), 1);
    let (h, p, _) = c.peer.open(&s[0]);
    assert_eq!(h.exchange_type, exchange::CREATE_CHILD_SA);
    let Some(Payload::Sa(props)) = p.iter().find(|x| matches!(x, Payload::Sa(_))) else {
        panic!("SA attendue")
    };
    assert!(props.iter().all(|p| p.protocol == 1 && p.spi.len() == 8));
    let spi_i_new: [u8; 8] = props[0].spi[..].try_into().unwrap();
    let ni = find_nonce_t(&p);
    let (_, kd) = find_ke_t(&p);
    let kp = dh();
    let shared = kp.shared_secret(&kd).unwrap();
    let (spi_r_new, nr) = ([0xB1u8; 8], vec![0x99u8; 32]);
    let keys = derive_sk_keys_rekey(
        &c.peer.cur.suite,
        &c.peer.cur.keys.sk_d,
        &ni,
        &nr,
        &spi_i_new,
        &spi_r_new,
        &shared,
    )
    .unwrap();
    let r = c.peer.respond(
        &h,
        false,
        &[
            Payload::Sa(vec![ike_prop(spi_r_new)]),
            Payload::Nonce(nr),
            Payload::Ke {
                group: 14,
                data: kp.public().to_vec(),
            },
        ],
    );
    let out = c.ini.handle_datagram(c.t0 + secs(1_002), &r);
    assert!(events(&out).is_empty());
    // Bascule côté passerelle : nouvelle SA = client initiateur.
    let suite = c.peer.cur.suite;
    let prev = core::mem::replace(
        &mut c.peer.cur,
        PSa {
            suite,
            keys,
            spi_i: spi_i_new,
            spi_r: spi_r_new,
            gw_init: false,
            next_mid: 0,
        },
    );
    c.peer.old = Some(prev);
    // Delete(IKE) sur l'ancienne SA.
    let s = sends(&out);
    assert_eq!(s.len(), 1);
    let (dh_, dp, old) = c.peer.open(&s[0]);
    assert!(old && dp.iter().filter_map(parse_delete).any(|(p, _)| p == 1));
    let ack = c.peer.respond(&dh_, true, &[]);
    assert!(c.ini.handle_datagram(c.t0 + secs(1_003), &ack).is_empty());
    let t = c.t0 + secs(1_004);
    dpd_on_cur(&mut c, t);
    // Le client peut aussi émettre un DPD sur la nouvelle SA (MID 0).
    let s = sends(&c.ini.handle_timeout(c.t0 + secs(1_100)));
    let (h, p, old) = c.peer.open(&s[0]);
    assert!(p.is_empty() && !old);
    assert_eq!(h.message_id, 0);
}

fn established_with(cfg: IkeConfig) -> Ctx {
    let mut ini = IkeInitiator::new(cfg, det_rng()).unwrap();
    let mut resp = Responder::new(Quirk::None);
    let t0 = Instant::now();
    let mut r = run(&mut ini, &mut resp);
    let Some(Event::Established { child_sa_keys, .. }) = r.events.pop() else {
        panic!("Established attendu");
    };
    let suite = resp.suite.unwrap();
    let esp = EspProposal {
        encr: child_sa_keys.encr,
        integ: child_sa_keys.integ,
    };
    Ctx {
        ini,
        peer: Peer {
            cur: PSa {
                suite,
                keys: resp.keys.take().unwrap(),
                spi_i: resp.spi_i,
                spi_r: SPI_R,
                gw_init: false,
                next_mid: 0,
            },
            old: None,
            gcm: 1000,
            esp,
        },
        keys: *child_sa_keys,
        t0,
        spi_gw_in: SPI_CHILD_R,
    }
}

#[test]
fn ike_rekey_initiated_by_gateway_then_roles_swapped() {
    let mut c = established();
    let (spi_i_new, ni) = ([0xC1u8; 8], vec![0x31u8; 32]);
    let kp = dh();
    let req = c.peer.request(
        false,
        exchange::CREATE_CHILD_SA,
        &[
            Payload::Sa(vec![ike_prop(spi_i_new)]),
            Payload::Nonce(ni.clone()),
            Payload::Ke {
                group: 14,
                data: kp.public().to_vec(),
            },
        ],
    );
    let out = c.ini.handle_datagram(c.t0 + secs(50), &req);
    assert!(events(&out).is_empty());
    let (h, p, _) = c.peer.open(&sends(&out)[0]);
    assert_ne!(h.flags & flags::RESPONSE, 0);
    let spi_r_new: [u8; 8] = match p.iter().find(|x| matches!(x, Payload::Sa(_))) {
        Some(Payload::Sa(v)) => v[0].spi[..].try_into().unwrap(),
        _ => panic!("SA attendue"),
    };
    let nr = find_nonce_t(&p);
    let (_, kd) = find_ke_t(&p);
    let shared = kp.shared_secret(&kd).unwrap();
    let keys = derive_sk_keys_rekey(
        &c.peer.cur.suite,
        &c.peer.cur.keys.sk_d,
        &ni,
        &nr,
        &spi_i_new,
        &spi_r_new,
        &shared,
    )
    .unwrap();
    let suite = c.peer.cur.suite;
    let prev = core::mem::replace(
        &mut c.peer.cur,
        PSa {
            suite,
            keys,
            spi_i: spi_i_new,
            spi_r: spi_r_new,
            gw_init: true,
            next_mid: 0,
        },
    );
    c.peer.old = Some(prev);
    // La passerelle supprime l'ancienne SA IKE : pas de fermeture.
    let del = c
        .peer
        .request(true, exchange::INFORMATIONAL, &[delete_payload(1, &[])]);
    let out = c.ini.handle_datagram(c.t0 + secs(51), &del);
    assert!(events(&out).is_empty(), "{:?}", events(&out));
    let (h, _, old) = c.peer.open(&sends(&out)[0]);
    assert!(old && h.flags & flags::RESPONSE != 0);
    // Nouvelle SA : le client y est répondeur ; DPD aller/retour, puis Delete(IKE) => Closed.
    let req = c.peer.request(false, exchange::INFORMATIONAL, &[]);
    let s = sends(&c.ini.handle_datagram(c.t0 + secs(52), &req));
    let (h, p, old) = c.peer.open(&s[0]);
    assert!(p.is_empty() && !old && h.message_id == 0);
    let s = sends(&c.ini.handle_timeout(c.t0 + secs(90)));
    let (h, _, _) = c.peer.open(&s[0]);
    assert_eq!(h.message_id, 0, "MID de nos requêtes repart à 0");
    let req = c
        .peer
        .request(false, exchange::INFORMATIONAL, &[delete_payload(1, &[])]);
    let out = c.ini.handle_datagram(c.t0 + secs(91), &req);
    assert!(matches!(
        events(&out).as_slice(),
        [Event::Closed(CloseReason::PeerDeletedIke)]
    ));
}

#[test]
fn ike_rekey_collision_answers_temporary_failure() {
    let mut cfg = cfg();
    cfg.lifetimes.ike_soft = secs(1_000);
    cfg.lifetimes.ike_hard = secs(2_000);
    let mut c = established_with(cfg);
    let s = sends(&c.ini.handle_timeout(c.t0 + secs(1_001)));
    let (ha, _, _) = c.peer.open(&s[0]);
    assert_eq!(ha.exchange_type, exchange::CREATE_CHILD_SA);
    let req = c.peer.request(
        false,
        exchange::CREATE_CHILD_SA,
        &[
            Payload::Sa(vec![ike_prop([0xD1; 8])]),
            Payload::Nonce(vec![1u8; 32]),
            Payload::Ke {
                group: 14,
                data: dh().public().to_vec(),
            },
        ],
    );
    let out = c.ini.handle_datagram(c.t0 + secs(1_002), &req);
    let (_, p, _) = c.peer.open(&sends(&out)[0]);
    assert!(matches!(
        p.as_slice(),
        [Payload::Notify(n)] if n.ty == notify::TEMPORARY_FAILURE
    ));
}
