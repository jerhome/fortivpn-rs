//! Phase « Established » de l'initiateur : INFORMATIONAL (DPD, Delete), CREATE_CHILD_SA
//! (rekey de la CHILD SA et de l'IKE SA, des deux côtés), durées de vie, fermeture.
//!
//! Sans I/O : mêmes entrées/sorties que le reste de [`IkeInitiator`]. Une seule requête de notre
//! part est en vol à la fois ([`Todo`] file les suivantes) ; les requêtes du pair sont traitées
//! dans l'ordre des Message IDs, la dernière réponse est mise en cache pour ses retransmissions.
//!
//! Collisions (RFC 7296 §2.8.1) : deux rekeys CHILD simultanés produisent deux SA ; celle dont le
//! plus petit nonce (parmi les quatre) est le plus bas est supprimée par son initiateur. Deux
//! rekeys IKE simultanés : on répond TEMPORARY_FAILURE à la requête du pair (le sien réessaiera).

use std::collections::VecDeque;

use super::{
    CloseReason, DhGroup, Duration, EspProposal, Event, FailReason, IkeConfig, IkeInitiator,
    IkeSuite, Instant, NATT_PORT, Output, Payload, Pending, Proposal, TrafficSelector, backoff,
    derive_child_keys_ex, derive_sk_keys_rekey, encr_transform, error_notify, integ_id,
    parse_chosen, proto,
};
use crate::crypto::{DhKeypair, Encr, Integ};
use crate::sk;
use crate::wire::{Header, Notify, delete_payload, exchange, flags, notify, parse_delete};
use crate::{ike::ChildSaKeys, ike::Phase};

/// IKE SA (courante ou en fin de vie après rekey).
pub(super) struct IkeSa {
    suite: IkeSuite,
    keys: crate::crypto::SkKeys,
    spi_i: [u8; 8],
    spi_r: [u8; 8],
    /// Nous sommes l'initiateur d'origine de cette IKE SA (flag Initiator, clés SK_*i/r).
    we_init: bool,
    /// Prochain Message ID de nos requêtes.
    next_mid: u32,
    /// Prochain Message ID attendu du pair.
    peer_mid: u32,
    last_resp: Option<(u32, Vec<u8>)>,
}

impl IkeSa {
    pub(super) fn new(
        suite: IkeSuite,
        keys: crate::crypto::SkKeys,
        spi_i: [u8; 8],
        spi_r: [u8; 8],
        we_init: bool,
        next_mid: u32,
    ) -> Self {
        Self {
            suite,
            keys,
            spi_i,
            spi_r,
            we_init,
            next_mid,
            peer_mid: 0,
            last_resp: None,
        }
    }

    fn matches(&self, h: &Header) -> bool {
        h.spi_i == self.spi_i && h.spi_r == self.spi_r
    }
}

pub(super) struct ChildInfo {
    pub(super) spi_in: u32,
    pub(super) spi_out: u32,
}

pub(super) struct ChildRekey {
    dh: DhKeypair,
    ni: Vec<u8>,
    new_spi: u32,
}

pub(super) struct IkeRekey {
    dh: DhKeypair,
    ni: Vec<u8>,
    new_spi: [u8; 8],
}

/// Nature de la requête en vol.
pub(super) enum ReqKind {
    Handshake,
    Dpd,
    RekeyChild(ChildRekey),
    RekeyIke(IkeRekey),
    DeleteChild,
    DeleteOldIke,
}

/// Requête à émettre dès que la fenêtre est libre.
#[derive(Clone, Copy)]
enum Todo {
    Dpd,
    RekeyChild,
    RekeyIke,
    DeleteChild(u32),
    DeleteOldIke,
}

/// CHILD SA négociée à l'initiative du pair, retenue le temps de résoudre une collision.
struct Held {
    keys: Box<ChildSaKeys>,
    min_nonce: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Which {
    Cur,
    Old,
}

pub(super) struct Est {
    cur: IkeSa,
    /// Ancienne IKE SA (après rekey), en attente de son Delete.
    old: Option<IkeSa>,
    old_ike_until: Option<Instant>,
    child: ChildInfo,
    /// (SPI entrant, SPI sortant, fin de fenêtre) de la CHILD SA précédente.
    old_child: Option<(u32, u32, Instant)>,
    group: DhGroup,
    ts_local: Vec<TrafficSelector>,
    ts_remote: Vec<TrafficSelector>,
    last_rx: Instant,
    ike_soft_at: Instant,
    ike_hard_at: Instant,
    child_soft_at: Instant,
    child_hard_at: Instant,
    todo: VecDeque<Todo>,
    held: Option<Held>,
}

impl Est {
    pub(super) fn new(
        now: Instant,
        cfg: &IkeConfig,
        cur: IkeSa,
        child: ChildInfo,
        group: DhGroup,
        ts: (Vec<TrafficSelector>, Vec<TrafficSelector>),
    ) -> Self {
        let lt = cfg.lifetimes;
        Self {
            cur,
            old: None,
            old_ike_until: None,
            child,
            old_child: None,
            group,
            ts_local: ts.0,
            ts_remote: ts.1,
            last_rx: now,
            ike_soft_at: now + lt.ike_soft,
            ike_hard_at: now + lt.ike_hard,
            child_soft_at: now + lt.child_soft,
            child_hard_at: now + lt.child_hard,
            todo: VecDeque::new(),
            held: None,
        }
    }

    fn which(&self, h: &Header) -> Option<Which> {
        if self.cur.matches(h) {
            Some(Which::Cur)
        } else if self.old.as_ref().is_some_and(|o| o.matches(h)) {
            Some(Which::Old)
        } else {
            None
        }
    }

    fn sa(&self, w: Which) -> Option<&IkeSa> {
        match w {
            Which::Cur => Some(&self.cur),
            Which::Old => self.old.as_ref(),
        }
    }

    fn sa_mut(&mut self, w: Which) -> Option<&mut IkeSa> {
        match w {
            Which::Cur => Some(&mut self.cur),
            Which::Old => self.old.as_mut(),
        }
    }
}

/// Réponse à une requête du pair, appliquée après son envoi.
#[derive(Default)]
struct Reply {
    payloads: Vec<Payload>,
    new_ike: Option<IkeSa>,
    close: Option<CloseReason>,
    drop_old: bool,
    events: Vec<Output>,
}

impl Reply {
    fn error(ty: u16, data: Vec<u8>) -> Self {
        Self {
            payloads: vec![Payload::Notify(Notify::new(ty, data))],
            ..Self::default()
        }
    }
}

fn min_nonce(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.min(b).to_vec()
}

fn find_nonce(p: &[Payload]) -> Option<&Vec<u8>> {
    p.iter().find_map(|x| match x {
        Payload::Nonce(n) => Some(n),
        _ => None,
    })
}

fn find_ke(p: &[Payload]) -> Option<(u16, &Vec<u8>)> {
    p.iter().find_map(|x| match x {
        Payload::Ke { group, data } => Some((*group, data)),
        _ => None,
    })
}

fn find_sa(p: &[Payload]) -> Option<&Vec<Proposal>> {
    p.iter().find_map(|x| match x {
        Payload::Sa(v) => Some(v),
        _ => None,
    })
}

fn find_ts(p: &[Payload], responder: bool) -> Option<&Vec<TrafficSelector>> {
    p.iter().find_map(|x| match x {
        Payload::Ts {
            responder: r,
            selectors,
        } if *r == responder => Some(selectors),
        _ => None,
    })
}

fn has_t(p: &Proposal, ty: u8, id: u16) -> bool {
    p.transforms.iter().any(|t| t.ty == ty && t.id == id)
}

fn has_encr(p: &Proposal, e: Encr) -> bool {
    p.transforms
        .iter()
        .any(|t| t.ty == 1 && Encr::from_id(t.id, t.key_len.unwrap_or(0)).ok() == Some(e))
}

fn has_integ(p: &Proposal, i: Option<Integ>) -> bool {
    match i {
        Some(i) => p
            .transforms
            .iter()
            .any(|t| t.ty == 3 && Integ::from_id(t.id).ok() == Some(i)),
        None => !p.transforms.iter().any(|t| t.ty == 3),
    }
}

/// Compatibilité DH : `Some(g)` exige le transform g ; `None` exige l'absence de DH (ou NONE).
fn dh_ok(p: &Proposal, ke: Option<u16>) -> bool {
    match ke {
        Some(g) => has_t(p, 4, g),
        None => !p.transforms.iter().any(|t| t.ty == 4 && t.id != 0),
    }
}

fn esn_ok(p: &Proposal) -> bool {
    !p.transforms.iter().any(|t| t.ty == 5) || has_t(p, 5, 0)
}

fn spi4(p: &Proposal) -> Option<u32> {
    <[u8; 4]>::try_from(p.spi.as_slice())
        .ok()
        .map(u32::from_be_bytes)
}

impl IkeInitiator {
    /// À appeler à chaque paquet ESP authentique reçu : repousse l'émission d'un DPD.
    pub fn note_inbound_traffic(&mut self, now: Instant) {
        if let Some(e) = self.est.as_mut() {
            e.last_rx = now;
        }
    }

    /// Fermeture locale : INFORMATIONAL Delete(IKE) (une seule émission, sans attente) puis
    /// [`Event::Closed`].
    pub fn close(&mut self) -> Vec<Output> {
        let mut out = Vec::new();
        if self.phase != Phase::Established {
            return out;
        }
        let sent = (|| {
            let est = self.est.as_mut()?;
            let mid = est.cur.next_mid;
            est.cur.next_mid += 1;
            Some(mid)
        })();
        if let Some(mid) = sent
            && let Ok(data) = self.seal_est(
                Which::Cur,
                false,
                exchange::INFORMATIONAL,
                mid,
                &[delete_payload(1, &[])],
            )
        {
            out.push(Output::Send {
                port: NATT_PORT,
                data,
            });
        }
        self.phase = Phase::Closed;
        self.pending = None;
        self.est = None;
        out.push(Output::Event(Event::Closed(CloseReason::Local)));
        out
    }

    // ---------- échéances ----------

    pub(super) fn est_deadline(&self) -> Option<Instant> {
        let e = self.est.as_ref()?;
        let mut v = vec![
            e.child_soft_at,
            e.child_hard_at,
            e.ike_soft_at,
            e.ike_hard_at,
        ];
        if self.pending.is_none() {
            v.push(e.last_rx + self.cfg.dpd_idle);
        }
        v.extend(e.old_child.map(|c| c.2));
        v.extend(e.old_ike_until);
        v.into_iter().min()
    }

    pub(super) fn est_timeout(&mut self, now: Instant, out: &mut Vec<Output>) {
        let (max, base) = (self.cfg.max_sends, self.cfg.retransmit_base);
        if let Some(p) = self.pending.as_mut()
            && now >= p.deadline
        {
            if p.sends >= max {
                let del_old = matches!(p.kind, ReqKind::DeleteOldIke);
                self.pending = None;
                if del_old {
                    if let Some(e) = self.est.as_mut() {
                        e.old = None;
                    }
                } else {
                    self.fail(FailReason::DeadPeer, out);
                    return;
                }
            } else {
                p.sends += 1;
                p.deadline = now + backoff(base, p.sends);
                out.push(Output::Send {
                    port: p.port,
                    data: p.data.clone(),
                });
            }
        }
        let (retry, idle) = (self.cfg.rekey_retry, self.cfg.dpd_idle);
        let rekey_ike_busy = self.busy_with(|k| matches!(k, ReqKind::RekeyIke(_)));
        let rekey_child_busy = self.busy_with(|k| matches!(k, ReqKind::RekeyChild(_)));
        let pending_none = self.pending.is_none();
        let Some(e) = self.est.as_mut() else { return };
        if now >= e.child_hard_at || now >= e.ike_hard_at {
            self.fail(FailReason::Expired, out);
            return;
        }
        if let Some((spi, _, t)) = e.old_child
            && now >= t
        {
            e.old_child = None;
            out.push(Output::Event(Event::OldChildExpired { spi }));
        }
        if e.old_ike_until.is_some_and(|t| now >= t) {
            e.old = None;
            e.old_ike_until = None;
        }
        if now >= e.ike_soft_at {
            if !rekey_ike_busy && !e.todo.iter().any(|t| matches!(t, Todo::RekeyIke)) {
                e.todo.push_back(Todo::RekeyIke);
            }
            e.ike_soft_at = now + retry;
        }
        if now >= e.child_soft_at {
            if !rekey_child_busy && !e.todo.iter().any(|t| matches!(t, Todo::RekeyChild)) {
                e.todo.push_back(Todo::RekeyChild);
            }
            e.child_soft_at = now + retry;
        }
        if pending_none && e.todo.is_empty() && now >= e.last_rx + idle {
            e.todo.push_back(Todo::Dpd);
        }
        self.pump(now, out);
    }

    fn busy_with(&self, f: impl Fn(&ReqKind) -> bool) -> bool {
        self.pending.as_ref().is_some_and(|p| f(&p.kind))
    }

    fn pump(&mut self, now: Instant, out: &mut Vec<Output>) {
        while self.pending.is_none() {
            let Some(t) = self.est.as_mut().and_then(|e| e.todo.pop_front()) else {
                break;
            };
            if let Err(r) = self.start_todo(now, t, out) {
                self.fail(r, out);
                return;
            }
        }
    }

    fn rand_spi32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        loop {
            self.rng.fill(&mut b);
            let v = u32::from_be_bytes(b);
            if v > 255 {
                return v;
            }
        }
    }

    fn rand_spi64(&mut self) -> [u8; 8] {
        let mut b = [0u8; 8];
        loop {
            self.rng.fill(&mut b);
            if b != [0; 8] {
                return b;
            }
        }
    }

    fn start_todo(
        &mut self,
        now: Instant,
        t: Todo,
        out: &mut Vec<Output>,
    ) -> Result<(), FailReason> {
        let Some(e) = self.est.as_ref() else {
            return Ok(());
        };
        let (group, spi_in) = (e.group, e.child.spi_in);
        let (tsl, tsr) = (e.ts_local.clone(), e.ts_remote.clone());
        let has_old = e.old.is_some();
        match t {
            Todo::Dpd => self.send_req(now, Which::Cur, ReqKind::Dpd, &[], out),
            Todo::DeleteChild(spi) => self.send_req(
                now,
                Which::Cur,
                ReqKind::DeleteChild,
                &[delete_payload(3, &[spi])],
                out,
            ),
            Todo::DeleteOldIke if has_old => self.send_req(
                now,
                Which::Old,
                ReqKind::DeleteOldIke,
                &[delete_payload(1, &[])],
                out,
            ),
            Todo::DeleteOldIke => Ok(()),
            Todo::RekeyChild => {
                let new_spi = self.rand_spi32();
                let mut ni = vec![0u8; 32];
                self.rng.fill(&mut ni);
                let dh = self.new_keypair(group)?;
                let inner = [
                    Payload::Notify(Notify {
                        protocol: 3,
                        spi: spi_in.to_be_bytes().to_vec(),
                        ty: notify::REKEY_SA,
                        data: Vec::new(),
                    }),
                    Payload::Sa(self.esp_proposals(new_spi)),
                    Payload::Nonce(ni.clone()),
                    Payload::Ke {
                        group: group.id(),
                        data: dh.public().to_vec(),
                    },
                    Payload::Ts {
                        responder: false,
                        selectors: tsl,
                    },
                    Payload::Ts {
                        responder: true,
                        selectors: tsr,
                    },
                ];
                self.send_req(
                    now,
                    Which::Cur,
                    ReqKind::RekeyChild(ChildRekey { dh, ni, new_spi }),
                    &inner,
                    out,
                )
            }
            Todo::RekeyIke => {
                let new_spi = self.rand_spi64();
                let mut ni = vec![0u8; 32];
                self.rng.fill(&mut ni);
                let dh = self.new_keypair(group)?;
                let mut props = self.ike_proposals();
                for p in &mut props {
                    p.spi = new_spi.to_vec();
                }
                let inner = [
                    Payload::Sa(props),
                    Payload::Nonce(ni.clone()),
                    Payload::Ke {
                        group: group.id(),
                        data: dh.public().to_vec(),
                    },
                ];
                self.send_req(
                    now,
                    Which::Cur,
                    ReqKind::RekeyIke(IkeRekey { dh, ni, new_spi }),
                    &inner,
                    out,
                )
            }
        }
    }

    fn seal_est(
        &mut self,
        which: Which,
        response: bool,
        exch: u8,
        mid: u32,
        inner: &[Payload],
    ) -> Result<Vec<u8>, FailReason> {
        let est = self.est.as_ref().ok_or_else(|| proto("pas d'état"))?;
        let sa = est.sa(which).ok_or_else(|| proto("IKE SA absente"))?;
        let iv = if sa.suite.encr.is_aead() {
            self.gcm_counter += 1;
            self.gcm_counter.to_be_bytes().to_vec()
        } else {
            let mut v = vec![0u8; 16];
            self.rng.fill(&mut v);
            v
        };
        let header = Header {
            spi_i: sa.spi_i,
            spi_r: sa.spi_r,
            next_payload: 0,
            exchange_type: exch,
            flags: (if sa.we_init { flags::INITIATOR } else { 0 })
                | (if response { flags::RESPONSE } else { 0 }),
            message_id: mid,
            length: 0,
        };
        let msg = sk::seal(&sa.suite, &sa.keys, sa.we_init, &header, inner, &iv)?;
        let mut data = vec![0u8; 4];
        data.extend_from_slice(&msg);
        Ok(data)
    }

    fn send_req(
        &mut self,
        now: Instant,
        which: Which,
        kind: ReqKind,
        inner: &[Payload],
        out: &mut Vec<Output>,
    ) -> Result<(), FailReason> {
        let (mid, spis) = {
            let sa = self
                .est
                .as_mut()
                .and_then(|e| e.sa_mut(which))
                .ok_or_else(|| proto("IKE SA absente"))?;
            let m = sa.next_mid;
            sa.next_mid += 1;
            (m, (sa.spi_i, sa.spi_r))
        };
        let exch = if matches!(kind, ReqKind::RekeyChild(_) | ReqKind::RekeyIke(_)) {
            exchange::CREATE_CHILD_SA
        } else {
            exchange::INFORMATIONAL
        };
        let data = self.seal_est(which, false, exch, mid, inner)?;
        self.arm(now, NATT_PORT, mid, data, out);
        if let Some(p) = self.pending.as_mut() {
            p.kind = kind;
            p.spis = spis;
        }
        Ok(())
    }

    // ---------- réception ----------

    pub(super) fn est_datagram(&mut self, now: Instant, raw: &[u8], out: &mut Vec<Output>) {
        let Ok(h) = Header::parse(raw) else { return };
        let Some(which) = self.est.as_ref().and_then(|e| e.which(&h)) else {
            return;
        };
        if h.flags & flags::RESPONSE != 0 {
            self.on_response(now, &h, raw, which, out);
        } else {
            self.on_request(now, &h, raw, which, out);
        }
        self.pump(now, out);
    }

    fn open_from_peer(&self, which: Which, h: &Header, raw: &[u8]) -> Option<Vec<Payload>> {
        let sa = self.est.as_ref()?.sa(which)?;
        // Flag Initiator du message = rôle de l'émetteur (le pair) dans cette IKE SA.
        if (h.flags & flags::INITIATOR != 0) == sa.we_init {
            return None;
        }
        sk::open(&sa.suite, &sa.keys, !sa.we_init, raw)
            .ok()
            .map(|(_, p)| p)
    }

    fn on_response(
        &mut self,
        now: Instant,
        h: &Header,
        raw: &[u8],
        which: Which,
        out: &mut Vec<Output>,
    ) {
        let ok = self
            .pending
            .as_ref()
            .is_some_and(|p| p.mid == h.message_id && p.spis == (h.spi_i, h.spi_r));
        if !ok {
            return;
        }
        let Some(payloads) = self.open_from_peer(which, h, raw) else {
            return;
        };
        let Some(Pending { kind, .. }) = self.pending.take() else {
            return;
        };
        let retry = self.cfg.rekey_retry;
        let Some(e) = self.est.as_mut() else { return };
        e.last_rx = now;
        match kind {
            ReqKind::Handshake | ReqKind::Dpd | ReqKind::DeleteChild => {}
            ReqKind::DeleteOldIke => {
                e.old = None;
                e.old_ike_until = None;
            }
            ReqKind::RekeyChild(rk) => {
                if self.child_rekey_done(now, &rk, &payloads, out).is_err()
                    && let Some(e) = self.est.as_mut()
                {
                    // Refus ou réponse invalide : on retentera plus tard (pas d'échec fatal).
                    e.child_soft_at = now + retry;
                    if let Some(h) = e.held.take() {
                        // La SA du pair, retenue pour la collision, devient la SA courante.
                        let mut ev = Vec::new();
                        Self::finish_rekey(e, now, h.keys, self.cfg.rekey_overlap, &mut ev);
                        out.extend(ev);
                    }
                }
            }
            ReqKind::RekeyIke(rk) => {
                if self.ike_rekey_done(now, &rk, &payloads).is_err()
                    && let Some(e) = self.est.as_mut()
                {
                    e.ike_soft_at = now + retry;
                }
            }
        }
    }

    fn child_rekey_done(
        &mut self,
        now: Instant,
        rk: &ChildRekey,
        payloads: &[Payload],
        out: &mut Vec<Output>,
    ) -> Result<(), FailReason> {
        if error_notify(payloads).is_some() {
            return Err(proto("rekey CHILD refusé"));
        }
        let (Some(props), Some(nr)) = (find_sa(payloads), find_nonce(payloads)) else {
            return Err(proto("rekey CHILD : SA/Nonce manquant"));
        };
        let [prop] = props.as_slice() else {
            return Err(proto("rekey CHILD : une proposition attendue"));
        };
        let spi_out = spi4(prop).filter(|_| prop.protocol == 3);
        let spi_out = spi_out.ok_or_else(|| proto("rekey CHILD : proposition ESP invalide"))?;
        let ch = parse_chosen(prop, 3)?;
        let esp = EspProposal {
            encr: ch.encr,
            integ: ch.integ,
        };
        if !self.cfg.esp_proposals.contains(&esp) {
            return Err(proto("rekey CHILD : transforms non proposés"));
        }
        let shared = if let Some(g) = ch.dh {
            let Some((kg, kd)) = find_ke(payloads) else {
                return Err(proto("rekey CHILD : KE manquant"));
            };
            if g != rk.dh.group() || kg != g.id() {
                return Err(proto("rekey CHILD : groupe KE inattendu"));
            }
            Some(rk.dh.shared_secret(kd)?)
        } else {
            // PFS proposé par nous : une réponse sans DH est un downgrade.
            return Err(proto("rekey CHILD : PFS exigé (DH absent de la réponse)"));
        };
        let overlap = self.cfg.rekey_overlap;
        let e = self.est.as_mut().ok_or_else(|| proto("pas d'état"))?;
        let keys = derive_child_keys_ex(
            e.cur.suite.prf,
            &e.cur.keys.sk_d,
            shared.as_ref().map(|s| &s[..]),
            &rk.ni,
            nr,
            esp,
            rk.new_spi,
            spi_out,
            true,
        )?;
        let min_a = min_nonce(&rk.ni, nr);
        let mut ev = Vec::new();
        match e.held.take() {
            Some(h) if min_a < h.min_nonce => {
                // Notre SA (A) porte le plus petit nonce : nous la supprimons, la SA du pair gagne.
                e.todo.push_back(Todo::DeleteChild(rk.new_spi));
                Self::finish_rekey(e, now, h.keys, overlap, &mut ev);
            }
            _ => {
                let old = Self::finish_rekey(e, now, Box::new(keys), overlap, &mut ev);
                e.todo.push_back(Todo::DeleteChild(old));
            }
        }
        let lt = self.cfg.lifetimes;
        if let Some(e) = self.est.as_mut() {
            e.child_soft_at = now + lt.child_soft;
            e.child_hard_at = now + lt.child_hard;
        }
        out.extend(ev);
        Ok(())
    }

    /// Installe la nouvelle CHILD SA ; renvoie l'ancien SPI entrant.
    fn finish_rekey(
        e: &mut Est,
        now: Instant,
        keys: Box<ChildSaKeys>,
        overlap: Duration,
        out: &mut Vec<Output>,
    ) -> u32 {
        let old = e.child.spi_in;
        e.old_child = Some((old, e.child.spi_out, now + overlap));
        e.child.spi_in = keys.spi_in;
        e.child.spi_out = keys.spi_out;
        e.todo.retain(|t| !matches!(t, Todo::RekeyChild));
        out.push(Output::Event(Event::ChildRekeyed { keys, old_spi: old }));
        old
    }

    fn ike_rekey_done(
        &mut self,
        now: Instant,
        rk: &IkeRekey,
        payloads: &[Payload],
    ) -> Result<(), FailReason> {
        if error_notify(payloads).is_some() {
            return Err(proto("rekey IKE refusé"));
        }
        let (Some(props), Some(nr), Some((kg, kd))) =
            (find_sa(payloads), find_nonce(payloads), find_ke(payloads))
        else {
            return Err(proto("rekey IKE : SA/Nonce/KE manquant"));
        };
        let [prop] = props.as_slice() else {
            return Err(proto("rekey IKE : une proposition attendue"));
        };
        let spi_r = <[u8; 8]>::try_from(prop.spi.as_slice())
            .map_err(|_| proto("rekey IKE : SPI de 8 octets attendu"))?;
        let ch = parse_chosen(prop, 1)?;
        let (Some(prf), Some(g)) = (ch.prf, ch.dh) else {
            return Err(proto("rekey IKE : PRF/KE manquant"));
        };
        let suite = IkeSuite::new(ch.encr, prf, ch.integ)?;
        if !self.cfg.ike_suites.contains(&suite) || g != rk.dh.group() || kg != g.id() {
            return Err(proto("rekey IKE : proposition inattendue"));
        }
        let shared = rk.dh.shared_secret(kd)?;
        let lt = self.cfg.lifetimes;
        let overlap = self.cfg.rekey_overlap;
        let e = self.est.as_mut().ok_or_else(|| proto("pas d'état"))?;
        let keys = derive_sk_keys_rekey(
            &suite,
            &e.cur.keys.sk_d,
            &rk.ni,
            nr,
            &rk.new_spi,
            &spi_r,
            &shared,
        )?;
        let new = IkeSa::new(suite, keys, rk.new_spi, spi_r, true, 0);
        e.old = Some(core::mem::replace(&mut e.cur, new));
        e.old_ike_until = Some(now + overlap * 3);
        e.ike_soft_at = now + lt.ike_soft;
        e.ike_hard_at = now + lt.ike_hard;
        e.todo.push_front(Todo::DeleteOldIke);
        Ok(())
    }

    fn on_request(
        &mut self,
        now: Instant,
        h: &Header,
        raw: &[u8],
        which: Which,
        out: &mut Vec<Output>,
    ) {
        {
            let Some(sa) = self.est.as_ref().and_then(|e| e.sa(which)) else {
                return;
            };
            if h.message_id.wrapping_add(1) == sa.peer_mid {
                // Retransmission d'une requête déjà traitée : renvoyer la réponse en cache.
                if let Some((m, d)) = &sa.last_resp
                    && *m == h.message_id
                {
                    out.push(Output::Send {
                        port: NATT_PORT,
                        data: d.clone(),
                    });
                }
                return;
            }
            if h.message_id != sa.peer_mid {
                return;
            }
        }
        let Some(payloads) = self.open_from_peer(which, h, raw) else {
            return;
        };
        if let Some(e) = self.est.as_mut() {
            e.last_rx = now;
        }
        let mut reply = match h.exchange_type {
            exchange::INFORMATIONAL => self.on_informational(which, &payloads),
            exchange::CREATE_CHILD_SA if which == Which::Cur => {
                self.on_create_child(now, &payloads)
            }
            _ => return,
        };
        let data = match self.seal_est(which, true, h.exchange_type, h.message_id, &reply.payloads)
        {
            Ok(d) => d,
            Err(r) => {
                self.fail(r, out);
                return;
            }
        };
        let lt = self.cfg.lifetimes;
        let overlap = self.cfg.rekey_overlap;
        let Some(e) = self.est.as_mut() else { return };
        if let Some(sa) = e.sa_mut(which) {
            sa.peer_mid = sa.peer_mid.wrapping_add(1);
            sa.last_resp = Some((h.message_id, data.clone()));
        }
        out.push(Output::Send {
            port: NATT_PORT,
            data,
        });
        out.append(&mut reply.events);
        if let Some(new) = reply.new_ike.take() {
            e.old = Some(core::mem::replace(&mut e.cur, new));
            e.old_ike_until = Some(now + overlap * 3);
            e.ike_soft_at = now + lt.ike_soft;
            e.ike_hard_at = now + lt.ike_hard;
        }
        if reply.drop_old && which == Which::Old {
            e.old = None;
            e.old_ike_until = None;
        }
        if let Some(reason) = reply.close {
            self.phase = Phase::Closed;
            self.pending = None;
            self.est = None;
            out.push(Output::Event(Event::Closed(reason)));
        }
    }

    fn on_informational(&mut self, which: Which, payloads: &[Payload]) -> Reply {
        let mut r = Reply::default();
        let Some(e) = self.est.as_ref() else { return r };
        let mut acked = Vec::new();
        for (proto, spis) in payloads.iter().filter_map(parse_delete) {
            if proto == 1 {
                if which == Which::Old {
                    r.drop_old = true;
                } else {
                    r.close = Some(CloseReason::PeerDeletedIke);
                }
            } else if proto == 3 && which == Which::Cur {
                for s in spis {
                    if s == e.child.spi_out {
                        acked.push(e.child.spi_in);
                        r.close = Some(CloseReason::PeerDeletedChild);
                    } else if let Some((spi_in, spi_out, _)) = e.old_child
                        && s == spi_out
                    {
                        acked.push(spi_in);
                    }
                }
            }
        }
        if !acked.is_empty() {
            r.payloads.push(delete_payload(3, &acked));
        }
        r
    }

    fn on_create_child(&mut self, now: Instant, payloads: &[Payload]) -> Reply {
        let busy_ike = self.busy_with(|k| matches!(k, ReqKind::RekeyIke(_)));
        let busy_child = self.busy_with(|k| matches!(k, ReqKind::RekeyChild(_)));
        let held = self.est.as_ref().is_some_and(|e| e.held.is_some());
        let is_ike = find_sa(payloads).is_some_and(|v| v.iter().any(|p| p.protocol == 1));
        let rekey_sa = payloads.iter().find_map(|p| match p {
            Payload::Notify(n) if n.ty == notify::REKEY_SA => Some(n),
            _ => None,
        });
        if is_ike {
            if busy_ike || busy_child || held {
                return Reply::error(notify::TEMPORARY_FAILURE, Vec::new());
            }
            return self.ike_rekey_request(now, payloads);
        }
        let Some(n) = rekey_sa else {
            return Reply::error(notify::NO_ADDITIONAL_SAS, Vec::new());
        };
        if busy_ike || held {
            return Reply::error(notify::TEMPORARY_FAILURE, Vec::new());
        }
        self.child_rekey_request(now, payloads, n.protocol, &n.spi, busy_child)
    }

    /// Choisit une proposition ESP parmi celles du pair (ordre du pair, transforms à nous).
    fn select_esp(&self, props: &[Proposal], ke: Option<u16>) -> Option<(Proposal, EspProposal)> {
        for p in props
            .iter()
            .filter(|p| p.protocol == 3 && spi4(p).is_some())
        {
            for e in &self.cfg.esp_proposals {
                if has_encr(p, e.encr) && has_integ(p, e.integ) && dh_ok(p, ke) && esn_ok(p) {
                    let mut t = vec![encr_transform(e.encr)];
                    if let Some(i) = e.integ {
                        t.push(crate::wire::Transform {
                            ty: 3,
                            id: integ_id(i),
                            key_len: None,
                        });
                    }
                    if let Some(g) = ke {
                        t.push(crate::wire::Transform {
                            ty: 4,
                            id: g,
                            key_len: None,
                        });
                    }
                    t.push(crate::wire::Transform {
                        ty: 5,
                        id: 0,
                        key_len: None,
                    });
                    let chosen = Proposal {
                        number: p.number,
                        protocol: 3,
                        spi: p.spi.clone(),
                        transforms: t,
                    };
                    return Some((chosen, *e));
                }
            }
        }
        None
    }

    #[allow(clippy::too_many_lines)]
    fn child_rekey_request(
        &mut self,
        now: Instant,
        payloads: &[Payload],
        n_proto: u8,
        n_spi: &[u8],
        collide: bool,
    ) -> Reply {
        let Some(e) = self.est.as_ref() else {
            return Reply::default();
        };
        let (group, ts_l, ts_r) = (e.group, e.ts_local.clone(), e.ts_remote.clone());
        let cur_out = e.child.spi_out;
        let sk_d = e.cur.keys.sk_d.clone();
        let prf = e.cur.suite.prf;
        let target = <[u8; 4]>::try_from(n_spi).ok().map(u32::from_be_bytes);
        if n_proto != 3 || target != Some(cur_out) {
            return Reply::error(notify::CHILD_SA_NOT_FOUND, Vec::new());
        }
        let (Some(props), Some(ni)) = (find_sa(payloads), find_nonce(payloads)) else {
            return Reply::error(7, Vec::new());
        };
        let ke = find_ke(payloads);
        // PFS exigé : un rekey du pair sans KE est refusé (NO_PROPOSAL_CHOSEN).
        if ke.is_none() {
            return Reply::error(14, Vec::new());
        }
        if let Some((g, _)) = ke
            && !self.cfg.dh_groups.iter().any(|x| x.id() == g)
        {
            return Reply::error(
                notify::INVALID_KE_PAYLOAD,
                group.id().to_be_bytes().to_vec(),
            );
        }
        let Some((mut chosen, esp)) = self.select_esp(props, ke.map(|k| k.0)) else {
            return Reply::error(14, Vec::new());
        };
        let Some(peer_spi) = spi4(&chosen) else {
            return Reply::error(7, Vec::new());
        };
        let (tsi_p, tsr_p) = (find_ts(payloads, false), find_ts(payloads, true));
        if tsi_p.is_some_and(|t| !crate::ike::ts_valid(t))
            || tsr_p.is_some_and(|t| !crate::ike::ts_valid(t))
        {
            return Reply::error(notify::TS_UNACCEPTABLE, Vec::new());
        }
        let new_spi = self.rand_spi32();
        chosen.spi = new_spi.to_be_bytes().to_vec();
        let mut nr = vec![0u8; 32];
        self.rng.fill(&mut nr);
        let mut resp = Vec::new();
        let mut shared = None;
        let mut ke_resp = None;
        if let Some((g, kd)) = ke {
            let Ok(dg) = DhGroup::from_id(g) else {
                return Reply::error(
                    notify::INVALID_KE_PAYLOAD,
                    group.id().to_be_bytes().to_vec(),
                );
            };
            let Ok(kp) = self.new_keypair(dg) else {
                return Reply::error(14, Vec::new());
            };
            let Ok(s) = kp.shared_secret(kd) else {
                return Reply::error(
                    notify::INVALID_KE_PAYLOAD,
                    group.id().to_be_bytes().to_vec(),
                );
            };
            ke_resp = Some(Payload::Ke {
                group: g,
                data: kp.public().to_vec(),
            });
            shared = Some(s);
        }
        let Ok(keys) = derive_child_keys_ex(
            prf,
            &sk_d,
            shared.as_ref().map(|s| &s[..]),
            ni,
            &nr,
            esp,
            new_spi,
            peer_spi,
            false,
        ) else {
            return Reply::error(14, Vec::new());
        };
        let min = min_nonce(ni, &nr);
        resp.push(Payload::Sa(vec![chosen]));
        resp.push(Payload::Nonce(nr));
        resp.extend(ke_resp);
        resp.push(Payload::Ts {
            responder: false,
            selectors: find_ts(payloads, false).cloned().unwrap_or(ts_l),
        });
        resp.push(Payload::Ts {
            responder: true,
            selectors: find_ts(payloads, true).cloned().unwrap_or(ts_r),
        });
        let mut reply = Reply {
            payloads: resp,
            ..Reply::default()
        };
        let lt = self.cfg.lifetimes;
        let overlap = self.cfg.rekey_overlap;
        let Some(e) = self.est.as_mut() else {
            return reply;
        };
        if collide {
            e.held = Some(Held {
                keys: Box::new(keys),
                min_nonce: min,
            });
        } else {
            Self::finish_rekey(e, now, Box::new(keys), overlap, &mut reply.events);
            e.child_soft_at = now + lt.child_soft;
            e.child_hard_at = now + lt.child_hard;
        }
        reply
    }

    fn ike_rekey_request(&mut self, _now: Instant, payloads: &[Payload]) -> Reply {
        let Some(e) = self.est.as_ref() else {
            return Reply::default();
        };
        let group = e.group;
        let sk_d = e.cur.keys.sk_d.clone();
        let (Some(props), Some(ni), Some((kg, kd))) =
            (find_sa(payloads), find_nonce(payloads), find_ke(payloads))
        else {
            return Reply::error(7, Vec::new());
        };
        let Ok(dg) = DhGroup::from_id(kg) else {
            return Reply::error(
                notify::INVALID_KE_PAYLOAD,
                group.id().to_be_bytes().to_vec(),
            );
        };
        if !self.cfg.dh_groups.contains(&dg) {
            return Reply::error(
                notify::INVALID_KE_PAYLOAD,
                group.id().to_be_bytes().to_vec(),
            );
        }
        let mut found = None;
        'outer: for p in props.iter().filter(|p| p.protocol == 1 && p.spi.len() == 8) {
            for s in &self.cfg.ike_suites {
                let prf_ok = has_t(p, 2, s.prf.id());
                if has_encr(p, s.encr) && prf_ok && has_integ(p, s.integ) && has_t(p, 4, kg) {
                    found = Some((p, *s));
                    break 'outer;
                }
            }
        }
        let Some((p, suite)) = found else {
            return Reply::error(14, Vec::new());
        };
        let Ok(peer_spi) = <[u8; 8]>::try_from(p.spi.as_slice()) else {
            return Reply::error(7, Vec::new());
        };
        let our_spi = self.rand_spi64();
        let mut nr = vec![0u8; 32];
        self.rng.fill(&mut nr);
        let Ok(kp) = self.new_keypair(dg) else {
            return Reply::error(14, Vec::new());
        };
        let Ok(shared) = kp.shared_secret(kd) else {
            return Reply::error(
                notify::INVALID_KE_PAYLOAD,
                group.id().to_be_bytes().to_vec(),
            );
        };
        let Ok(keys) = derive_sk_keys_rekey(&suite, &sk_d, ni, &nr, &peer_spi, &our_spi, &shared)
        else {
            return Reply::error(14, Vec::new());
        };
        let mut t = vec![encr_transform(suite.encr)];
        t.push(crate::wire::Transform {
            ty: 2,
            id: suite.prf.id(),
            key_len: None,
        });
        if let Some(i) = suite.integ {
            t.push(crate::wire::Transform {
                ty: 3,
                id: integ_id(i),
                key_len: None,
            });
        }
        t.push(crate::wire::Transform {
            ty: 4,
            id: kg,
            key_len: None,
        });
        let chosen = Proposal {
            number: p.number,
            protocol: 1,
            spi: our_spi.to_vec(),
            transforms: t,
        };
        Reply {
            payloads: vec![
                Payload::Sa(vec![chosen]),
                Payload::Nonce(nr),
                Payload::Ke {
                    group: kg,
                    data: kp.public().to_vec(),
                },
            ],
            new_ike: Some(IkeSa::new(suite, keys, peer_spi, our_spi, false, 0)),
            ..Reply::default()
        }
    }
}
