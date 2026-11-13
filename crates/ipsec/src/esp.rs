//! ESP (RFC 4303) en mode tunnel IPv4, encapsulé dans UDP 4500 (RFC 3948). Sans I/O.
//!
//! Suites : AES-GCM-16 (RFC 4106, 128/256) et AES-CBC + HMAC-SHA256-128 / HMAC-SHA1-96.
//! Les charges UDP sont traitées par [`classify`] (keepalive / IKE / ESP). L'aléa (IV CBC) est
//! fourni par l'appelant ; pour GCM l'IV est dérivé du compteur 64 bits si non fourni.

#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce, Tag};
use zeroize::Zeroizing;

use crate::crypto::{Encr, Integ, ct_eq};
use crate::ike::ChildSaKeys;

/// Next Header d'un paquet IPv4 en mode tunnel.
pub const NH_IPV4: u8 = 4;
/// Next Header « no next header » : paquet factice (TFC), à jeter.
pub const NH_NONE: u8 = 59;
/// Taille de la fenêtre anti-rejeu (bits).
pub const REPLAY_WINDOW: u64 = 128;
/// Charge UDP du keepalive NAT-T (RFC 3948 §2.3).
pub const KEEPALIVE: [u8; 1] = [0xff];

/// Erreur ESP.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EspError {
    #[error("paquet ESP tronqué ou de longueur invalide")]
    Truncated,
    #[error("SPI inattendu")]
    BadSpi,
    #[error("échec de vérification d'intégrité")]
    Integrity,
    #[error("paquet rejoué ou hors fenêtre")]
    Replay,
    #[error("padding ou trailer invalide : {0}")]
    BadPadding(&'static str),
    #[error("next header non supporté : {0}")]
    UnsupportedNextHeader(u8),
    #[error("numéros de séquence épuisés (rekey nécessaire)")]
    SeqExhausted,
    #[error("IV CBC de 16 octets requis")]
    MissingIv,
    #[error("paquet trop grand")]
    TooLarge,
    #[error("paquet IPv4 interne invalide : {0}")]
    BadInner(&'static str),
    #[error("paramètres de SA invalides : {0}")]
    BadKeys(&'static str),
}

/// Classification d'une charge UDP reçue sur le port 4500.
#[derive(Debug, PartialEq, Eq)]
pub enum Datagram<'a> {
    /// Keepalive NAT-T (un octet 0xFF) : à ignorer.
    Keepalive,
    /// Message IKE (marqueur non-ESP de 4 octets retiré).
    Ike(&'a [u8]),
    /// Paquet ESP (SPI non nul en tête).
    Esp(&'a [u8]),
}

/// Démultiplexe une charge UDP du port 4500 (RFC 3948 §2.1-2.3).
pub fn classify(payload: &[u8]) -> Result<Datagram<'_>, EspError> {
    if payload == KEEPALIVE {
        return Ok(Datagram::Keepalive);
    }
    if payload.len() < 4 {
        return Err(EspError::Truncated);
    }
    if payload[..4] == [0; 4] {
        Ok(Datagram::Ike(&payload[4..]))
    } else {
        Ok(Datagram::Esp(payload))
    }
}

/// Préfixe un message IKE du marqueur non-ESP pour l'envoi sur le port 4500.
#[must_use]
pub fn wrap_ike(msg: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + msg.len());
    v.extend_from_slice(&[0; 4]);
    v.extend_from_slice(msg);
    v
}

/// Résultat du traitement d'un paquet ESP authentique.
#[derive(Debug, PartialEq, Eq)]
pub enum Inbound {
    /// Paquet IPv4 interne.
    Packet(Vec<u8>),
    /// Paquet factice (Next Header 59), à ignorer.
    Dummy,
}

/// Fenêtre anti-rejeu glissante (RFC 4303 §3.4.3 et annexe A).
#[derive(Debug, Default)]
struct ReplayWindow {
    top: u64,
    bitmap: u128,
}

impl ReplayWindow {
    fn check(&self, seq: u64) -> bool {
        if seq == 0 {
            return false;
        }
        if seq > self.top {
            return true;
        }
        let diff = self.top - seq;
        diff < REPLAY_WINDOW && (self.bitmap >> diff) & 1 == 0
    }

    fn update(&mut self, seq: u64) {
        if seq > self.top {
            let shift = seq - self.top;
            self.bitmap = if shift >= REPLAY_WINDOW {
                0
            } else {
                self.bitmap << shift
            };
            self.bitmap |= 1;
            self.top = seq;
        } else {
            let diff = self.top - seq;
            if diff < REPLAY_WINDOW {
                self.bitmap |= 1 << diff;
            }
        }
    }

    /// Reconstitue les 32 bits de poids fort (ESN, RFC 4303 annexe A2).
    fn seq_hi(&self, seql: u32) -> u32 {
        let tl = (self.top & 0xffff_ffff) as u32;
        let th = (self.top >> 32) as u32;
        let w = REPLAY_WINDOW as u32;
        if tl >= w - 1 {
            if seql >= tl - (w - 1) {
                th
            } else {
                th.wrapping_add(1)
            }
        } else if seql >= tl.wrapping_sub(w - 1) {
            th.saturating_sub(1)
        } else {
            th
        }
    }
}

/// Chiffreur ESP mis en cache (clé développée une seule fois ; effacée à la destruction grâce
/// à la feature `zeroize` de `aes`/`aes-gcm`).
enum Cipher {
    Gcm128(Box<Aes128Gcm>),
    Gcm256(Box<Aes256Gcm>),
    Cbc128(Box<aes::Aes128>),
    Cbc256(Box<aes::Aes256>),
}

struct Suite {
    encr: Encr,
    integ: Option<Integ>,
    cipher: Cipher,
    salt: [u8; 4],
    integ_key: Zeroizing<Vec<u8>>,
}

impl Suite {
    fn new(
        encr: Encr,
        integ: Option<Integ>,
        encr_key: &[u8],
        integ_key: &[u8],
    ) -> Result<Self, EspError> {
        if encr.is_aead() != integ.is_none() {
            return Err(EspError::BadKeys("combinaison ENCR/INTEG"));
        }
        if encr_key.len() != encr.key_len() + encr.salt_len() {
            return Err(EspError::BadKeys("longueur de clé de chiffrement"));
        }
        if integ_key.len() != integ.map_or(0, Integ::key_len) {
            return Err(EspError::BadKeys("longueur de clé d'intégrité"));
        }
        let (k, s) = encr_key.split_at(encr.key_len());
        let mut salt = [0u8; 4];
        salt[..s.len()].copy_from_slice(s);
        let bad = |_| EspError::BadKeys("clé de chiffrement");
        let cipher = match encr {
            Encr::AesGcm16_128 => {
                Cipher::Gcm128(Box::new(Aes128Gcm::new_from_slice(k).map_err(bad)?))
            }
            Encr::AesGcm16_256 => {
                Cipher::Gcm256(Box::new(Aes256Gcm::new_from_slice(k).map_err(bad)?))
            }
            Encr::AesCbc128 => Cipher::Cbc128(Box::new(
                <aes::Aes128 as aes::cipher::KeyInit>::new_from_slice(k).map_err(bad)?,
            )),
            Encr::AesCbc256 => Cipher::Cbc256(Box::new(
                <aes::Aes256 as aes::cipher::KeyInit>::new_from_slice(k).map_err(bad)?,
            )),
        };
        Ok(Self {
            encr,
            integ,
            cipher,
            salt,
            integ_key: Zeroizing::new(integ_key.to_vec()),
        })
    }

    fn iv_len(&self) -> usize {
        self.encr.iv_len()
    }
    fn icv_len(&self) -> usize {
        self.integ.map_or(16, Integ::icv_len)
    }
    fn align(&self) -> usize {
        if self.encr.is_aead() { 4 } else { 16 }
    }

    fn gcm(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: GcmTag<'_>,
    ) -> Result<Option<[u8; 16]>, EspError> {
        let n = Nonce::from_slice(nonce);
        match (&self.cipher, tag) {
            (Cipher::Gcm128(c), GcmTag::Seal) => {
                let t = c
                    .encrypt_in_place_detached(n, aad, buf)
                    .map_err(|_| EspError::TooLarge)?;
                Ok(Some(t.into()))
            }
            (Cipher::Gcm256(c), GcmTag::Seal) => {
                let t = c
                    .encrypt_in_place_detached(n, aad, buf)
                    .map_err(|_| EspError::TooLarge)?;
                Ok(Some(t.into()))
            }
            (Cipher::Gcm128(c), GcmTag::Open(t)) => {
                c.decrypt_in_place_detached(n, aad, buf, Tag::from_slice(t))
                    .map_err(|_| EspError::Integrity)?;
                Ok(None)
            }
            (Cipher::Gcm256(c), GcmTag::Open(t)) => {
                c.decrypt_in_place_detached(n, aad, buf, Tag::from_slice(t))
                    .map_err(|_| EspError::Integrity)?;
                Ok(None)
            }
            _ => Err(EspError::BadKeys("pas GCM")),
        }
    }

    fn cbc(&self, iv: &[u8], buf: &mut [u8], enc: bool) -> Result<(), EspError> {
        use aes::cipher::InnerIvInit;
        let bad = |_| EspError::BadKeys("IV CBC");
        let len = buf.len();
        let ok = match (&self.cipher, enc) {
            (Cipher::Cbc128(c), true) => {
                cbc::Encryptor::<aes::Aes128>::inner_iv_slice_init((**c).clone(), iv)
                    .map_err(bad)?
                    .encrypt_padded_mut::<NoPadding>(buf, len)
                    .is_ok()
            }
            (Cipher::Cbc256(c), true) => {
                cbc::Encryptor::<aes::Aes256>::inner_iv_slice_init((**c).clone(), iv)
                    .map_err(bad)?
                    .encrypt_padded_mut::<NoPadding>(buf, len)
                    .is_ok()
            }
            (Cipher::Cbc128(c), false) => {
                cbc::Decryptor::<aes::Aes128>::inner_iv_slice_init((**c).clone(), iv)
                    .map_err(bad)?
                    .decrypt_padded_mut::<NoPadding>(buf)
                    .is_ok()
            }
            (Cipher::Cbc256(c), false) => {
                cbc::Decryptor::<aes::Aes256>::inner_iv_slice_init((**c).clone(), iv)
                    .map_err(bad)?
                    .decrypt_padded_mut::<NoPadding>(buf)
                    .is_ok()
            }
            _ => return Err(EspError::BadKeys("pas CBC")),
        };
        if ok { Ok(()) } else { Err(EspError::Truncated) }
    }

    /// ICV HMAC : SPI | SeqLo | IV | chiffré [| SeqHi si ESN].
    fn hmac_icv(&self, integ: Integ, body: &[u8], seq_hi: Option<u32>) -> Vec<u8> {
        let mut data = Vec::with_capacity(body.len() + 4);
        data.extend_from_slice(body);
        if let Some(h) = seq_hi {
            data.extend_from_slice(&h.to_be_bytes());
        }
        integ.icv(&self.integ_key, &data)
    }
}

enum GcmTag<'a> {
    Seal,
    Open(&'a [u8]),
}

/// Direction sortante (client → passerelle).
struct Outbound {
    spi: u32,
    next_seq: u64,
    suite: Suite,
}

/// Direction entrante (passerelle → client).
struct InboundSa {
    spi: u32,
    window: ReplayWindow,
    suite: Suite,
}

/// Paire de SA ESP d'une CHILD SA (émission + réception).
pub struct EspTunnel {
    esn: bool,
    out: Outbound,
    inn: InboundSa,
    /// Ancienne SA entrante, acceptée pendant la transition d'un rekey.
    old_inn: Option<InboundSa>,
}

impl core::fmt::Debug for EspTunnel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EspTunnel")
            .field("esn", &self.esn)
            .field("spi_out", &self.out.spi)
            .field("spi_in", &self.inn.spi)
            .finish_non_exhaustive()
    }
}

impl EspTunnel {
    /// Construit les deux directions depuis les clés issues de `derive_child_keys`.
    /// `esn` : numéros de séquence étendus (64 bits) négociés.
    pub fn new(keys: &ChildSaKeys, esn: bool) -> Result<Self, EspError> {
        Ok(Self {
            esn,
            out: Outbound {
                spi: keys.spi_out,
                next_seq: 1,
                suite: Suite::new(
                    keys.encr,
                    keys.integ,
                    &keys.encr_key_out,
                    &keys.integ_key_out,
                )?,
            },
            inn: InboundSa {
                spi: keys.spi_in,
                window: ReplayWindow::default(),
                suite: Suite::new(keys.encr, keys.integ, &keys.encr_key_in, &keys.integ_key_in)?,
            },
            old_inn: None,
        })
    }

    /// Bascule sur la CHILD SA issue d'un rekey : l'émission utilise immédiatement la nouvelle SA
    /// (SPI, clés, séquence repartent à 1) ; l'ancienne SA entrante reste acceptée jusqu'à
    /// [`EspTunnel::drop_old`] (fenêtre de transition).
    pub fn rekey(&mut self, keys: &ChildSaKeys) -> Result<(), EspError> {
        let new = Self::new(keys, self.esn)?;
        self.out = new.out;
        self.old_inn = Some(core::mem::replace(&mut self.inn, new.inn));
        Ok(())
    }

    /// Fin de la fenêtre de transition : l'ancien SPI entrant n'est plus accepté.
    pub fn drop_old(&mut self, spi: u32) {
        if self.old_inn.as_ref().is_some_and(|o| o.spi == spi) {
            self.old_inn = None;
        }
    }

    /// SPI entrants actuellement acceptés (courant, puis ancien en transition).
    #[must_use]
    pub fn inbound_spis(&self) -> Vec<u32> {
        let mut v = vec![self.inn.spi];
        v.extend(self.old_inn.as_ref().map(|o| o.spi));
        v
    }

    /// Prochain numéro de séquence émis (pour décider d'un rekey).
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.out.next_seq
    }

    /// Encapsule un paquet IPv4 (Next Header 4).
    ///
    /// `iv` : IV fourni par l'appelant (16 octets pour CBC, aléatoire ; pour GCM les 8 premiers
    /// octets sont utilisés, sinon dérivés du compteur de séquence).
    pub fn seal(&mut self, packet: &[u8], iv: Option<&[u8; 16]>) -> Result<Vec<u8>, EspError> {
        self.seal_nh(packet, NH_IPV4, iv)
    }

    /// Paquet factice (Next Header 59, TFC) contenant `len` octets de bourrage.
    pub fn seal_dummy(&mut self, len: usize, iv: Option<&[u8; 16]>) -> Result<Vec<u8>, EspError> {
        self.seal_nh(&vec![0u8; len], NH_NONE, iv)
    }

    fn seal_nh(
        &mut self,
        payload: &[u8],
        nh: u8,
        iv: Option<&[u8; 16]>,
    ) -> Result<Vec<u8>, EspError> {
        if payload.len() > 65_535 {
            return Err(EspError::TooLarge);
        }
        let o = &mut self.out;
        let seq = o.next_seq;
        if (!self.esn && seq > u64::from(u32::MAX)) || seq == u64::MAX {
            return Err(EspError::SeqExhausted);
        }
        let s = &o.suite;
        let iv_len = s.iv_len();
        let iv: Vec<u8> = match (s.encr.is_aead(), iv) {
            (true, Some(v)) => v[..iv_len].to_vec(),
            (true, None) => seq.to_be_bytes().to_vec(),
            (false, Some(v)) => v.to_vec(),
            (false, None) => return Err(EspError::MissingIv),
        };
        // Trailer : payload | 1,2,3.. | PadLen | NH
        let align = s.align();
        let pad = (align - (payload.len() + 2) % align) % align;
        let mut ct = Vec::with_capacity(payload.len() + pad + 2);
        ct.extend_from_slice(payload);
        ct.extend((1..=pad).map(|i| i as u8));
        ct.push(pad as u8);
        ct.push(nh);

        let seq_lo = (seq & 0xffff_ffff) as u32;
        let seq_hi = (seq >> 32) as u32;
        let mut out = Vec::with_capacity(8 + iv_len + ct.len() + s.icv_len());
        out.extend_from_slice(&o.spi.to_be_bytes());
        out.extend_from_slice(&seq_lo.to_be_bytes());
        out.extend_from_slice(&iv);

        if let Some(integ) = s.integ {
            s.cbc(&iv, &mut ct, true)?;
            out.extend_from_slice(&ct);
            let icv = s.hmac_icv(integ, &out, self.esn.then_some(seq_hi));
            out.extend_from_slice(&icv);
        } else {
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&s.salt);
            nonce[4..].copy_from_slice(&iv);
            let aad = gcm_aad(o.spi, seq_hi, seq_lo, self.esn);
            let tag = s
                .gcm(&nonce, &aad, &mut ct, GcmTag::Seal)?
                .ok_or(EspError::TooLarge)?;
            out.extend_from_slice(&ct);
            out.extend_from_slice(&tag);
        }
        o.next_seq = seq + 1;
        Ok(out)
    }

    /// Décapsule un paquet ESP (charge UDP sans marqueur). La fenêtre anti-rejeu n'est mise à
    /// jour qu'après vérification de l'intégrité.
    pub fn open(&mut self, data: &[u8]) -> Result<Inbound, EspError> {
        if data.len() < 8 {
            return Err(EspError::Truncated);
        }
        let spi = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let i = if spi == self.inn.spi {
            &mut self.inn
        } else if let Some(o) = self.old_inn.as_mut().filter(|o| o.spi == spi) {
            o
        } else {
            return Err(EspError::BadSpi);
        };
        let s = &i.suite;
        let (iv_len, icv_len) = (s.iv_len(), s.icv_len());
        if data.len() < 8 + iv_len + icv_len {
            return Err(EspError::Truncated);
        }
        let seq_lo = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let seq_hi = if self.esn { i.window.seq_hi(seq_lo) } else { 0 };
        let seq = (u64::from(seq_hi) << 32) | u64::from(seq_lo);
        if !i.window.check(seq) {
            return Err(EspError::Replay);
        }
        let body_end = data.len() - icv_len;
        let iv = &data[8..8 + iv_len];
        let mut pt = data[8 + iv_len..body_end].to_vec();
        let icv = &data[body_end..];

        if let Some(integ) = s.integ {
            let exp = s.hmac_icv(integ, &data[..body_end], self.esn.then_some(seq_hi));
            if !ct_eq(&exp, icv) {
                return Err(EspError::Integrity);
            }
            if pt.is_empty() || pt.len() % 16 != 0 {
                return Err(EspError::Truncated);
            }
            s.cbc(iv, &mut pt, false)?;
        } else {
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&s.salt);
            nonce[4..].copy_from_slice(iv);
            let aad = gcm_aad(spi, seq_hi, seq_lo, self.esn);
            s.gcm(&nonce, &aad, &mut pt, GcmTag::Open(icv))?;
        }
        i.window.update(seq);

        // Trailer.
        if pt.len() < 2 {
            return Err(EspError::BadPadding("trop court"));
        }
        let nh = pt[pt.len() - 1];
        let pad = usize::from(pt[pt.len() - 2]);
        if pad + 2 > pt.len() {
            return Err(EspError::BadPadding("PadLen hors limites"));
        }
        let start = pt.len() - 2 - pad;
        if !pt[start..pt.len() - 2]
            .iter()
            .enumerate()
            .all(|(k, &b)| usize::from(b) == k + 1)
        {
            return Err(EspError::BadPadding("octets de padding"));
        }
        pt.truncate(start);
        match nh {
            NH_IPV4 => {
                validate_ipv4(&pt)?;
                // Le total length IPv4 fait foi : tout excédent est du bourrage.
                let total = usize::from(u16::from_be_bytes([pt[2], pt[3]]));
                pt.truncate(total);
                Ok(Inbound::Packet(pt))
            }
            NH_NONE => Ok(Inbound::Dummy),
            other => Err(EspError::UnsupportedNextHeader(other)),
        }
    }
}

/// Validation minimale d'un paquet IPv4 déchiffré avant livraison : version 4, IHL >= 5,
/// longueur totale cohérente avec les données disponibles.
fn validate_ipv4(p: &[u8]) -> Result<(), EspError> {
    if p.len() < 20 {
        return Err(EspError::BadInner("trop court"));
    }
    if p[0] >> 4 != 4 {
        return Err(EspError::BadInner("version != 4"));
    }
    let ihl = usize::from(p[0] & 0x0f) * 4;
    if ihl < 20 || ihl > p.len() {
        return Err(EspError::BadInner("IHL invalide"));
    }
    let total = usize::from(u16::from_be_bytes([p[2], p[3]]));
    if total < ihl || total > p.len() {
        return Err(EspError::BadInner("longueur totale incohérente"));
    }
    Ok(())
}

fn gcm_aad(spi: u32, seq_hi: u32, seq_lo: u32, esn: bool) -> Vec<u8> {
    let mut a = Vec::with_capacity(12);
    a.extend_from_slice(&spi.to_be_bytes());
    if esn {
        a.extend_from_slice(&seq_hi.to_be_bytes());
    }
    a.extend_from_slice(&seq_lo.to_be_bytes());
    a
}

#[cfg(test)]
#[path = "esp_tests.rs"]
mod tests;
