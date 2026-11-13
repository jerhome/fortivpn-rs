//! Payload SK (chiffré + intégrité) : AES-CBC + HMAC et AES-GCM-16 (RFC 7296 §3.14, RFC 5282).

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce, Tag};

use zeroize::Zeroizing;

use crate::crypto::{Encr, IkeSuite, SkKeys, ct_eq};
use crate::error::{Error, Result};
use crate::wire::{
    HEADER_LEN, Header, MAX_MESSAGE_LEN, Message, Payload, decode_chain, encode_chain, ptype,
};

/// Construit un message IKE dont les payloads `inner` sont protégés par un SK.
///
/// `from_initiator` : l'émetteur est l'initiateur IKE (clés SK_ei/SK_ai). `iv` : 16 octets
/// (CBC, aléatoires) ou 8 octets (GCM, compteur unique), fournis par l'appelant.
pub fn seal(
    suite: &IkeSuite,
    keys: &SkKeys,
    from_initiator: bool,
    header: &Header,
    inner: &[Payload],
    iv: &[u8],
) -> Result<Vec<u8>> {
    if iv.len() != suite.encr.iv_len() {
        return Err(Error::Crypto("taille d'IV invalide"));
    }
    let (sk_a, sk_e) = if from_initiator {
        (&keys.sk_ai, &keys.sk_ei)
    } else {
        (&keys.sk_ar, &keys.sk_er)
    };
    let (first, pt) = encode_chain(inner)?;
    let mut pt = Zeroizing::new(pt);
    let block = if suite.encr.is_aead() { 4 } else { 16 };
    let pad = (block - (pt.len() + 1) % block) % block;
    pt.extend(std::iter::repeat_n(0u8, pad));
    pt.push(u8::try_from(pad).map_err(|_| Error::Crypto("padding"))?);

    let icv_len = suite.icv_len();
    let sk_len = 4 + iv.len() + pt.len() + icv_len;
    let total = HEADER_LEN + sk_len;
    if total > MAX_MESSAGE_LEN {
        return Err(Error::TooLarge("message IKE"));
    }
    let mut msg = Vec::with_capacity(total);
    // En-tête IKE : on réutilise l'encodeur public avec un chargement vide puis on corrige.
    let mut h = header.clone();
    h.next_payload = ptype::SK;
    h.length = u32::try_from(total).map_err(|_| Error::TooLarge("message IKE"))?;
    msg.extend_from_slice(&h.spi_i);
    msg.extend_from_slice(&h.spi_r);
    msg.extend_from_slice(&[h.next_payload, 0x20, h.exchange_type, h.flags]);
    msg.extend_from_slice(&h.message_id.to_be_bytes());
    msg.extend_from_slice(&h.length.to_be_bytes());
    let sk_len16 = u16::try_from(sk_len).map_err(|_| Error::TooLarge("SK"))?;
    msg.extend_from_slice(&[first, 0]);
    msg.extend_from_slice(&sk_len16.to_be_bytes());
    let aad_len = msg.len();
    msg.extend_from_slice(iv);

    if suite.encr.is_aead() {
        let n = nonce(&sk_e[sk_e.len() - 4..], iv);
        let tag = gcm_encrypt(
            suite.encr,
            &sk_e[..suite.encr.key_len()],
            &n,
            &msg[..aad_len],
            &mut pt,
        )?;
        msg.extend_from_slice(&pt);
        msg.extend_from_slice(&tag);
    } else {
        cbc_encrypt(suite.encr, sk_e, iv, &mut pt)?;
        msg.extend_from_slice(&pt);
        let integ = suite.integ.ok_or(Error::Crypto("INTEG manquant"))?;
        let icv = integ.icv(sk_a, &msg);
        msg.extend_from_slice(&icv);
    }
    debug_assert_eq!(msg.len(), total);
    Ok(msg)
}

/// Vérifie l'intégrité puis déchiffre un message dont le dernier payload est un SK.
///
/// `from_initiator` : l'émetteur du message reçu est l'initiateur IKE.
pub fn open(
    suite: &IkeSuite,
    keys: &SkKeys,
    from_initiator: bool,
    raw: &[u8],
) -> Result<(Header, Vec<Payload>)> {
    let msg = Message::decode(raw)?;
    let Some(Payload::Sk { next, data }) = msg.payloads.last() else {
        return Err(Error::Malformed("pas de payload SK"));
    };
    let (sk_a, sk_e) = if from_initiator {
        (&keys.sk_ai, &keys.sk_ei)
    } else {
        (&keys.sk_ar, &keys.sk_er)
    };
    let iv_len = suite.encr.iv_len();
    let icv_len = suite.icv_len();
    let block = if suite.encr.is_aead() { 4 } else { 16 };
    if data.len() < iv_len + icv_len + block {
        return Err(Error::Malformed("SK trop court"));
    }
    let ct_len = data.len() - iv_len - icv_len;
    if ct_len % block != 0 {
        return Err(Error::Malformed("SK : longueur chiffrée non alignée"));
    }
    let body_start = raw.len() - data.len();
    let iv = &raw[body_start..body_start + iv_len];
    let ct = &raw[body_start + iv_len..raw.len() - icv_len];
    let icv = &raw[raw.len() - icv_len..];

    let mut pt = Zeroizing::new(ct.to_vec());
    if suite.encr.is_aead() {
        let n = nonce(&sk_e[sk_e.len() - 4..], iv);
        gcm_decrypt(
            suite.encr,
            &sk_e[..suite.encr.key_len()],
            &n,
            &raw[..body_start],
            &mut pt,
            icv,
        )?;
    } else {
        let integ = suite.integ.ok_or(Error::Crypto("INTEG manquant"))?;
        let expect = integ.icv(sk_a, &raw[..raw.len() - icv_len]);
        if !ct_eq(&expect, icv) {
            return Err(Error::Integrity);
        }
        cbc_decrypt(suite.encr, sk_e, iv, &mut pt)?;
    }
    let pad = usize::from(*pt.last().ok_or(Error::Malformed("SK vide"))?);
    if pad + 1 > pt.len() {
        return Err(Error::Malformed("pad length invalide"));
    }
    let keep = pt.len() - 1 - pad;
    pt.truncate(keep);
    let payloads = decode_chain(*next, &pt)?;
    if payloads.iter().any(|p| matches!(p, Payload::Sk { .. })) {
        return Err(Error::Malformed("SK imbriqué"));
    }
    Ok((msg.header, payloads))
}

fn nonce(salt: &[u8], iv: &[u8]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(salt);
    n[4..].copy_from_slice(iv);
    n
}

fn gcm_encrypt(
    encr: Encr,
    key: &[u8],
    n: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; 16]> {
    let nonce = Nonce::from_slice(n);
    let tag = match encr {
        Encr::AesGcm16_128 => Aes128Gcm::new_from_slice(key)
            .map_err(|_| Error::Crypto("clé GCM"))?
            .encrypt_in_place_detached(nonce, aad, buf),
        Encr::AesGcm16_256 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| Error::Crypto("clé GCM"))?
            .encrypt_in_place_detached(nonce, aad, buf),
        _ => return Err(Error::Crypto("pas GCM")),
    }
    .map_err(|_| Error::Crypto("chiffrement GCM"))?;
    Ok(tag.into())
}

fn gcm_decrypt(
    encr: Encr,
    key: &[u8],
    n: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8],
) -> Result<()> {
    let nonce = Nonce::from_slice(n);
    let tag = Tag::from_slice(tag);
    match encr {
        Encr::AesGcm16_128 => Aes128Gcm::new_from_slice(key)
            .map_err(|_| Error::Crypto("clé GCM"))?
            .decrypt_in_place_detached(nonce, aad, buf, tag),
        Encr::AesGcm16_256 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| Error::Crypto("clé GCM"))?
            .decrypt_in_place_detached(nonce, aad, buf, tag),
        _ => return Err(Error::Crypto("pas GCM")),
    }
    .map_err(|_| Error::Integrity)
}

fn cbc_encrypt(encr: Encr, key: &[u8], iv: &[u8], buf: &mut [u8]) -> Result<()> {
    let len = buf.len();
    let r = match encr {
        Encr::AesCbc128 => cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv)
            .map_err(|_| Error::Crypto("clé/IV CBC"))?
            .encrypt_padded_mut::<NoPadding>(buf, len)
            .map(|_| ()),
        Encr::AesCbc256 => cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
            .map_err(|_| Error::Crypto("clé/IV CBC"))?
            .encrypt_padded_mut::<NoPadding>(buf, len)
            .map(|_| ()),
        _ => return Err(Error::Crypto("pas CBC")),
    };
    r.map_err(|_| Error::Crypto("chiffrement CBC"))
}

fn cbc_decrypt(encr: Encr, key: &[u8], iv: &[u8], buf: &mut [u8]) -> Result<()> {
    let r = match encr {
        Encr::AesCbc128 => cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
            .map_err(|_| Error::Crypto("clé/IV CBC"))?
            .decrypt_padded_mut::<NoPadding>(buf)
            .map(|_| ()),
        Encr::AesCbc256 => cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
            .map_err(|_| Error::Crypto("clé/IV CBC"))?
            .decrypt_padded_mut::<NoPadding>(buf)
            .map(|_| ()),
        _ => return Err(Error::Crypto("pas CBC")),
    };
    r.map_err(|_| Error::Crypto("déchiffrement CBC"))
}
