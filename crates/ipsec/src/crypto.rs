//! Primitives cryptographiques IKEv2 : PRF, prf+, DH, dérivation des clés, AUTH.

use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

/// Fonction pseudo-aléatoire IKEv2 (identifiants IANA 2 et 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prf {
    HmacSha1,
    HmacSha256,
}

impl Prf {
    pub fn from_id(id: u16) -> Result<Self> {
        match id {
            2 => Ok(Self::HmacSha1),
            5 => Ok(Self::HmacSha256),
            _ => Err(Error::Unsupported("PRF")),
        }
    }
    pub fn id(self) -> u16 {
        match self {
            Self::HmacSha1 => 2,
            Self::HmacSha256 => 5,
        }
    }
    /// Taille de sortie en octets.
    pub fn output_len(self) -> usize {
        match self {
            Self::HmacSha1 => 20,
            Self::HmacSha256 => 32,
        }
    }
    /// `prf(key, data)`.
    pub fn compute(self, key: &[u8], data: &[&[u8]]) -> Zeroizing<Vec<u8>> {
        match self {
            Self::HmacSha1 => hmac_over::<Hmac<Sha1>>(key, data),
            Self::HmacSha256 => hmac_over::<Hmac<Sha256>>(key, data),
        }
    }
}

fn hmac_over<M: Mac + hmac::digest::KeyInit>(key: &[u8], data: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    // HMAC accepte toute longueur de clé ; l'erreur est impossible.
    let mut m = <M as Mac>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC: clé de toute taille"));
    for d in data {
        m.update(d);
    }
    Zeroizing::new(m.finalize().into_bytes().to_vec())
}

/// `prf+(key, seed)` sur `len` octets (RFC 7296 §2.13).
pub fn prf_plus(prf: Prf, key: &[u8], seed: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>> {
    if len > 255 * prf.output_len() {
        return Err(Error::TooLarge("prf+"));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(len + prf.output_len()));
    let mut t: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut n: u8 = 1;
    while out.len() < len {
        t = prf.compute(key, &[&t, seed, &[n]]);
        out.extend_from_slice(&t);
        n = n.wrapping_add(1);
    }
    out.truncate(len);
    Ok(out)
}

/// Algorithme de chiffrement IKE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encr {
    AesCbc128,
    AesCbc256,
    AesGcm16_128,
    AesGcm16_256,
}

impl Encr {
    /// Depuis (ID de transform IANA, key length en bits).
    pub fn from_id(id: u16, key_bits: u16) -> Result<Self> {
        match (id, key_bits) {
            (12, 128) => Ok(Self::AesCbc128),
            (12, 256) => Ok(Self::AesCbc256),
            (20, 128) => Ok(Self::AesGcm16_128),
            (20, 256) => Ok(Self::AesGcm16_256),
            _ => Err(Error::Unsupported("ENCR")),
        }
    }
    pub fn is_aead(self) -> bool {
        matches!(self, Self::AesGcm16_128 | Self::AesGcm16_256)
    }
    /// Longueur de clé AES (octets).
    pub fn key_len(self) -> usize {
        match self {
            Self::AesCbc128 | Self::AesGcm16_128 => 16,
            Self::AesCbc256 | Self::AesGcm16_256 => 32,
        }
    }
    /// Sel GCM (RFC 5282) inclus dans SK_e*.
    pub fn salt_len(self) -> usize {
        if self.is_aead() { 4 } else { 0 }
    }
    pub fn iv_len(self) -> usize {
        if self.is_aead() { 8 } else { 16 }
    }
}

/// Algorithme d'intégrité (absent en AEAD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integ {
    HmacSha1_96,
    HmacSha256_128,
}

impl Integ {
    pub fn from_id(id: u16) -> Result<Self> {
        match id {
            2 => Ok(Self::HmacSha1_96),
            12 => Ok(Self::HmacSha256_128),
            _ => Err(Error::Unsupported("INTEG")),
        }
    }
    pub fn key_len(self) -> usize {
        match self {
            Self::HmacSha1_96 => 20,
            Self::HmacSha256_128 => 32,
        }
    }
    pub fn icv_len(self) -> usize {
        match self {
            Self::HmacSha1_96 => 12,
            Self::HmacSha256_128 => 16,
        }
    }
    pub(crate) fn icv(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let full = match self {
            Self::HmacSha1_96 => Prf::HmacSha1.compute(key, &[data]),
            Self::HmacSha256_128 => Prf::HmacSha256.compute(key, &[data]),
        };
        full[..self.icv_len()].to_vec()
    }
}

/// Suite cryptographique négociée de l'IKE SA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IkeSuite {
    pub prf: Prf,
    pub encr: Encr,
    /// `None` ssi `encr` est AEAD.
    pub integ: Option<Integ>,
}

impl IkeSuite {
    pub fn new(encr: Encr, prf: Prf, integ: Option<Integ>) -> Result<Self> {
        if encr.is_aead() != integ.is_none() {
            return Err(Error::Unsupported(
                "combinaison ENCR/INTEG (AEAD sans INTEG, CBC avec)",
            ));
        }
        Ok(Self { prf, encr, integ })
    }
    pub(crate) fn icv_len(self) -> usize {
        self.integ.map_or(16, Integ::icv_len)
    }
}

/// Clés de l'IKE SA. Zeroize à la destruction ; `Debug` masqué.
pub struct SkKeys {
    pub sk_d: Zeroizing<Vec<u8>>,
    pub sk_ai: Zeroizing<Vec<u8>>,
    pub sk_ar: Zeroizing<Vec<u8>>,
    /// Clé AES (+ sel GCM de 4 octets en fin).
    pub sk_ei: Zeroizing<Vec<u8>>,
    pub sk_er: Zeroizing<Vec<u8>>,
    pub sk_pi: Zeroizing<Vec<u8>>,
    pub sk_pr: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for SkKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SkKeys(<masqué>)")
    }
}

/// Dérive SKEYSEED puis SK_* (RFC 7296 §2.14). `shared` = g^ir.
pub fn derive_sk_keys(
    suite: &IkeSuite,
    ni: &[u8],
    nr: &[u8],
    spi_i: &[u8; 8],
    spi_r: &[u8; 8],
    shared: &[u8],
) -> Result<SkKeys> {
    let mut nonces = Vec::with_capacity(ni.len() + nr.len());
    nonces.extend_from_slice(ni);
    nonces.extend_from_slice(nr);
    let skeyseed = suite.prf.compute(&nonces, &[shared]);
    expand_sk_keys(*suite, &skeyseed, nonces, *spi_i, *spi_r)
}

/// SK_* d'une IKE SA issue d'un rekey (RFC 7296 §2.18) :
/// `SKEYSEED = prf(SK_d(ancienne), g^ir(new) | Ni | Nr)`, SPI = ceux de la nouvelle SA.
pub fn derive_sk_keys_rekey(
    suite: &IkeSuite,
    sk_d_old: &[u8],
    ni: &[u8],
    nr: &[u8],
    spi_i: &[u8; 8],
    spi_r: &[u8; 8],
    shared: &[u8],
) -> Result<SkKeys> {
    let skeyseed = suite.prf.compute(sk_d_old, &[shared, ni, nr]);
    let mut nonces = Vec::with_capacity(ni.len() + nr.len());
    nonces.extend_from_slice(ni);
    nonces.extend_from_slice(nr);
    expand_sk_keys(*suite, &skeyseed, nonces, *spi_i, *spi_r)
}

fn expand_sk_keys(
    suite: IkeSuite,
    skeyseed: &[u8],
    nonces: Vec<u8>,
    spi_i: [u8; 8],
    spi_r: [u8; 8],
) -> Result<SkKeys> {
    let mut seed = nonces;
    seed.extend_from_slice(&spi_i);
    seed.extend_from_slice(&spi_r);

    let p = suite.prf.output_len();
    let a = suite.integ.map_or(0, Integ::key_len);
    let e = suite.encr.key_len() + suite.encr.salt_len();
    let total = p + 2 * a + 2 * e + 2 * p;
    let km = prf_plus(suite.prf, skeyseed, &seed, total)?;
    let mut pos = 0;
    let mut take = |n: usize| {
        let v = Zeroizing::new(km[pos..pos + n].to_vec());
        pos += n;
        v
    };
    let keys = SkKeys {
        sk_d: take(p),
        sk_ai: take(a),
        sk_ar: take(a),
        sk_ei: take(e),
        sk_er: take(e),
        sk_pi: take(p),
        sk_pr: take(p),
    };
    seed.zeroize();
    Ok(keys)
}

/// Valeur AUTH (méthode 2, clé partagée) — RFC 7296 §2.15.
///
/// `real_message` : IKE_SA_INIT envoyé par l'émetteur de l'AUTH ; `peer_nonce` : nonce de
/// l'autre partie ; `sk_p` : SK_pi (initiateur) ou SK_pr ; `id_body` : IDx' ([`crate::wire::id_body`]).
/// `secret` : PSK (ASCII) ou MSK EAP.
pub fn auth_value(
    prf: Prf,
    secret: &[u8],
    real_message: &[u8],
    peer_nonce: &[u8],
    sk_p: &[u8],
    id_body: &[u8],
) -> Zeroizing<Vec<u8>> {
    let maced_id = prf.compute(sk_p, &[id_body]);
    let key = prf.compute(secret, &[b"Key Pad for IKEv2"]);
    prf.compute(&key, &[real_message, peer_nonce, &maced_id])
}

/// Comparaison en temps constant.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Groupe Diffie-Hellman.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhGroup {
    /// Groupe 14, MODP 2048 bits.
    Modp2048,
    /// Groupe 19, ECP 256 bits.
    Ecp256,
}

const MODP2048_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

fn modp_prime() -> BigUint {
    let bytes: Vec<u8> = (0..MODP2048_HEX.len() / 2)
        .filter_map(|i| u8::from_str_radix(&MODP2048_HEX[2 * i..2 * i + 2], 16).ok())
        .collect();
    BigUint::from_bytes_be(&bytes)
}

/// `base^exp mod p` par carré-multiplié sur les octets de l'exposant : l'exposant secret ne
/// passe jamais dans un `BigUint` (non effaçable) et reste dans le tampon `Zeroizing` de l'appelant.
fn modpow_secret(base: &BigUint, exp_be: &[u8], p: &BigUint) -> BigUint {
    let mut acc = BigUint::from(1u8);
    for byte in exp_be {
        for i in (0..8).rev() {
            acc = (&acc * &acc) % p;
            if (byte >> i) & 1 == 1 {
                acc = (&acc * base) % p;
            }
        }
    }
    acc
}

fn pad_be(n: &BigUint, len: usize) -> Vec<u8> {
    let b = n.to_bytes_be();
    let mut v = vec![0u8; len.saturating_sub(b.len())];
    v.extend_from_slice(&b);
    v
}

impl DhGroup {
    pub fn from_id(id: u16) -> Result<Self> {
        match id {
            14 => Ok(Self::Modp2048),
            19 => Ok(Self::Ecp256),
            _ => Err(Error::Unsupported("groupe DH")),
        }
    }
    pub fn id(self) -> u16 {
        match self {
            Self::Modp2048 => 14,
            Self::Ecp256 => 19,
        }
    }
    /// Taille de la valeur publique (payload KE) en octets.
    pub fn public_len(self) -> usize {
        match self {
            Self::Modp2048 => 256,
            Self::Ecp256 => 64,
        }
    }
}

/// Paire de clés DH éphémère. L'aléa (32 octets) est fourni par l'appelant (sans-io).
pub struct DhKeypair {
    group: DhGroup,
    private: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
}

impl core::fmt::Debug for DhKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DhKeypair")
            .field("group", &self.group)
            .finish_non_exhaustive()
    }
}

impl DhKeypair {
    /// `private` : 32 octets aléatoires (CSPRNG). Pour ECP, doit être un scalaire valide
    /// (tirer à nouveau en cas d'erreur, probabilité ~2^-128).
    pub fn new(group: DhGroup, private: &[u8]) -> Result<Self> {
        if private.len() != 32 {
            return Err(Error::Crypto("clé privée DH : 32 octets requis"));
        }
        let public = match group {
            DhGroup::Modp2048 => {
                if private.iter().all(|&b| b == 0)
                    || private[..31].iter().all(|&b| b == 0) && private[31] < 2
                {
                    return Err(Error::Crypto("exposant DH trop petit"));
                }
                pad_be(
                    &modpow_secret(&BigUint::from(2u8), private, &modp_prime()),
                    256,
                )
            }
            DhGroup::Ecp256 => {
                let sk = p256::SecretKey::from_slice(private)
                    .map_err(|_| Error::Crypto("scalaire P-256 invalide"))?;
                let pt = p256::EncodedPoint::from(sk.public_key());
                pt.as_bytes()[1..].to_vec()
            }
        };
        Ok(Self {
            group,
            private: Zeroizing::new(private.to_vec()),
            public,
        })
    }

    pub fn group(&self) -> DhGroup {
        self.group
    }

    /// Valeur du payload KE.
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// Secret partagé g^ir (MODP : 256 octets avec zéros de tête ; ECP : x sur 32 octets).
    pub fn shared_secret(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if peer.len() != self.group.public_len() {
            return Err(Error::Crypto("valeur KE du pair de taille invalide"));
        }
        match self.group {
            DhGroup::Modp2048 => {
                let p = modp_prime();
                let y = BigUint::from_bytes_be(peer);
                if y <= BigUint::from(1u8) || y >= &p - BigUint::from(1u8) {
                    return Err(Error::Crypto("valeur publique DH hors plage"));
                }
                Ok(Zeroizing::new(pad_be(
                    &modpow_secret(&y, &self.private, &p),
                    256,
                )))
            }
            DhGroup::Ecp256 => {
                let mut sec1 = Vec::with_capacity(65);
                sec1.push(4);
                sec1.extend_from_slice(peer);
                let pk = p256::PublicKey::from_sec1_bytes(&sec1)
                    .map_err(|_| Error::Crypto("point P-256 invalide"))?;
                let sk = p256::SecretKey::from_slice(&self.private)
                    .map_err(|_| Error::Crypto("scalaire P-256 invalide"))?;
                let ss = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
                Ok(Zeroizing::new(ss.raw_secret_bytes().to_vec()))
            }
        }
    }
}
