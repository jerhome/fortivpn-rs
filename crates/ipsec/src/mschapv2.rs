//! EAP-MSCHAPv2 (RFC 2759, draft-kamath-pppext-eap-mschapv2) et MSK (RFC 3079).
//!
//! Le mot de passe est un [`SecretString`] ; tous les secrets intermédiaires sont zeroizés.

use core::fmt::Write as _;
use des::Des;
use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockEncrypt, KeyInit};
use md4::{Digest as _, Md4};
use secrecy::{ExposeSecret, SecretString};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const MAGIC1: &[u8] = b"Magic server to client signing constant";
const MAGIC2: &[u8] = b"Pad to make it do more than one iteration";
const MPPE_MAGIC1: &[u8] = b"This is the MPPE Master Key";
const MPPE_MAGIC2: &[u8] =
    b"On the client side, this is the send key; on the server side, it is the receive key.";
const MPPE_MAGIC3: &[u8] =
    b"On the client side, this is the receive key; on the server side, it is the send key.";

/// Type EAP de MS-CHAPv2.
pub const EAP_TYPE_MSCHAPV2: u8 = 26;

/// `NtPasswordHash` : MD4(UTF-16LE(mot de passe)).
pub fn nt_password_hash(password: &SecretString) -> Zeroizing<[u8; 16]> {
    let mut utf16: Zeroizing<Vec<u8>> = Zeroizing::new(
        password
            .expose_secret()
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect(),
    );
    let h = Md4::digest(&utf16[..]);
    utf16.iter_mut().for_each(|b| *b = 0);
    Zeroizing::new(h.into())
}

fn hash_hash(password_hash: &[u8; 16]) -> Zeroizing<[u8; 16]> {
    Zeroizing::new(Md4::digest(password_hash).into())
}

/// `ChallengeHash` : SHA1(PeerChallenge | AuthenticatorChallenge | UserName)[..8].
/// `user` : nom sans préfixe `DOMAINE\`.
pub fn challenge_hash(peer: &[u8; 16], auth: &[u8; 16], user: &str) -> [u8; 8] {
    use sha1::Digest;
    let user = user.rsplit('\\').next().unwrap_or(user);
    let mut h = Sha1::new();
    h.update(peer);
    h.update(auth);
    h.update(user.as_bytes());
    let d = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    out
}

fn des_key_from_7(k: &[u8]) -> Zeroizing<[u8; 8]> {
    let mut o = Zeroizing::new([0u8; 8]);
    o[0] = k[0] & 0xfe;
    o[1] = (k[0] << 7) | (k[1] >> 1);
    o[2] = (k[1] << 6) | (k[2] >> 2);
    o[3] = (k[2] << 5) | (k[3] >> 3);
    o[4] = (k[3] << 4) | (k[4] >> 4);
    o[5] = (k[4] << 3) | (k[5] >> 5);
    o[6] = (k[5] << 2) | (k[6] >> 6);
    o[7] = k[6] << 1;
    // Bits de parité impaire (ignorés par DES mais fournis pour la forme).
    for b in o.iter_mut() {
        let ones = (*b & 0xfe).count_ones();
        *b = (*b & 0xfe) | u8::from(ones % 2 == 0);
    }
    o
}

/// `ChallengeResponse` (RFC 2759 §8.5) : 3 × DES-ECB du ChallengeHash.
pub fn challenge_response(challenge: &[u8; 8], password_hash: &[u8; 16]) -> [u8; 24] {
    let mut z = Zeroizing::new([0u8; 21]);
    z[..16].copy_from_slice(password_hash);
    let mut out = [0u8; 24];
    for i in 0..3 {
        let key = des_key_from_7(&z[i * 7..i * 7 + 7]);
        // Une clé de 8 octets est toujours valide pour DES.
        let cipher = Des::new(GenericArray::from_slice(&key[..]));
        let mut block = GenericArray::clone_from_slice(challenge);
        cipher.encrypt_block(&mut block);
        out[i * 8..i * 8 + 8].copy_from_slice(&block);
    }
    out
}

/// `GenerateNTResponse` (RFC 2759 §8.1).
pub fn generate_nt_response(
    auth_challenge: &[u8; 16],
    peer_challenge: &[u8; 16],
    user: &str,
    password: &SecretString,
) -> [u8; 24] {
    let ch = challenge_hash(peer_challenge, auth_challenge, user);
    let ph = nt_password_hash(password);
    challenge_response(&ch, &ph)
}

/// `GenerateAuthenticatorResponse` (RFC 2759 §8.7) : `"S=" + 40 hex majuscules`.
pub fn generate_authenticator_response(
    password: &SecretString,
    nt_response: &[u8; 24],
    peer_challenge: &[u8; 16],
    auth_challenge: &[u8; 16],
    user: &str,
) -> String {
    use sha1::Digest;
    let phh = hash_hash(&nt_password_hash(password));
    let mut h = Sha1::new();
    h.update(&phh[..]);
    h.update(nt_response);
    h.update(MAGIC1);
    let d1 = h.finalize();
    let ch = challenge_hash(peer_challenge, auth_challenge, user);
    let mut h = Sha1::new();
    h.update(d1);
    h.update(ch);
    h.update(MAGIC2);
    let d2 = h.finalize();
    let mut s = String::from("S=");
    for b in d2 {
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// `MasterKey` RFC 3079 §3.4 (GetMasterKey).
pub fn mppe_master_key(password: &SecretString, nt_response: &[u8; 24]) -> Zeroizing<[u8; 16]> {
    use sha1::Digest;
    let phh = hash_hash(&nt_password_hash(password));
    let mut h = Sha1::new();
    h.update(&phh[..]);
    h.update(nt_response);
    h.update(MPPE_MAGIC1);
    let d = h.finalize();
    let mut k = Zeroizing::new([0u8; 16]);
    k.copy_from_slice(&d[..16]);
    k
}

fn start_key(master: &[u8; 16], magic: &[u8]) -> Zeroizing<[u8; 16]> {
    use sha1::Digest;
    let mut h = Sha1::new();
    h.update(master);
    h.update([0u8; 40]);
    h.update(magic);
    h.update([0xf2u8; 40]);
    let d = h.finalize();
    let mut k = Zeroizing::new([0u8; 16]);
    k.copy_from_slice(&d[..16]);
    k
}

/// MSK EAP (64 octets) : MasterReceiveKey | MasterSendKey | 32 × 0 (cf. protocol-ipsec.md §2.6).
pub fn eap_msk(password: &SecretString, nt_response: &[u8; 24]) -> Zeroizing<[u8; 64]> {
    let master = mppe_master_key(password, nt_response);
    let mut msk = Zeroizing::new([0u8; 64]);
    msk[..16].copy_from_slice(&start_key(&master, MPPE_MAGIC2)[..]);
    msk[16..32].copy_from_slice(&start_key(&master, MPPE_MAGIC3)[..]);
    msk
}

/// Paquet EAP (RFC 3748).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapPacket {
    /// 1 Request, 2 Response, 3 Success, 4 Failure.
    pub code: u8,
    pub id: u8,
    /// Type + données ; vide pour Success/Failure.
    pub data: Vec<u8>,
}

impl EapPacket {
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < 4 {
            return Err(Error::Truncated);
        }
        let len = usize::from(u16::from_be_bytes([b[2], b[3]]));
        if len < 4 || len > b.len() {
            return Err(Error::Malformed("longueur EAP invalide"));
        }
        Ok(Self {
            code: b[0],
            id: b[1],
            data: b[4..len].to_vec(),
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let len = u16::try_from(self.data.len() + 4).map_err(|_| Error::TooLarge("EAP"))?;
        let mut v = vec![self.code, self.id];
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(&self.data);
        Ok(v)
    }
    /// Response/Identity portant le nom d'utilisateur.
    pub fn identity_response(id: u8, user: &str) -> Self {
        let mut data = vec![1];
        data.extend_from_slice(user.as_bytes());
        Self { code: 2, id, data }
    }
}

/// Message MS-CHAPv2 (corps après le type EAP 26).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsChapV2 {
    Challenge {
        id: u8,
        challenge: [u8; 16],
        name: Vec<u8>,
    },
    Response {
        id: u8,
        peer_challenge: [u8; 16],
        nt_response: [u8; 24],
        name: Vec<u8>,
    },
    /// `message` : texte « S=… M=… » côté serveur ; vide côté client.
    Success {
        id: u8,
        message: Vec<u8>,
    },
    Failure {
        id: u8,
        message: Vec<u8>,
    },
}

impl MsChapV2 {
    /// Décode les données d'un paquet EAP (type + corps) de type 26.
    pub fn parse(eap_data: &[u8]) -> Result<Self> {
        if eap_data.first() != Some(&EAP_TYPE_MSCHAPV2) {
            return Err(Error::Malformed("pas EAP-MSCHAPv2"));
        }
        let b = &eap_data[1..];
        if b.len() < 4 {
            return Err(Error::Truncated);
        }
        let (op, id) = (b[0], b[1]);
        let ms_len = usize::from(u16::from_be_bytes([b[2], b[3]]));
        if ms_len < 4 || ms_len > b.len() {
            return Err(Error::Malformed("MS-Length invalide"));
        }
        let d = &b[4..ms_len];
        match op {
            1 => {
                if d.len() < 17 || d[0] != 16 {
                    return Err(Error::Malformed("Challenge invalide"));
                }
                let mut challenge = [0u8; 16];
                challenge.copy_from_slice(&d[1..17]);
                Ok(Self::Challenge {
                    id,
                    challenge,
                    name: d[17..].to_vec(),
                })
            }
            2 => {
                if d.len() < 50 || d[0] != 49 {
                    return Err(Error::Malformed("Response invalide"));
                }
                let mut peer_challenge = [0u8; 16];
                peer_challenge.copy_from_slice(&d[1..17]);
                let mut nt_response = [0u8; 24];
                nt_response.copy_from_slice(&d[25..49]);
                Ok(Self::Response {
                    id,
                    peer_challenge,
                    nt_response,
                    name: d[50..].to_vec(),
                })
            }
            3 => Ok(Self::Success {
                id,
                message: d.to_vec(),
            }),
            4 => Ok(Self::Failure {
                id,
                message: d.to_vec(),
            }),
            _ => Err(Error::Unsupported("OpCode MS-CHAPv2")),
        }
    }

    /// Encode en données EAP (type 26 + corps).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let (op, id, body): (u8, u8, Vec<u8>) = match self {
            Self::Challenge {
                id,
                challenge,
                name,
            } => {
                let mut v = vec![16];
                v.extend_from_slice(challenge);
                v.extend_from_slice(name);
                (1, *id, v)
            }
            Self::Response {
                id,
                peer_challenge,
                nt_response,
                name,
            } => {
                let mut v = vec![49];
                v.extend_from_slice(peer_challenge);
                v.extend_from_slice(&[0u8; 8]);
                v.extend_from_slice(nt_response);
                v.push(0);
                v.extend_from_slice(name);
                (2, *id, v)
            }
            Self::Success { id, message } => (3, *id, message.clone()),
            Self::Failure { id, message } => (4, *id, message.clone()),
        };
        let ms_len = u16::try_from(body.len() + 4).map_err(|_| Error::TooLarge("MS-CHAPv2"))?;
        let mut v = vec![EAP_TYPE_MSCHAPV2, op, id];
        v.extend_from_slice(&ms_len.to_be_bytes());
        v.extend_from_slice(&body);
        Ok(v)
    }
}

/// Résultat du traitement d'un Challenge côté client.
pub struct ClientResponse {
    /// Données EAP de la Response (à placer dans un EapPacket code 2).
    pub eap_data: Vec<u8>,
    pub nt_response: [u8; 24],
    pub peer_challenge: [u8; 16],
    pub auth_challenge: [u8; 16],
}

impl core::fmt::Debug for ClientResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ClientResponse(<masqué>)")
    }
}

/// Construit la Response à partir d'un Challenge (`peer_challenge` : 16 octets aléatoires).
pub fn respond(
    id: u8,
    auth_challenge: &[u8; 16],
    peer_challenge: &[u8; 16],
    user: &str,
    password: &SecretString,
) -> Result<ClientResponse> {
    let nt_response = generate_nt_response(auth_challenge, peer_challenge, user, password);
    let eap_data = MsChapV2::Response {
        id,
        peer_challenge: *peer_challenge,
        nt_response,
        name: user.as_bytes().to_vec(),
    }
    .encode()?;
    Ok(ClientResponse {
        eap_data,
        nt_response,
        peer_challenge: *peer_challenge,
        auth_challenge: *auth_challenge,
    })
}

/// Vérifie le `S=…` du Success serveur (authentification mutuelle, comparaison en temps constant).
pub fn verify_success(
    message: &[u8],
    password: &SecretString,
    resp: &ClientResponse,
    user: &str,
) -> bool {
    let expect = generate_authenticator_response(
        password,
        &resp.nt_response,
        &resp.peer_challenge,
        &resp.auth_challenge,
        user,
    );
    message.len() >= 42 && crate::crypto::ct_eq(&message[..42], expect.as_bytes())
}
