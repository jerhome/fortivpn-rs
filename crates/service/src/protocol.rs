//! Protocole client ↔ service : une requête JSON par connexion, une réponse JSON,
//! chacune sur **une ligne** (`\n`) de **16 Kio au plus**.
//!
//! La requête ne porte que des ordres : `connect{password}`, `disconnect`,
//! `status`. Elle ne peut jamais fournir hôte, utilisateur, realm, empreinte,
//! chemin, ni aucune option (revue 5.3, M4) : tout champ inconnu est refusé
//! (`deny_unknown_fields`) et la configuration vient d'un fichier protégé côté
//! service.
//!
//! Le mot de passe n'existe que dans un `Zeroizing<String>` / `SecretString` ; les
//! tampons de lecture/écriture sont effacés au `Drop`, préalloués à leur taille
//! maximale (aucune réallocation qui laisserait une copie), et les messages
//! d'erreur ne recopient jamais l'entrée (une erreur `serde_json` peut citer la
//! valeur fautive).

use std::io;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};
use zeroize::Zeroizing;

/// Nom du named pipe.
pub const PIPE_NAME: &str = r"\\.\pipe\fortivpn-rs";

/// Taille maximale d'un message, `\n` final compris.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;

/// Longueur maximale du mot de passe (octets UTF-8).
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Délai accordé au client pour envoyer sa requête complète.
pub(crate) const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Droits accordés aux utilisateurs interactifs sur le pipe : lecture/écriture de
/// données (`FILE_GENERIC_READ | FILE_GENERIC_WRITE` **sans**
/// `FILE_CREATE_PIPE_INSTANCE`, alias `FILE_APPEND_DATA`, qui permettrait de créer
/// une instance concurrente du pipe et d'intercepter des connexions).
pub const PIPE_USER_ACCESS_MASK: u32 = 0x0012_019B;

/// DACL du pipe : SYSTEM et Administrateurs en contrôle total, utilisateurs
/// interactifs (`IU`) en lecture/écriture seulement ; DACL protégée (pas d'héritage).
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)";

/// Requête du client.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Établit la connexion VPN (la configuration est celle du service).
    Connect {
        /// Mot de passe, saisi à chaque connexion, jamais stocké.
        password: Zeroizing<String>,
    },
    /// Coupe la connexion (idempotent).
    // Variantes à champs (vides) et non unitaires : `deny_unknown_fields` n'est
    // pas appliqué aux variantes unitaires d'une énumération à tag interne.
    Disconnect {},
    /// État courant.
    Status {},
}

// Jamais de `derive(Debug)` : il afficherait le mot de passe.
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect { .. } => f.write_str("Connect { password: <masqué> }"),
            Self::Disconnect {} => f.write_str("Disconnect"),
            Self::Status {} => f.write_str("Status"),
        }
    }
}

/// Code d'erreur stable (aussi utilisé pour l'issue d'une session).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Requête invalide (syntaxe, taille, champ inconnu, mot de passe vide/trop long).
    BadRequest,
    /// Une connexion est déjà en cours ou établie.
    Busy,
    /// Configuration du service absente, invalide ou non protégée.
    Config,
    /// Identifiants refusés par la passerelle.
    AuthRejected,
    /// Erreur côté passerelle (connexion, TLS, tunnel perdu).
    Connection,
    /// Erreur réseau locale (TUN, routes, DNS).
    LocalNetwork,
    /// Une autre instance tient déjà le verrou réseau.
    AlreadyRunning,
    /// Délai d'attente dépassé (la connexion peut encore aboutir : `status`).
    Timeout,
    /// Erreur interne.
    Internal,
    /// Opération réservée au propriétaire de la session (ou à un administrateur).
    Forbidden,
    /// Trop d'échecs d'authentification : attendre avant de réessayer.
    RateLimited,
}

/// Issue de la dernière session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    /// `None` : arrêt demandé (succès) ; sinon, la cause.
    pub error: Option<ErrorCode>,
    /// Texte lisible, sans secret.
    pub message: String,
}

impl Outcome {
    /// Arrêt demandé.
    pub fn requested() -> Self {
        Self {
            error: None,
            message: "arrêt demandé".into(),
        }
    }

    /// Échec.
    pub fn failed(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            error: Some(code),
            message: message.into(),
        }
    }
}

/// État du service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Aucune connexion.
    Idle,
    /// Connexion à la passerelle.
    Connecting,
    /// Identifiants acceptés.
    Authenticated,
    /// Configuration reçue.
    ConfigReceived,
    /// Tunnel actif.
    TunnelUp,
    /// Arrêt en cours (nettoyage réseau).
    Disconnecting,
}

/// Instants (ms depuis le début de la connexion) où chaque étape a été atteinte.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepTimings {
    /// Début de la connexion (normalement 0).
    pub connecting_ms: Option<u64>,
    /// Authentification acceptée.
    pub authenticated_ms: Option<u64>,
    /// Configuration reçue.
    pub config_received_ms: Option<u64>,
    /// Tunnel actif.
    pub tunnel_up_ms: Option<u64>,
}

/// Rapport d'état.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusReport {
    /// État courant.
    pub state: State,
    /// Chronométrage des étapes de la connexion courante (ou de la dernière).
    pub steps: StepTimings,
    /// Durée depuis l'établissement du tunnel, si actif.
    pub connected_for_ms: Option<u64>,
    /// Description du tunnel (interface, adresse), si actif.
    pub tunnel: Option<String>,
    /// Issue de la dernière session terminée.
    pub last_outcome: Option<Outcome>,
}

/// Réponse du service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    /// Succès.
    Ok {
        /// État après l'ordre.
        status: StatusReport,
    },
    /// Échec.
    Error {
        /// Code stable.
        code: ErrorCode,
        /// Texte lisible, sans secret.
        message: String,
    },
}

impl Response {
    /// Réponse d'erreur.
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error {
            code,
            message: message.into(),
        }
    }
}

/// Erreur de protocole (jamais de contenu de l'entrée dans les messages).
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// Message de plus de [`MAX_MESSAGE_BYTES`] octets.
    #[error("message trop long (> {MAX_MESSAGE_BYTES} octets)")]
    TooLong,
    /// Fin de flux avant le `\n` final, ou octets après le `\n`.
    #[error("message mal terminé")]
    Framing,
    /// JSON invalide, champ inconnu ou type incorrect.
    #[error("message invalide")]
    Invalid,
    /// Mot de passe vide, trop long ou contenant un NUL.
    #[error("mot de passe invalide")]
    BadPassword,
    /// Erreur d'entrée/sortie.
    #[error("erreur d'E/S : {0}")]
    Io(#[from] io::Error),
}

/// Valide une requête décodée.
pub(crate) fn validate(request: &Request) -> Result<(), ProtocolError> {
    if let Request::Connect { password } = request
        && (password.is_empty() || password.len() > MAX_PASSWORD_BYTES || password.contains('\0'))
    {
        return Err(ProtocolError::BadPassword);
    }
    Ok(())
}

/// Lit un message (une ligne ≤ [`MAX_MESSAGE_BYTES`]) dans un tampon effacé au
/// `Drop`. Le `\n` final est retiré. Les octets au-delà du `\n` sont une erreur
/// (une seule requête par connexion).
pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    // Capacité fixe : `read_buf` n'a jamais à réallouer (ce qui laisserait une copie
    // non effacée) tant que `len < MAX_MESSAGE_BYTES`.
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_MESSAGE_BYTES));
    let mut scanned = 0;
    loop {
        if buf.len() >= MAX_MESSAGE_BYTES && !buf[scanned..].contains(&b'\n') {
            return Err(ProtocolError::TooLong);
        }
        if let Some(pos) = buf[scanned..].iter().position(|&b| b == b'\n') {
            let end = scanned + pos;
            if end + 1 != buf.len() {
                return Err(ProtocolError::Framing);
            }
            buf.truncate(end);
            return Ok(buf);
        }
        scanned = buf.len();
        if reader.read_buf(&mut *buf).await? == 0 {
            return Err(ProtocolError::Framing);
        }
    }
}

/// Décode et valide une requête (sans la recopier dans l'erreur).
pub fn decode_request(line: &[u8]) -> Result<Request, ProtocolError> {
    let request: Request = serde_json::from_slice(line).map_err(|_| ProtocolError::Invalid)?;
    validate(&request)?;
    Ok(request)
}

/// Encode un message : JSON + `\n`, dans un tampon préalloué effacé au `Drop`.
fn encode<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_MESSAGE_BYTES));
    serde_json::to_writer(&mut *buf, value).map_err(|_| ProtocolError::Invalid)?;
    buf.push(b'\n');
    if buf.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::TooLong);
    }
    Ok(buf)
}

/// Encode une requête (validée) en une ligne.
pub fn encode_request(request: &Request) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    validate(request)?;
    encode(request)
}

/// Encode une réponse en une ligne.
pub fn encode_response(response: &Response) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    encode(response)
}

/// Décode une réponse.
pub fn decode_response(line: &[u8]) -> Result<Response, ProtocolError> {
    serde_json::from_slice(line).map_err(|_| ProtocolError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect(pw: &str) -> Request {
        Request::Connect {
            password: Zeroizing::new(pw.to_owned()),
        }
    }

    async fn read(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let mut r = bytes;
        read_message(&mut r).await
    }

    #[test]
    fn roundtrip_requests() {
        for req in [
            connect("pässwörd \"q\" \\"),
            Request::Disconnect {},
            Request::Status {},
        ] {
            let line = encode_request(&req).unwrap();
            assert_eq!(line.last(), Some(&b'\n'));
            assert_eq!(decode_request(&line[..line.len() - 1]).unwrap(), req);
        }
    }

    #[test]
    fn wire_format_is_stable() {
        assert_eq!(
            &**encode_request(&Request::Status {}).unwrap(),
            b"{\"cmd\":\"status\"}\n"
        );
        assert_eq!(
            decode_request(br#"{"cmd":"connect","password":"x"}"#).unwrap(),
            connect("x")
        );
    }

    #[test]
    fn requests_cannot_carry_options() {
        // Revue 5.3 M4 : ni hôte, ni chemin, ni DLL, ni état, ni option quelconque.
        for bad in [
            &br#"{"cmd":"connect","password":"x","host":"evil"}"#[..],
            br#"{"cmd":"connect","password":"x","wintun_dll":"C:\\evil.dll"}"#,
            br#"{"cmd":"connect","password":"x","state_path":"x"}"#,
            br#"{"cmd":"connect","password":"x","config":"x"}"#,
            br#"{"cmd":"status","config":"x"}"#,
            br#"{"cmd":"disconnect","x":1}"#,
            br#"{"cmd":"shutdown"}"#,
            br#"{"cmd":"connect"}"#,
            br#"{"password":"x"}"#,
            b"[]",
            b"",
            b"\xff\xfe",
        ] {
            assert!(
                matches!(decode_request(bad), Err(ProtocolError::Invalid)),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn password_rules() {
        assert!(matches!(
            decode_request(br#"{"cmd":"connect","password":""}"#),
            Err(ProtocolError::BadPassword)
        ));
        assert!(matches!(
            decode_request(br#"{"cmd":"connect","password":"a\u0000b"}"#),
            Err(ProtocolError::BadPassword)
        ));
        let long = "a".repeat(MAX_PASSWORD_BYTES + 1);
        assert!(matches!(
            encode_request(&connect(&long)),
            Err(ProtocolError::BadPassword)
        ));
        assert!(encode_request(&connect(&"a".repeat(MAX_PASSWORD_BYTES))).is_ok());
    }

    #[test]
    fn errors_never_echo_input() {
        let secret = "TOPSECRET-value";
        let line = format!(r#"{{"cmd":"connect","password":"{secret}","host":1}}"#);
        let e = decode_request(line.as_bytes()).unwrap_err().to_string();
        assert!(!e.contains(secret), "{e}");
        let dbg = format!("{:?}", connect(secret));
        assert!(!dbg.contains(secret));
    }

    #[tokio::test]
    async fn framing_and_size_limits() {
        assert_eq!(
            &**read(b"{\"cmd\":\"status\"}\n").await.unwrap(),
            b"{\"cmd\":\"status\"}"
        );
        // Pas de \n final, flux vide, octets après le \n.
        assert!(matches!(
            read(b"{\"cmd\":\"status\"}").await,
            Err(ProtocolError::Framing)
        ));
        assert!(matches!(read(b"").await, Err(ProtocolError::Framing)));
        assert!(matches!(
            read(b"{}\n{}\n").await,
            Err(ProtocolError::Framing)
        ));
        // Exactement 16 Kio avec \n : accepté ; un octet de plus : refusé.
        let mut ok = vec![b'a'; MAX_MESSAGE_BYTES - 1];
        ok.push(b'\n');
        assert_eq!(read(&ok).await.unwrap().len(), MAX_MESSAGE_BYTES - 1);
        let mut big = vec![b'a'; MAX_MESSAGE_BYTES];
        big.push(b'\n');
        assert!(matches!(read(&big).await, Err(ProtocolError::TooLong)));
        // Sans jamais de \n : borné aussi.
        assert!(matches!(
            read(&vec![b'a'; 10 * MAX_MESSAGE_BYTES]).await,
            Err(ProtocolError::TooLong)
        ));
    }

    #[tokio::test]
    async fn read_works_across_small_chunks() {
        let (mut tx, mut rx) = tokio::io::duplex(8);
        let writer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            tx.write_all(b"{\"cmd\":\"status\"}\n").await.unwrap();
        });
        assert_eq!(
            &**read_message(&mut rx).await.unwrap(),
            b"{\"cmd\":\"status\"}"
        );
        writer.await.unwrap();
    }

    #[test]
    fn sddl_is_strict() {
        // Pas de SID large (WD, AU, BU, NU…), DACL protégée, pas d'écriture-ajout
        // (FILE_CREATE_PIPE_INSTANCE = 0x4) pour IU.
        assert!(PIPE_SDDL.starts_with("D:P("));
        for wide in [";WD)", ";AU)", ";BU)", ";NU)", ";AN)", ";S-1-1-0)"] {
            assert!(!PIPE_SDDL.contains(wide), "{wide}");
        }
        assert!(PIPE_SDDL.contains("(A;;GA;;;SY)") && PIPE_SDDL.contains("(A;;GA;;;BA)"));
        assert_eq!(PIPE_USER_ACCESS_MASK & 0x4, 0);
        assert_eq!(PIPE_USER_ACCESS_MASK & 0x3, 0x3);
        assert!(PIPE_SDDL.contains(&format!("(A;;{PIPE_USER_ACCESS_MASK:#x};;;IU)")));
    }

    #[test]
    fn response_roundtrip() {
        let r = Response::error(ErrorCode::Busy, "occupé");
        let line = encode_response(&r).unwrap();
        assert_eq!(decode_response(&line[..line.len() - 1]).unwrap(), r);
    }
}
