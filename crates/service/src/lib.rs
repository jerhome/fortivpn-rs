//! Service Windows (compte SYSTEM) piloté par un client non administrateur via un
//! named pipe (story 4.3).
//!
//! # Architecture
//!
//! - `protocol` : messages JSON ligne par ligne (≤ 16 Kio), validation, DACL du
//!   pipe — pur, testé sous Linux.
//! - `status` : machine d'états (`idle → connecting → authenticated →
//!   config_received → tunnel_up → disconnecting`) et chronométrage — pur.
//! - `controller` : applique les requêtes, lance la session sur un thread dédié via
//!   [`SessionRunner`] (fourni par le binaire : il lit la configuration protégée,
//!   construit transport et backend réseau) ; sert une connexion sur n'importe quel
//!   flux async — testé sous Linux avec des flux en mémoire.
//! - `client` : un échange requête/réponse.
//! - `win` (`cfg(windows)`) : named pipe serveur (DACL stricte, instance
//!   unique, clients distants refusés), client vérifiant l'identité du serveur,
//!   contrôle du service (SCM), répertoire de données admin-only. Seul code
//!   `unsafe`, compilé en cross, jamais exécuté depuis WSL.
//!
//! # Sécurité
//!
//! La session appartient au SID de l'utilisateur qui a fait `connect` (relevé par
//! le service sur le pipe) : seul ce SID ou un administrateur peut la couper ou en
//! voir le détail ; les échecs d'authentification sont limités par SID (`access`).
//!
//! Le client ne fournit **que** le mot de passe : hôte, utilisateur, realm,
//! empreinte, interface viennent de `%ProgramData%\fortivpn-rs\config.toml`
//! (vérifié admin-only par le service) ; `wintun.dll` et le journal d'état gardent
//! leurs emplacements fixes (revue 5.3, M4). Le mot de passe est saisi à chaque
//! connexion, jamais stocké ni journalisé.

mod access;
mod client;
mod controller;
mod protocol;
mod status;
#[cfg(windows)]
mod win;

pub use access::{AuthThrottle, Caller, SE_GROUP_ENABLED};
pub use client::call;
pub use controller::{
    CONNECT_TIMEOUT, Controller, EventSink, STOP_TIMEOUT, SessionRunner, serve_connection,
};
pub use protocol::{
    ErrorCode, MAX_MESSAGE_BYTES, MAX_PASSWORD_BYTES, Outcome, PIPE_NAME, PIPE_SDDL,
    PIPE_USER_ACCESS_MASK, ProtocolError, Request, Response, State, StatusReport, StepTimings,
    decode_request, decode_response, encode_request, encode_response, read_message,
};
pub use status::{Busy, Stage, StatusTracker};
#[cfg(windows)]
pub use win::{
    SERVICE_NAME, connect_pipe, create_admin_only_dir, install, run_service, start, stop, uninstall,
};
