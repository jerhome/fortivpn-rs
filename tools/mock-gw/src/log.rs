//! Journal des requêtes reçues, consultable par les tests.
//!
//! Aucun secret n'y est conservé : le mot de passe (`credential`) et la valeur du
//! `SVPNCOOKIE` sont remplacés par [`REDACTED`] ; seul le résultat de leur vérification
//! est enregistré.

use std::sync::{Arc, Mutex, MutexGuard};

/// Valeur substituée aux secrets dans le journal.
pub const REDACTED: &str = "<redacted>";

/// Résultat de la vérification du cookie `SVPNCOOKIE` d'une requête.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieCheck {
    /// Pas d'en-tête `Cookie`, ou pas de `SVPNCOOKIE` dedans.
    Absent,
    /// `SVPNCOOKIE=` sans valeur.
    Empty,
    /// Cookie d'une session ouverte.
    Valid,
    /// Cookie inconnu, expiré, déconnecté ou refusé par le scénario.
    Rejected,
}

/// Décision prise sur un `POST /remote/logincheck`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Identifiants corrects, cookie émis.
    Accepted,
    /// Identifiants (ou realm) incorrects, ou champs manquants.
    Rejected,
    /// Identifiants corrects mais 2FA exigée (`tokeninfo=`), pas de cookie.
    SecondFactorRequested,
}

/// Ce que la passerelle a fait de la requête.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoggedResponse {
    /// Réponse HTTP avec ce code de statut.
    Status(u16),
    /// Réponse HTTP envoyée puis connexion coupée sans `close_notify`.
    StatusThenDropped(u16),
    /// Connexion coupée (sans `close_notify`) sans réponse.
    Dropped,
    /// Bascule en flux binaire, connexion remise au [`crate::TunnelHandler`].
    TunnelOpened,
}

/// Une requête HTTP reçue, secrets masqués.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedRequest {
    /// Numéro de la connexion TLS (croissant à partir de 1, dans l'ordre d'acceptation).
    pub conn_id: u64,
    pub method: String,
    /// Cible complète (chemin + requête), ex. `/remote/login?realm=staff`.
    pub target: String,
    /// Chemin sans la requête.
    pub path: String,
    /// En-têtes dans l'ordre reçu ; la valeur de `Cookie` est masquée.
    pub headers: Vec<(String, String)>,
    pub cookie: CookieCheck,
    /// Champs de formulaire décodés (`credential` masqué).
    pub form: Vec<(String, String)>,
    pub auth: Option<AuthOutcome>,
    pub response: LoggedResponse,
}

impl LoggedRequest {
    /// Première valeur de l'en-tête `name` (insensible à la casse).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Valeur du champ de formulaire `name`.
    pub fn form_field(&self, name: &str) -> Option<&str> {
        self.form
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Journal partagé (clonable) des requêtes reçues.
#[derive(Debug, Clone, Default)]
pub struct RequestLog {
    inner: Arc<Mutex<Vec<LoggedRequest>>>,
}

impl RequestLog {
    fn lock(&self) -> MutexGuard<'_, Vec<LoggedRequest>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn push(&self, entry: LoggedRequest) {
        self.lock().push(entry);
    }

    /// Copie des entrées, dans l'ordre de réception.
    pub fn entries(&self) -> Vec<LoggedRequest> {
        self.lock().clone()
    }

    /// Entrées dont le chemin vaut `path`.
    pub fn for_path(&self, path: &str) -> Vec<LoggedRequest> {
        self.lock()
            .iter()
            .filter(|e| e.path == path)
            .cloned()
            .collect()
    }

    /// Chemins reçus, dans l'ordre (pratique pour vérifier une séquence).
    pub fn paths(&self) -> Vec<String> {
        self.lock().iter().map(|e| e.path.clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    pub fn clear(&self) {
        self.lock().clear();
    }
}
