//! Icône de zone de notification et notifications système.
//!
//! La logique (état → icône, infobulle, menu, notification) est pure et testée sur
//! toutes les plateformes. Le branchement système n'existe que sous Windows
//! (`tray-icon`, `notify-rust`) et Linux (`ksni` SNI + `notify-rust`/zbus, sans GTK) ;
//! ailleurs, [`install`] échoue proprement et la
//! fenêtre se comporte comme avant (fermer = quitter). Aucune information secrète
//! n'entre jamais dans une infobulle ni dans une notification.

use crate::model::{Phase, UiState};

/// Couleur de l'icône (bouclier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconKind {
    /// Déconnecté.
    Grey,
    /// Connexion, reconnexion ou arrêt en cours.
    Orange,
    /// Tunnel actif.
    Green,
}

impl IconKind {
    /// Couleur d'icône d'une phase (même code couleur que la fenêtre).
    pub fn of(phase: Phase) -> Self {
        match phase.tone() {
            0 => Self::Grey,
            1 => Self::Orange,
            _ => Self::Green,
        }
    }

    fn rgb(self) -> [u8; 3] {
        match self {
            Self::Grey => [0x8b, 0x93, 0xa1],
            Self::Orange => [0xf0, 0xa0, 0x30],
            Self::Green => [0x3c, 0xcf, 0x6e],
        }
    }
}

/// Côté (pixels) des icônes générées.
pub const ICON_SIZE: u32 = 32;

/// Bouclier RGBA (`ICON_SIZE`², fond transparent, liseré sombre, reflet clair),
/// généré à l'exécution : aucun fichier image à embarquer.
#[allow(clippy::many_single_char_names)] // coordonnées et canaux de couleur
pub fn icon_rgba(kind: IconKind) -> Vec<u8> {
    let [r, g, b] = kind.rgb();
    let n = f64::from(ICON_SIZE);
    // Demi-largeur du bouclier à la hauteur `v` (−1 haut, +1 bas), 0 hors forme.
    let half = |v: f64| -> f64 {
        if !(-0.9..=0.95).contains(&v) {
            0.0
        } else if v < 0.1 {
            0.78
        } else {
            0.78 * ((0.95 - v) / 0.85).sqrt()
        }
    };
    let mut out = Vec::with_capacity((ICON_SIZE * ICON_SIZE * 4) as usize);
    for y in 0..ICON_SIZE {
        for x in 0..ICON_SIZE {
            let u = (f64::from(x) + 0.5) / n * 2.0 - 1.0;
            let v = (f64::from(y) + 0.5) / n * 2.0 - 1.0;
            let w = half(v);
            let px = if u.abs() > w || w == 0.0 {
                [0, 0, 0, 0]
            } else if u.abs() > w - 0.12 || v < -0.78 || (v > 0.0 && w < 0.12 + 0.02) {
                [0x14, 0x16, 0x1c, 0xff]
            } else if u < -0.08 && u > -0.45 && v > -0.6 && v < 0.2 {
                let lift = |c: u8| c.saturating_add(60);
                [lift(r), lift(g), lift(b), 0xff]
            } else {
                [r, g, b, 0xff]
            };
            out.extend_from_slice(&px);
        }
    }
    out
}

/// Action demandée depuis le menu de l'icône.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    /// Afficher la fenêtre.
    Open,
    /// Se connecter : affiche la fenêtre (le mot de passe se saisit toujours là).
    Connect,
    /// Se déconnecter.
    Disconnect,
    /// Entrée Connecter/Déconnecter du menu : résolue selon la phase courante.
    Toggle,
    /// Quitter l'application.
    Quit,
}

impl TrayAction {
    /// Résout [`Toggle`](Self::Toggle) selon la phase ; les autres actions sont inchangées.
    #[must_use]
    pub fn resolve(self, phase: Phase) -> Self {
        if self == Self::Toggle {
            TrayView::of(phase, "").toggle_action
        } else {
            self
        }
    }
}

/// Contenu du menu et de l'infobulle pour une phase donnée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayView {
    /// Couleur de l'icône.
    pub icon: IconKind,
    /// Infobulle (bornée à 127 caractères, limite Windows).
    pub tooltip: String,
    /// Libellé de l'entrée Connecter/Déconnecter.
    pub toggle_label: &'static str,
    /// L'entrée Connecter/Déconnecter est utilisable.
    pub toggle_enabled: bool,
    /// Action de cette entrée.
    pub toggle_action: TrayAction,
}

impl TrayView {
    /// Vue correspondant à une phase (`host` : passerelle, non secrète).
    pub fn of(phase: Phase, host: &str) -> Self {
        let at = if host.is_empty() {
            String::new()
        } else {
            format!(" ({host})")
        };
        let state = match phase {
            Phase::Idle => "déconnecté".to_owned(),
            Phase::Connecting => format!("connexion en cours{at}"),
            Phase::Reconnecting => format!("reconnexion en cours{at}"),
            Phase::Disconnecting => format!("déconnexion en cours{at}"),
            Phase::Connected => format!("connecté{at}"),
        };
        let (toggle_label, toggle_enabled, toggle_action) = match phase {
            Phase::Idle => ("Connecter…", true, TrayAction::Connect),
            Phase::Disconnecting => ("Déconnexion…", false, TrayAction::Disconnect),
            _ => ("Déconnecter", true, TrayAction::Disconnect),
        };
        Self {
            icon: IconKind::of(phase),
            tooltip: truncate(&format!("fortivpn : {state}"), 127),
            toggle_label,
            toggle_enabled,
            toggle_action,
        }
    }
}

/// Libellés fixes du menu, dans l'ordre : Ouvrir, Connecter/Déconnecter, Quitter.
pub const MENU_OPEN: &str = "Ouvrir";
/// Libellé de l'entrée Quitter.
pub const MENU_QUIT: &str = "Quitter";

/// Notification système.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toast {
    /// Titre.
    pub title: &'static str,
    /// Corps (jamais de secret).
    pub body: String,
}

/// Tronque à `max` caractères (ajoute « … »).
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
    t.push('…');
    t
}

/// Notification à émettre quand la phase passe de `prev` à `ui.phase` (`None` :
/// rien à signaler, par ex. déconnexion voulue ou simple progression).
pub fn toast(prev: Phase, ui: &UiState) -> Option<Toast> {
    let host = if ui.host.is_empty() {
        "la passerelle".to_owned()
    } else {
        ui.host.clone()
    };
    match (prev, ui.phase) {
        (Phase::Connecting, Phase::Connected) => {
            let ms = ui.marks.total().map_or(0, |d| d.as_millis());
            Some(Toast {
                title: "VPN connecté",
                body: format!("Connecté à {host} en {} s.", format_seconds(ms)),
            })
        }
        (Phase::Reconnecting, Phase::Connected) => Some(Toast {
            title: "VPN reconnecté",
            body: format!("Connexion à {host} rétablie."),
        }),
        (Phase::Connected, Phase::Reconnecting) => Some(Toast {
            title: "VPN interrompu",
            body: format!("Connexion à {host} perdue, reconnexion en cours…"),
        }),
        (Phase::Connecting | Phase::Reconnecting, Phase::Idle) => {
            ui.error.as_deref().map(|e| Toast {
                title: "Échec de la connexion VPN",
                body: truncate(e, 200),
            })
        }
        (Phase::Connected, Phase::Idle) => ui.error.as_deref().map(|e| Toast {
            title: "VPN déconnecté",
            body: truncate(e, 200),
        }),
        _ => None,
    }
}

/// Millisecondes → secondes avec une décimale (« 1,2 »).
fn format_seconds(ms: u128) -> String {
    format!("{},{}", ms / 1000, (ms % 1000) / 100)
}

/// Même icône au format SNI : ARGB32, octets dans l'ordre réseau (A, R, G, B).
pub fn icon_argb(kind: IconKind) -> Vec<u8> {
    let mut v = icon_rgba(kind);
    for px in v.chunks_exact_mut(4) {
        px.rotate_right(1);
    }
    v
}

#[cfg(windows)]
mod sys;
#[cfg(windows)]
pub use sys::{install, is_installed, notify, update};

#[cfg(all(target_os = "linux", feature = "linux-tray"))]
#[path = "tray/sys_linux.rs"]
mod sys;
#[cfg(all(target_os = "linux", feature = "linux-tray"))]
pub use sys::{install, is_installed, notify, update};

/// Sans zone de notification disponible (autre OS, ou feature `linux-tray` absente).
#[cfg(not(any(windows, all(target_os = "linux", feature = "linux-tray"))))]
pub fn install(_on_action: impl Fn(TrayAction) + Send + Sync + 'static) -> Result<(), String> {
    Err("zone de notification non disponible sur cette plateforme".to_owned())
}

/// Sans objet sans zone de notification.
#[cfg(not(any(windows, all(target_os = "linux", feature = "linux-tray"))))]
pub fn is_installed() -> bool {
    false
}

/// Sans objet sans zone de notification.
#[cfg(not(any(windows, all(target_os = "linux", feature = "linux-tray"))))]
pub fn update(_view: &TrayView) {}

/// Sans objet sans zone de notification (l'état reste visible dans la fenêtre).
#[cfg(not(any(windows, all(target_os = "linux", feature = "linux-tray"))))]
pub fn notify(toast: &Toast) {
    tracing::debug!("notification ignorée : {}", toast.title);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Marks, Mode, ProxyInfo};

    #[test]
    fn phase_maps_to_grey_orange_green() {
        assert_eq!(IconKind::of(Phase::Idle), IconKind::Grey);
        for p in [Phase::Connecting, Phase::Reconnecting, Phase::Disconnecting] {
            assert_eq!(IconKind::of(p), IconKind::Orange);
        }
        assert_eq!(IconKind::of(Phase::Connected), IconKind::Green);
    }

    #[test]
    fn icons_are_distinct_shields_with_transparent_corners() {
        let g = icon_rgba(IconKind::Grey);
        let o = icon_rgba(IconKind::Orange);
        let v = icon_rgba(IconKind::Green);
        assert_eq!(g.len(), (ICON_SIZE * ICON_SIZE * 4) as usize);
        assert!(g != o && o != v && g != v);
        assert_eq!(g[3], 0, "coin haut-gauche transparent");
        let center = ((ICON_SIZE / 2 * ICON_SIZE + ICON_SIZE / 2) * 4) as usize;
        assert_eq!(g[center + 3], 0xff, "centre opaque");
        assert!(g.chunks(4).any(|p| p[3] == 0xff));
    }

    #[test]
    fn view_gives_tooltip_and_menu_per_phase() {
        let v = TrayView::of(Phase::Idle, "vpn.example.com");
        assert_eq!(v.tooltip, "fortivpn : déconnecté");
        assert_eq!(v.toggle_label, "Connecter…");
        assert_eq!(v.toggle_action, TrayAction::Connect);
        assert!(v.toggle_enabled);
        let v = TrayView::of(Phase::Connected, "vpn.example.com");
        assert_eq!(v.icon, IconKind::Green);
        assert_eq!(v.tooltip, "fortivpn : connecté (vpn.example.com)");
        assert_eq!(v.toggle_label, "Déconnecter");
        assert_eq!(v.toggle_action, TrayAction::Disconnect);
        let v = TrayView::of(Phase::Reconnecting, "");
        assert_eq!(v.icon, IconKind::Orange);
        assert_eq!(v.tooltip, "fortivpn : reconnexion en cours");
        let v = TrayView::of(Phase::Disconnecting, "h");
        assert!(!v.toggle_enabled);
        let long = TrayView::of(Phase::Connected, &"x".repeat(500));
        assert_eq!(long.tooltip.chars().count(), 127);
    }

    fn ui(phase: Phase) -> UiState {
        let mut u = UiState::new();
        u.begin(Mode::Proxy, "vpn.example.com", ProxyInfo::default(), "t");
        u.phase = phase;
        u
    }

    #[test]
    fn connected_toast_carries_the_duration() {
        let mut u = ui(Phase::Connected);
        u.marks = Marks::default();
        let t = toast(Phase::Connecting, &u).unwrap();
        assert_eq!(t.title, "VPN connecté");
        assert_eq!(t.body, "Connecté à vpn.example.com en 0,0 s.");
        assert_eq!(format_seconds(1234), "1,2");
        assert_eq!(
            toast(Phase::Reconnecting, &u).unwrap().title,
            "VPN reconnecté"
        );
    }

    #[test]
    fn loss_and_failure_toasts() {
        let u = ui(Phase::Reconnecting);
        assert_eq!(toast(Phase::Connected, &u).unwrap().title, "VPN interrompu");
        let mut u = ui(Phase::Idle);
        assert_eq!(toast(Phase::Connecting, &u), None, "annulation : silence");
        u.error = Some("certificat refusé".into());
        let t = toast(Phase::Connecting, &u).unwrap();
        assert_eq!(t.title, "Échec de la connexion VPN");
        assert_eq!(t.body, "certificat refusé");
        assert_eq!(toast(Phase::Connected, &u).unwrap().title, "VPN déconnecté");
        u.error = Some("é".repeat(500));
        assert_eq!(
            toast(Phase::Connecting, &u).unwrap().body.chars().count(),
            200
        );
    }

    #[test]
    fn no_toast_for_user_actions_or_progress() {
        let u = ui(Phase::Idle);
        assert_eq!(toast(Phase::Disconnecting, &u), None);
        assert_eq!(toast(Phase::Connected, &u), None);
        let u = ui(Phase::Connecting);
        assert_eq!(toast(Phase::Idle, &u), None);
        let u = ui(Phase::Disconnecting);
        assert_eq!(toast(Phase::Connected, &u), None);
    }

    #[test]
    fn toggle_resolves_from_the_current_phase() {
        assert_eq!(TrayAction::Toggle.resolve(Phase::Idle), TrayAction::Connect);
        assert_eq!(
            TrayAction::Toggle.resolve(Phase::Connected),
            TrayAction::Disconnect
        );
        assert_eq!(TrayAction::Open.resolve(Phase::Connected), TrayAction::Open);
    }

    #[test]
    fn close_to_tray_needs_an_installed_tray() {
        // Sans zone de notification, fermer la fenêtre doit continuer à quitter.
        #[cfg(not(any(windows, all(target_os = "linux", feature = "linux-tray"))))]
        {
            assert!(!is_installed());
            assert!(install(|_| {}).is_err());
        }
        // Avec ksni : sans hôte SNI (CI, WSLg) l'installation échoue sans panique.
        #[cfg(all(target_os = "linux", feature = "linux-tray"))]
        assert!(!is_installed());
    }

    #[test]
    fn argb_is_rgba_rotated_for_sni() {
        let rgba = icon_rgba(IconKind::Green);
        let argb = icon_argb(IconKind::Green);
        assert_eq!(rgba.len(), argb.len());
        for (p, q) in rgba.chunks(4).zip(argb.chunks(4)) {
            assert_eq!([q[0], q[1], q[2], q[3]], [p[3], p[0], p[1], p[2]]);
        }
    }
}
