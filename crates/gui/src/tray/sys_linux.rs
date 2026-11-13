//! Branchement Linux : `ksni` (`StatusNotifierItem` en D-Bus pur Rust, sans GTK ni
//! libdbus C) et `notify-rust` (backend `zbus`). Sans hôte `SNI` (`WSLg`, GNOME sans
//! extension…), [`install`] échoue et l'appelant dégrade silencieusement.

use std::sync::{Arc, Mutex, PoisonError};

use ksni::blocking::{Handle, TrayMethods};
use ksni::menu::{MenuItem, StandardItem};

use super::{ICON_SIZE, MENU_OPEN, MENU_QUIT, Toast, TrayAction, TrayView, icon_argb};

type Callback = Arc<dyn Fn(TrayAction) + Send + Sync>;

struct SniTray {
    view: TrayView,
    on_action: Callback,
}

impl std::fmt::Debug for SniTray {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniTray")
            .field("view", &self.view)
            .finish_non_exhaustive()
    }
}

impl ksni::Tray for SniTray {
    fn id(&self) -> String {
        "fortivpn-gui".into()
    }
    fn title(&self) -> String {
        "fortivpn".into()
    }
    fn category(&self) -> ksni::Category {
        ksni::Category::ApplicationStatus
    }
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        let side = i32::try_from(ICON_SIZE).unwrap_or(32);
        vec![ksni::Icon {
            width: side,
            height: side,
            data: icon_argb(self.view.icon),
        }]
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: self.view.tooltip.clone(),
            ..Default::default()
        }
    }
    fn activate(&mut self, _x: i32, _y: i32) {
        (self.on_action)(TrayAction::Open);
    }
    fn menu(&self) -> Vec<MenuItem<Self>> {
        let item = |label: &str, enabled: bool, action: TrayAction| -> MenuItem<Self> {
            StandardItem {
                label: label.to_owned(),
                enabled,
                activate: Box::new(move |t: &mut Self| (t.on_action)(action)),
                ..Default::default()
            }
            .into()
        };
        vec![
            item(MENU_OPEN, true, TrayAction::Open),
            item(
                self.view.toggle_label,
                self.view.toggle_enabled,
                TrayAction::Toggle,
            ),
            MenuItem::Separator,
            item(MENU_QUIT, true, TrayAction::Quit),
        ]
    }
}

static HANDLE: Mutex<Option<Handle<SniTray>>> = Mutex::new(None);

/// Enregistre l'icône auprès du `StatusNotifierWatcher`.
pub fn install(on_action: impl Fn(TrayAction) + Send + Sync + 'static) -> Result<(), String> {
    let tray = SniTray {
        view: TrayView::of(crate::model::Phase::Idle, ""),
        on_action: Arc::new(on_action),
    };
    let handle = tray.spawn().map_err(|e| e.to_string())?;
    *HANDLE.lock().unwrap_or_else(PoisonError::into_inner) = Some(handle);
    Ok(())
}

/// L'icône est enregistrée et le service D-Bus tourne encore.
pub fn is_installed() -> bool {
    HANDLE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .is_some_and(|h| !h.is_closed())
}

/// Met à jour icône, infobulle et menu (seulement ce qui change).
pub fn update(view: &TrayView) {
    if let Some(h) = HANDLE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
    {
        let _ = h.update(|t| {
            if t.view != *view {
                t.view = view.clone();
            }
        });
    }
}

/// Notification système discrète (thread dédié : l'appel peut bloquer).
pub fn notify(toast: &Toast) {
    #[cfg(feature = "linux-tray")]
    {
        let (title, body) = (toast.title, toast.body.clone());
        std::thread::spawn(move || {
            if let Err(e) = notify_rust::Notification::new()
                .appname("fortivpn")
                .summary(title)
                .body(&body)
                .icon("fortivpn-gui")
                .show()
            {
                tracing::debug!("notification impossible : {e}");
            }
        });
    }
}
