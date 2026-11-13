//! Branchement Windows : `tray-icon` (icône + menu) et `notify-rust` (toasts).
//!
//! Tout s'exécute sur le thread UI (celui de la boucle de messages de Slint) ;
//! l'icône vit dans un `thread_local`.

use std::cell::RefCell;

use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use super::{ICON_SIZE, IconKind, MENU_OPEN, MENU_QUIT, Toast, TrayAction, TrayView, icon_rgba};

struct Tray {
    icon: TrayIcon,
    toggle: MenuItem,
    shown: Option<TrayView>,
}

thread_local! {
    static TRAY: RefCell<Option<Tray>> = const { RefCell::new(None) };
}

fn icon(kind: IconKind) -> Result<Icon, String> {
    Icon::from_rgba(icon_rgba(kind), ICON_SIZE, ICON_SIZE).map_err(|e| e.to_string())
}

/// Crée l'icône (état initial : déconnecté). `on_action` peut être appelée depuis
/// n'importe quel thread : elle doit seulement poster l'action vers la boucle UI.
pub fn install(on_action: impl Fn(TrayAction) + Send + Sync + 'static) -> Result<(), String> {
    let initial = TrayView::of(crate::model::Phase::Idle, "");
    let open = MenuItem::new(MENU_OPEN, true, None);
    let toggle = MenuItem::new(initial.toggle_label, initial.toggle_enabled, None);
    let quit = MenuItem::new(MENU_QUIT, true, None);
    let menu = Menu::new();
    menu.append_items(&[&open, &toggle, &PredefinedMenuItem::separator(), &quit])
        .map_err(|e| e.to_string())?;
    let (open_id, toggle_id, quit_id): (MenuId, MenuId, MenuId) =
        (open.id().clone(), toggle.id().clone(), quit.id().clone());
    let action = std::sync::Arc::new(on_action);
    let a = std::sync::Arc::clone(&action);
    MenuEvent::set_event_handler(Some(move |e: MenuEvent| {
        if e.id == open_id {
            a(TrayAction::Open);
        } else if e.id == quit_id {
            a(TrayAction::Quit);
        } else if e.id == toggle_id {
            a(TrayAction::Toggle);
        }
    }));
    let a = action;
    TrayIconEvent::set_event_handler(Some(move |e: TrayIconEvent| {
        if let TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        } = e
        {
            a(TrayAction::Open);
        }
    }));
    let tray = TrayIconBuilder::new()
        .with_icon(icon(initial.icon)?)
        .with_tooltip(&initial.tooltip)
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .build()
        .map_err(|e| e.to_string())?;
    TRAY.with(|t| {
        *t.borrow_mut() = Some(Tray {
            icon: tray,
            toggle,
            shown: Some(initial),
        });
    });
    Ok(())
}

/// L'icône existe (sur ce thread).
pub fn is_installed() -> bool {
    TRAY.with(|t| t.borrow().is_some())
}

/// Met à jour icône, infobulle et menu (seulement ce qui change).
pub fn update(view: &TrayView) {
    TRAY.with(|t| {
        let mut guard = t.borrow_mut();
        let Some(tray) = guard.as_mut() else { return };
        if tray.shown.as_ref() == Some(view) {
            return;
        }
        if tray.shown.as_ref().is_none_or(|s| s.icon != view.icon) {
            if let Ok(i) = icon(view.icon) {
                let _ = tray.icon.set_icon(Some(i));
            }
        }
        let _ = tray.icon.set_tooltip(Some(&view.tooltip));
        tray.toggle.set_text(view.toggle_label);
        tray.toggle.set_enabled(view.toggle_enabled);
        tray.shown = Some(view.clone());
    });
}

/// Notification système discrète (thread dédié : l'appel peut bloquer).
pub fn notify(toast: &Toast) {
    let (title, body) = (toast.title, toast.body.clone());
    std::thread::spawn(move || {
        if let Err(e) = notify_rust::Notification::new()
            .appname("fortivpn")
            .summary(title)
            .body(&body)
            .show()
        {
            tracing::debug!("notification impossible : {e}");
        }
    });
}
