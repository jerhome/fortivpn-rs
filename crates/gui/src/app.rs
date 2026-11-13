//! Fenêtre Slint : rendu de l'état partagé et câblage des callbacks.
//!
//! Tout ce module s'exécute sur le thread UI et ne fait aucune I/O : les actions
//! sont transmises au [`worker`](crate::worker) par un canal non bloquant.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fortivpn_app::sudo;
use secrecy::SecretString;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::model::{Mode, STEP_LABELS, StepState, format_step};
use crate::settings::SettingsForm;
use crate::tray::{self, TrayAction, TrayView};
use crate::ui::{LogItem, MainWindow, RedirItem, StepItem};
use crate::worker::{Command, Notice, Shared, Sink, WorkerHandle};

/// Reflète l'état partagé dans la fenêtre.
pub fn render(win: &MainWindow, shared: &mut Shared, now: Instant) {
    let ui = &shared.ui;
    win.set_screen(ui.phase.screen());
    win.set_tone(ui.phase.tone());
    win.set_host_label(ui.host.as_str().into());
    win.set_status_text(ui.status_text().into());
    let steps: Vec<StepItem> = ui
        .marks
        .steps()
        .iter()
        .zip(STEP_LABELS)
        .map(|(st, label)| StepItem {
            label: label.into(),
            state: match st {
                StepState::Pending => 0,
                StepState::Running => 1,
                StepState::Done(_) => 2,
            },
            time: format_step(*st).into(),
        })
        .collect();
    win.set_steps(ModelRc::new(VecModel::from(steps)));
    win.set_progress(ui.progress());
    win.set_step_hint(ui.step_hint().into());
    win.set_error_text(ui.error.clone().unwrap_or_default().into());
    win.set_address(ui.address.clone().unwrap_or_default().into());
    win.set_duration(ui.duration_text(now).into());
    win.set_socks_text(ui.proxy.socks.clone().unwrap_or_default().into());
    let forwards: Vec<RedirItem> = ui
        .proxy
        .forwards
        .iter()
        .map(|(l, t)| RedirItem {
            listen: l.as_str().into(),
            target: t.as_str().into(),
        })
        .collect();
    win.set_forwards(ModelRc::new(VecModel::from(forwards)));
    win.set_reconnect_auto(ui.reconnect_auto);
    win.set_service_hint(ui.service_hint.as_str().into());
    win.set_root_warning(ui.root_warning.as_str().into());
    let log: Vec<LogItem> = ui
        .log
        .iter()
        .map(|l| LogItem {
            ts: l.ts.as_str().into(),
            level: l.level.index(),
            text: l.text.as_str().into(),
        })
        .collect();
    win.set_log(ModelRc::new(VecModel::from(log)));
    win.set_busy(shared.busy);
    win.set_app_version(env!("CARGO_PKG_VERSION").into());
    win.set_app_repo(env!("CARGO_PKG_REPOSITORY").into());
    let sf = ui.second_factor.as_ref();
    win.set_otp_open(sf.is_some());
    win.set_otp_push(sf.is_some_and(|p| p.push));
    win.set_otp_message(sf.map(|p| p.message.as_str()).unwrap_or_default().into());
    win.set_settings_message(shared.settings_message.as_str().into());
    win.set_settings_ok(shared.settings_ok);
    if let Some(form) = shared.pending_form.take() {
        win.set_s_host(form.host.into());
        win.set_s_port(form.port.into());
        win.set_s_user(form.username.into());
        win.set_s_fingerprint(form.fingerprint.into());
        win.set_s_socks_addr(form.socks_addr.into());
        win.set_s_socks_port(form.socks_port.into());
        win.set_s_forwards(form.forwards.into());
        win.set_s_reconnect(form.reconnect);
        win.set_s_owner_check(form.owner_check);
        win.set_s_close_to_tray(form.close_to_tray);
    }
    win.set_service_available(shared.service_available);
    win.set_pin_offer(ui.visible_pin_offer().unwrap_or_default().into());
    if let Some(mode) = shared.pending_mode.take() {
        win.set_mode(mode.index());
    }
    if std::mem::take(&mut shared.open_settings) {
        win.set_settings_open(true);
    }
    if let Some(user) = shared.pending_username.take() {
        win.set_username(user.into());
    }
}

/// Formulaire des réglages tel que saisi.
pub fn read_form(win: &MainWindow) -> SettingsForm {
    SettingsForm {
        host: win.get_s_host().into(),
        port: win.get_s_port().into(),
        username: win.get_s_user().into(),
        fingerprint: win.get_s_fingerprint().into(),
        socks_addr: win.get_s_socks_addr().into(),
        socks_port: win.get_s_socks_port().into(),
        forwards: win.get_s_forwards().into(),
        reconnect: win.get_s_reconnect(),
        owner_check: win.get_s_owner_check(),
        close_to_tray: win.get_s_close_to_tray(),
    }
}

/// Branche les callbacks de la fenêtre sur le worker.
pub fn wire(win: &MainWindow, sink: &Sink, worker: &WorkerHandle) {
    let weak = win.as_weak();
    let (w, s) = (worker.clone(), sink.clone());
    win.on_connect(move || {
        let Some(win) = weak.upgrade() else { return };
        // Le mot de passe quitte le modèle Slint dès la lecture.
        let typed: SharedString = win.get_password();
        win.set_password(SharedString::new());
        if typed.is_empty() {
            s.update(|sh, _| sh.ui.error = Some("Saisissez le mot de passe.".to_owned()));
            return;
        }
        let password = SecretString::from(typed.as_str());
        drop(typed);
        w.send(Command::Connect {
            mode: Mode::from_index(win.get_mode()),
            username: win.get_username().into(),
            password,
        });
    });
    let (weak, w) = (win.as_weak(), worker.clone());
    win.on_otp_submit(move || {
        let Some(win) = weak.upgrade() else { return };
        // Comme le mot de passe : effacé du modèle Slint dès la lecture.
        let typed = win.get_otp_code();
        win.set_otp_code(SharedString::new());
        let code = (!typed.is_empty()).then(|| SecretString::from(typed.as_str()));
        drop(typed);
        w.send(Command::SecondFactor(code));
    });
    let (weak, w) = (win.as_weak(), worker.clone());
    win.on_otp_cancel(move || {
        if let Some(win) = weak.upgrade() {
            win.set_otp_code(SharedString::new());
        }
        w.send(Command::SecondFactor(None));
        w.send(Command::Disconnect);
    });
    let w = worker.clone();
    win.on_cancel(move || w.send(Command::Disconnect));
    let w = worker.clone();
    win.on_disconnect(move || w.send(Command::Disconnect));
    let w = worker.clone();
    win.on_mode_changed(move |i| {
        if Mode::from_index(i) == Mode::Service {
            w.send(Command::ProbeService);
        }
    });
    let (w, s) = (worker.clone(), sink.clone());
    let weak = win.as_weak();
    win.on_open_settings(move || {
        // L'écran s'ouvre toujours, quel que soit le résultat du chargement.
        if let Some(win) = weak.upgrade() {
            win.set_settings_open(true);
        }
        s.update(|sh, _| sh.settings_message.clear());
        w.send(Command::LoadSettings);
    });
    let w = worker.clone();
    win.on_pin_fingerprint(move || w.send(Command::PinFingerprint));
    let weak = win.as_weak();
    let w = worker.clone();
    win.on_save_settings(move || {
        if let Some(win) = weak.upgrade() {
            w.send(Command::SaveSettings(read_form(&win)));
        }
    });
    let (w, s) = (worker.clone(), sink.clone());
    win.window().on_close_requested(move || {
        if tray::is_installed() && s.lock().close_to_tray {
            // Réduit dans la zone de notification : la session continue.
            return slint::CloseRequestResponse::HideWindow;
        }
        w.send(Command::Quit);
        slint::CloseRequestResponse::KeepWindowShown
    });
}

/// Icône et notifications : suit l'état partagé (thread UI).
fn sync_tray(win: &MainWindow, shared: &mut Shared) {
    tray::update(&TrayView::of(shared.ui.phase, &shared.ui.host));
    let prev = std::mem::replace(&mut shared.notified_phase, shared.ui.phase);
    // Fenêtre visible : l'état s'y lit déjà, pas de notification redondante.
    if !win.window().is_visible()
        && let Some(t) = tray::toast(prev, &shared.ui)
    {
        tray::notify(&t);
    }
}

/// Affiche et ramène la fenêtre au premier plan.
fn show_window(win: &MainWindow) {
    let _ = win.show();
}

/// Crée l'icône et route ses actions vers la fenêtre et le worker (best effort :
/// sans zone de notification, la fenêtre garde son comportement classique).
fn install_tray(win: &MainWindow, sink: &Sink, worker: &WorkerHandle) {
    let (weak, sink, worker) = (win.as_weak(), sink.clone(), worker.clone());
    let result = tray::install(move |action| {
        let (weak, sink, worker) = (weak.clone(), sink.clone(), worker.clone());
        let _ = slint::invoke_from_event_loop(move || {
            let phase = sink.lock().ui.phase;
            match action.resolve(phase) {
                TrayAction::Open | TrayAction::Connect => {
                    if let Some(win) = weak.upgrade() {
                        show_window(&win);
                    }
                }
                TrayAction::Disconnect => worker.send(Command::Disconnect),
                TrayAction::Quit => worker.send(Command::Quit),
                TrayAction::Toggle => {}
            }
        });
    });
    if let Err(e) = result {
        tracing::debug!("pas d'icône de notification : {e}");
    }
}

/// Première lettre en majuscule (texte affiché).
fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map_or_else(String::new, |f| f.to_uppercase().chain(c).collect())
}

/// Lance l'application : fenêtre, worker, minuteur de durée ; bloque jusqu'à la fin.
pub fn run(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let win = MainWindow::new()?;
    let shared = Arc::new(Mutex::new(Shared::new()));
    let weak = win.as_weak();
    let for_render = Arc::clone(&shared);
    let sink = Sink::with_shared(shared, move |notice| {
        let weak = weak.clone();
        let shared = Arc::clone(&for_render);
        // File d'attente de la boucle d'événements : le worker ne bloque jamais.
        let _ = slint::invoke_from_event_loop(move || match notice {
            Notice::Render => {
                if let Some(win) = weak.upgrade() {
                    let mut guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
                    render(&win, &mut guard, Instant::now());
                    sync_tray(&win, &mut guard);
                }
            }
            Notice::Quit => {
                let _ = slint::quit_event_loop();
            }
        });
    });
    if sudo::is_root(&sudo::SystemEnv) {
        tracing::warn!("{}", sudo::GUI_ROOT_WARNING);
        eprintln!("fortivpn-gui : {}", sudo::GUI_ROOT_WARNING);
        sink.lock().ui.root_warning = capitalize(sudo::GUI_ROOT_WARNING);
    }
    let (worker, thread) = crate::worker::spawn(sink.clone(), config_path)?;
    wire(&win, &sink, &worker);
    install_tray(&win, &sink, &worker);
    worker.send(Command::Startup);

    // Durée de session : mise à jour chaque seconde, sans repasser par le worker.
    let timer = slint::Timer::default();
    let weak = win.as_weak();
    let tick = sink.clone();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_secs(1),
        move || {
            if let Some(win) = weak.upgrade() {
                let text = tick.lock().ui.duration_text(Instant::now());
                win.set_duration(text.into());
            }
        },
    );

    win.show()?;
    // Fenêtre masquée (réduite dans la zone de notification) : la boucle continue.
    slint::run_event_loop_until_quit()?;
    drop(timer);
    let _ = thread.join();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::model::{Mode, ProxyInfo};

    #[test]
    fn root_warning_is_shown_in_the_window() {
        i_slint_backend_testing::init_no_event_loop();
        let win = MainWindow::new().unwrap();
        let mut shared = Shared::new();
        render(&win, &mut shared, Instant::now());
        assert_eq!(win.get_root_warning().as_str(), "");
        shared.ui.root_warning = capitalize(sudo::GUI_ROOT_WARNING);
        render(&win, &mut shared, Instant::now());
        assert!(
            win.get_root_warning()
                .as_str()
                .starts_with("Inutile de lancer l'interface avec sudo")
        );
    }

    #[test]
    fn render_reflects_state_and_clears_nothing_secret() {
        i_slint_backend_testing::init_no_event_loop();
        let win = MainWindow::new().unwrap();
        let mut shared = Shared::new();
        render(&win, &mut shared, Instant::now());
        assert_eq!(win.get_screen(), 0);
        assert_eq!(win.get_tone(), 0);
        assert_eq!(win.get_status_text().as_str(), "Déconnecté");

        shared.ui.begin(
            Mode::Proxy,
            "vpn.example.com",
            ProxyInfo {
                socks: Some("127.0.0.1:1080".into()),
                forwards: vec![("127.0.0.1:2222".into(), "10.0.0.10:22".into())],
            },
            "14:02:11",
        );
        render(&win, &mut shared, Instant::now());
        assert_eq!(win.get_screen(), 1);
        assert_eq!(win.get_tone(), 1);
        assert_eq!(win.get_host_label().as_str(), "vpn.example.com");
        assert_eq!(slint::Model::row_count(&win.get_steps()), 3);

        shared.ui.ask_second_factor("t", false, Some("Code"));
        render(&win, &mut shared, Instant::now());
        assert!(win.get_otp_open());
        assert!(!win.get_otp_push());

        shared.ui.second_factor = None;
        shared.pending_form = Some(SettingsForm {
            host: "gw".into(),
            port: "443".into(),
            ..SettingsForm::default()
        });
        render(&win, &mut shared, Instant::now());
        assert!(!win.get_otp_open());
        assert_eq!(win.get_s_host().as_str(), "gw");
        assert!(shared.pending_form.is_none());
        assert_eq!(read_form(&win).host, "gw");
    }

    #[test]
    fn password_is_cleared_from_the_slint_model_after_connect() {
        i_slint_backend_testing::init_no_event_loop();
        let win = MainWindow::new().unwrap();
        let sink = Sink::new(|_| {});
        let (worker, thread) = crate::worker::spawn(sink.clone(), None).unwrap();
        wire(&win, &sink, &worker);
        // Champ vide : message d'erreur, rien n'est envoyé.
        win.invoke_connect();
        assert!(sink.lock().ui.error.is_some());
        win.set_password("secret-de-test".into());
        win.invoke_connect();
        assert_eq!(win.get_password().as_str(), "", "mot de passe non effacé");
        win.set_otp_code("123456".into());
        win.invoke_otp_submit();
        assert_eq!(win.get_otp_code().as_str(), "");
        worker.send(Command::Quit);
        thread.join().unwrap();
    }

    fn wait_until(sink: &Sink, cond: impl Fn(&Shared) -> bool) {
        for _ in 0..500 {
            if cond(&sink.lock()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("condition non atteinte");
    }

    #[test]
    fn settings_button_always_opens_the_screen() {
        i_slint_backend_testing::init_no_event_loop();
        let win = MainWindow::new().unwrap();
        let sink = Sink::new(|_| {});
        let missing = std::env::temp_dir()
            .join("fvpn-gui-absent")
            .join("config.toml");
        let (worker, thread) = crate::worker::spawn(sink.clone(), Some(missing)).unwrap();
        wire(&win, &sink, &worker);
        assert!(!win.get_settings_open());
        win.invoke_open_settings();
        assert!(win.get_settings_open(), "l'écran Réglages ne s'ouvre pas");
        worker.send(Command::Quit);
        thread.join().unwrap();
    }

    #[test]
    fn first_run_opens_settings_with_welcome_and_save_creates_the_file() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = std::env::temp_dir().join(format!("fvpn-gui-first-{}", std::process::id()));
        let path = dir.join("nouveau").join("config.toml");
        let win = MainWindow::new().unwrap();
        let sink = Sink::new(|_| {});
        let (worker, thread) = crate::worker::spawn(sink.clone(), Some(path.clone())).unwrap();
        wire(&win, &sink, &worker);
        worker.send(Command::Startup);
        wait_until(&sink, |s| s.open_settings && s.pending_form.is_some());
        render(&win, &mut sink.lock(), Instant::now());
        assert!(win.get_settings_open());
        assert_eq!(win.get_mode(), 1, "mode Proxy par défaut");
        assert_eq!(win.get_s_host().as_str(), "");
        assert_eq!(win.get_s_port().as_str(), "443");
        assert!(
            win.get_settings_message()
                .as_str()
                .starts_with("Première utilisation : renseignez la passerelle")
        );
        assert!(!path.exists());

        win.set_s_host("vpn.example.com".into());
        win.set_s_user("alice".into());
        win.invoke_save_settings();
        wait_until(&sink, |s| {
            s.settings_ok && s.settings_message == "Réglages enregistrés."
        });
        let saved = fortivpn_app::config::load(&path).unwrap();
        assert_eq!(saved.host, "vpn.example.com");
        assert_eq!(saved.username, "alice");
        worker.send(Command::Quit);
        thread.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unusable_config_still_leaves_a_working_settings_form() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = std::env::temp_dir().join(format!("fvpn-gui-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "ceci n'est pas du toml = = =").unwrap();
        let win = MainWindow::new().unwrap();
        let sink = Sink::new(|_| {});
        let (worker, thread) = crate::worker::spawn(sink.clone(), Some(path)).unwrap();
        wire(&win, &sink, &worker);
        win.invoke_open_settings();
        wait_until(&sink, |s| s.pending_form.is_some());
        render(&win, &mut sink.lock(), Instant::now());
        assert!(win.get_settings_open());
        assert!(
            win.get_settings_message()
                .as_str()
                .starts_with("Lecture impossible")
        );
        worker.send(Command::Quit);
        thread.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn service_mode_is_greyed_with_explanation_when_unavailable() {
        i_slint_backend_testing::init_no_event_loop();
        let win = MainWindow::new().unwrap();
        let mut shared = Shared::new();
        shared.service_available = false;
        shared.ui.service_hint = crate::worker::SERVICE_ABSENT.into();
        render(&win, &mut shared, Instant::now());
        assert!(!win.get_service_available());
        assert!(
            win.get_service_hint()
                .as_str()
                .starts_with("Service non installé")
        );
    }
}
