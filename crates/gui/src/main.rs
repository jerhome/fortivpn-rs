//! Binaire `fortivpn-gui` : interface graphique (sans console sous Windows).
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    // Durcissement du chargement des DLL (Windows), avant tout le reste.
    if fortivpn_app::platform::harden_process().is_err() {
        return;
    }
    let config = std::env::args()
        .skip_while(|a| a != "--config")
        .nth(1)
        .map(std::path::PathBuf::from);
    if let Err(e) = fortivpn_gui::app::run(config) {
        // Pas de console sous Windows : l'erreur est visible seulement sous Linux.
        eprintln!("fortivpn-gui : {e}");
    }
}
