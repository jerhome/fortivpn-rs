//! Partie Windows : named pipe, contrôle du service, répertoire de données.
//!
//! Seul code `unsafe` du crate. Chaque bloc est minimal, encapsulé dans une
//! fonction sûre, et justifié par un commentaire `SAFETY`.
//! Compilé en cross (`x86_64-pc-windows-gnu`), jamais exécuté depuis WSL.
#![allow(unsafe_code)]

mod caller;
mod client;
mod dir;
mod pipe;
mod scm;
mod sd;

pub use client::connect_pipe;
pub use dir::create_admin_only_dir;
pub use scm::{SERVICE_NAME, install, run_service, start, stop, uninstall};
