//! Serveur du named pipe `\\.\pipe\fortivpn-rs`.

use std::io;
use std::sync::Arc;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{Semaphore, watch};

use super::sd::SecurityDescriptor;
use crate::controller::{Controller, SessionRunner, serve_connection};
use crate::protocol::{PIPE_NAME, PIPE_SDDL};

/// Instances simultanées du pipe (côté noyau).
const MAX_INSTANCES: usize = 16;
/// Connexions servies simultanément ; les suivantes sont fermées aussitôt.
const MAX_CLIENTS: usize = 8;

/// Crée une instance du pipe : DACL `PIPE_SDDL`, clients distants refusés ; la
/// première porte `FILE_FLAG_FIRST_PIPE_INSTANCE` (échoue si le nom est déjà pris :
/// pas de 2e serveur, pas d'usurpation par un processus lancé avant nous).
fn create_instance(first: bool) -> io::Result<NamedPipeServer> {
    let sd = SecurityDescriptor::from_sddl(PIPE_SDDL)?;
    let mut sa = sd.attributes();
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true)
        .max_instances(MAX_INSTANCES);
    // SAFETY: `sa` est une SECURITY_ATTRIBUTES valide dont le descripteur (porté
    // par `sd`) vit jusqu'à la fin de l'appel ; CreateNamedPipe en copie le contenu.
    unsafe { options.create_with_security_attributes_raw(PIPE_NAME, (&raw mut sa).cast()) }
}

/// Accepte les clients jusqu'à ce que `stop` passe à `true`.
pub(super) async fn serve<R: SessionRunner>(
    controller: Arc<Controller<R>>,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()> {
    let limit = Arc::new(Semaphore::new(MAX_CLIENTS));
    let mut server = create_instance(true)?;
    tracing::info!(pipe = PIPE_NAME, "named pipe prêt");
    loop {
        tokio::select! {
            connected = server.connect() => connected?,
            _ = stop.wait_for(|stopping| *stopping) => return Ok(()),
        }
        // Nouvelle instance avant de traiter celle-ci : le nom n'est jamais libre.
        let client = std::mem::replace(&mut server, create_instance(false)?);
        let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
            tracing::warn!("trop de clients simultanés : connexion refusée");
            continue;
        };
        let controller = Arc::clone(&controller);
        tokio::spawn(async move {
            let _permit = permit;
            serve_connection(client, &controller).await;
        });
    }
}
