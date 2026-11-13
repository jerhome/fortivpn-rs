//! Côté client (CLI non-admin) : un échange requête/réponse sur un flux déjà ouvert.

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::protocol::{self, ProtocolError, Request, Response};

/// Envoie `request` (validée, une ligne) puis lit la réponse (une ligne bornée).
/// Pas de délai ici : `connect` peut durer jusqu'au délai du service (90 s).
pub async fn call<S>(stream: &mut S, request: &Request) -> Result<Response, ProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let line = protocol::encode_request(request)?;
    stream.write_all(&line).await?;
    stream.flush().await?;
    drop(line);
    let reply = protocol::read_message(stream).await?;
    protocol::decode_response(&reply)
}
