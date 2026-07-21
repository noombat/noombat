// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! WebSocket endpoint for the chat relay.
//!
//! Upgrades an HTTP connection to a WebSocket and bridges
//! [`noombat_chat::relay::ClientMessage`] / [`ServerMessage`] between
//! the browser and the Chatmail IMAP/SMTP server.

use axum::Router;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::get;
use noombat_chat::relay::{ClientMessage, ServerMessage};
use noombat_core::error::NoombatError;
use tracing::{info, warn};

use crate::error::ApiError;
use crate::middleware::Principal;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/api/v1/chat/ws", get(ws_upgrade))
}

/// Axum handler: upgrade the HTTP request to a WebSocket.
async fn ws_upgrade(
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
    principal: Option<axum::Extension<Principal>>,
) -> Result<Response, ApiError> {
    let principal = principal.ok_or(ApiError(NoombatError::Forbidden))?;
    let actor_id = principal
        .actor_id()
        .ok_or(ApiError(NoombatError::Forbidden))?;

    // Verify that chat is configured on this instance.
    if state.chatmail_domain.is_none() {
        return Err(ApiError(NoombatError::ServiceUnavailable(
            "chat not configured".into(),
        )));
    }

    // Fetch the actor's Chatmail address and moderation status.
    let (chatmail_addr, actor_status): (Option<String>, String) = sqlx::query_as(
        "SELECT chatmail_addr, actor_status FROM actors WHERE id = $1",
    )
    .bind(actor_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError(NoombatError::Internal(format!("actor lookup failed: {e}"))))?;

    // Reject suspended actors.
    if actor_status == "suspended" {
        return Err(ApiError(NoombatError::Forbidden));
    }

    let chatmail_addr = chatmail_addr.ok_or(ApiError(NoombatError::BadRequest(
        "chat not provisioned for this account".into(),
    )))?;

    let pool = state.pool.clone();

    Ok(ws.on_upgrade(move |socket| handle_ws(socket, pool, actor_id, chatmail_addr)))
}

/// Main WebSocket loop: read client messages, dispatch to
/// IMAP/SMTP, and write server messages back.
async fn handle_ws(
    mut socket: WebSocket,
    pool: sqlx::PgPool,
    actor_id: uuid::Uuid,
    chatmail_addr: String,
) {
    info!(actor = %actor_id, addr = %chatmail_addr, "chat WebSocket connected");

    loop {
        let msg = match socket.recv().await {
            Some(Ok(msg)) => msg,
            Some(Err(e)) => {
                warn!(actor = %actor_id, error = %e, "WebSocket recv error");
                break;
            }
            None => break, // Client disconnected.
        };

        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => break,
            Message::Ping(p) => {
                let _ = socket.send(Message::Pong(p)).await;
                continue;
            }
            _ => continue, // Ignore binary, pong.
        };

        let client_msg: ClientMessage = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                let err = ServerMessage::Error {
                    message: format!("invalid message: {e}"),
                };
                let _ = send_json(&mut socket, &err).await;
                continue;
            }
        };

        match client_msg {
            ClientMessage::Send {
                to,
                body_b64,
                autocrypt_header_b64: _,
            } => {
                // Check whether the recipient has blocked this sender.
                if noombat_chat::relay::is_sender_blocked(&pool, actor_id, &to).await {
                    let err = ServerMessage::Error {
                        message: "recipient has blocked this address".into(),
                    };
                    let _ = send_json(&mut socket, &err).await;
                    continue;
                }

                // The actual SMTP send is delegated to the chat crate.
                //
                // TODO!
                // For now, this is a protocol-level stub: the server
                // acknowledges the send and logs it. Full SMTP relay
                // requires the decrypted Chatmail password, which is
                // held client-side and must be passed in a secure
                // session-establishment handshake (deferred to the
                // full relay implementation).
                info!(
                    from = %chatmail_addr,
                    to = %to,
                    body_len = body_b64.len(),
                    "relay: send (stub)"
                );

                let ack = ServerMessage::Sent { to };
                let _ = send_json(&mut socket, &ack).await;
            }

            ClientMessage::Fetch { since_uid } => {
                // The actual IMAP fetch is delegated to the chat crate.
                //
                // TODO!
                // For now, this is a protocol-level stub.
                info!(
                    addr = %chatmail_addr,
                    since_uid = since_uid,
                    "relay: fetch (stub)"
                );

                // No messages to return in the stub.
            }

            ClientMessage::Ack { uid } => {
                info!(
                    addr = %chatmail_addr,
                    uid = uid,
                    "relay: ack (stub)"
                );
            }
        }
    }

    info!(actor = %actor_id, "chat WebSocket disconnected");
}

/// Serialise a [`ServerMessage`] and send it over the WebSocket.
async fn send_json(socket: &mut WebSocket, msg: &ServerMessage) -> Result<(), axum::Error> {
    let text = serde_json::to_string(msg)
        .unwrap_or_else(|_| r#"{"type":"error","message":"serialisation failed"}"#.into());
    socket.send(Message::Text(text.into())).await
}
