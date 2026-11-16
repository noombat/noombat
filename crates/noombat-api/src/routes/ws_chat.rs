// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! WebSocket endpoint for the chat relay.
//!
//! Upgrades an HTTP connection to a WebSocket and bridges
//! [`noombat_chat::relay::ClientMessage`] / [`ServerMessage`] between
//! the browser and the Chatmail IMAP/SMTP server.
//!
//! All IMAP/SMTP operations are delegated to [`noombat_chat::session`];
//! this module handles only the Axum WebSocket lifecycle, authentication,
//! and message dispatch.

use axum::Router;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::get;
use noombat_chat::relay::{ClientMessage, ErrorCode, IdleTimer, RelayConfig, ServerMessage};
use noombat_chat::session;
use noombat_core::error::NoombatError;
use tracing::{info, warn};

use crate::error::ApiError;
use crate::middleware::Viewer;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/api/v1/chat/ws", get(ws_upgrade))
}

/// Axum handler: upgrade the HTTP request to a WebSocket.
async fn ws_upgrade(
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<Response, ApiError> {
    let viewer = viewer.ok_or(ApiError(NoombatError::Forbidden))?;
    let actor_id = viewer.actor_id;

    let chatmail_domain = state
        .chatmail_domain
        .as_deref()
        .ok_or(ApiError(NoombatError::ServiceUnavailable(
            "chat not configured".into(),
        )))?
        .to_owned();

    // Fetch the actor's Chatmail address and moderation status.
    let (chatmail_addr, actor_status): (Option<String>, String) =
        sqlx::query_as("SELECT chatmail_addr, actor_status FROM actors WHERE id = $1")
            .bind(actor_id)
            .fetch_one(&state.pool)
            .await
            .map_err(|e| ApiError(NoombatError::Internal(format!("actor lookup failed: {e}"))))?;

    // An allowlist, not a denylist. Stated as `== "suspended"` this admitted
    // every status added later, which the pending admission state made real.
    if !matches!(actor_status.as_str(), "active" | "silenced") {
        return Err(ApiError(NoombatError::Forbidden));
    }

    let chatmail_addr = chatmail_addr.ok_or(ApiError(NoombatError::BadRequest(
        "chat not provisioned for this account".into(),
    )))?;

    let pool = state.pool.clone();
    let relay_config = RelayConfig::from_domain(&chatmail_domain);

    Ok(ws.on_upgrade(move |socket| handle_ws(socket, pool, actor_id, chatmail_addr, relay_config)))
}

/// Main WebSocket loop.
async fn handle_ws(
    mut socket: WebSocket,
    pool: sqlx::PgPool,
    actor_id: uuid::Uuid,
    chatmail_addr: String,
    relay_config: RelayConfig,
) {
    info!(actor = %actor_id, addr = %chatmail_addr, "chat WebSocket connected");

    // ..... Phase 1: await Auth message .....

    let password =
        match tokio::time::timeout(std::time::Duration::from_secs(30), await_auth(&mut socket))
            .await
        {
            Ok(Some(pw)) => pw,
            Ok(None) => {
                info!(actor = %actor_id, "WebSocket closed before auth");
                return;
            }
            Err(_) => {
                let _ = send_json(
                    &mut socket,
                    &ServerMessage::Error {
                        code: ErrorCode::AuthTimeout,
                        message: "auth timeout".into(),
                    },
                )
                .await;
                info!(actor = %actor_id, "WebSocket auth timed out");
                return;
            }
        };

    // ..... Phase 2: establish IMAP session .....

    let tls_connector = session::build_tls_connector();

    let imap_session =
        match session::connect_imap(&tls_connector, &relay_config, &chatmail_addr, &password).await
        {
            Ok(s) => s,
            Err(e) => {
                warn!(actor = %actor_id, error = %e, "IMAP session not opened");
                let _ = send_json(&mut socket, &connect_error(&e)).await;
                return;
            }
        };

    let mut imap_session = Some(imap_session);
    let _ = send_json(&mut socket, &ServerMessage::Ready).await;
    info!(actor = %actor_id, "IMAP session established");

    // ..... Phase 3: relay loop with idle timeout .....

    let mut idle_timer = IdleTimer::new(relay_config.idle_timeout_secs);

    loop {
        let remaining = idle_timer.remaining();

        let msg = tokio::select! {
            recv = socket.recv() => {
                match recv {
                    Some(Ok(msg)) => msg,
                    Some(Err(e)) => {
                        warn!(actor = %actor_id, error = %e, "WebSocket recv error");
                        break;
                    }
                    None => break,
                }
            }
            _ = tokio::time::sleep(remaining) => {
                info!(actor = %actor_id, "idle timeout reached; closing WebSocket");
                let _ = send_json(
                    &mut socket,
                    &ServerMessage::Error {
                        code: ErrorCode::IdleTimeout,
                        message: "session timed out due to inactivity".into(),
                    },
                )
                .await;
                break;
            }
        };

        // Record activity on every inbound client message.
        idle_timer.touch();

        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => break,
            Message::Ping(p) => {
                let _ = socket.send(Message::Pong(p)).await;
                continue;
            }
            _ => continue,
        };

        let client_msg: ClientMessage = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                let _ = send_json(
                    &mut socket,
                    &ServerMessage::Error {
                        code: ErrorCode::InvalidMessage,
                        message: format!("invalid message: {e}"),
                    },
                )
                .await;
                continue;
            }
        };

        match client_msg {
            ClientMessage::Auth { .. } => {
                let _ = send_json(
                    &mut socket,
                    &ServerMessage::Error {
                        code: ErrorCode::AlreadyAuthenticated,
                        message: "already authenticated".into(),
                    },
                )
                .await;
            }

            ClientMessage::Send {
                to,
                body_b64,
                autocrypt_header_b64,
            } => {
                if noombat_chat::relay::is_sender_blocked(&pool, actor_id, &to).await {
                    let _ = send_json(
                        &mut socket,
                        &ServerMessage::Error {
                            code: ErrorCode::Blocked,
                            message: "recipient has blocked this address".into(),
                        },
                    )
                    .await;
                    continue;
                }

                match session::send_message(
                    &relay_config,
                    &chatmail_addr,
                    &password,
                    &to,
                    &body_b64,
                    autocrypt_header_b64.as_deref(),
                )
                .await
                {
                    Ok(()) => {
                        let _ = send_json(&mut socket, &ServerMessage::Sent { to }).await;
                    }
                    Err(e) => {
                        warn!(from = %chatmail_addr, to = %to, error = %e, "SMTP send failed");
                        let _ = send_json(
                            &mut socket,
                            &ServerMessage::Error {
                                code: ErrorCode::SendFailed,
                                message: format!("send failed: {e}"),
                            },
                        )
                        .await;
                    }
                }
            }

            ClientMessage::Fetch { since_uid } => {
                if let Some(ref mut s) = imap_session {
                    match session::fetch_messages(s, since_uid).await {
                        Ok(msgs) => {
                            for server_msg in msgs {
                                if send_json(&mut socket, &server_msg).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            warn!(addr = %chatmail_addr, error = %e, "IMAP fetch failed");
                            let _ = send_json(
                                &mut socket,
                                &ServerMessage::Error {
                                    code: ErrorCode::FetchFailed,
                                    message: format!("fetch failed: {e}"),
                                },
                            )
                            .await;
                        }
                    }
                }
            }

            ClientMessage::Ack { uid } => {
                if let Some(ref mut s) = imap_session {
                    let _ = s.uid_store(format!("{uid}"), "+FLAGS (\\Seen)").await;
                }
            }
        }
    }

    // ..... Cleanup .....

    if let Some(mut s) = imap_session.take() {
        let _ = s.logout().await;
    }
    drop(password);
    info!(actor = %actor_id, "chat WebSocket disconnected");
}

/// Wait for the first message, which must be an `Auth`.
async fn await_auth(socket: &mut WebSocket) -> Option<String> {
    loop {
        let msg = match socket.recv().await {
            Some(Ok(msg)) => msg,
            _ => return None,
        };

        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => return None,
            Message::Ping(p) => {
                let _ = socket.send(Message::Pong(p)).await;
                continue;
            }
            _ => continue,
        };

        let client_msg: ClientMessage = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(_) => {
                let _ = send_json(
                    socket,
                    &ServerMessage::Error {
                        code: ErrorCode::AuthRequired,
                        message: "first message must be auth".into(),
                    },
                )
                .await;
                return None;
            }
        };

        match client_msg {
            ClientMessage::Auth { password } => return Some(password),
            _ => {
                let _ = send_json(
                    socket,
                    &ServerMessage::Error {
                        code: ErrorCode::AuthRequired,
                        message: "first message must be auth".into(),
                    },
                )
                .await;
                return None;
            }
        }
    }
}

/// Serialise a [`ServerMessage`] and send it over the WebSocket.
async fn send_json(socket: &mut WebSocket, msg: &ServerMessage) -> Result<(), axum::Error> {
    let text = serde_json::to_string(msg).unwrap_or_else(|_| {
        r#"{"type":"error","code":"internal","message":"serialisation failed"}"#.into()
    });
    socket.send(Message::Text(text.into())).await
}

/// What the page is told when no session with the relay could be opened:
/// a refused password apart from a relay that could not be reached.
fn connect_error(error: &session::ConnectError) -> ServerMessage {
    let (code, message) = match error {
        session::ConnectError::Refused(_) => (ErrorCode::LoginFailed, "IMAP authentication failed"),
        session::ConnectError::Unreachable(_) => (
            ErrorCode::ConnectFailed,
            "the chat relay could not be reached",
        ),
    };
    ServerMessage::Error {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refused_password_is_told_from_an_unreachable_relay() {
        let refused = connect_error(&session::ConnectError::Refused("no".into()));
        let unreachable = connect_error(&session::ConnectError::Unreachable("down".into()));
        assert!(matches!(
            refused,
            ServerMessage::Error {
                code: ErrorCode::LoginFailed,
                ..
            }
        ));
        assert!(matches!(
            unreachable,
            ServerMessage::Error {
                code: ErrorCode::ConnectFailed,
                ..
            }
        ));
    }

    /// The client translates on `code`, so its spelling is the protocol.
    #[test]
    fn an_error_carries_its_code_in_snake_case() {
        let error = ServerMessage::Error {
            code: ErrorCode::LoginFailed,
            message: "IMAP authentication failed".into(),
        };
        assert_eq!(
            serde_json::to_value(&error).expect("serialised"),
            serde_json::json!({
                "type": "error",
                "code": "login_failed",
                "message": "IMAP authentication failed",
            })
        );
    }

    /// Every code, spelt as the page reads it. A code added without a line
    /// here fails to compile at the `match`.
    #[test]
    fn every_error_code_is_spelt_as_the_page_reads_it() {
        use ErrorCode::*;
        for (code, wire) in [
            (AuthTimeout, "auth_timeout"),
            (AuthRequired, "auth_required"),
            (AlreadyAuthenticated, "already_authenticated"),
            (LoginFailed, "login_failed"),
            (ConnectFailed, "connect_failed"),
            (IdleTimeout, "idle_timeout"),
            (InvalidMessage, "invalid_message"),
            (Blocked, "blocked"),
            (SendFailed, "send_failed"),
            (FetchFailed, "fetch_failed"),
            (Internal, "internal"),
        ] {
            match code {
                AuthTimeout | AuthRequired | AlreadyAuthenticated | LoginFailed | ConnectFailed
                | IdleTimeout | InvalidMessage | Blocked | SendFailed | FetchFailed | Internal => {}
            }
            assert_eq!(serde_json::to_value(code).expect("serialised"), wire);
        }
    }
}
