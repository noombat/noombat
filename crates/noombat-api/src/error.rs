// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Maps [`NoombatError`] to Axum HTTP responses.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use noombat_ap::error_body::ApError;
use noombat_core::error::NoombatError;

/// Wrapper that implements [`IntoResponse`] for [`NoombatError`].
pub struct ApiError(pub NoombatError);

impl From<NoombatError> for ApiError {
    fn from(e: NoombatError) -> Self {
        Self(e)
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        Self(NoombatError::from(e))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = match &self.0 {
            NoombatError::ActorNotFound(detail) => {
                (StatusCode::NOT_FOUND, ApError::actor_not_found(detail))
            }
            NoombatError::NotFound { entity, id } => (
                StatusCode::NOT_FOUND,
                ApError::actor_not_found(format!("{entity}/{id}")),
            ),
            NoombatError::ActorAlreadyExists(detail) => (
                StatusCode::CONFLICT,
                ApError::bad_request(format!("actor already exists: {detail}")),
            ),
            NoombatError::BadRequest(detail) => {
                // Only the peer is told why, and peers do not always log
                // the body. An inbox rejection is unreadable without it.
                tracing::debug!(%detail, "request rejected");
                (StatusCode::BAD_REQUEST, ApError::bad_request(detail))
            }
            NoombatError::SignatureVerification => {
                (StatusCode::UNAUTHORIZED, ApError::signature_failed())
            }
            NoombatError::Forbidden => (StatusCode::FORBIDDEN, ApError::bad_request("forbidden")),
            // 422 rather than 400: the activity was understood and is
            // well formed, and this instance declines to act on it.
            NoombatError::MoveRejected(detail) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                ApError::move_rejected(detail),
            ),
            NoombatError::ServiceUnavailable(detail) => {
                (StatusCode::SERVICE_UNAVAILABLE, ApError::internal(detail))
            }
            _ => {
                // The peer is told nothing, deliberately. Log the cause
                // here or a 500 leaves no trace of what failed.
                tracing::error!(error = %self.0, "request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ApError::internal("an internal error occurred"),
                )
            }
        };

        (status, Json(body)).into_response()
    }
}
