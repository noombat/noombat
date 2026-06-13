// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Maps [`NoombatError`] to Axum HTTP responses.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use noombat_ap::error_body::ApError;
use noombat_core::error::NoombatError;

/// Wrapper that implements [`IntoResponse`] for [`NoombatError`].
pub struct ApiError(pub NoombatError);

impl From<NoombatError> for ApiError {
    fn from(e: NoombatError) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = match &self.0 {
            NoombatError::ActorNotFound(detail) => (
                StatusCode::NOT_FOUND,
                ApError::actor_not_found(detail),
            ),
            NoombatError::NotFound { entity, id } => (
                StatusCode::NOT_FOUND,
                ApError::actor_not_found(format!("{entity}/{id}")),
            ),
            NoombatError::ActorAlreadyExists(detail) => (
                StatusCode::CONFLICT,
                ApError::bad_request(format!("actor already exists: {detail}")),
            ),
            NoombatError::BadRequest(detail) => (
                StatusCode::BAD_REQUEST,
                ApError::bad_request(detail),
            ),
            NoombatError::SignatureVerification => (
                StatusCode::UNAUTHORIZED,
                ApError::signature_failed(),
            ),
            NoombatError::Forbidden => (
                StatusCode::FORBIDDEN,
                ApError::bad_request("forbidden"),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApError::internal("an internal error occurred"),
            ),
        };

        (status, Json(body)).into_response()
    }
}
