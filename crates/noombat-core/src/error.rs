// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Application-wide error types.

use thiserror::Error;
use uuid::Uuid;

/// Top-level error type for the Noombat application.
#[derive(Debug, Error)]
pub enum NoombatError {
    #[error("actor not found: {0}")]
    ActorNotFound(String),

    #[error("actor already exists: {0}")]
    ActorAlreadyExists(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("serialisation error: {0}")]
    Serialisation(#[from] serde_json::Error),

    #[error("federation error: {0}")]
    Federation(String),

    #[error("HTTP signature verification failed")]
    SignatureVerification,

    #[error("resource not found: {entity} / {id}")]
    NotFound { entity: &'static str, id: Uuid },

    #[error("forbidden")]
    Forbidden,

    /// An inbound `Move` this instance refuses to follow.
    ///
    /// Distinct from `BadRequest` because the peer needs to tell a
    /// malformed activity from a well-formed one whose target does not
    /// claim the source: the first is a bug on their side, the second is
    /// a step they have not completed yet, and a generic 400 does not
    /// say which. FEP-c180 gives it its own error code.
    #[error("move rejected: {0}")]
    MoveRejected(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, NoombatError>;
