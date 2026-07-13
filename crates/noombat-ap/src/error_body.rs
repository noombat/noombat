// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Structured JSON-LD error bodies for federation-facing endpoints.

use serde::Serialize;
use serde_json::Value;

use crate::context::error_context;

/// A JSON-LD error body conforming to the ActivityStreams Error type.
#[derive(Debug, Clone, Serialize)]
pub struct ApError {
    #[serde(rename = "@context")]
    pub context: Value,
    #[serde(rename = "type")]
    pub error_type: &'static str,
    pub summary: &'static str,
    pub content: String,
    #[serde(rename = "noombat:errorCode")]
    pub error_code: &'static str,
}

impl ApError {
    pub fn actor_not_found(detail: impl Into<String>) -> Self {
        Self {
            context: error_context(),
            error_type: "Error",
            summary: "actor_not_found",
            content: detail.into(),
            error_code: "ACTOR_NOT_FOUND",
        }
    }

    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self {
            context: error_context(),
            error_type: "Error",
            summary: "bad_request",
            content: detail.into(),
            error_code: "BAD_REQUEST",
        }
    }

    pub fn signature_failed() -> Self {
        Self {
            context: error_context(),
            error_type: "Error",
            summary: "signature_verification_failed",
            content: "HTTP Signature verification failed.".to_owned(),
            error_code: "SIGNATURE_FAILED",
        }
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self {
            context: error_context(),
            error_type: "Error",
            summary: "internal_error",
            content: detail.into(),
            error_code: "INTERNAL_ERROR",
        }
    }

    pub fn gone(detail: impl Into<String>) -> Self {
        Self {
            context: error_context(),
            error_type: "Error",
            summary: "gone",
            content: detail.into(),
            error_code: "GONE",
        }
    }

    pub fn rate_limited() -> Self {
        Self {
            context: error_context(),
            error_type: "Error",
            summary: "rate_limited",
            content: "Rate limit exceeded. Please retry later.".to_owned(),
            error_code: "RATE_LIMITED",
        }
    }

    pub fn move_rejected(detail: impl Into<String>) -> Self {
        Self {
            context: error_context(),
            error_type: "Error",
            summary: "move_rejected",
            content: detail.into(),
            error_code: "MOVE_REJECTED",
        }
    }
}
