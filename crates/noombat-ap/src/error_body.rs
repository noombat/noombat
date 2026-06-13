// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Structured JSON-LD error bodies for federation-facing endpoints.

use serde::Serialize;

use crate::context::AS_CONTEXT;

/// A JSON-LD error body conforming to the ActivityStreams Error type.
#[derive(Debug, Clone, Serialize)]
pub struct ApError {
    #[serde(rename = "@context")]
    pub context: &'static str,
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
            context: AS_CONTEXT,
            error_type: "Error",
            summary: "actor_not_found",
            content: detail.into(),
            error_code: "ACTOR_NOT_FOUND",
        }
    }

    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self {
            context: AS_CONTEXT,
            error_type: "Error",
            summary: "bad_request",
            content: detail.into(),
            error_code: "BAD_REQUEST",
        }
    }

    pub fn signature_failed() -> Self {
        Self {
            context: AS_CONTEXT,
            error_type: "Error",
            summary: "signature_verification_failed",
            content: "HTTP Signature verification failed.".to_owned(),
            error_code: "SIGNATURE_FAILED",
        }
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self {
            context: AS_CONTEXT,
            error_type: "Error",
            summary: "internal_error",
            content: detail.into(),
            error_code: "INTERNAL_ERROR",
        }
    }
}
