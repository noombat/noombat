// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Chat moderation: report submission.
//!
//! Because messages are end-to-end encrypted and the server cannot
//! read them, reporting operates client-side: the browser decrypts
//! the reported message, extracts the plaintext, and submits it to
//! the server via a REST endpoint.

use chrono::{DateTime, Utc};
use noombat_core::error::{NoombatError, Result};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// Request body for `POST /api/v1/chat/reports`.
#[derive(Debug, Deserialize)]
pub struct ChatReportRequest {
    /// The sender's Chatmail address.
    pub target_addr: String,
    /// Decrypted message content (submitted by the reporter).
    pub message_content: Option<String>,
    /// Timestamp of the reported message.
    pub message_date: Option<DateTime<Utc>>,
    /// Reason category.
    pub reason: ChatReportReason,
    /// Optional free-text comment.
    pub comment: Option<String>,
}

/// Reason categories for chat reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChatReportReason {
    Spam,
    Harassment,
    Illegal,
    Impersonation,
    Other,
}

impl ChatReportReason {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Spam => "spam",
            Self::Harassment => "harassment",
            Self::Illegal => "illegal",
            Self::Impersonation => "impersonation",
            Self::Other => "other",
        }
    }
}

/// Response body for a submitted report.
#[derive(Debug, Serialize)]
pub struct ChatReportResponse {
    pub report_id: Uuid,
}

/// Submit a chat report.
pub async fn submit_report(
    pool: &PgPool,
    reporter_id: Uuid,
    req: &ChatReportRequest,
) -> Result<ChatReportResponse> {
    if req.target_addr.is_empty() {
        return Err(NoombatError::BadRequest(
            "target_addr must not be empty".into(),
        ));
    }

    let id = Uuid::new_v4();

    sqlx::query(
        r#"INSERT INTO chat_reports
               (id, reporter_id, target_addr, message_content,
                message_date, reason, comment)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(id)
    .bind(reporter_id)
    .bind(&req.target_addr)
    .bind(&req.message_content)
    .bind(req.message_date)
    .bind(req.reason.as_str())
    .bind(&req.comment)
    .execute(pool)
    .await?;

    tracing::info!(
        report_id = %id,
        reporter = %reporter_id,
        target = %req.target_addr,
        reason = %req.reason.as_str(),
        "chat report submitted"
    );

    Ok(ChatReportResponse { report_id: id })
}
