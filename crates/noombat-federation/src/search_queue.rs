// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Writing to the search-index work queue.
//!
//! Two crates put work in it and one takes work out. Ingestion is here,
//! erasure is in `noombat-api`, and the worker that drains it is there
//! too, where the search backend lives. This module is the writing half,
//! in the lower crate, because the same `ON CONFLICT` rules have to hold
//! for both writers and a second copy of them is a second answer.
//!
//! The precedence between the two operations is the rule worth stating:
//! **a removal beats an upsert, in both directions.** A removal replaces
//! a pending upsert, and an upsert will not replace a pending removal.
//! The removal is the one with a person behind it, and an upsert winning
//! the race would put erased content back.

use noombat_core::error::Result;
use serde_json::Value;
use sqlx::PgPool;

/// Record that a document must leave the index.
pub async fn enqueue_removal(pool: &PgPool, index: &str, document_id: &str) -> Result<()> {
    sqlx::query(
        r#"INSERT INTO search_index_operations (index_name, document_id, operation, document)
           VALUES ($1, $2, 'remove', NULL)
           ON CONFLICT (index_name, document_id) DO UPDATE
             SET operation = 'remove',
                 document = NULL,
                 state = 'pending',
                 attempts = 0,
                 last_error = NULL,
                 next_attempt_at = now(),
                 completed_at = NULL"#,
    )
    .bind(index)
    .bind(document_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Record that a document should enter the index.
///
/// The `WHERE` clause is what makes a pending removal win: without it
/// the upsert would overwrite the removal and the document would be put
/// back into the index it was asked to leave.
pub async fn enqueue_upsert(
    pool: &PgPool,
    index: &str,
    document_id: &str,
    document: &Value,
) -> Result<()> {
    sqlx::query(
        r#"INSERT INTO search_index_operations (index_name, document_id, operation, document)
           VALUES ($1, $2, 'upsert', $3)
           ON CONFLICT (index_name, document_id) DO UPDATE
             SET document = EXCLUDED.document,
                 state = 'pending',
                 attempts = 0,
                 last_error = NULL,
                 next_attempt_at = now(),
                 completed_at = NULL
           WHERE search_index_operations.operation <> 'remove'"#,
    )
    .bind(index)
    .bind(document_id)
    .bind(document)
    .execute(pool)
    .await?;

    Ok(())
}
