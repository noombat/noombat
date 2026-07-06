// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Full-text search route backed by the [`SearchBackend`] extension point.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::error::ApiError;
use crate::state::AppState;

/// Query parameters for `GET /search`.
#[derive(Debug, Deserialize)]
pub struct SearchParams {
    /// The search query string.
    pub q: String,
    /// Index to search (`profiles`, `jobs`, `posts`). Defaults to `profiles`.
    #[serde(default = "default_index")]
    pub index: String,
    /// Optional Meilisearch filter expression.
    pub filter: Option<String>,
    /// Maximum number of results (default 20, capped at 100).
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Result offset for pagination (default 0).
    #[serde(default)]
    pub offset: usize,
}

fn default_index() -> String {
    "profiles".to_owned()
}

fn default_limit() -> usize {
    20
}

const MAX_LIMIT: usize = 100;
const ALLOWED_INDICES: &[&str] = &["profiles", "jobs", "posts"];

pub fn router() -> Router<AppState> {
    Router::new().route("/search", get(search))
}

/// `GET /search?q=…&index=…&filter=…&limit=…&offset=…`
///
/// Returns a JSON array of matching documents. Responds with
/// `503 Service Unavailable` when no search backend is configured.
async fn search(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> Result<impl IntoResponse, ApiError> {
    let backend = state.search.as_ref().ok_or_else(|| {
        ApiError(noombat_core::error::NoombatError::ServiceUnavailable(
            "search is not configured".into(),
        ))
    })?;

    if !ALLOWED_INDICES.contains(&params.index.as_str()) {
        return Err(ApiError(noombat_core::error::NoombatError::BadRequest(
            format!(
                "invalid index '{}'; expected one of: {}",
                params.index,
                ALLOWED_INDICES.join(", ")
            ),
        )));
    }

    let limit = params.limit.min(MAX_LIMIT);

    let results = backend
        .search(
            &params.index,
            &params.q,
            params.filter.as_deref(),
            limit,
            params.offset,
        )
        .await
        .map_err(|e| {
            // When a user-supplied filter is present and the search
            // fails, the most likely cause is an invalid filter
            // expression. Surface this as 400 Bad Request rather than
            // an opaque 500 so the caller can correct the query.
            if params.filter.is_some() {
                ApiError(noombat_core::error::NoombatError::BadRequest(format!(
                    "search failed (likely invalid filter): {e}"
                )))
            } else {
                ApiError::from(e)
            }
        })?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "index": params.index,
            "query": params.q,
            "hits": results,
            "limit": limit,
            "offset": params.offset,
        })),
    ))
}
