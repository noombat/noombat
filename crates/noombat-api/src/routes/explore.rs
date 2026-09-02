// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Explore routes: trending hashtags.
//!
//! - `GET /explore/trending`: trending hashtags, for the local or the
//!   fediverse-wide corpus.

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/explore/trending", get(trending_hashtags))
}

/// Query parameters for `GET /explore/trending`.
#[derive(serde::Deserialize)]
pub struct TrendingParams {
    /// `local` (the default) or `fediverse`.
    pub scope: Option<String>,
}

/// `GET /explore/trending?scope=local|fediverse`
///
/// The scope is echoed back: the two lists are identical when the
/// operator has not enabled remote indexing, and a reader is owed the
/// difference between "the same" and "not applied".
async fn trending_hashtags(
    State(state): State<AppState>,
    Query(params): Query<TrendingParams>,
) -> impl IntoResponse {
    let scope = crate::trending::Scope::from_param(params.scope.as_deref());
    let tags = match state.trending_cache {
        Some(ref cache) => cache.get(scope).await,
        None => Vec::new(),
    };
    Json(serde_json::json!({ "scope": scope, "tags": tags }))
}
