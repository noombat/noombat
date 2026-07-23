// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Explore routes: trending hashtags.
//!
//! - `GET /explore/trending`: JSON list of trending hashtags.

use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/explore/trending", get(trending_hashtags))
}

/// `GET /explore/trending`
///
/// Returns the cached trending hashtags list. The list is recomputed
/// periodically by the background worker
/// ([`crate::trending::run_worker`]).
async fn trending_hashtags(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let tags = match state.trending_cache {
        Some(ref cache) => cache.get().await,
        None => Vec::new(),
    };
    Json(tags)
}
