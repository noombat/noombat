// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

#![forbid(unsafe_code)]
//! Axum routes, server-side HTML Askama templates, and internationalisation.

rust_i18n::i18n!("locales", fallback = "en-US");

pub mod error;
pub mod i18n;
pub mod middleware;
pub mod routes;
pub mod state;

use axum::Router;
use tower_http::compression::CompressionLayer;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Build the top-level Axum [`Router`] with all routes.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .merge(routes::federation::router())
        .merge(routes::actors::router())
        .merge(routes::feed::router())
        .merge(routes::posts::router())
        .merge(routes::health::router())
        .nest_service("/assets", ServeDir::new("frontend/dist/assets"))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::authorisation,
        ))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
