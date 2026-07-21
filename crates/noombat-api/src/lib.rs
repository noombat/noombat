// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

#![forbid(unsafe_code)]
//! Axum routes, server-side HTML Askama templates, and internationalisation.

rust_i18n::i18n!("locales", fallback = "en-US");

pub mod auth;
pub mod cookie;
pub mod error;
pub mod i18n;
pub mod middleware;
pub mod rate_limit;
pub mod routes;
pub mod search_sync;
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
        .merge(routes::auth::router())
        .merge(routes::chat::router())
        .merge(routes::cv::router())
        .merge(routes::feed::router())
        .merge(routes::follows::router())
        .merge(routes::hashtags::router())
        .merge(routes::interactions::router())
        .merge(routes::moderation::router())
        .merge(routes::posts::router())
        .merge(routes::jobs::router())
        .merge(routes::profile_sections::router())
        .merge(routes::search::router())
        .merge(routes::health::router())
        .merge(routes::pages::router())
        .merge(routes::ws_chat::router())
        .nest_service("/assets", ServeDir::new("frontend/dist/assets"))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::authorisation,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limit::rate_limit,
        ))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
