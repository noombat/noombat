// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

#![forbid(unsafe_code)]
//! Axum routes, server-side HTML Askama templates, and internationalisation.

rust_i18n::i18n!("locales", fallback = "en-US");

pub mod analytics;
pub mod auth;
pub mod chatmail_ops;
pub mod cookie;
pub mod erasure;
pub mod error;
pub mod housekeeping;
pub mod i18n;
pub mod interactions;
pub mod jobs_federation;
pub mod media;
pub mod media_ops;
pub mod middleware;
pub mod rate_limit;
pub mod routes;
pub mod search_ops;
pub mod search_sync;
pub mod state;
pub mod theme;
pub mod trending;

use axum::Router;
use tower_http::compression::CompressionLayer;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Build the top-level Axum [`Router`] with all routes.
///
/// Response security headers are applied outermost, after every
/// route and after the `/assets` service, so that static assets and
/// error responses produced by the inner layers carry them as well.
pub fn build_router(state: AppState) -> Router {
    let domain = state.domain.clone();
    let public_port = state.public_port;

    let router = Router::new()
        .merge(routes::federation::router())
        .merge(routes::actors::router())
        .merge(routes::applications::router())
        .merge(routes::auth::router())
        .merge(routes::chat::router())
        .merge(routes::connections::router())
        .merge(routes::cv::router())
        .merge(routes::feed::router())
        .merge(routes::follows::router())
        .merge(routes::hashtags::router())
        .merge(routes::interactions::router())
        .merge(routes::media::router())
        .merge(routes::moderation::router())
        .merge(routes::posts::router())
        .merge(routes::preview::router())
        .merge(routes::jobs::router())
        .merge(routes::profile_sections::router())
        .merge(routes::search::router())
        .merge(routes::health::router())
        .merge(routes::wellknown::router())
        .merge(routes::pages::router())
        .merge(routes::ws_chat::router())
        .merge(routes::admin_relays::router())
        .merge(routes::organization::router())
        .merge(routes::explore::router())
        .merge(routes::admin::router())
        .merge(routes::account::router())
        .nest_service("/assets", ServeDir::new("frontend/dist/assets"))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::authentication,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limit::rate_limit,
        ))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http());

    middleware::security_headers(router, &domain, public_port).with_state(state)
}
