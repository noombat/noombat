// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#![allow(unused)] // Template structs: fields read by Askama at compile time.
//! Feed route: server-rendered home feed with HTMX pagination.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use serde::Deserialize;

use crate::i18n::{negotiate_locale, I18n};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(feed_page))
        .route("/feed", get(feed_partial))
}

#[derive(Deserialize)]
struct FeedQuery {
    #[serde(default = "default_page")]
    page: u32,
}

fn default_page() -> u32 {
    1
}

/// Full feed page (initial load).
async fn feed_page(headers: HeaderMap) -> impl IntoResponse {
    let i18n = I18n {
        locale: negotiate_locale(&headers),
    };
    FeedPage { i18n }
}

/// HTMX partial: returns only the feed items fragment.
async fn feed_partial(
    State(_state): State<AppState>,
    Query(query): Query<FeedQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let i18n = I18n {
        locale: negotiate_locale(&headers),
    };
    FeedPartial {
        permalink_label: i18n.t("feed_permalink"),
        loading_more_label: i18n.t("feed_loading_more"),
        posts: vec![],
        has_next: false,
        next_page: query.page + 1,
    }
}

#[derive(Template, WebTemplate)]
#[template(path = "feed.html")]
struct FeedPage {
    i18n: I18n,
}

/// A single post in the feed, passed to the template.
pub struct FeedPost {
    pub author: String,
    pub author_display: String,
    pub content_html: String,
    pub created_at: String,
    pub ap_id: String,
    /// Pre-computed ARIA label (e.g. "Post by Alice").
    pub aria_label: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "feed_page.html")]
struct FeedPartial {
    posts: Vec<FeedPost>,
    has_next: bool,
    next_page: u32,
    permalink_label: String,
    loading_more_label: String,
}
