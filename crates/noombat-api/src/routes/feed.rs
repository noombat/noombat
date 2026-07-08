// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#![allow(unused)] // Template structs: fields read by Askama at compile time.
//! Feed route: server-rendered home feed with HTMX pagination.
//!
//! The feed merges posts from followed actors and posts matching
//! followed hashtags, deduplicated by post ID.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use serde::Deserialize;

use crate::i18n::I18n;
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
    /// Optional username whose followed actors and hashtags determine
    /// the feed composition. Without this, only public posts are shown.
    user: Option<String>,
}

fn default_page() -> u32 {
    1
}

const PAGE_SIZE: i64 = 20;

/// Full feed page (initial load).
async fn feed_page(i18n: I18n) -> impl IntoResponse {
    FeedPage { i18n }
}

/// HTMX partial: returns only the feed items fragment.
///
/// When `user` is specified, the feed includes posts from that user's
/// followed actors and posts tagged with that user's followed hashtags.
async fn feed_partial(
    State(state): State<AppState>,
    Query(query): Query<FeedQuery>,
    i18n: I18n,
) -> impl IntoResponse {
    let offset = (query.page.saturating_sub(1) as i64) * PAGE_SIZE;
    let mut post_ids: Vec<uuid::Uuid> = Vec::new();

    // If a user is specified, fetch posts matching their followed hashtags.
    if let Some(ref username) = query.user {
        if let Ok(actor) =
            noombat_identity::repo::find_local_by_username(&state.pool, username).await
        {
            if let Ok(tags) =
                noombat_identity::hashtags::list_followed_hashtags(&state.pool, actor.id).await
            {
                let tag_ids: Vec<uuid::Uuid> = tags.iter().map(|t| t.id).collect();
                if !tag_ids.is_empty() {
                    if let Ok(ids) = noombat_identity::hashtags::posts_by_hashtags(
                        &state.pool,
                        &tag_ids,
                        PAGE_SIZE,
                        offset,
                    )
                    .await
                    {
                        post_ids.extend(ids);
                    }
                }
            }
        }
    }

    // TODO: Also fetch posts from followed actors and merge/deduplicate.
    // Deferred until proper authentication is available.

    // Fetch the actual post data for the collected IDs.
    let mut posts: Vec<FeedPost> = Vec::new();
    for id in &post_ids {
        if let Ok(Some(row)) = sqlx::query_as::<_, PostRow>(
            r#"SELECT p.id, p.actor_id, p.content_html, p.created_at,
                      p.ap_id, a.username, a.display_name
               FROM posts p
               INNER JOIN actors a ON a.id = p.actor_id
               WHERE p.id = $1 AND p.visibility = 'public'"#,
        )
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        {
            posts.push(FeedPost {
                author: row.username.clone(),
                author_display: row.display_name.unwrap_or(row.username),
                content_html: row.content_html,
                created_at: row.created_at.to_rfc3339(),
                ap_id: row.ap_id,
                post_id: row.id.to_string(),
                aria_label: String::new(),
            });
        }
    }

    let has_next = posts.len() as i64 >= PAGE_SIZE;

    FeedPartial {
        permalink_label: i18n.t("feed_permalink"),
        loading_more_label: i18n.t("feed_loading_more"),
        posts,
        has_next,
        next_page: query.page + 1,
    }
}

/// Database row for a post joined with its author.
#[derive(sqlx::FromRow)]
struct PostRow {
    id: uuid::Uuid,
    actor_id: uuid::Uuid,
    content_html: String,
    created_at: chrono::DateTime<chrono::Utc>,
    ap_id: String,
    username: String,
    display_name: Option<String>,
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
    /// The post's UUID, used for permalink construction.
    pub post_id: String,
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
