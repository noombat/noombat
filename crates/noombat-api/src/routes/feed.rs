// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#![allow(unused)] // Template structs: fields read by Askama at compile time.
//! Feed route: server-rendered home feed with HTMX pagination.
//!
//! The feed merges posts from followed actors and posts matching
//! followed hashtags, deduplicated by post ID. Articles are rendered
//! with their title and a truncated preview; Notes are rendered inline.

use askama::Template;
use askama_web::WebTemplate;
use axum::Router;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::routing::get;
use serde::Deserialize;

use crate::i18n::I18n;
use crate::middleware::Viewer;
use crate::state::AppState;
use crate::theme::{Contrast, Theme};

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

/// The URL the container fetches for a page of the feed.
///
/// The viewer travels in the query string, so page two stays on the
/// timeline page one showed. Built here rather than in the template:
/// a username is user input, and this is the only place that encodes it.
fn feed_url(page: u32, viewer: Option<&str>) -> String {
    match viewer {
        Some(username) => format!("/feed?page={page}&user={}", urlencoding::encode(username)),
        None => format!("/feed?page={page}"),
    }
}

/// Full feed page (initial load).
async fn feed_page(
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    viewer: Option<axum::Extension<Viewer>>,
) -> impl IntoResponse {
    let viewer = viewer.as_ref().map(|p| p.username.clone());

    FeedPage {
        feed_url: feed_url(1, viewer.as_deref()),
        i18n,
        theme,
        contrast,
    }
}

/// HTMX partial: returns only the feed items fragment.
///
/// When `user` is specified, the feed includes posts from that user's
/// followed actors and posts tagged with that user's followed hashtags.
async fn feed_partial(
    State(state): State<AppState>,
    Query(query): Query<FeedQuery>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
) -> impl IntoResponse {
    let offset = (query.page.saturating_sub(1) as i64) * PAGE_SIZE;
    let mut post_ids: Vec<uuid::Uuid> = Vec::new();
    // Resolved viewer actor ID, if a valid `user` parameter was
    // supplied. Reused for follow, mute, and silenced-actor queries.
    let mut viewer_actor_id: Option<uuid::Uuid> = None;

    // If a user is specified, fetch posts matching their followed hashtags.
    if let Some(ref username) = query.user
        && let Ok(actor) =
            noombat_identity::repo::find_local_by_username(&state.pool, username).await
    {
        viewer_actor_id = Some(actor.id);

        // Posts from followed hashtags.
        if let Ok(tags) =
            noombat_identity::hashtags::list_followed_hashtags(&state.pool, actor.id).await
        {
            let tag_ids: Vec<uuid::Uuid> = tags.iter().map(|t| t.id).collect();
            if !tag_ids.is_empty()
                && let Ok(ids) = noombat_identity::hashtags::posts_by_hashtags(
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

        // Posts from followed actors (accepted follows only).
        if let Ok(followed_post_ids) = sqlx::query_scalar::<_, uuid::Uuid>(
            r#"SELECT p.id FROM posts p
               JOIN follows f ON f.following_id = p.actor_id
               WHERE f.follower_id = $1
                 AND f.accepted = TRUE
                 AND p.visibility IN ('public', 'unlisted')
               ORDER BY p.created_at DESC
               LIMIT $2 OFFSET $3"#,
        )
        .bind(actor.id)
        .bind(PAGE_SIZE)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
        {
            post_ids.extend(followed_post_ids);
        }

        // Deduplicate post IDs while preserving insertion order
        // (posts from followed actors are already ordered by
        // created_at DESC; sorting by UUID would destroy this).
        let mut seen = std::collections::HashSet::new();
        post_ids.retain(|id| seen.insert(*id));
    }

    // With no viewer identified, the feed is the public timeline, and a
    // signed-in viewer who follows nobody sees it as well rather than an
    // empty page. First page only: falling back further in would switch
    // timelines mid-scroll and repeat posts already shown.
    //
    // `unlisted` is excluded by definition: it is the visibility that
    // means "not on public timelines".
    let public_timeline = viewer_actor_id.is_none() || (post_ids.is_empty() && query.page <= 1);

    if public_timeline
        && let Ok(ids) = sqlx::query_scalar::<_, uuid::Uuid>(
            r#"SELECT p.id FROM posts p
               WHERE p.visibility = 'public'
               ORDER BY p.created_at DESC
               LIMIT $1 OFFSET $2"#,
        )
        .bind(PAGE_SIZE)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
    {
        post_ids.extend(ids);
    }

    // Mute filtering, resolved once for the page rather than per post.
    // Keyed on this page's authors, so a viewer with a long mute list
    // does not load all of it to render twenty posts.
    let muted = match viewer_actor_id {
        Some(viewer_id) => {
            let authors: Vec<uuid::Uuid> =
                sqlx::query_scalar("SELECT DISTINCT actor_id FROM posts WHERE id = ANY($1)")
                    .bind(&post_ids)
                    .fetch_all(&state.pool)
                    .await
                    .unwrap_or_default();
            crate::interactions::Interactions::new(state.pool.clone())
                .muted_among(&viewer_id, &authors)
                .await
        }
        None => crate::interactions::MutedAuthors::default(),
    };

    // Collect the IDs of actors the viewer explicitly follows.
    // Posts by silenced actors are excluded from public timelines
    // unless the viewer follows them.
    let followed_actor_ids: std::collections::HashSet<uuid::Uuid> =
        if let Some(actor_id) = viewer_actor_id {
            sqlx::query_scalar::<_, uuid::Uuid>(
                "SELECT following_id FROM follows \
                 WHERE follower_id = $1 AND accepted = TRUE",
            )
            .bind(actor_id)
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect()
        } else {
            std::collections::HashSet::new()
        };

    // Fetch the actual post data for the collected IDs.
    let mut posts: Vec<FeedPost> = Vec::new();
    for id in &post_ids {
        if let Ok(Some(row)) = sqlx::query_as::<_, PostRow>(
            r#"SELECT p.id, p.actor_id, p.post_type, p.title,
                      p.featured_image_url, p.content_html, p.created_at,
                      p.ap_id, a.username, a.display_name, a.actor_status
               FROM posts p
               INNER JOIN actors a ON a.id = p.actor_id
               WHERE p.id = $1 AND p.visibility IN ('public', 'unlisted')"#,
        )
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        {
            // Mute filter: skip posts by muted actors.
            if !muted.restriction(&row.actor_id).appears_in_feed() {
                continue;
            }

            // Silenced-actor filter: exclude posts by silenced
            // actors from public timelines unless the viewer
            // explicitly follows them.
            if row.actor_status.is_silenced() && !followed_actor_ids.contains(&row.actor_id) {
                continue;
            }

            let is_article = row.post_type == "article";

            // For articles, compute a plain-text preview by stripping
            // HTML tags from content_html and truncating. Notes render
            // their full HTML inline, so no preview is needed.
            let preview_text = if is_article {
                let plain = noombat_markup::sanitise::strip_tags(&row.content_html);
                if plain.len() > 280 {
                    let boundary = plain.floor_char_boundary(280);
                    format!("{}…", &plain[..boundary])
                } else {
                    plain
                }
            } else {
                String::new()
            };

            let author_display = row.display_name.unwrap_or_else(|| row.username.clone());

            // Populate a meaningful ARIA label. An empty aria-label is
            // worse than none: screen readers would announce the element
            // as having no accessible name, overriding the text content.
            let aria_label = if is_article {
                let t = row.title.as_deref().unwrap_or("");
                i18n.tf("aria_article_by", &[("title", t)])
            } else {
                i18n.tf("aria_post_by", &[("name", &author_display)])
            };

            // Ensure articles always carry a display title, using the
            // i18n fallback rather than a hardcoded English string.
            let title = if is_article && row.title.is_none() {
                Some(i18n.t("article_untitled"))
            } else {
                row.title
            };

            posts.push(FeedPost {
                author: row.username,
                author_display,
                content_html: row.content_html,
                created_at: row.created_at.to_rfc3339(),
                ap_id: row.ap_id,
                post_id: row.id.to_string(),
                is_article,
                title,
                featured_image_url: row.featured_image_url,
                preview_text,
                aria_label,
            });
        }
    }

    let has_next = posts.len() as i64 >= PAGE_SIZE;

    let status_announcement = if posts.is_empty() {
        i18n.t("feed_loaded_none")
    } else {
        i18n.tf(
            "feed_loaded_announcement",
            &[("count", &posts.len().to_string())],
        )
    };

    FeedPartial {
        permalink_label: i18n.t("feed_permalink"),
        loading_more_label: i18n.t("feed_loading_more"),
        read_more_label: i18n.t("feed_read_more"),
        status_announcement,
        posts,
        has_next,
        next_url: feed_url(query.page + 1, query.user.as_deref()),
    }
}

/// Database row for a post joined with its author.
#[derive(sqlx::FromRow)]
struct PostRow {
    id: uuid::Uuid,
    actor_id: uuid::Uuid,
    post_type: String,
    title: Option<String>,
    featured_image_url: Option<String>,
    content_html: String,
    created_at: chrono::DateTime<chrono::Utc>,
    ap_id: String,
    username: String,
    display_name: Option<String>,
    /// The author's moderation status; used to filter silenced actors
    /// from public timelines.
    actor_status: noombat_core::actor::ActorStatus,
}

#[derive(Template, WebTemplate)]
#[template(path = "feed.html")]
struct FeedPage {
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
    feed_url: String,
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
    /// Whether this post is an article (affects rendering in the feed).
    pub is_article: bool,
    /// Article title (non-`None` when `is_article` is `true`).
    pub title: Option<String>,
    /// Featured image URL (optional, primarily for articles).
    pub featured_image_url: Option<String>,
    /// Plain-text preview for articles (HTML-stripped, truncated).
    /// Empty for Notes (which render their full HTML inline).
    pub preview_text: String,
    /// Pre-computed ARIA label (e.g. "Post by Alice").
    pub aria_label: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "feed_page.html")]
struct FeedPartial {
    posts: Vec<FeedPost>,
    has_next: bool,
    next_url: String,
    /// Text swapped out of band into the `#a11y-status` live region in
    /// `base.html`, so assistive technology learns that items arrived.
    ///
    /// Phrased to avoid number agreement, which `I18n::tf` cannot handle:
    /// "Posts loaded: 1" reads correctly where "Loaded 1 posts" would
    /// not. An empty page announces the end of the feed instead of a
    /// count of zero.
    status_announcement: String,
    permalink_label: String,
    loading_more_label: String,
    read_more_label: String,
}
