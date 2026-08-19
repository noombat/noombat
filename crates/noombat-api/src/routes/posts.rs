// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#![allow(unused)] // Template structs: fields read by Askama at compile time.
//! Post routes: single post view (HTML and ActivityPub JSON).
//!
//! Handles both Note and Article post types. Articles receive a
//! dedicated template with a table of contents extracted from headings.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use uuid::Uuid;

use noombat_ap::context::{AS_CONTEXT, default_context};
use noombat_core::error::NoombatError;
use noombat_markup::headings::Heading;
use tracing::warn;

use crate::error::ApiError;
use crate::i18n::I18n;
use crate::middleware::Principal;
use crate::state::AppState;
use crate::theme::Theme;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/users/{username}/posts/{post_id}", get(get_post))
        // Human-facing URL alias, consistent with the /@{username}
        // convention used by the profile page (actors.rs).
        .route("/@{username}/posts/{post_id}", get(get_post))
}

async fn get_post(
    State(state): State<AppState>,
    Path((username, post_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    i18n: I18n,
    theme: Theme,
    principal: Option<axum::Extension<Principal>>,
) -> Result<impl IntoResponse, ApiError> {
    let row = sqlx::query_as::<_, PostRow>(
        r#"SELECT p.id, p.actor_id, p.ap_id, p.post_type, p.title,
                  p.featured_image_url, p.content_md, p.content_html,
                  p.visibility, p.ap_object, p.created_at,
                  a.username, a.display_name
           FROM posts p
           JOIN actors a ON a.id = p.actor_id
           WHERE p.id = $1 AND a.username = $2"#,
    )
    .bind(post_id)
    .bind(&username)
    .fetch_optional(&state.pool)
    .await
    .map_err(NoombatError::from)?
    .ok_or_else(|| NoombatError::NotFound {
        entity: "post",
        id: post_id,
    })?;

    // ---- Visibility check ----
    //
    // Followers-only posts must not be served to unauthenticated
    // viewers or to viewers who are neither the author nor an
    // accepted follower. Public and unlisted posts are visible to
    // anyone (unlisted posts are excluded from timelines/search but
    // accessible via direct URL, per the Fediverse convention).
    if row.visibility == "followers" {
        let viewer_id = principal.as_ref().and_then(|p| p.actor_id());
        let is_author = viewer_id == Some(row.actor_id);
        let is_follower = if let Some(vid) = viewer_id {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(\
                   SELECT 1 FROM follows \
                   WHERE follower_id = $1 AND following_id = $2 AND accepted = TRUE\
                 )",
            )
            .bind(vid)
            .bind(row.actor_id)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(false)
        } else {
            false
        };
        if !is_author && !is_follower {
            return Err(NoombatError::NotFound {
                entity: "post",
                id: post_id,
            }
            .into());
        }
    }

    // ---- ActivityPub JSON (content negotiation) ----
    let wants_json = headers
        .get_all("accept")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.contains("application/activity+json") || v.contains("application/ld+json"));

    if wants_json {
        // Return the inner object from the stored AP activity.
        //
        // For local posts, `ap_object` contains the full `Create`
        // activity; the inner Note/Article is at `["object"]`.
        // For remote (federated) posts, `ap_object` contains the
        // inner object directly. Try the nested path first; fall
        // back to the stored value itself.
        let inner = row
            .ap_object
            .get("object")
            .cloned()
            .unwrap_or_else(|| row.ap_object.clone());

        // Fill these in only when they are missing.
        //
        // Both used to be overwritten unconditionally: `@context` because
        // an inner object nested in a Create may omit it, and `id` to
        // guard against a stale stored value. Neither can be rewritten
        // now. Locally published objects carry an FEP-8b32 proof computed
        // over the document including these properties, so replacing them
        // invalidates the proof of every object we serve, which is the
        // one redistribution path that exists today.
        //
        // A stored `id` that disagrees with the column is a real
        // inconsistency rather than an absence, so it is still corrected,
        // and loudly: the proof is already void in that case.
        let mut obj = inner;
        if obj.get("@context").is_none() {
            obj["@context"] = serde_json::json!(default_context());
        }
        match obj.get("id").and_then(|v| v.as_str()) {
            Some(stored) if stored == row.ap_id => {}
            Some(stored) => {
                warn!(
                    stored,
                    authoritative = %row.ap_id,
                    "stored ap_object id disagrees with the posts row; correcting"
                );
                obj["id"] = serde_json::json!(row.ap_id);
            }
            None => obj["id"] = serde_json::json!(row.ap_id),
        }

        // Set the human-facing `url` property if absent.
        if obj.get("url").is_none() {
            obj["url"] = serde_json::json!(format!(
                "https://{}/@{}/posts/{}",
                state.domain, row.username, row.id
            ));
        }

        return Ok((
            StatusCode::OK,
            [(CONTENT_TYPE, "application/activity+json; charset=utf-8")],
            Json(obj),
        )
            .into_response());
    }

    // ---- HTML rendering ----

    let author_display = row
        .display_name
        .clone()
        .unwrap_or_else(|| row.username.clone());

    // ---- Article rendering ----
    if row.post_type == "article" {
        let article_title = row
            .title
            .clone()
            .unwrap_or_else(|| i18n.t("article_untitled"));

        // Extract headings from the Markdown source for the TOC.
        // Heading `id` attributes are already present in content_html
        // (injected at render time by the outbox handler via
        // MarkupOptions::inject_heading_ids).
        //
        // Remote posts without a Markdown source yield no headings, and
        // so no table of contents. That is a correction, not a
        // regression: this used to run over a copy of the *HTML*, which
        // produced entries whose `#slug` anchors matched nothing.
        let headings = row
            .content_md
            .as_deref()
            .map(noombat_markup::extract_headings)
            .unwrap_or_default();
        let content_html = row.content_html;

        let aria_article_label = i18n.tf("aria_article_by", &[("title", &article_title)]);
        let canonical_url = format!(
            "https://{}/users/{}/posts/{}",
            state.domain, row.username, row.id
        );

        let page = ArticlePage {
            i18n,
            theme,
            article_title,
            aria_article_label,
            canonical_url,
            author: row.username.clone(),
            author_display,
            featured_image_url: row.featured_image_url,
            headings,
            content_html,
            created_at: row.created_at.to_rfc3339(),
        };
        return Ok(page.into_response());
    }

    // ---- Note rendering ----
    let page_title = i18n.tf("post_title_pattern", &[("name", &author_display)]);
    let aria_post_label = i18n.tf("aria_post_by", &[("name", &author_display)]);

    let page = PostPage {
        i18n,
        theme,
        page_title,
        aria_post_label,
        post_id: row.id.to_string(),
        author: row.username.clone(),
        author_display,
        content_html: row.content_html,
        created_at: row.created_at.to_rfc3339(),
    };
    Ok(page.into_response())
}

#[derive(sqlx::FromRow)]
struct PostRow {
    id: Uuid,
    actor_id: Uuid,
    ap_id: String,
    post_type: String,
    title: Option<String>,
    featured_image_url: Option<String>,
    /// `None` for remote posts whose author sent no Markdown source.
    /// Nullable rather than holding a copy of `content_html` in that
    /// case, which would put HTML in a column named for Markdown.
    content_md: Option<String>,
    content_html: String,
    visibility: String,
    ap_object: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
    username: String,
    display_name: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "post.html")]
struct PostPage {
    i18n: I18n,
    theme: Theme,
    page_title: String,
    aria_post_label: String,
    post_id: String,
    author: String,
    author_display: String,
    content_html: String,
    created_at: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "article.html")]
struct ArticlePage {
    i18n: I18n,
    theme: Theme,
    article_title: String,
    aria_article_label: String,
    canonical_url: String,
    author: String,
    author_display: String,
    featured_image_url: Option<String>,
    headings: Vec<Heading>,
    content_html: String,
    created_at: String,
}
