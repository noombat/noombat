// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#![allow(unused)] // Template structs: fields read by Askama at compile time.
//! Post routes: single post view (HTML and ActivityPub JSON).

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};

use noombat_core::error::NoombatError;

use crate::error::ApiError;
use crate::i18n::{negotiate_locale, I18n};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/posts/{id}", get(get_post))
}

async fn get_post(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let row = sqlx::query_as::<_, PostRow>(
        r#"SELECT p.ap_id, p.content_html, p.created_at,
                  a.username, a.display_name
           FROM posts p
           JOIN actors a ON a.id = p.actor_id
           WHERE p.ap_id = $1"#,
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .map_err(NoombatError::from)?
    .ok_or_else(|| NoombatError::NotFound {
        entity: "post",
        id: uuid::Uuid::nil(),
    })?;

    let wants_json = headers
        .get_all("accept")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| {
            v.contains("application/activity+json")
                || v.contains("application/ld+json")
        });

    if wants_json {
        let obj = serde_json::json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": row.ap_id,
            "type": "Note",
            "attributedTo": format!("https://{}/users/{}", state.domain, row.username),
            "content": row.content_html
        });
        return Ok((
            StatusCode::OK,
            [(CONTENT_TYPE, "application/activity+json; charset=utf-8")],
            Json(obj),
        )
            .into_response());
    }

    let i18n = I18n {
        locale: negotiate_locale(&headers),
    };
    let author_display = row
        .display_name
        .clone()
        .unwrap_or_else(|| row.username.clone());
    let page_title = i18n.tf("post_title_pattern", &[("name", &author_display)]);
    let aria_post_label = i18n.tf("aria_post_by", &[("name", &author_display)]);

    let page = PostPage {
        i18n,
        page_title,
        aria_post_label,
        author: row.username.clone(),
        author_display,
        content_html: row.content_html,
        created_at: row.created_at.to_rfc3339(),
    };
    Ok(page.into_response())
}

#[derive(sqlx::FromRow)]
struct PostRow {
    ap_id: String,
    content_html: String,
    created_at: chrono::DateTime<chrono::Utc>,
    username: String,
    display_name: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "post.html")]
struct PostPage {
    i18n: I18n,
    page_title: String,
    aria_post_label: String,
    author: String,
    author_display: String,
    content_html: String,
    created_at: String,
}
