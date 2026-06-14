// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Actor routes: ActivityPub actor JSON, HTML profile page, and C2S outbox.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use noombat_ap::context::default_context;
use noombat_ap::object::{ApActor, ApPublicKey};
use noombat_core::error::NoombatError;

use crate::error::ApiError;
use crate::i18n::{negotiate_locale, I18n};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/users/{username}", get(get_actor))
        .route(
            "/users/{username}/outbox",
            get(get_outbox).post(post_outbox),
        )
}

// ..... HELPERS .....

fn wants_activity_json(headers: &HeaderMap) -> bool {
    headers
        .get_all("accept")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.contains("application/activity+json") || v.contains("application/ld+json"))
}

/// Verify the `Authorization: Bearer <token>` header against the
/// configured admin token. Returns `Err(Forbidden)` on mismatch or
/// if no admin token is configured.
fn verify_bearer_token(headers: &HeaderMap, expected: &Option<String>) -> Result<(), NoombatError> {
    let expected = expected.as_deref().ok_or(NoombatError::Forbidden)?;

    let header = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(NoombatError::Forbidden)?;

    let token = header
        .strip_prefix("Bearer ")
        .ok_or(NoombatError::Forbidden)?;

    if token != expected {
        return Err(NoombatError::Forbidden);
    }
    Ok(())
}

// ..... GET /users/{username} .....

async fn get_actor(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

    if wants_activity_json(&headers) {
        let ap_actor = ApActor {
            context: Some(default_context()),
            id: actor.ap_id.clone(),
            actor_type: match actor.actor_type {
                noombat_core::actor::ActorType::Individual => "Person".to_owned(),
                noombat_core::actor::ActorType::Company => "Organization".to_owned(),
                noombat_core::actor::ActorType::Group => "Group".to_owned(),
            },
            preferred_username: actor.username.clone(),
            name: actor.display_name.clone(),
            summary: actor.summary_html.clone(),
            icon: None,
            image: None,
            inbox: format!("{}/inbox", &actor.ap_id),
            outbox: format!("{}/outbox", &actor.ap_id),
            followers: Some(format!("{}/followers", &actor.ap_id)),
            following: Some(format!("{}/following", &actor.ap_id)),
            public_key: ApPublicKey {
                id: format!("{}#main-key", &actor.ap_id),
                owner: actor.ap_id.clone(),
                public_key_pem: actor.public_key_pem.clone(),
            },
            url: Some(actor.ap_id.clone()),
            attachment: None,
            endpoints: None,
        };

        return Ok((
            StatusCode::OK,
            [(CONTENT_TYPE, "application/activity+json; charset=utf-8")],
            Json(ap_actor),
        )
            .into_response());
    }

    let i18n = I18n {
        locale: negotiate_locale(&headers),
    };
    let display_name = actor
        .display_name
        .clone()
        .unwrap_or_else(|| actor.username.clone());
    let handle = format!("{}@{}", actor.username, state.domain);
    let page_title = i18n.tf(
        "profile_title_pattern",
        &[("display_name", &display_name), ("handle", &handle)],
    );

    let page = ProfilePage {
        i18n,
        page_title,
        username: actor.username.clone(),
        display_name,
        summary_html: actor.summary_html.clone().unwrap_or_default(),
        domain: state.domain.clone(),
    };

    Ok(page.into_response())
}

// ..... GET /users/{username}/outbox .....

async fn get_outbox(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

    let total = noombat_identity::repo::count_public_posts(&state.pool, actor.id)
        .await
        .unwrap_or(0);
    let posts = noombat_identity::repo::list_public_posts(&state.pool, actor.id, 20, 0)
        .await
        .unwrap_or_default();

    let items: Vec<serde_json::Value> = posts.into_iter().map(|p| p.ap_object).collect();

    let collection = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{}/outbox", actor.ap_id),
        "type": "OrderedCollection",
        "totalItems": total,
        "orderedItems": items
    });

    Ok((
        StatusCode::OK,
        [(CONTENT_TYPE, "application/activity+json; charset=utf-8")],
        Json(collection),
    ))
}

// ..... POST /users/{username}/outbox .....

/// Request body for the C2S outbox POST.
///
/// Accepts a simplified `Create { Note }` payload. The `content` field
/// is plain text (Markdown processing to be added!).
#[derive(Deserialize)]
struct OutboxPostBody {
    content: String,
    /// Post visibility: `"public"`, `"unlisted"`, or `"followers"`.
    /// Defaults to `"public"`.
    #[serde(default = "default_visibility")]
    visibility: String,
}

fn default_visibility() -> String {
    "public".to_owned()
}

/// Create a Note via the C2S outbox endpoint.
///
/// # Authentication
///
/// This development-only endpoint is protected by a bearer token configured via
/// `NOOMBAT_ADMIN_TOKEN`. A request must include:
///
/// ```text
/// Authorization: Bearer <token>
/// ```
///
/// This mechanism is a development-only placeholder!
/// To be replaced by full OAuth and session-based authentication!
///
/// # Request body
///
/// ```json
/// {
///     "content": "Hello, Fediverse!",
///     "visibility": "public"
/// }
/// ```
///
/// # Response
///
/// On success, returns `201 Created` with the ActivityPub `Create`
/// activity as JSON. The activity is also enqueued for delivery to
/// all accepted followers.
async fn post_outbox(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, ApiError> {
    // Authenticate via bearer token BEFORE parsing the body.
    verify_bearer_token(&headers, &state.admin_token)?;

    // Resolve the local actor.
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

    // Parse the request body.
    let body: OutboxPostBody = serde_json::from_slice(&body)
        .map_err(|e| NoombatError::BadRequest(format!("invalid JSON: {e}")))?;

    // Validate visibility.
    if !matches!(
        body.visibility.as_str(),
        "public" | "unlisted" | "followers"
    ) {
        return Err(NoombatError::BadRequest(
            "visibility must be public, unlisted, or followers".into(),
        )
        .into());
    }

    // Generate a unique AP ID for the Note.
    let note_id = format!(
        "https://{}/users/{}/posts/{}",
        state.domain,
        username,
        Uuid::new_v4()
    );

    // For now, content is stored as-is (no Markdown processing).
    // To be implemented in the `noombat-markup` pipeline!
    let content_html = format!("<p>{}</p>", escape_html(&body.content));

    // Build the ActivityPub object.
    let mut to = vec![];
    let mut cc = vec![];
    match body.visibility.as_str() {
        "public" => {
            to.push("https://www.w3.org/ns/activitystreams#Public".to_owned());
            cc.push(format!("{}/followers", actor.ap_id));
        }
        "unlisted" => {
            to.push(format!("{}/followers", actor.ap_id));
            cc.push("https://www.w3.org/ns/activitystreams#Public".to_owned());
        }
        "followers" => {
            to.push(format!("{}/followers", actor.ap_id));
        }
        _ => {}
    }

    let note_object = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": note_id,
        "type": "Note",
        "attributedTo": actor.ap_id,
        "content": content_html,
        "source": {
            "content": body.content,
            "mediaType": "text/plain"
        },
        "to": to,
        "cc": cc,
        "published": chrono::Utc::now().to_rfc3339()
    });

    let create_activity = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{}/activity", note_id),
        "type": "Create",
        "actor": actor.ap_id,
        "object": note_object,
        "to": to,
        "cc": cc,
        "published": chrono::Utc::now().to_rfc3339()
    });

    // Persist the post locally.
    let new_post = noombat_identity::repo::NewPost {
        actor_id: actor.id,
        ap_id: note_id.clone(),
        post_type: "note".to_owned(),
        content_md: body.content.clone(),
        content_html: content_html.clone(),
        visibility: body.visibility.clone(),
        ap_object: create_activity.clone(),
    };
    noombat_identity::repo::create_local_post(&state.pool, &new_post).await?;

    // Enqueue delivery to all accepted followers.
    let inboxes = noombat_identity::repo::get_follower_inboxes(&state.pool, actor.id).await?;
    for inbox in inboxes {
        noombat_federation::delivery::enqueue(&state.pool, &create_activity, &inbox).await?;
    }

    Ok((
        StatusCode::CREATED,
        [(CONTENT_TYPE, "application/activity+json; charset=utf-8")],
        Json(create_activity),
    ))
}

/// Minimal HTML entity escaping for plain text content (development-only).
///
/// To be replaced by the `noombat-markup` crate's Markdown with `ammonia`
/// HTML sanitisation pipeline!
fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ..... TEMPLATES .....

#[derive(Template, WebTemplate)]
#[template(path = "profile.html")]
struct ProfilePage {
    i18n: I18n,
    page_title: String,
    username: String,
    display_name: String,
    summary_html: String,
    domain: String,
}
