// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Actor routes: ActivityPub actor JSON, HTML profile page, and C2S outbox.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use noombat_ap::context::{default_context, AS_CONTEXT};
use noombat_ap::object::{ApActor, ApPublicKey};
use noombat_core::error::NoombatError;

use crate::error::ApiError;
use crate::i18n::{negotiate_locale, I18n};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/users/{username}",
            get(get_actor)
                .patch(patch_actor)
                .delete(delete_actor_handler),
        )
        .route(
            "/users/{username}/outbox",
            get(get_outbox).post(post_outbox),
        )
        .route("/users/{username}/followers", get(get_followers))
        .route("/users/{username}/following", get(get_following))
}

// ..... HELPERS .....

fn wants_activity_json(headers: &HeaderMap) -> bool {
    headers
        .get_all("accept")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.contains("application/activity+json") || v.contains("application/ld+json"))
}

use crate::auth::verify_bearer_token;

// ..... GET /users/{username} .....

async fn get_actor(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

    if wants_activity_json(&headers) {
        // Build the AP actor attachment (ORCID, verified links) only
        // when federate_profile is enabled.
        let attachment = if actor.actor_privacy.federate_profile {
            let mut entries: Vec<serde_json::Value> = Vec::new();
            if let Some(ref orcid) = actor.orcid {
                entries.push(serde_json::json!({
                    "type": "PropertyValue",
                    "name": "ORCID",
                    "value": format!("<a href=\"https://orcid.org/{orcid}\" rel=\"me\">{orcid}</a>")
                }));
            }
            if let Ok(links) =
                noombat_identity::verification::list_links(&state.pool, actor.id).await
            {
                for link in links {
                    if link.verified_at.is_some() {
                        entries.push(serde_json::json!({
                            "type": "PropertyValue",
                            "name": "Website",
                            "value": format!("<a rel=\"me\" href=\"{url}\">{url}</a>", url = link.url)
                        }));
                    }
                }
            }
            if entries.is_empty() { None } else { Some(entries) }
        } else {
            None
        };

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
            attachment,
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

    // Load profile sections (public visibility only for unauthenticated view).
    let vis = noombat_core::privacy::SectionVisibility::Public;
    let (experiences, educations, skills, publications, verified_links, custom_sections) =
        tokio::join!(
            noombat_identity::profile::list_experiences(&state.pool, actor.id, &vis),
            noombat_identity::profile::list_educations(&state.pool, actor.id, &vis),
            noombat_identity::profile::list_skills(&state.pool, actor.id, false),
            noombat_identity::profile::list_publications(&state.pool, actor.id, &vis),
            noombat_identity::verification::list_links(&state.pool, actor.id),
            noombat_identity::profile::list_custom_sections(&state.pool, actor.id, &vis),
        );

    let page = ProfilePage {
        i18n,
        page_title,
        username: actor.username.clone(),
        display_name,
        headline: actor.headline.clone().unwrap_or_default(),
        summary_html: actor.summary_html.clone().unwrap_or_default(),
        domain: state.domain.clone(),
        indexable: actor.actor_privacy.indexable,
        experiences: experiences.unwrap_or_default(),
        educations: educations.unwrap_or_default(),
        skills: skills.unwrap_or_default(),
        publications: publications.unwrap_or_default(),
        verified_links: verified_links.unwrap_or_default(),
        custom_sections: custom_sections.unwrap_or_default(),
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
        "@context": AS_CONTEXT,
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
    Json(body): Json<OutboxPostBody>,
) -> Result<impl IntoResponse, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;

    // Resolve the local actor.
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

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

    // Render Markdown through the noombat-markup pipeline.
    let markup_output = noombat_markup::render(&body.content);
    let content_html = markup_output.html;
    let hashtags = markup_output.hashtags;

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

    // Build Mastodon-convention hashtag tags for federation.
    let tag_objects: Vec<serde_json::Value> = hashtags
        .iter()
        .map(|t| {
            json!({
                "type": "Hashtag",
                "name": format!("#{t}"),
                "href": format!("https://{}/tags/{t}", state.domain)
            })
        })
        .collect();

    let note_object = json!({
        "@context": AS_CONTEXT,
        "id": note_id,
        "type": "Note",
        "attributedTo": actor.ap_id,
        "content": content_html,
        "source": {
            "content": body.content,
            "mediaType": "text/markdown"
        },
        "to": to,
        "cc": cc,
        "tag": tag_objects,
        "published": chrono::Utc::now().to_rfc3339()
    });

    let create_activity = json!({
        "@context": AS_CONTEXT,
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

    // Link extracted hashtags to the newly created post.
    if !hashtags.is_empty() {
        // Resolve post UUID from the ap_id (last path segment).
        if let Some(uuid_str) = note_id.rsplit('/').next() {
            if let Ok(post_uuid) = uuid_str.parse::<Uuid>() {
                let _ = noombat_identity::hashtags::link_post_hashtags(
                    &state.pool,
                    post_uuid,
                    &hashtags,
                )
                .await;
            }
        }
    }

    // Index the post in Meilisearch (fire-and-forget; public only).
    crate::search_sync::index_post(
        &state.search,
        &note_id,
        &actor.id.to_string(),
        &content_html,
        &body.visibility,
    );

    // Enqueue delivery to all accepted followers.
    let inboxes = noombat_identity::repo::get_follower_inboxes(&state.pool, actor.id).await?;
    for inbox in inboxes {
        noombat_federation::delivery::enqueue(&state.pool, actor.id, &create_activity, &inbox)
            .await?;
    }

    Ok((
        StatusCode::CREATED,
        [(CONTENT_TYPE, "application/activity+json; charset=utf-8")],
        Json(create_activity),
    ))
}

// ..... PATCH /users/{username} .....

#[derive(Deserialize)]
struct PatchActorBody {
    display_name: Option<String>,
    headline: Option<String>,
    summary_md: Option<String>,
}

async fn patch_actor(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PatchActorBody>,
) -> Result<impl IntoResponse, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;

    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

    // Render Markdown summary through the noombat-markup pipeline.
    let summary_html = body
        .summary_md
        .as_ref()
        .map(|md| noombat_markup::render(md).html);

    let params = noombat_identity::repo::UpdateActor {
        display_name: body.display_name,
        headline: body.headline,
        summary_md: body.summary_md,
        summary_html,
        avatar_url: None,
        header_url: None,
    };

    let updated = noombat_identity::repo::update_actor(&state.pool, actor.id, &params).await?;

    // Synchronise search index with current skills (fire-and-forget).
    let skills = noombat_identity::profile::list_skills(&state.pool, actor.id, false)
        .await
        .unwrap_or_default();
    let skill_names: Vec<String> = skills.into_iter().map(|s| s.name).collect();
    crate::search_sync::index_profile(&state.search, &updated, &skill_names);

    Ok((
        StatusCode::OK,
        [(CONTENT_TYPE, "application/activity+json; charset=utf-8")],
        Json(json!({
            "id": updated.ap_id,
            "type": "Person",
            "preferredUsername": updated.username,
            "name": updated.display_name,
            "summary": updated.summary_html
        })),
    ))
}

// ..... DELETE /users/{username} .....

async fn delete_actor_handler(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;

    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    noombat_identity::repo::delete_actor(&state.pool, actor.id).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ..... GET /users/{username}/followers .....

async fn get_followers(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

    let total = noombat_identity::repo::count_followers(&state.pool, actor.id)
        .await
        .unwrap_or(0);
    let items = noombat_identity::repo::list_follower_ap_ids(&state.pool, actor.id, 40, 0)
        .await
        .unwrap_or_default();

    let collection = json!({
        "@context": AS_CONTEXT,
        "id": format!("{}/followers", actor.ap_id),
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

// ..... GET /users/{username}/following .....

async fn get_following(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

    let total = noombat_identity::repo::count_following(&state.pool, actor.id)
        .await
        .unwrap_or(0);
    let items = noombat_identity::repo::list_following_ap_ids(&state.pool, actor.id, 40, 0)
        .await
        .unwrap_or_default();

    let collection = json!({
        "@context": AS_CONTEXT,
        "id": format!("{}/following", actor.ap_id),
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

// ..... TEMPLATES .....
#[derive(Template, WebTemplate)]
#[template(path = "profile.html")]
struct ProfilePage {
    i18n: I18n,
    page_title: String,
    username: String,
    display_name: String,
    headline: String,
    summary_html: String,
    domain: String,
    /// When `false`, emit `<meta name="robots" content="noindex">`.
    indexable: bool,
    experiences: Vec<noombat_identity::profile::Experience>,
    educations: Vec<noombat_identity::profile::Education>,
    skills: Vec<noombat_identity::profile::Skill>,
    publications: Vec<noombat_identity::profile::Publication>,
    verified_links: Vec<noombat_identity::verification::VerifiedLink>,
    custom_sections: Vec<noombat_identity::profile::CustomSection>,
}
