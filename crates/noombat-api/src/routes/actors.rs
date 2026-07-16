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

use noombat_ap::context::{AS_CONTEXT, default_context};
use noombat_ap::object::{ApActor, ApMultikey, ApPublicKey};
use noombat_core::error::NoombatError;

use crate::error::ApiError;
use crate::i18n::I18n;
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
        // Human-facing profile URL. Serves the same HTML profile page
        // as GET /users/{username}. Content-negotiates AP JSON like
        // Mastodon's /@{username} endpoint; the canonical AP `id`
        // remains at /users/{username}.
        .route("/@{username}", get(get_actor_human))
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
    principal: Option<axum::Extension<crate::middleware::Principal>>,
    i18n: I18n,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

    // Block guard: if the viewer is blocked by the profile owner,
    // return 403 before serving any content.
    if let Some(ref principal) = principal
        && let Some(ref viewer_username) = principal.username
    {
        let is_blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                     SELECT 1 FROM blocks b
                     JOIN actors blocker ON blocker.id = b.actor_id
                     JOIN actors target  ON target.id  = b.target_id
                     WHERE blocker.username = $1 AND blocker.is_local = TRUE
                       AND target.username  = $2 AND target.is_local  = TRUE
                 )",
        )
        .bind(&actor.username)
        .bind(viewer_username.as_str())
        .fetch_one(&state.pool)
        .await
        .unwrap_or(false);

        if is_blocked {
            return Err(NoombatError::Forbidden.into());
        }
    }

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
            if entries.is_empty() {
                None
            } else {
                Some(entries)
            }
        } else {
            None
        };

        // Fetch aliases for the alsoKnownAs property (Move support).
        let aliases = noombat_federation::move_actor::list_aliases(&state.pool, actor.id)
            .await
            .unwrap_or_default();

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
            inbox: format!("{}/inbox", actor.ap_id),
            outbox: format!("{}/outbox", actor.ap_id),
            followers: Some(format!("{}/followers", actor.ap_id)),
            following: Some(format!("{}/following", actor.ap_id)),
            public_key: ApPublicKey {
                id: format!("{}#main-key", actor.ap_id),
                owner: actor.ap_id.clone(),
                public_key_pem: actor.public_key_pem.clone(),
            },
            url: Some(format!("https://{}/@{}", state.domain, actor.username)),
            attachment,
            endpoints: Some(serde_json::json!({
                "sharedInbox": format!("https://{}/inbox", state.domain)
            })),
            assertion_method: actor.ed25519_public_key.as_ref().map(|pk| {
                vec![ApMultikey {
                    id: format!("{}#ed25519-key", actor.ap_id),
                    key_type: "Multikey".to_owned(),
                    controller: actor.ap_id.clone(),
                    public_key_multibase: pk.clone(),
                }]
            }),
            moved_to: actor.moved_to.clone(),
            also_known_as: if aliases.is_empty() {
                None
            } else {
                Some(aliases)
            },
        };

        return Ok((
            StatusCode::OK,
            [(CONTENT_TYPE, "application/activity+json; charset=utf-8")],
            Json(ap_actor),
        )
            .into_response());
    }

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
    let (experiences, educations, skills, publications, verified_links, custom_sections) = tokio::join!(
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

// ..... GET /@{username} .....
//
// Human-facing profile URL. Delegates to `get_actor` which handles
// both AP JSON and HTML responses via content negotiation. When a
// Fediverse client sends `Accept: application/activity+json` to
// this path, it receives the AP actor object, i.e. this is harmless
// (the canonical `id` still points to `/users/{username}`) and
// matches the behaviour of Mastodon, which serves AP JSON at
// `/@{username}` as well.

async fn get_actor_human(
    state: State<AppState>,
    path: Path<String>,
    headers: HeaderMap,
    principal: Option<axum::Extension<crate::middleware::Principal>>,
    i18n: I18n,
) -> Result<impl IntoResponse, ApiError> {
    get_actor(state, path, headers, principal, i18n).await
}

// ..... GET /users/{username}/outbox .......

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
/// Accepts a simplified `Create { Note | Article }` payload.
#[derive(Deserialize)]
struct OutboxPostBody {
    content: String,
    /// Post visibility: `"public"`, `"unlisted"`, or `"followers"`.
    /// Defaults to `"public"`.
    #[serde(default = "default_visibility")]
    visibility: String,
    /// Post type: `"note"` (default) or `"article"`.
    #[serde(default = "default_post_type")]
    post_type: String,
    /// Article title. Required when `post_type` is `"article"`;
    /// ignored for Notes.
    title: Option<String>,
    /// Featured image URL (optional, primarily for Articles).
    featured_image_url: Option<String>,
    /// The AP URI of the post this is a reply to. `None` for
    /// top-level posts.
    in_reply_to: Option<String>,
}

fn default_visibility() -> String {
    "public".to_owned()
}

fn default_post_type() -> String {
    "note".to_owned()
}

/// Create a Note or Article via the C2S outbox endpoint.
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
///     "visibility": "public",
///     "post_type": "note"
/// }
/// ```
///
/// For an Article:
///
/// ```json
/// {
///     "content": "# My Article\n\nBody text in Markdown.",
///     "visibility": "public",
///     "post_type": "article",
///     "title": "My Article",
///     "featured_image_url": "https://example.com/image.jpg"
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

    // Validate post type.
    let is_article = match body.post_type.as_str() {
        "note" => false,
        "article" => true,
        _ => {
            return Err(
                NoombatError::BadRequest("post_type must be note or article".into()).into(),
            );
        }
    };

    // Articles require a title.
    if is_article && body.title.as_deref().is_none_or(str::is_empty) {
        return Err(NoombatError::BadRequest(
            "article post_type requires a non-empty title".into(),
        )
        .into());
    }

    // Generate a unique AP ID for the post.
    let post_id = format!(
        "https://{}/users/{}/posts/{}",
        state.domain,
        username,
        Uuid::new_v4()
    );

    // Render Markdown through the noombat-markup pipeline.
    // Offloaded to a blocking thread because KaTeX embeds QuickJS.
    // Articles use the strict sanitisation mode so that user-authored
    // `<span style="...">` elements are stripped (CSS-based attack
    // prevention); Notes use the default mode, which permits `style`
    // on `<span>` because only the trusted KaTeX renderer produces
    // styled spans.
    let markup_opts = noombat_markup::MarkupOptions {
        strict_sanitisation: is_article,
    };
    let markup_output =
        noombat_markup::render_async_with_options(body.content.clone(), markup_opts).await?;
    let content_html = markup_output.html;
    let hashtags = markup_output.hashtags;

    // Build the ActivityPub addressing arrays.
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

    // When replying to a post, include the parent post's author in
    // `cc` so that the reply is delivered to them even if they do
    // not follow the replying actor (Mastodon convention).
    let mut reply_target_inbox: Option<String> = None;
    if let Some(ref reply_to_uri) = body.in_reply_to {
        // Look up the parent post locally (by ap_id) and resolve
        // the author's AP identifier. If the parent post is not
        // known locally, skip the addressing enhancement, i.e. the
        // reply still federates normally via follower delivery.
        let parent_author: Option<(String, Option<String>)> = sqlx::query_as(
            r#"SELECT a.ap_id, a.inbox_url
               FROM posts p
               JOIN actors a ON a.id = p.actor_id
               WHERE p.ap_id = $1"#,
        )
        .bind(reply_to_uri)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);

        if let Some((author_ap_id, inbox_url)) = parent_author {
            // Avoid adding the replying actor to their own cc.
            if author_ap_id != actor.ap_id && !cc.contains(&author_ap_id) {
                cc.push(author_ap_id);
            }
            // Record the inbox for direct delivery after the
            // follower-inbox loop (the parent author may not be a
            // follower).
            reply_target_inbox = inbox_url;
        }
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

    // ActivityStreams type: Note or Article.
    let ap_type = if is_article { "Article" } else { "Note" };

    let mut ap_object = json!({
        "@context": default_context(),
        "id": post_id,
        "type": ap_type,
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

    // Articles carry a title in the `name` property and may carry
    // a featured image in the `image` property.
    if let Some(ref title) = body.title {
        ap_object["name"] = json!(title);
    }
    if let Some(ref image_url) = body.featured_image_url {
        ap_object["image"] = json!({
            "type": "Image",
            "url": image_url
        });
    }
    if let Some(ref reply_to) = body.in_reply_to {
        ap_object["inReplyTo"] = json!(reply_to);
    }

    let create_activity = json!({
        "@context": default_context(),
        "id": format!("{}/activity", post_id),
        "type": "Create",
        "actor": actor.ap_id,
        "object": ap_object,
        "to": to,
        "cc": cc,
        "published": chrono::Utc::now().to_rfc3339()
    });

    // Persist the post locally.
    let new_post = noombat_identity::repo::NewPost {
        actor_id: actor.id,
        ap_id: post_id.clone(),
        post_type: body.post_type.clone(),
        title: body.title.clone(),
        featured_image_url: body.featured_image_url.clone(),
        content_md: body.content.clone(),
        content_html: content_html.clone(),
        in_reply_to: body.in_reply_to.clone(),
        visibility: body.visibility.clone(),
        ap_object: create_activity.clone(),
    };
    noombat_identity::repo::create_local_post(&state.pool, &new_post).await?;

    // Link extracted hashtags to the newly created post.
    if !hashtags.is_empty()
        && let Some(uuid_str) = post_id.rsplit('/').next()
        && let Ok(post_uuid) = uuid_str.parse::<Uuid>()
    {
        let _ =
            noombat_identity::hashtags::link_post_hashtags(&state.pool, post_uuid, &hashtags).await;
    }

    // Index the post in Meilisearch (fire-and-forget; public only).
    crate::search_sync::index_post(
        &state.search,
        &post_id,
        &actor.id.to_string(),
        &content_html,
        &body.visibility,
    );

    // Enqueue delivery to all accepted followers.
    let inboxes = noombat_identity::repo::get_follower_inboxes(&state.pool, actor.id).await?;
    for inbox in &inboxes {
        noombat_federation::delivery::enqueue(&state.pool, actor.id, &create_activity, inbox)
            .await?;
    }

    // If replying to a post, deliver directly to the parent author's
    // inbox when it is not already covered by the follower set.
    if let Some(ref target_inbox) = reply_target_inbox
        && !inboxes.contains(target_inbox)
    {
        let _ = noombat_federation::delivery::enqueue(
            &state.pool,
            actor.id,
            &create_activity,
            target_inbox,
        )
        .await;
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
    let summary_html = match body.summary_md.as_deref() {
        Some(md) => Some(noombat_markup::render_async(md.to_owned()).await?.html),
        None => None,
    };

    let params = noombat_identity::repo::UpdateActor {
        display_name: body.display_name.map(Some),
        headline: body.headline.map(Some),
        summary_md: body.summary_md.map(Some),
        summary_html: summary_html.map(Some),
        avatar_url: None,
        header_url: None,
    };

    let updated = noombat_identity::repo::update_actor(&state.pool, actor.id, &params).await?;

    // Broadcast an Update activity to all accepted followers so that
    // remote instances refresh their cached copy of the profile.
    noombat_federation::update::enqueue_actor_update(&state.pool, &updated, &state.domain).await;

    // Synchronise search index with current skills (fire-and-forget).
    let skills = noombat_identity::profile::list_skills(&state.pool, actor.id, false)
        .await
        .unwrap_or_default();
    let search_data = crate::search_sync::ProfileSearchData {
        skills: skills.into_iter().map(|s| s.name).collect(),
        ..Default::default()
    };
    crate::search_sync::index_profile(&state.search, &updated, &search_data);

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

    // Fetch the follower inbox list BEFORE tombstoning, because
    // tombstone_actor deletes the follow relationships.
    let inboxes = noombat_identity::repo::get_follower_inboxes(&state.pool, actor.id)
        .await
        .unwrap_or_default();

    // Tombstone the actor (clears personal data, retains ap_id for
    // federation consistency) and retrieve the pre-tombstone snapshot.
    let pre_tombstone = noombat_identity::repo::tombstone_actor(&state.pool, actor.id).await?;

    // Broadcast a Delete activity to all accepted followers so that
    // remote instances remove their cached copy.
    noombat_federation::delete::broadcast_delete(&state.pool, &pre_tombstone, &inboxes).await;

    // Purge the actor's data from Meilisearch search indices.
    crate::search_sync::remove_from_index(&state.search, "profiles", &actor.id.to_string());
    // Posts were deleted by tombstone_actor; their Meilisearch
    // documents will become stale. A full reindex or per-post
    // removal is deferred to the search sync worker.

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
