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

use noombat_ap::context::{AS_CONTEXT, Extension, context_with};
use noombat_core::error::NoombatError;

use crate::error::ApiError;
use crate::i18n::I18n;
use crate::state::AppState;
use crate::theme::{Contrast, Theme};

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
        // Aliases (account migration prerequisite).
        .route(
            "/users/{username}/aliases",
            axum::routing::post(create_alias),
        )
        .route(
            "/users/{username}/aliases/{alias_id}",
            axum::routing::delete(delete_alias),
        )
        // Account Move.
        .route("/users/{username}/move", axum::routing::post(initiate_move))
        // Human-facing profile URL. Serves the same HTML profile page
        // as GET /users/{username}. Content-negotiates AP JSON like
        // Mastodon's /@{username} endpoint; the canonical AP `id`
        // remains at /users/{username}.
        .route("/@{username}", get(get_actor_human))
}

// ..... HELPERS .....

/// Minimal HTML escaping for dynamic content in inline HTML fragments.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Verify that the authenticated viewer owns the actor identified
/// by the path `username`. Returns the actor's UUID on success, or
/// `Forbidden` if the viewer does not match.
fn require_owner(
    viewer: &Option<axum::Extension<crate::middleware::Viewer>>,
    path_username: &str,
) -> Result<Uuid, ApiError> {
    let p = viewer.as_ref().ok_or(ApiError(NoombatError::Forbidden))?;
    if p.username != path_username {
        return Err(ApiError(NoombatError::Forbidden));
    }
    Ok(p.actor_id)
}

fn wants_activity_json(headers: &HeaderMap) -> bool {
    headers
        .get_all("accept")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.contains("application/activity+json") || v.contains("application/ld+json"))
}

use crate::auth::{require_acts_for, require_local_actor};
use crate::middleware::Viewer;
use noombat_core::authorisation::{InteractionService, OrganizationRole};

// ..... GET /users/{username} .....

async fn get_actor(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
    viewer: Option<axum::Extension<crate::middleware::Viewer>>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

    // A withdrawn identity answers `410 Gone` with a `Tombstone`, not a
    // stripped actor document. `is_suspended`'s own doc comment says
    // federation requests receive 410, and nothing served one: a peer
    // that fetched an erased actor got a nameless but live-looking
    // document and had no reason to drop its cached copy.
    //
    // `deleted` is what makes the answer actionable. Without it the
    // peer knows the identity is gone but not when, which is the
    // difference between "withdrawn" and "never existed".
    if let Some(deleted) = noombat_identity::repo::tombstoned_at(&state.pool, &actor.ap_id).await? {
        let body = json!({
            "@context": AS_CONTEXT,
            "id": actor.ap_id,
            "type": "Tombstone",
            "formerType": actor.actor_type.ap_type(),
            "deleted": deleted.to_rfc3339(),
        });

        return Ok((
            StatusCode::GONE,
            [(CONTENT_TYPE, "application/activity+json; charset=utf-8")],
            Json(body),
        )
            .into_response());
    }

    // Block guard: if the viewer is blocked by the profile owner,
    // return 403 before serving any content.
    if let Some(ref viewer) = viewer {
        let restriction = crate::interactions::Interactions::new(state.pool.clone())
            .owner_restriction(&actor.id, &viewer.actor_id)
            .await;
        if !restriction.may_view_profile() {
            return Err(NoombatError::Forbidden.into());
        }
    }

    if wants_activity_json(&headers) {
        let document =
            noombat_federation::actor_document::build(&state.pool, &actor, &state.domain).await;

        return Ok((
            StatusCode::OK,
            [(CONTENT_TYPE, "application/activity+json; charset=utf-8")],
            Json(document),
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

    // Load profile sections at the widest tier this viewer qualifies
    // for. Passing `Public` unconditionally, as this did, hid an
    // owner's own followers-only and private sections from their own
    // profile page while the CV route showed them, so the two surfaces
    // disagreed about the same rows.
    let viewer_id = viewer.as_ref().map(|v| v.actor_id);
    let relationship =
        noombat_identity::connections::relationship(&state.pool, viewer_id, actor.id).await?;
    let vis = noombat_core::authorisation::section_tier_for(viewer_id, actor.id, &relationship);
    let (
        work_experiences,
        education_entries,
        skills,
        scholarly_articles,
        verified_links,
        custom_sections,
    ) = tokio::join!(
        noombat_identity::profile::list_work_experiences(&state.pool, actor.id, &vis),
        noombat_identity::profile::list_education_entries(&state.pool, actor.id, &vis),
        noombat_identity::profile::list_skills(&state.pool, actor.id, &vis),
        noombat_identity::profile::list_scholarly_articles(&state.pool, actor.id, &vis),
        noombat_identity::verification::list_links(&state.pool, actor.id),
        noombat_identity::profile::list_custom_sections(&state.pool, actor.id, &vis),
    );

    let page = ProfilePage {
        i18n,
        theme,
        contrast,
        page_title,
        username: actor.username.clone(),
        display_name,
        headline: actor.headline.clone().unwrap_or_default(),
        location: actor.location.clone().unwrap_or_default(),
        summary_html: actor.summary_html.clone().unwrap_or_default(),
        domain: state.domain.clone(),
        indexable: actor.is_indexable(),
        actor_id: actor.id.to_string(),
        show_report: viewer
            .as_ref()
            .map(|p| p.username.as_str())
            .is_some_and(|viewer| viewer != actor.username),
        work_experiences: work_experiences.unwrap_or_default(),
        education_entries: education_entries.unwrap_or_default(),
        skills: skills.unwrap_or_default(),
        scholarly_articles: scholarly_articles.unwrap_or_default(),
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
    viewer: Option<axum::Extension<crate::middleware::Viewer>>,
    i18n: I18n,
    theme: Theme,
    contrast: Contrast,
) -> Result<impl IntoResponse, ApiError> {
    get_actor(state, path, headers, viewer, i18n, theme, contrast).await
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
    /// Post visibility: `"public"`, `"unlisted"`, `"followers"` or
    /// `"connections"`.
    ///
    /// Absent means the account's stored `default_post_visibility`, not
    /// `"public"`. A compose path that ignores the setting makes it a
    /// control that changes nothing, which is the whole reason the
    /// column had no reader.
    #[serde(default)]
    visibility: Option<String>,
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

fn default_post_type() -> String {
    "note".to_owned()
}

/// The parts of a locally authored post its ActivityPub document is built
/// from.
struct LocalPost<'a> {
    post_id: &'a str,
    ap_type: &'a str,
    content_html: &'a str,
    source_markdown: &'a str,
    title: Option<&'a str>,
    featured_image_url: Option<&'a str>,
    in_reply_to: Option<&'a str>,
    to: &'a [String],
    cc: &'a [String],
    tags: &'a [serde_json::Value],
    published: &'a str,
}

/// Build the `Create` activity for a locally authored post, with an
/// FEP-8b32 proof attached to the inner object.
///
/// Split out of the handler to give the signing step a seam. The proof on
/// the inner object is the only proof a receiving instance can record,
/// because the envelope is transport and is not stored; if this quietly
/// stopped attaching one, every Noombat-to-Noombat post would silently
/// federate as unproven and nothing else in the suite would notice. That
/// is the shape of failure this codebase has already had once, when the
/// sanitiser existed, was tested, and was not called.
///
/// Signing is the last step: JCS hashes the document as it stands, so
/// every property has to be in place first. Failure is non-fatal, as in
/// `delivery.rs`, since HTTP Signatures remain the primary authentication
/// mechanism and an unproven post beats a failed publish.
fn build_create_activity(
    post: &LocalPost<'_>,
    actor_ap_id: &str,
    ed25519_private_base64: Option<&str>,
) -> serde_json::Value {
    // `Hashtag` is an ActivityStreams extension rather than a core
    // term, so it is declared only when the post actually carries tags,
    // which is how Mastodon and GoToSocial both spell it.
    let extensions: &[Extension] = if post.tags.is_empty() {
        &[]
    } else {
        &[Extension::Hashtag]
    };

    let mut ap_object = json!({
        "@context": context_with(extensions),
        "id": post.post_id,
        "type": post.ap_type,
        "attributedTo": actor_ap_id,
        "content": post.content_html,
        "source": {
            "content": post.source_markdown,
            "mediaType": "text/markdown"
        },
        "to": post.to,
        "cc": post.cc,
        "tag": post.tags,
        "published": post.published
    });

    // Articles carry a title in the `name` property and may carry
    // a featured image in the `image` property.
    if let Some(title) = post.title {
        ap_object["name"] = json!(title);
    }
    if let Some(image_url) = post.featured_image_url {
        ap_object["image"] = json!({
            "type": "Image",
            "url": image_url
        });
    }
    if let Some(reply_to) = post.in_reply_to {
        ap_object["inReplyTo"] = json!(reply_to);
    }

    if let Some(key) = ed25519_private_base64 {
        noombat_federation::integrity_proof::sign_as_actor(&mut ap_object, key, actor_ap_id);
    }

    json!({
        "@context": context_with(extensions),
        "id": format!("{}/activity", post.post_id),
        "type": "Create",
        "actor": actor_ap_id,
        "object": ap_object,
        "to": post.to,
        "cc": post.cc,
        "published": post.published
    })
}

/// `POST /users/{username}/outbox`: create a Note or Article.
///
/// Authenticated as the account being posted for. Returns `201` with
/// the `Create` activity, which is also enqueued for delivery to
/// accepted followers.
async fn post_outbox(
    State(state): State<AppState>,
    Path(username): Path<String>,
    viewer: Option<axum::Extension<Viewer>>,
    Json(body): Json<OutboxPostBody>,
) -> Result<impl IntoResponse, ApiError> {
    // Posting to an outbox is acting as that account.
    let actor = require_local_actor(&state.pool, &viewer, &username).await?;

    // Validate visibility, falling back to the account's own default
    // where the request states none.
    let visibility = match body.visibility.clone() {
        Some(stated) => stated,
        None => sqlx::query_scalar::<_, String>(
            "SELECT default_post_visibility FROM actors WHERE id = $1",
        )
        .bind(actor.id)
        .fetch_one(&state.pool)
        .await
        .map_err(NoombatError::from)?,
    };

    if !matches!(
        visibility.as_str(),
        "public" | "unlisted" | "followers" | "connections"
    ) {
        return Err(NoombatError::BadRequest(
            "visibility must be public, unlisted, followers, or connections".into(),
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

    // Articles use strict sanitisation, so user-authored
    // `<span style="...">` is stripped; Notes use the default profile,
    // which permits `style` on `<span>` because only the trusted maths
    // renderer produces styled spans. Articles also get heading `id`
    // attributes, so table-of-contents anchors work in federated HTML.
    let markup_opts = noombat_markup::MarkupOptions {
        strict_sanitisation: is_article,
        inject_heading_ids: is_article,
    };
    let markup_output =
        noombat_markup::render_async_with_options(body.content.clone(), markup_opts).await?;
    let content_html = markup_output.html;
    let hashtags = markup_output.hashtags;

    // Build the ActivityPub addressing arrays.
    let mut to = vec![];
    let mut cc = vec![];
    match visibility.as_str() {
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
        // Addressed to the connections collection alone. Followers are
        // deliberately not included: the nesting runs the other way, so
        // a follower who is not a connection is not an audience here.
        "connections" => {
            to.push(format!("{}/connections", actor.ap_id));
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

    let published = chrono::Utc::now().to_rfc3339();
    let create_activity = build_create_activity(
        &LocalPost {
            post_id: &post_id,
            ap_type,
            content_html: &content_html,
            source_markdown: &body.content,
            title: body.title.as_deref(),
            featured_image_url: body.featured_image_url.as_deref(),
            in_reply_to: body.in_reply_to.as_deref(),
            to: &to,
            cc: &cc,
            tags: &tag_objects,
            published: &published,
        },
        &actor.ap_id,
        actor.ed25519_private_key.as_deref(),
    );

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
        visibility: visibility.clone(),
        ap_object: create_activity.clone(),
    };
    let created = noombat_identity::repo::create_local_post(&state.pool, &new_post).await?;

    // Link extracted hashtags to the newly created post.
    //
    // The id the insert returned, not one parsed from the AP id's last
    // path segment: those are different UUIDs, because
    // `create_local_post` generates its own primary key and the URL
    // carries one made separately. The wrong one fails the foreign key
    // to `posts(id)` every time.
    if !hashtags.is_empty() {
        let _ = noombat_identity::hashtags::link_post_hashtags(&state.pool, created.id, &hashtags)
            .await;
    }

    // Index the post in Meilisearch (fire-and-forget; public only).
    crate::search_sync::index_post(
        &state.search,
        &crate::search_sync::IndexedPost {
            id: created.id,
            ap_id: &post_id,
            actor_id: &actor.id.to_string(),
            content_html: &content_html,
            visibility: &visibility,
            post_type: &body.post_type,
            title: body.title.as_deref(),
        },
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

    // And to the relays this instance subscribes to, which is the half
    // that made the subscription one-way: an administrator could
    // subscribe, the instance received relayed content, and nothing it
    // published ever reached the relay. Public posts only, because a
    // relay fans out to everyone by definition and a followers-tier
    // post addressed to one is a post published to strangers.
    if visibility == "public"
        && let Ok(instance_actor_id) =
            noombat_federation::signed_fetch::find_local_signing_actor(&state.pool).await
        && let Ok(instance_actor) =
            noombat_identity::repo::find_by_id(&state.pool, instance_actor_id).await
    {
        noombat_federation::relay::broadcast_to_relays(
            &state.pool,
            instance_actor_id,
            &instance_actor.ap_id,
            &create_activity,
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
    location: Option<String>,
    summary_md: Option<String>,
}

async fn patch_actor(
    State(state): State<AppState>,
    Path(username): Path<String>,
    viewer: Option<axum::Extension<Viewer>>,
    Json(body): Json<PatchActorBody>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = require_local_actor(&state.pool, &viewer, &username).await?;

    // Render Markdown summary through the noombat-markup pipeline.
    let summary_html = match body.summary_md.as_deref() {
        Some(md) => Some(noombat_markup::render_async(md.to_owned()).await?.html),
        None => None,
    };

    let params = noombat_identity::repo::UpdateActor {
        display_name: body.display_name.map(Some),
        headline: body.headline.map(Some),
        location: body.location.map(Some),
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
    let skills = noombat_identity::profile::list_skills(
        &state.pool,
        actor.id,
        &noombat_core::privacy::SectionVisibility::Public,
    )
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
            "type": updated.actor_type.ap_type(),
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
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<StatusCode, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

    // Erasing an account is the least reversible thing a session can do,
    // so the general "acts for" rule is not enough here: a recruiter
    // acting for an organisation must not be able to erase it. The
    // account itself and an organisation's owners, nobody else.
    match require_acts_for(&state.pool, actor.id, &viewer).await? {
        None | Some(OrganizationRole::Owner) => {}
        Some(OrganizationRole::Recruiter) => {
            return Err(ApiError(NoombatError::Forbidden));
        }
    }

    // Shared with the grace-period worker in `crate::erasure`, which
    // is where the inbox-before-tombstone ordering is explained.
    crate::erasure::erase_actor(&state.pool, &state.search, &state.media, actor.id).await?;
    // Posts were deleted by tombstone_actor; their Meilisearch
    // documents will become stale. A full reindex or per-post
    // removal is deferred to the search sync worker.

    Ok(StatusCode::NO_CONTENT)
}

// ..... Relationship collections .....

/// Build a relationship collection, honouring the owner's count setting.
///
/// `totalItems` is governed separately from the items, because the two
/// disclose different things: an owner may publish that they have five
/// hundred followers without publishing who they are, and `totalItems`
/// is the only part of this document a peer can use to build a metric.
/// It is omitted rather than sent as zero, which would be a lie a peer
/// would cache.
fn relationship_collection(
    owner: &noombat_core::actor::Actor,
    viewer: &Option<axum::Extension<Viewer>>,
    collection: &str,
    total: i64,
    items: Vec<String>,
) -> serde_json::Value {
    let is_owner = viewer.as_ref().map(|v| v.actor_id) == Some(owner.id);

    let mut document = json!({
        "@context": AS_CONTEXT,
        "id": format!("{}/{collection}", owner.ap_id),
        "type": "OrderedCollection",
        "orderedItems": items,
    });

    if is_owner || owner.shows_followers_count() {
        document["totalItems"] = json!(total);
    }

    document
}

/// Refuse a relationship-list request the owner's setting does not admit.
///
/// The refusal is [`NoombatError::ActorNotFound`], as on the CV route: a
/// `403` distinguishes "this account exists and keeps its list private"
/// from "no such account", and the list setting exists precisely to stop
/// an outsider mapping the graph.
async fn require_list_visible(
    state: &AppState,
    actor: &noombat_core::actor::Actor,
    viewer: &Option<axum::Extension<Viewer>>,
    setting: noombat_core::privacy::ListVisibility,
) -> Result<(), ApiError> {
    let viewer_id = viewer.as_ref().map(|v| v.actor_id);
    let relationship =
        noombat_identity::connections::relationship(&state.pool, viewer_id, actor.id).await?;

    if noombat_core::authorisation::list_visible_to(setting, viewer_id, actor.id, &relationship) {
        Ok(())
    } else {
        Err(ApiError(NoombatError::ActorNotFound(
            actor.username.clone(),
        )))
    }
}

// ..... GET /users/{username}/followers .....

async fn get_followers(
    State(state): State<AppState>,
    Path(username): Path<String>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    let settings = noombat_identity::connections::list_settings(&state.pool, actor.id).await?;
    require_list_visible(&state, &actor, &viewer, settings.followers).await?;

    let total = noombat_identity::repo::count_followers(&state.pool, actor.id)
        .await
        .unwrap_or(0);
    let items = noombat_identity::repo::list_follower_ap_ids(&state.pool, actor.id, 40, 0)
        .await
        .unwrap_or_default();

    let collection = relationship_collection(&actor, &viewer, "followers", total, items);

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
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    let settings = noombat_identity::connections::list_settings(&state.pool, actor.id).await?;
    require_list_visible(&state, &actor, &viewer, settings.following).await?;

    let total = noombat_identity::repo::count_following(&state.pool, actor.id)
        .await
        .unwrap_or(0);
    let items = noombat_identity::repo::list_following_ap_ids(&state.pool, actor.id, 40, 0)
        .await
        .unwrap_or_default();

    let collection = relationship_collection(&actor, &viewer, "following", total, items);

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
    theme: Theme,
    contrast: Contrast,
    page_title: String,
    username: String,
    display_name: String,
    headline: String,
    location: String,
    summary_html: String,
    domain: String,
    /// When `false`, emit `<meta name="robots" content="noindex">`.
    indexable: bool,
    /// The actor's UUID (used by the report form hidden input).
    actor_id: String,
    /// Whether to show the "Report" button (true when the viewer is
    /// authenticated and is not viewing their own profile).
    show_report: bool,
    work_experiences: Vec<noombat_identity::profile::WorkExperience>,
    education_entries: Vec<noombat_identity::profile::EducationEntry>,
    skills: Vec<noombat_identity::profile::Skill>,
    scholarly_articles: Vec<noombat_identity::profile::ScholarlyArticle>,
    verified_links: Vec<noombat_identity::verification::VerifiedLink>,
    custom_sections: Vec<noombat_identity::profile::CustomSection>,
}

// ..... Alias CRUD .....

#[derive(Deserialize)]
struct CreateAliasRequest {
    alias: String,
}

async fn create_alias(
    State(state): State<AppState>,
    Path(username): Path<String>,
    viewer: Option<axum::Extension<crate::middleware::Viewer>>,
    Json(req): Json<CreateAliasRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let actor_id = require_owner(&viewer, &username)?;

    // Through the helper rather than inlined: the inline INSERT had no
    // conflict clause, so adding an alias twice failed the request, and
    // it was the same shape as the move route bypassing initiate_move.
    let id = noombat_federation::move_actor::add_alias(&state.pool, actor_id, &req.alias).await?;

    // Return an HTML fragment for HTMX to append.
    let html = format!(
        r##"<li class="flex items-center gap-2 border-b border-border-default pb-2 text-sm" id="alias-{id}"><span class="flex-1 truncate font-mono">{alias}</span><button type="button" hx-delete="/users/{username}/aliases/{id}" hx-target="#alias-{id}" hx-swap="outerHTML" class="text-text-secondary hover:text-text-danger text-xs">✕</button></li>"##,
        id = id,
        alias = html_escape(&req.alias),
        username = username,
    );
    Ok((StatusCode::CREATED, axum::response::Html(html)))
}

async fn delete_alias(
    State(state): State<AppState>,
    Path((username, alias_id)): Path<(String, Uuid)>,
    viewer: Option<axum::Extension<crate::middleware::Viewer>>,
) -> Result<StatusCode, ApiError> {
    let actor_id = require_owner(&viewer, &username)?;

    noombat_federation::move_actor::remove_alias_by_id(&state.pool, actor_id, alias_id).await?;

    Ok(StatusCode::OK)
}

// ..... Account Move .....

#[derive(Deserialize)]
struct MoveRequest {
    target: String,
}

async fn initiate_move(
    State(state): State<AppState>,
    Path(username): Path<String>,
    viewer: Option<axum::Extension<crate::middleware::Viewer>>,
    Json(req): Json<MoveRequest>,
) -> Result<StatusCode, ApiError> {
    let actor_id = require_owner(&viewer, &username)?;
    let actor = noombat_identity::repo::find_by_id(&state.pool, actor_id).await?;

    // Three things, in this order. The grants are revoked *before*
    // `moved_to` is set, so a CV capability is never still served from
    // an instance the applicant has left; then the column is set; then
    // the `Move` reaches the followers who have to follow the new
    // account.
    //
    // Nothing detects a non-NULL `moved_to` and emits the activity
    // later, so a route that only writes the column emits nothing.
    noombat_federation::move_actor::initiate_move(&state.pool, actor_id, &actor.ap_id, &req.target)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noombat_federation::integrity_proof::{self, VerificationResult};

    const ACTOR: &str = "https://noombat.social/users/alice";

    fn sample_post<'a>(
        to: &'a [String],
        cc: &'a [String],
        tags: &'a [serde_json::Value],
    ) -> LocalPost<'a> {
        LocalPost {
            post_id: "https://noombat.social/posts/1",
            ap_type: "Note",
            content_html: "<p>hello</p>",
            source_markdown: "hello",
            title: None,
            featured_image_url: None,
            in_reply_to: None,
            to,
            cc,
            tags,
            published: "2026-01-01T00:00:00+00:00",
        }
    }

    /// The proof has to be on the object, and it has to survive being
    /// wrapped in the `Create`. A receiving instance records the object's
    /// proof; the envelope is transport and is never stored.
    #[test]
    fn the_published_object_carries_a_verifiable_proof() {
        let keypair = noombat_identity::keys::generate_ed25519_keypair().unwrap();
        let to = vec!["https://www.w3.org/ns/activitystreams#Public".to_owned()];
        let cc: Vec<String> = vec![];
        let tags: Vec<serde_json::Value> = vec![];

        let activity = build_create_activity(
            &sample_post(&to, &cc, &tags),
            ACTOR,
            Some(&keypair.private_base64),
        );

        assert!(
            activity.get("proof").is_none(),
            "the envelope is signed at delivery, not here"
        );

        let object = &activity["object"];
        assert_eq!(
            integrity_proof::verify(object, &keypair.public_multibase),
            VerificationResult::Valid,
            "the nested object must still verify after wrapping"
        );
    }

    /// What we publish must satisfy the binding the receiving side
    /// enforces: the proof's verification method, with its fragment
    /// stripped, has to be the actor the object is attributed to.
    /// Otherwise `verify_object_proof` refuses our own posts.
    #[test]
    fn the_proof_is_bound_to_the_actor_the_object_is_attributed_to() {
        let keypair = noombat_identity::keys::generate_ed25519_keypair().unwrap();
        let to: Vec<String> = vec![];
        let cc: Vec<String> = vec![];
        let tags: Vec<serde_json::Value> = vec![];

        let activity = build_create_activity(
            &sample_post(&to, &cc, &tags),
            ACTOR,
            Some(&keypair.private_base64),
        );
        let object = &activity["object"];

        let vm = integrity_proof::extract_verification_method_id(object)
            .expect("the object carries a proof");
        assert_eq!(vm.split('#').next().unwrap(), ACTOR);
        assert_eq!(object["attributedTo"], serde_json::json!(ACTOR));
        assert_eq!(activity["actor"], serde_json::json!(ACTOR));
    }

    /// An actor with no Ed25519 key still publishes, unproven.
    #[test]
    fn an_actor_without_a_key_publishes_without_a_proof() {
        let to: Vec<String> = vec![];
        let cc: Vec<String> = vec![];
        let tags: Vec<serde_json::Value> = vec![];

        let activity = build_create_activity(&sample_post(&to, &cc, &tags), ACTOR, None);

        assert!(activity["object"].get("proof").is_none());
        assert_eq!(
            activity["object"]["content"],
            serde_json::json!("<p>hello</p>")
        );
        assert_eq!(activity["type"], serde_json::json!("Create"));
    }

    /// The optional properties are set before signing, so a document
    /// carrying them still verifies. Ordering here is easy to get wrong
    /// and silent when it is.
    #[test]
    fn optional_properties_are_covered_by_the_proof() {
        let keypair = noombat_identity::keys::generate_ed25519_keypair().unwrap();
        let to: Vec<String> = vec![];
        let cc: Vec<String> = vec![];
        let tags = vec![serde_json::json!({"type": "Hashtag", "name": "#rust"})];

        let mut post = sample_post(&to, &cc, &tags);
        post.ap_type = "Article";
        post.title = Some("On numbats");
        post.featured_image_url = Some("https://noombat.social/media/1.png");
        post.in_reply_to = Some("https://remote.example/posts/9");

        let activity = build_create_activity(&post, ACTOR, Some(&keypair.private_base64));
        let object = &activity["object"];

        assert_eq!(object["name"], serde_json::json!("On numbats"));
        assert_eq!(
            object["inReplyTo"],
            serde_json::json!("https://remote.example/posts/9")
        );
        assert!(object.get("image").is_some());
        assert_eq!(
            integrity_proof::verify(object, &keypair.public_multibase),
            VerificationResult::Valid
        );
    }
}
