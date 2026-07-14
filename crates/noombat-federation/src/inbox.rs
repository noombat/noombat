// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Inbox handler for processing inbound ActivityPub activities.

use noombat_ap::activity::{Activity, types};
use noombat_ap::context::{AS_PUBLIC, default_context};
use noombat_ap::object::ApActor;
use noombat_core::actor::Actor;
use noombat_core::error::{NoombatError, Result};
use noombat_identity::repo;
use serde_json::json;
use sqlx::PgPool;
use tracing::{info, warn};

use crate::delivery;

/// Dispatch an inbound activity to the appropriate handler.
pub async fn process_activity(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: Activity,
) -> Result<()> {
    let activity_type = activity.activity_type.as_str();
    info!(
        actor = %activity.actor,
        activity_type,
        "processing inbound activity"
    );

    match activity_type {
        types::FOLLOW => handle_follow(pool, http_client, &activity).await,
        types::UNDO => handle_undo(pool, http_client, &activity).await,
        types::CREATE => handle_create(pool, http_client, &activity).await,
        types::DELETE => handle_delete(pool, &activity).await,
        types::ACCEPT => handle_accept(pool, http_client, &activity).await,
        types::REJECT => handle_reject(pool, http_client, &activity).await,
        types::ANNOUNCE => handle_announce(pool, http_client, &activity).await,
        types::LIKE => handle_like(pool, http_client, &activity).await,
        types::UPDATE => handle_update(pool, http_client, &activity).await,
        types::BLOCK => handle_block(pool, http_client, &activity).await,
        types::MOVE => crate::move_actor::handle_inbound_move(pool, http_client, &activity).await,
        types::FLAG => crate::flag::handle_inbound_flag(pool, http_client, &activity).await,
        other => {
            warn!(activity_type = other, "unsupported activity type; ignoring");
            Ok(())
        }
    }
}

// ..... REMOTE ACTOR RESOLUTION .....

/// Fetch and persist a remote actor's ActivityPub profile.
///
/// Checks the local database cache first. On cache miss, fetches the
/// profile over HTTP and upserts it into the `actors` table.
pub async fn resolve_remote_actor(
    pool: &PgPool,
    http_client: &reqwest::Client,
    actor_uri: &str,
) -> Result<Actor> {
    if let Some(cached) = repo::find_by_ap_id(pool, actor_uri).await? {
        return Ok(cached);
    }

    // Check whether this actor has been tombstoned (410 Gone) before
    // incurring an HTTP round-trip.
    let is_tombstoned: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tombstoned_actors WHERE ap_id = $1)")
            .bind(actor_uri)
            .fetch_one(pool)
            .await
            .unwrap_or(false);

    if is_tombstoned {
        return Err(NoombatError::Federation(format!(
            "actor {actor_uri} is tombstoned (previously returned 410 Gone)"
        )));
    }

    let response = http_client
        .get(actor_uri)
        .header("Accept", "application/activity+json")
        .send()
        .await
        .map_err(|e| NoombatError::Federation(format!("failed to fetch {actor_uri}: {e}")))?;

    if response.status().as_u16() == 410 {
        // Record the tombstone for future short-circuiting.
        let _ = sqlx::query(
            "INSERT INTO tombstoned_actors (ap_id) VALUES ($1) \
             ON CONFLICT (ap_id) DO NOTHING",
        )
        .bind(actor_uri)
        .execute(pool)
        .await;
        return Err(NoombatError::Federation(format!(
            "remote actor {actor_uri} returned 410 Gone; tombstoned"
        )));
    }

    if !response.status().is_success() {
        return Err(NoombatError::Federation(format!(
            "remote actor returned HTTP {}",
            response.status()
        )));
    }

    let ap_actor: ApActor = response
        .json()
        .await
        .map_err(|e| NoombatError::Federation(format!("invalid actor JSON: {e}")))?;

    let domain = extract_domain(actor_uri).unwrap_or_default();
    let remote = ap_actor_to_remote(&ap_actor, domain);

    repo::upsert_remote_actor(pool, &remote).await
}

/// Convert a fetched [`ApActor`] into a [`repo::RemoteActor`] for
/// persistence.
///
/// This function is the single conversion point used by both
/// [`resolve_remote_actor`] and [`handle_update_actor`], ensuring
/// that the field mapping remains consistent.
fn ap_actor_to_remote(ap_actor: &ApActor, domain: String) -> repo::RemoteActor {
    let shared_inbox_url = ap_actor
        .endpoints
        .as_ref()
        .and_then(|ep| ep.get("sharedInbox"))
        .and_then(|v| v.as_str())
        .map(String::from);

    repo::RemoteActor {
        ap_id: ap_actor.id.clone(),
        username: ap_actor.preferred_username.clone(),
        domain,
        display_name: ap_actor.name.clone(),
        summary_html: ap_actor.summary.clone(),
        public_key_pem: ap_actor.public_key.public_key_pem.clone(),
        actor_type: match ap_actor.actor_type.as_str() {
            "Person" => "individual".to_owned(),
            "Organization" => "company".to_owned(),
            "Group" => "group".to_owned(),
            _ => "individual".to_owned(),
        },
        inbox_url: ap_actor.inbox.clone(),
        shared_inbox_url,
    }
}

/// Extract the domain from a URI (e.g. `https://noombat.social/users/alice` to `noombat.social`).
pub fn extract_domain(uri: &str) -> Option<String> {
    uri.strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .and_then(|rest| rest.split('/').next())
        .map(String::from)
}

/// Extract the local username from an actor URI.
///
/// Accepts URIs of the form `https://{domain}/users/{username}` (with
/// an optional trailing slash). Returns `None` if the URI does not
/// contain a `/users/` segment or if the extracted username is empty.
fn extract_local_username(actor_uri: &str) -> Option<&str> {
    // Strip the scheme and domain prefix, leaving `/users/{username}[/]`.
    let path = actor_uri
        .strip_prefix("https://")
        .or_else(|| actor_uri.strip_prefix("http://"))
        .and_then(|rest| rest.find('/').map(|pos| &rest[pos..]))?;

    let after_users = path.strip_prefix("/users/")?;
    let username = after_users.strip_suffix('/').unwrap_or(after_users);

    // Reject empty usernames and paths with additional segments
    // (e.g. `/users/alice/inbox` contains '/' after stripping).
    if username.is_empty() || username.contains('/') {
        return None;
    }

    Some(username)
}

// ..... FOLLOW .....

async fn handle_follow(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    let target_uri = activity
        .object
        .as_str()
        .ok_or_else(|| NoombatError::BadRequest("Follow object must be a string URI".into()))?;

    let target_username = extract_local_username(target_uri)
        .ok_or_else(|| NoombatError::BadRequest("cannot parse target actor URI".into()))?;

    info!(follower = %activity.actor, target = %target_uri, "received Follow");

    // Resolve the remote follower and the local target concurrently.
    let (remote_actor, local_actor) = tokio::try_join!(
        resolve_remote_actor(pool, http_client, &activity.actor),
        repo::find_local_by_username(pool, target_username),
    )?;

    // Determine whether to auto-accept based on the local actor's privacy settings.
    let auto_accept = !local_actor.actor_privacy.require_follow_approval;

    // Persist the follow relationship, recording the Follow activity's
    // AP id so that Accept / Reject can reference it.
    repo::create_follow_with_ap_id(
        pool,
        remote_actor.id,
        local_actor.id,
        auto_accept,
        Some(&activity.id),
    )
    .await?;

    if auto_accept {
        // Construct and deliver an Accept { Follow } activity.
        let accept_id = format!(
            "{}#accept-follow-{}",
            local_actor.ap_id,
            chrono::Utc::now().timestamp()
        );
        let accept_activity = json!({
            "@context": default_context(),
            "id": accept_id,
            "type": "Accept",
            "actor": local_actor.ap_id,
            "object": {
                "id": activity.id,
                "type": "Follow",
                "actor": remote_actor.ap_id,
                "object": local_actor.ap_id
            }
        });

        let remote_inbox = remote_actor
            .inbox_url
            .clone()
            .unwrap_or_else(|| format!("{}/inbox", remote_actor.ap_id));
        delivery::enqueue(pool, local_actor.id, &accept_activity, &remote_inbox).await?;

        info!(
            follower = %remote_actor.ap_id,
            target = %local_actor.ap_id,
            "follow auto-accepted; Accept enqueued"
        );
    } else {
        info!(
            follower = %remote_actor.ap_id,
            target = %local_actor.ap_id,
            "follow pending approval"
        );
    }

    Ok(())
}

// ..... UNDO .....

async fn handle_undo(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    // The `object` of an Undo is the activity being reversed.
    let inner_type = activity
        .object
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match inner_type {
        "Follow" => {
            let target_uri = activity
                .object
                .get("object")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    NoombatError::BadRequest("Undo Follow: missing inner object".into())
                })?;

            let target_username = extract_local_username(target_uri)
                .ok_or_else(|| NoombatError::BadRequest("cannot parse target actor URI".into()))?;

            let remote_actor = resolve_remote_actor(pool, http_client, &activity.actor).await?;
            let local_actor = repo::find_local_by_username(pool, target_username).await?;

            repo::delete_follow(pool, remote_actor.id, local_actor.id).await?;
            info!(
                follower = %remote_actor.ap_id,
                target = %local_actor.ap_id,
                "follow undone"
            );
        }
        "Like" => {
            let inner_ap_id = activity
                .object
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| NoombatError::BadRequest("Undo Like: missing id".into()))?;

            let remote_actor = resolve_remote_actor(pool, http_client, &activity.actor).await?;
            sqlx::query("DELETE FROM likes WHERE ap_id = $1 AND actor_id = $2")
                .bind(inner_ap_id)
                .bind(remote_actor.id)
                .execute(pool)
                .await?;
            info!(ap_id = %inner_ap_id, "like undone");
        }
        "Announce" => {
            let inner_ap_id = activity
                .object
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| NoombatError::BadRequest("Undo Announce: missing id".into()))?;

            let remote_actor = resolve_remote_actor(pool, http_client, &activity.actor).await?;
            sqlx::query("DELETE FROM boosts WHERE ap_id = $1 AND actor_id = $2")
                .bind(inner_ap_id)
                .bind(remote_actor.id)
                .execute(pool)
                .await?;
            info!(ap_id = %inner_ap_id, "boost undone");
        }
        "Block" => {
            // The inner object of Undo { Block } is the blocked actor's URI.
            let target_uri = activity
                .object
                .get("object")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    NoombatError::BadRequest("Undo Block: missing inner object".into())
                })?;

            let target_username = extract_local_username(target_uri)
                .ok_or_else(|| NoombatError::BadRequest("cannot parse target actor URI".into()))?;

            let remote_actor = resolve_remote_actor(pool, http_client, &activity.actor).await?;
            let local_actor = repo::find_local_by_username(pool, target_username).await?;

            sqlx::query("DELETE FROM blocks WHERE actor_id = $1 AND target_id = $2")
                .bind(remote_actor.id)
                .bind(local_actor.id)
                .execute(pool)
                .await?;
            info!(
                actor = %remote_actor.ap_id,
                target = %local_actor.ap_id,
                "block undone"
            );
        }
        other => {
            warn!(inner_type = other, "unsupported Undo target; ignoring");
        }
    }

    Ok(())
}

// ..... CREATE .....

async fn handle_create(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    let object = &activity.object;

    let object_type = object.get("type").and_then(|v| v.as_str()).unwrap_or("");

    let ap_id = object
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| NoombatError::BadRequest("Create object missing id".into()))?;

    let content_html = object.get("content").and_then(|v| v.as_str()).unwrap_or("");

    // Extract the Mastodon-convention `source` property when available.
    // If the source carries `text/markdown`, store it in `content_md`;
    // otherwise fall back to `content_html` (the previous behaviour).
    let content_md = object
        .get("source")
        .and_then(|src| {
            let media = src.get("mediaType").and_then(|v| v.as_str()).unwrap_or("");
            if media == "text/markdown" {
                src.get("content").and_then(|v| v.as_str())
            } else {
                None
            }
        })
        .unwrap_or(content_html);

    let post_type = match object_type {
        "Note" => "note",
        "Article" => "article",
        _ => {
            warn!(object_type, "unsupported Create object type; ignoring");
            return Ok(());
        }
    };

    info!(actor = %activity.actor, object_type, ap_id, "received Create");

    // ..... ARTICLE-SPECIFIC FIELDS .....
    //
    // Articles carry a title in the `name` property (ActivityStreams)
    // and may carry a featured image as the `image` property (used by
    // Ghost) or as the first `Image`-typed element in `attachment`
    // (used by WordPress, Mastodon, and others).

    let title = object
        .get("name")
        .and_then(|v| v.as_str())
        .map(String::from);

    let featured_image_url = extract_image_url(object);

    // Resolve the remote author.
    let remote_actor = resolve_remote_actor(pool, http_client, &activity.actor).await?;

    // Derive visibility from the activity's to/cc addressing.
    //
    // Some implementations place to/cc only on the inner object (the
    // Note or Article) rather than on the wrapping Create activity.
    // Fall back to the inner object's addressing when the envelope
    // fields are absent.
    let to = activity
        .to
        .clone()
        .or_else(|| extract_string_array(&activity.object, "to"));
    let cc = activity
        .cc
        .clone()
        .or_else(|| extract_string_array(&activity.object, "cc"));
    let visibility = derive_visibility(&to, &cc);

    // Cross-post de-duplication: if an existing local post matches
    // the canonical URI or URL of the inbound object, link to it
    // rather than creating a duplicate.
    if let Ok(Some(existing_id)) = crate::crosspost::try_dedup(pool, &activity.object).await {
        info!(
            ap_id,
            existing_id = %existing_id,
            "inbound Create de-duplicated; skipping insertion"
        );
        return Ok(());
    }

    // Persist the remote post.
    let remote_post = repo::RemotePost {
        actor_id: remote_actor.id,
        ap_id: ap_id.to_owned(),
        post_type: post_type.to_owned(),
        title,
        featured_image_url,
        content_md: content_md.to_owned(),
        content_html: content_html.to_owned(),
        visibility,
        ap_object: activity.object.clone(),
    };

    let post_id = repo::create_remote_post(pool, &remote_post).await?;

    // ..... HASHTAG LINKING .....
    //
    // The ActivityPub `tag` array carries `Hashtag` objects (the same
    // format used by Mastodon, Lemmy, and others):
    //
    //   { "type": "Hashtag", "name": "#rust", "href": "https://..." }
    //
    // Extract the names and link them to the newly persisted post so
    // that hashtag-following feeds include federated content.

    if let Some(post_id) = post_id {
        let hashtag_names = extract_hashtags_from_tags(object);
        if !hashtag_names.is_empty()
            && let Err(e) =
                noombat_identity::hashtags::link_post_hashtags(pool, post_id, &hashtag_names).await
        {
            warn!(ap_id, "failed to link hashtags for remote post: {e}");
        }
        info!(ap_id, "remote post persisted");
    } else {
        info!(ap_id, "remote post already known; skipped");
    }

    Ok(())
}

// ..... DELETE .....

async fn handle_delete(pool: &PgPool, activity: &Activity) -> Result<()> {
    let object_id = activity
        .object
        .get("id")
        .and_then(|v| v.as_str())
        .or_else(|| activity.object.as_str())
        .ok_or_else(|| NoombatError::BadRequest("Delete: missing object id".into()))?;

    info!(actor = %activity.actor, object = %object_id, "received Delete");

    // Verify that the requesting actor owns the post before deleting.
    let is_authorised = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM posts p
           JOIN actors a ON a.id = p.actor_id
           WHERE p.ap_id = $1 AND a.ap_id = $2"#,
    )
    .bind(object_id)
    .bind(&activity.actor)
    .fetch_one(pool)
    .await?;

    if is_authorised == 0 {
        // Either the post does not exist locally, or the requesting
        // actor is not its author.  Both cases are safe to ignore:
        // the post may have already been deleted, or the request is
        // unauthorised.
        warn!(
            actor = %activity.actor,
            object = %object_id,
            "Delete ignored: post not found or actor mismatch"
        );
        return Ok(());
    }

    sqlx::query("DELETE FROM posts WHERE ap_id = $1")
        .bind(object_id)
        .execute(pool)
        .await?;

    info!(object = %object_id, "post deleted");
    Ok(())
}

// ..... UPDATE .....

async fn handle_update(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    let object = &activity.object;

    // Determine what kind of object is being updated.
    let object_type = object
        .get("type")
        .and_then(|v| {
            // `type` may be a string or an array (dual-typed objects).
            v.as_str()
                .map(String::from)
                .or_else(|| v.as_array().and_then(|a| a.first()).and_then(|v| v.as_str()).map(String::from))
        })
        .unwrap_or_default();

    let object_id = object
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    info!(
        actor = %activity.actor,
        object_type = %object_type,
        object_id = %object_id,
        "received Update"
    );

    match object_type.as_str() {
        // Actor profile update: re-fetch and upsert the remote actor.
        "Person" | "Organization" | "Group" | "Application" | "Service" => {
            handle_update_actor(pool, http_client, activity).await
        }
        // Post edit: update the cached remote post.
        "Note" | "Article" => handle_update_post(pool, http_client, activity).await,
        _ => {
            warn!(
                object_type = %object_type,
                "Update for unsupported object type; ignoring"
            );
            Ok(())
        }
    }
}

/// Handle an `Update` activity targeting a remote actor (profile refresh).
///
/// Verifies that the activity's `actor` matches the object's `id`
/// (an actor may only update itself), then re-fetches the actor
/// profile and upserts it (the `upsert_remote_actor` function's
/// `ON CONFLICT` clause updates the existing row in place, preserving
/// all FK-dependent data such as follows and posts).
async fn handle_update_actor(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    let object_id = activity
        .object
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Security: an actor may only update its own profile.
    if activity.actor != object_id {
        warn!(
            actor = %activity.actor,
            object = %object_id,
            "Update actor mismatch; ignoring"
        );
        return Ok(());
    }

    // Re-fetch the remote actor profile and upsert it. The inbound
    // Update may carry the full actor object in its body, but
    // re-fetching from the authoritative source is safer (the Update
    // body could be stale or tampered with by a relay).
    //
    // To force a fresh HTTP fetch, we must bypass the local cache.
    // Rather than deleting the row (which would cascade-delete all
    // dependent data, e.g. follows, posts, likes), we fetch directly and
    // let upsert_remote_actor's ON CONFLICT clause update in place.
    let response = http_client
        .get(&activity.actor)
        .header("Accept", "application/activity+json")
        .send()
        .await
        .map_err(|e| NoombatError::Federation(format!("failed to re-fetch {}: {e}", activity.actor)))?;

    if !response.status().is_success() {
        warn!(
            actor = %activity.actor,
            status = response.status().as_u16(),
            "failed to re-fetch actor during Update; ignoring"
        );
        return Ok(());
    }

    let ap_actor: ApActor = response
        .json()
        .await
        .map_err(|e| NoombatError::Federation(format!("invalid actor JSON on re-fetch: {e}")))?;

    let domain = extract_domain(&activity.actor).unwrap_or_default();
    let remote = ap_actor_to_remote(&ap_actor, domain);

    repo::upsert_remote_actor(pool, &remote).await?;
    info!(actor = %activity.actor, "remote actor profile refreshed via Update");

    Ok(())
}

/// Handle an `Update` activity targeting a remote post (edit).
///
/// Verifies that the activity's `actor` matches the post's
/// `attributedTo`, then updates the cached content.
async fn handle_update_post(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    let object = &activity.object;

    let ap_id = object
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| NoombatError::BadRequest("Update object missing id".into()))?;

    let attributed_to = object
        .get("attributedTo")
        .and_then(|v| {
            v.as_str().or_else(|| {
                v.as_array()
                    .and_then(|arr| arr.iter().find_map(|item| item.as_str()))
            })
        })
        .unwrap_or("");

    // Security: the activity actor must match the post author.
    if activity.actor != attributed_to {
        warn!(
            actor = %activity.actor,
            attributed_to = %attributed_to,
            "Update post: actor does not match attributedTo; ignoring"
        );
        return Ok(());
    }

    // Resolve the remote author (may already be cached).
    let _remote_actor = resolve_remote_actor(pool, http_client, &activity.actor).await?;

    let content_html = object.get("content").and_then(|v| v.as_str()).unwrap_or("");

    let content_md = object
        .get("source")
        .and_then(|src| {
            let media = src.get("mediaType").and_then(|v| v.as_str()).unwrap_or("");
            if media == "text/markdown" {
                src.get("content").and_then(|v| v.as_str())
            } else {
                None
            }
        })
        .unwrap_or(content_html);

    let title = object
        .get("name")
        .and_then(|v| v.as_str());

    let featured_image_url = extract_image_url(object);

    // Derive updated visibility from the object's to/cc addressing.
    let to = extract_string_array(object, "to");
    let cc = extract_string_array(object, "cc");
    let visibility = derive_visibility(&to, &cc);

    let rows_affected = sqlx::query(
        r#"UPDATE posts
           SET content_md = $2,
               content_html = $3,
               title = $4,
               featured_image_url = $5,
               visibility = $6,
               ap_object = $7
           WHERE ap_id = $1"#,
    )
    .bind(ap_id)
    .bind(content_md)
    .bind(content_html)
    .bind(title)
    .bind(&featured_image_url)
    .bind(&visibility)
    .bind(object)
    .execute(pool)
    .await?
    .rows_affected();

    if rows_affected > 0 {
        // Refresh hashtag links: the edit may have added or removed
        // hashtags. Delete existing links and re-insert from the
        // updated `tag` array.
        let post_id =
            sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM posts WHERE ap_id = $1")
                .bind(ap_id)
                .fetch_optional(pool)
                .await?;

        if let Some(post_id) = post_id {
            sqlx::query("DELETE FROM post_hashtags WHERE post_id = $1")
                .bind(post_id)
                .execute(pool)
                .await?;

            let hashtag_names = extract_hashtags_from_tags(object);
            if !hashtag_names.is_empty()
                && let Err(e) =
                    noombat_identity::hashtags::link_post_hashtags(pool, post_id, &hashtag_names)
                        .await
            {
                warn!(ap_id, "failed to re-link hashtags after post Update: {e}");
            }
        }

        info!(ap_id, "remote post updated via Update activity");
    } else {
        // The post is not known locally; this is common when the
        // instance does not follow the author.
        info!(ap_id, "Update for unknown post; ignoring");
    }

    Ok(())
}

// ..... ACCEPT .....

async fn handle_accept(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    // An Accept wraps the original Follow activity.
    let inner_type = activity
        .object
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if inner_type != "Follow" {
        warn!(inner_type, "Accept of non-Follow; ignoring");
        return Ok(());
    }

    // Check whether this is a relay accepting our subscription
    // before proceeding with normal follow-accept logic.
    if let Ok(true) = crate::relay::try_handle_relay_accept(pool, &activity.actor).await {
        return Ok(());
    }

    // The Follow's actor is the local user who sent the follow request.
    let follower_uri = activity
        .object
        .get("actor")
        .and_then(|v| v.as_str())
        .ok_or_else(|| NoombatError::BadRequest("Accept: missing Follow actor".into()))?;

    let follower_username = extract_local_username(follower_uri)
        .ok_or_else(|| NoombatError::BadRequest("cannot parse follower URI".into()))?;

    let local_actor = repo::find_local_by_username(pool, follower_username).await?;
    let remote_actor = resolve_remote_actor(pool, http_client, &activity.actor).await?;

    repo::accept_follow(pool, local_actor.id, remote_actor.id).await?;
    info!(
        follower = %local_actor.ap_id,
        target = %remote_actor.ap_id,
        "outbound follow accepted by remote"
    );

    Ok(())
}

// ..... REJECT .....

async fn handle_reject(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    // A Reject wraps the original Follow activity.
    let inner_type = activity
        .object
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if inner_type != "Follow" {
        warn!(inner_type, "Reject of non-Follow; ignoring");
        return Ok(());
    }

    // The Follow's actor is the local user who sent the follow request.
    let follower_uri = activity
        .object
        .get("actor")
        .and_then(|v| v.as_str())
        .ok_or_else(|| NoombatError::BadRequest("Reject: missing Follow actor".into()))?;

    let follower_username = extract_local_username(follower_uri)
        .ok_or_else(|| NoombatError::BadRequest("cannot parse follower URI".into()))?;

    let local_actor = repo::find_local_by_username(pool, follower_username).await?;
    let remote_actor = resolve_remote_actor(pool, http_client, &activity.actor).await?;

    // Delete the pending follow: local_actor follows remote_actor.
    repo::delete_follow(pool, local_actor.id, remote_actor.id).await?;
    info!(
        follower = %local_actor.ap_id,
        target = %remote_actor.ap_id,
        "outbound follow rejected by remote; follow deleted"
    );

    Ok(())
}

// ..... ANNOUNCE .....

async fn handle_announce(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    // The `object` of an Announce is the AP ID of the boosted post.
    let object_uri = activity
        .object
        .as_str()
        .or_else(|| activity.object.get("id").and_then(|v| v.as_str()))
        .ok_or_else(|| NoombatError::BadRequest("Announce: missing object id".into()))?;

    info!(actor = %activity.actor, object = %object_uri, "received Announce");

    let remote_actor = resolve_remote_actor(pool, http_client, &activity.actor).await?;

    // Look up the boosted post locally; if absent, fetch it from the
    // remote instance so that boosts of non-local content are visible
    // in timelines. This mirrors Mastodon's dereference-on-boost
    // behaviour.
    let post_id =
        match sqlx::query_scalar::<_, uuid::Uuid>(r#"SELECT id FROM posts WHERE ap_id = $1"#)
            .bind(object_uri)
            .fetch_optional(pool)
            .await?
        {
            Some(id) => id,
            None => match fetch_and_persist_remote_post(pool, http_client, object_uri).await {
                Ok(id) => id,
                Err(e) => {
                    warn!(
                        object = %object_uri,
                        error = %e,
                        "Announce: failed to fetch remote post; ignoring"
                    );
                    return Ok(());
                }
            },
        };

    let boost_ap_id = &activity.id;
    sqlx::query(
        r#"INSERT INTO boosts (id, actor_id, post_id, ap_id)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (actor_id, post_id) DO NOTHING"#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(remote_actor.id)
    .bind(post_id)
    .bind(boost_ap_id)
    .execute(pool)
    .await?;

    info!(actor = %remote_actor.ap_id, post = %object_uri, "boost recorded");
    Ok(())
}

/// Fetch a remote post by its AP URI, resolve its author, persist both,
/// and return the new post's local UUID.
///
/// Used by [`handle_announce`] when the boosted object is not already
/// known locally. The fetched object must be a `Note` or `Article`;
/// other types are rejected.
async fn fetch_and_persist_remote_post(
    pool: &PgPool,
    http_client: &reqwest::Client,
    object_uri: &str,
) -> Result<uuid::Uuid> {
    let response = http_client
        .get(object_uri)
        .header("Accept", "application/activity+json")
        .send()
        .await
        .map_err(|e| NoombatError::Federation(format!("failed to fetch {object_uri}: {e}")))?;

    if !response.status().is_success() {
        return Err(NoombatError::Federation(format!(
            "remote object returned HTTP {}",
            response.status()
        )));
    }

    let object: serde_json::Value = response
        .json()
        .await
        .map_err(|e| NoombatError::Federation(format!("invalid object JSON: {e}")))?;

    let object_type = object.get("type").and_then(|v| v.as_str()).unwrap_or("");

    let post_type = match object_type {
        "Note" => "note",
        "Article" => "article",
        _ => {
            return Err(NoombatError::Federation(format!(
                "Announce references unsupported object type: {object_type}"
            )));
        }
    };

    let ap_id = object
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| NoombatError::Federation("fetched object missing id".into()))?;

    // `attributedTo` may be a single URI string (Mastodon) or an array
    // of URIs or objects (Lemmy, PeerTube). Extract the first usable
    // string in either case.
    let author_uri = object
        .get("attributedTo")
        .and_then(|v| {
            v.as_str().or_else(|| {
                v.as_array()
                    .and_then(|arr| arr.iter().find_map(|item| item.as_str()))
            })
        })
        .ok_or_else(|| NoombatError::Federation("fetched object missing attributedTo".into()))?;

    let content_html = object.get("content").and_then(|v| v.as_str()).unwrap_or("");

    let content_md = object
        .get("source")
        .and_then(|src| {
            let media = src.get("mediaType").and_then(|v| v.as_str()).unwrap_or("");
            if media == "text/markdown" {
                src.get("content").and_then(|v| v.as_str())
            } else {
                None
            }
        })
        .unwrap_or(content_html);

    let title = object
        .get("name")
        .and_then(|v| v.as_str())
        .map(String::from);

    let featured_image_url = extract_image_url(&object);

    // Derive visibility from the object's own to/cc addressing.
    let to = extract_string_array(&object, "to");
    let cc = extract_string_array(&object, "cc");
    let visibility = derive_visibility(&to, &cc);

    // Resolve the author (creates a remote actor record if needed).
    let author = resolve_remote_actor(pool, http_client, author_uri).await?;

    let remote_post = repo::RemotePost {
        actor_id: author.id,
        ap_id: ap_id.to_owned(),
        post_type: post_type.to_owned(),
        title,
        featured_image_url,
        content_md: content_md.to_owned(),
        content_html: content_html.to_owned(),
        visibility,
        ap_object: object.clone(),
    };

    // Persist the post. If it was inserted by a concurrent request in
    // the meantime, `create_remote_post` returns `None`; fall back to
    // a lookup.
    let post_id = match repo::create_remote_post(pool, &remote_post).await? {
        Some(id) => {
            // Link hashtags from the tag array (best-effort).
            let hashtag_names = extract_hashtags_from_tags(&object);
            if !hashtag_names.is_empty()
                && let Err(e) =
                    noombat_identity::hashtags::link_post_hashtags(pool, id, &hashtag_names).await
            {
                warn!(ap_id, "failed to link hashtags for fetched post: {e}");
            }
            info!(ap_id, "remote post fetched and persisted via Announce");
            id
        }
        None => {
            // Concurrent insert; look up the existing row.
            sqlx::query_scalar::<_, uuid::Uuid>(r#"SELECT id FROM posts WHERE ap_id = $1"#)
                .bind(ap_id)
                .fetch_one(pool)
                .await
                .map_err(|e| {
                    NoombatError::Internal(format!(
                        "post {ap_id} not found after concurrent insert: {e}"
                    ))
                })?
        }
    };

    Ok(post_id)
}

// ..... LIKE .....

async fn handle_like(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    let object_uri = activity
        .object
        .as_str()
        .or_else(|| activity.object.get("id").and_then(|v| v.as_str()))
        .ok_or_else(|| NoombatError::BadRequest("Like: missing object id".into()))?;

    info!(actor = %activity.actor, object = %object_uri, "received Like");

    let remote_actor = resolve_remote_actor(pool, http_client, &activity.actor).await?;

    let post_id = sqlx::query_scalar::<_, uuid::Uuid>(r#"SELECT id FROM posts WHERE ap_id = $1"#)
        .bind(object_uri)
        .fetch_optional(pool)
        .await?;

    let post_id = match post_id {
        Some(id) => id,
        None => {
            warn!(object = %object_uri, "Like references unknown post; ignoring");
            return Ok(());
        }
    };

    let like_ap_id = &activity.id;
    sqlx::query(
        r#"INSERT INTO likes (id, actor_id, post_id, ap_id)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (actor_id, post_id) DO NOTHING"#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(remote_actor.id)
    .bind(post_id)
    .bind(like_ap_id)
    .execute(pool)
    .await?;

    info!(actor = %remote_actor.ap_id, post = %object_uri, "like recorded");
    Ok(())
}

// ..... BLOCK .....

async fn handle_block(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    // The `object` of a Block is the URI of the actor being blocked.
    let target_uri = activity
        .object
        .as_str()
        .or_else(|| activity.object.get("id").and_then(|v| v.as_str()))
        .ok_or_else(|| NoombatError::BadRequest("Block: missing target actor id".into()))?;

    let target_username = extract_local_username(target_uri)
        .ok_or_else(|| NoombatError::BadRequest("cannot parse target actor URI".into()))?;

    info!(actor = %activity.actor, target = %target_uri, "received Block");

    let remote_actor = resolve_remote_actor(pool, http_client, &activity.actor).await?;
    let local_actor = repo::find_local_by_username(pool, target_username).await?;

    // Persist the block (idempotent).
    sqlx::query(
        r#"INSERT INTO blocks (id, actor_id, target_id)
           VALUES ($1, $2, $3)
           ON CONFLICT (actor_id, target_id) DO NOTHING"#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(remote_actor.id)
    .bind(local_actor.id)
    .execute(pool)
    .await?;

    // Sever any follow relationships in both directions.
    repo::delete_follow(pool, remote_actor.id, local_actor.id).await?;
    repo::delete_follow(pool, local_actor.id, remote_actor.id).await?;

    info!(
        actor = %remote_actor.ap_id,
        target = %local_actor.ap_id,
        "block recorded; mutual follows severed"
    );
    Ok(())
}

// ..... VISIBILITY DERIVATION .....

/// Derive post visibility from the `to` and `cc` addressing arrays of
/// an inbound ActivityPub activity.
///
/// The ActivityStreams Public collection URI ([`AS_PUBLIC`]) determines
/// the audience:
///
/// | `to` contains Public | `cc` contains Public | Result       |
/// |----------------------|----------------------|--------------|
/// | yes                  | —                    | `"public"`   |
/// | no                   | yes                  | `"unlisted"` |
/// | no                   | no                   | `"followers"`|
///
/// Some implementations use the shorthand `"Public"` (case-insensitive)
/// in place of the full URI; this function accepts both forms.
fn derive_visibility(to: &Option<Vec<String>>, cc: &Option<Vec<String>>) -> String {
    if list_contains_public(to) {
        "public".to_owned()
    } else if list_contains_public(cc) {
        "unlisted".to_owned()
    } else {
        "followers".to_owned()
    }
}

/// Whether an addressing list contains the ActivityStreams Public
/// collection URI or the `"Public"` shorthand.
fn list_contains_public(list: &Option<Vec<String>>) -> bool {
    list.as_ref().is_some_and(|items| {
        items
            .iter()
            .any(|uri| uri == AS_PUBLIC || uri.eq_ignore_ascii_case("Public"))
    })
}

/// Extract an addressing field (`to` or `cc`) from a JSON object.
///
/// ActivityStreams allows addressing to be either an array of strings
/// or a single string. This function normalises both forms into
/// `Option<Vec<String>>`.
fn extract_string_array(value: &serde_json::Value, key: &str) -> Option<Vec<String>> {
    let field = value.get(key)?;
    if let Some(arr) = field.as_array() {
        let strings: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        if strings.is_empty() {
            None
        } else {
            Some(strings)
        }
    } else {
        field.as_str().map(|s| vec![s.to_owned()])
    }
}

// ..... ARTICLE FIELD EXTRACTION .....

/// Extract a featured-image URL from an inbound ActivityPub object.
///
/// Checks two locations, in order:
///
/// 1. The `image` property: used by Ghost and some CMS-based
///    Fediverse publishers. May be a bare URL string or an object
///    with a `url` field.
/// 2. The first element of the `attachment` array whose `type` is
///    `"Image"`: used by WordPress and Mastodon.
///
/// Returns `None` if neither location contains a usable URL.
fn extract_image_url(object: &serde_json::Value) -> Option<String> {
    // 1. `image` property (string or object).
    if let Some(image) = object.get("image") {
        if let Some(url) = image.as_str() {
            return Some(url.to_owned());
        }
        if let Some(url) = image.get("url").and_then(|v| v.as_str()) {
            return Some(url.to_owned());
        }
    }

    // 2. First `Image` in `attachment`.
    if let Some(attachments) = object.get("attachment").and_then(|v| v.as_array()) {
        for att in attachments {
            let att_type = att.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if att_type == "Image"
                && let Some(url) = att.get("url").and_then(|v| v.as_str())
            {
                return Some(url.to_owned());
            }
        }
    }

    None
}

// ..... HASHTAG EXTRACTION FROM TAG ARRAY .....

/// Extract hashtag names from the `tag` array of an inbound object.
///
/// Mastodon, Lemmy, GotoSocial, and other Fediverse software include
/// hashtags as:
///
/// ```json
/// { "type": "Hashtag", "name": "#rust", "href": "https://.../tags/rust" }
/// ```
///
/// Returns a `Vec<String>` of normalised names (lowercase, leading
/// `#` stripped), suitable for passing to
/// [`noombat_identity::hashtags::link_post_hashtags`].
fn extract_hashtags_from_tags(object: &serde_json::Value) -> Vec<String> {
    let tags = match object.get("tag").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return Vec::new(),
    };

    tags.iter()
        .filter_map(|tag| {
            let tag_type = tag.get("type").and_then(|v| v.as_str())?;
            if tag_type != "Hashtag" {
                return None;
            }
            let name = tag.get("name").and_then(|v| v.as_str())?;
            let stripped = name.strip_prefix('#').unwrap_or(name);
            if stripped.is_empty() {
                return None;
            }
            Some(stripped.to_lowercase())
        })
        .collect()
}

// ..... TESTS .....

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_domain_https() {
        assert_eq!(
            extract_domain("https://noombat.social/users/alice"),
            Some("noombat.social".to_owned())
        );
    }

    #[test]
    fn extract_domain_with_port() {
        assert_eq!(
            extract_domain("http://localhost:8443/users/alice"),
            Some("localhost:8443".to_owned())
        );
    }

    #[test]
    fn extract_local_username_valid() {
        assert_eq!(
            extract_local_username("https://noombat.social/users/alice"),
            Some("alice")
        );
    }

    #[test]
    fn extract_local_username_with_port() {
        assert_eq!(
            extract_local_username("http://localhost:8443/users/alice"),
            Some("alice")
        );
    }

    #[test]
    fn extract_local_username_trailing_slash() {
        assert_eq!(
            extract_local_username("https://noombat.social/users/alice/"),
            Some("alice")
        );
    }

    #[test]
    fn extract_local_username_rejects_subpath() {
        // `/users/alice/inbox` has an additional segment; must return None.
        assert_eq!(
            extract_local_username("https://noombat.social/users/alice/inbox"),
            None
        );
    }

    #[test]
    fn extract_local_username_rejects_non_users_path() {
        assert_eq!(
            extract_local_username("https://noombat.social/@alice"),
            None
        );
    }

    #[test]
    fn extract_local_username_rejects_empty() {
        assert_eq!(
            extract_local_username("https://noombat.social/users/"),
            None
        );
    }

    #[test]
    fn extract_local_username_rejects_bare_domain() {
        assert_eq!(extract_local_username("https://noombat.social"), None);
    }

    #[test]
    fn visibility_public_in_to() {
        let to = Some(vec![AS_PUBLIC.to_owned()]);
        assert_eq!(derive_visibility(&to, &None), "public");
    }

    #[test]
    fn visibility_public_shorthand_in_to() {
        let to = Some(vec!["Public".to_owned()]);
        assert_eq!(derive_visibility(&to, &None), "public");
    }

    #[test]
    fn visibility_unlisted_public_in_cc() {
        let to = Some(vec![
            "https://noombat.social/users/alice/followers".to_owned(),
        ]);
        let cc = Some(vec![AS_PUBLIC.to_owned()]);
        assert_eq!(derive_visibility(&to, &cc), "unlisted");
    }

    #[test]
    fn visibility_unlisted_shorthand_in_cc() {
        let to = Some(vec![
            "https://noombat.social/users/alice/followers".to_owned(),
        ]);
        let cc = Some(vec!["Public".to_owned()]);
        assert_eq!(derive_visibility(&to, &cc), "unlisted");
    }

    #[test]
    fn visibility_followers_no_public() {
        let to = Some(vec![
            "https://noombat.social/users/alice/followers".to_owned(),
        ]);
        assert_eq!(derive_visibility(&to, &None), "followers");
    }

    #[test]
    fn visibility_followers_empty_addressing() {
        assert_eq!(derive_visibility(&None, &None), "followers");
    }

    #[test]
    fn extract_string_array_from_array() {
        let obj = serde_json::json!({
            "to": ["https://www.w3.org/ns/activitystreams#Public"]
        });
        let result = extract_string_array(&obj, "to");
        assert_eq!(result, Some(vec![AS_PUBLIC.to_owned()]));
    }

    #[test]
    fn extract_string_array_from_single_string() {
        let obj = serde_json::json!({
            "to": "https://www.w3.org/ns/activitystreams#Public"
        });
        let result = extract_string_array(&obj, "to");
        assert_eq!(result, Some(vec![AS_PUBLIC.to_owned()]));
    }

    #[test]
    fn extract_string_array_missing_key() {
        let obj = serde_json::json!({});
        assert_eq!(extract_string_array(&obj, "to"), None);
    }

    // ..... extract_image_url .....

    #[test]
    fn image_url_from_string_property() {
        let obj = serde_json::json!({
            "type": "Article",
            "image": "https://example.com/photo.jpg"
        });
        assert_eq!(
            extract_image_url(&obj),
            Some("https://example.com/photo.jpg".to_owned())
        );
    }

    #[test]
    fn image_url_from_object_property() {
        let obj = serde_json::json!({
            "type": "Article",
            "image": { "type": "Image", "url": "https://example.com/photo.jpg" }
        });
        assert_eq!(
            extract_image_url(&obj),
            Some("https://example.com/photo.jpg".to_owned())
        );
    }

    #[test]
    fn image_url_from_attachment_array() {
        let obj = serde_json::json!({
            "type": "Article",
            "attachment": [
                { "type": "Document", "url": "https://example.com/file.pdf" },
                { "type": "Image", "url": "https://example.com/photo.jpg" }
            ]
        });
        assert_eq!(
            extract_image_url(&obj),
            Some("https://example.com/photo.jpg".to_owned())
        );
    }

    #[test]
    fn image_url_prefers_image_property_over_attachment() {
        let obj = serde_json::json!({
            "type": "Article",
            "image": "https://example.com/featured.jpg",
            "attachment": [
                { "type": "Image", "url": "https://example.com/other.jpg" }
            ]
        });
        assert_eq!(
            extract_image_url(&obj),
            Some("https://example.com/featured.jpg".to_owned())
        );
    }

    #[test]
    fn image_url_none_when_absent() {
        let obj = serde_json::json!({ "type": "Note", "content": "hello" });
        assert_eq!(extract_image_url(&obj), None);
    }

    // ..... extract_hashtags_from_tags .....

    #[test]
    fn hashtags_from_tag_array() {
        let obj = serde_json::json!({
            "type": "Note",
            "tag": [
                { "type": "Hashtag", "name": "#Rust", "href": "https://example.com/tags/rust" },
                { "type": "Mention", "name": "@alice", "href": "https://example.com/users/alice" },
                { "type": "Hashtag", "name": "#ActivityPub" }
            ]
        });
        let tags = extract_hashtags_from_tags(&obj);
        assert_eq!(tags, vec!["rust".to_owned(), "activitypub".to_owned()]);
    }

    #[test]
    fn hashtags_without_leading_hash() {
        let obj = serde_json::json!({
            "tag": [
                { "type": "Hashtag", "name": "noHash" }
            ]
        });
        let tags = extract_hashtags_from_tags(&obj);
        assert_eq!(tags, vec!["nohash".to_owned()]);
    }

    #[test]
    fn hashtags_empty_when_no_tag_array() {
        let obj = serde_json::json!({ "type": "Note" });
        assert!(extract_hashtags_from_tags(&obj).is_empty());
    }

    #[test]
    fn hashtags_skips_empty_names() {
        let obj = serde_json::json!({
            "tag": [
                { "type": "Hashtag", "name": "#" },
                { "type": "Hashtag", "name": "" }
            ]
        });
        assert!(extract_hashtags_from_tags(&obj).is_empty());
    }
}
