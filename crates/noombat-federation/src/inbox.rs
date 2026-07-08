// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Inbox handler for processing inbound ActivityPub activities.

use noombat_ap::activity::{types, Activity};
use noombat_ap::context::{default_context, AS_PUBLIC};
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
        types::BLOCK => handle_block(pool, http_client, &activity).await,
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

    let response = http_client
        .get(actor_uri)
        .header("Accept", "application/activity+json")
        .send()
        .await
        .map_err(|e| NoombatError::Federation(format!("failed to fetch {actor_uri}: {e}")))?;

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

    let remote = repo::RemoteActor {
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
    };

    repo::upsert_remote_actor(pool, &remote).await
}

/// Extract the domain from a URI (e.g. `https://noombat.social/users/alice` to `noombat.social`).
pub fn extract_domain(uri: &str) -> Option<String> {
    uri.strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .and_then(|rest| rest.split('/').next())
        .map(String::from)
}

/// Extract the local username from an actor URI.
fn extract_local_username(actor_uri: &str) -> Option<&str> {
    actor_uri.rsplit('/').next()
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
        if !hashtag_names.is_empty() {
            if let Err(e) =
                noombat_identity::hashtags::link_post_hashtags(pool, post_id, &hashtag_names).await
            {
                warn!(ap_id, "failed to link hashtags for remote post: {e}");
            }
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

    // Look up the boosted post locally.
    let post = sqlx::query_scalar::<_, uuid::Uuid>(r#"SELECT id FROM posts WHERE ap_id = $1"#)
        .bind(object_uri)
        .fetch_optional(pool)
        .await?;

    let post_id = match post {
        Some(id) => id,
        None => {
            warn!(object = %object_uri, "Announce references unknown post; ignoring");
            return Ok(());
        }
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
            if att_type == "Image" {
                if let Some(url) = att.get("url").and_then(|v| v.as_str()) {
                    return Some(url.to_owned());
                }
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
/// { "type": "Hashtag", "name": "#rust", "href": "https://…/tags/rust" }
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
            "https://noombat.social/users/alice/followers".to_owned()
        ]);
        let cc = Some(vec![AS_PUBLIC.to_owned()]);
        assert_eq!(derive_visibility(&to, &cc), "unlisted");
    }

    #[test]
    fn visibility_unlisted_shorthand_in_cc() {
        let to = Some(vec![
            "https://noombat.social/users/alice/followers".to_owned()
        ]);
        let cc = Some(vec!["Public".to_owned()]);
        assert_eq!(derive_visibility(&to, &cc), "unlisted");
    }

    #[test]
    fn visibility_followers_no_public() {
        let to = Some(vec![
            "https://noombat.social/users/alice/followers".to_owned()
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
