// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Inbox handler for processing inbound ActivityPub activities.

use noombat_ap::activity::{types, Activity};
use noombat_ap::context::default_context;
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
fn extract_domain(uri: &str) -> Option<String> {
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
            sqlx::query(
                "DELETE FROM likes WHERE ap_id = $1 AND actor_id = $2",
            )
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
            sqlx::query(
                "DELETE FROM boosts WHERE ap_id = $1 AND actor_id = $2",
            )
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

            sqlx::query(
                "DELETE FROM blocks WHERE actor_id = $1 AND target_id = $2",
            )
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

    // Resolve the remote author.
    let remote_actor = resolve_remote_actor(pool, http_client, &activity.actor).await?;

    // Persist the remote post.
    let remote_post = repo::RemotePost {
        actor_id: remote_actor.id,
        ap_id: ap_id.to_owned(),
        post_type: post_type.to_owned(),
        content_md: content_md.to_owned(),
        content_html: content_html.to_owned(),
        ap_object: activity.object.clone(),
    };

    repo::create_remote_post(pool, &remote_post).await?;
    info!(ap_id, "remote post persisted");

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
    let post = sqlx::query_scalar::<_, uuid::Uuid>(
        r#"SELECT id FROM posts WHERE ap_id = $1"#,
    )
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

    let post_id = sqlx::query_scalar::<_, uuid::Uuid>(
        r#"SELECT id FROM posts WHERE ap_id = $1"#,
    )
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
}
