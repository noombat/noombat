// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Report forwarding via the ActivityPub `Flag` activity.
//!
//! When a local user reports a remote actor or post, the instance may
//! optionally forward the report to the remote instance as a `Flag`
//! activity, following the Mastodon convention. The remote instance
//! can then act on the report within its own moderation workflow.

use noombat_ap::context::default_context;
use noombat_core::error::Result;
use serde_json::{Value, json};
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use crate::delivery;
use crate::inbox::extract_domain;

/// Forward a report to a remote instance as a `Flag` activity.
///
/// # Arguments
///
/// * `pool`: Database connection pool.
/// * `instance_actor_id`: The UUID of the instance-level actor (used
///   for signing). Typically the first admin actor.
/// * `instance_ap_id`: The instance actor's AP URI.
/// * `target_actor_ap_id`: The AP URI of the reported remote actor.
/// * `target_post_ap_ids`: AP URIs of the reported posts (may be
///   empty if the report targets an actor rather than a specific post).
/// * `reason`: The report reason category.
/// * `comment`: Optional free-text comment.
pub async fn forward_report(
    pool: &PgPool,
    instance_actor_id: Uuid,
    instance_ap_id: &str,
    target_actor_ap_id: &str,
    target_post_ap_ids: &[String],
    reason: &str,
    comment: Option<&str>,
) -> Result<()> {
    // Determine the remote instance's inbox.
    let remote_domain = extract_domain(target_actor_ap_id).unwrap_or_default();
    let remote_inbox = format!("https://{remote_domain}/inbox");

    let flag_id = format!(
        "{instance_ap_id}#flag-{}",
        chrono::Utc::now().timestamp_millis()
    );

    // The `object` of a Flag is an array containing the reported
    // actor and any reported posts.
    let mut objects: Vec<Value> = vec![json!(target_actor_ap_id)];
    for post_id in target_post_ap_ids {
        objects.push(json!(post_id));
    }

    let mut flag_activity = json!({
        "@context": default_context(),
        "id": flag_id,
        "type": "Flag",
        "actor": instance_ap_id,
        "object": objects,
    });

    // Include the reason and comment in the content field, following
    // the Mastodon convention of embedding the report text in
    // `content`.
    let content = match comment {
        Some(c) => format!("{reason}: {c}"),
        None => reason.to_owned(),
    };
    flag_activity["content"] = json!(content);

    delivery::enqueue(pool, instance_actor_id, &flag_activity, &remote_inbox).await?;
    info!(
        target = target_actor_ap_id,
        remote_domain, "Flag activity enqueued for remote instance"
    );
    Ok(())
}

/// Handle an inbound `Flag` activity from a remote instance.
///
/// Creates a report in the local `reports` table with `forwarded = TRUE`
/// so that moderators can see that the report originated from a remote
/// instance.
pub async fn handle_inbound_flag(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &noombat_ap::activity::Activity,
) -> Result<()> {
    // The report text is carried in the activity-level `content`
    // field (Mastodon convention), not in the object.
    let content = activity.content.as_deref();

    // Parse the `object` array to extract the target actor and posts.
    // In the Mastodon convention, `object` is an array of URI strings
    // referencing the reported actor and any reported posts.
    let objects = activity
        .object
        .as_array()
        .cloned()
        .or_else(|| {
            // Single-object form (string URI).
            activity.object.as_str().map(|s| vec![json!(s)])
        })
        .unwrap_or_default();

    let mut target_actor_id: Option<Uuid> = None;
    let mut target_post_id: Option<Uuid> = None;

    for obj in &objects {
        if let Some(uri) = obj.as_str() {
            // Try to match against a known actor.
            if target_actor_id.is_none() {
                let actor_row: Option<Uuid> =
                    sqlx::query_scalar("SELECT id FROM actors WHERE ap_id = $1")
                        .bind(uri)
                        .fetch_optional(pool)
                        .await?;
                if let Some(id) = actor_row {
                    target_actor_id = Some(id);
                    continue;
                }
            }
            // Try to match against a known post.
            if target_post_id.is_none() {
                let post_row: Option<Uuid> =
                    sqlx::query_scalar("SELECT id FROM posts WHERE ap_id = $1")
                        .bind(uri)
                        .fetch_optional(pool)
                        .await?;
                if let Some(id) = post_row {
                    target_post_id = Some(id);
                }
            }
        }
    }

    if target_actor_id.is_none() && target_post_id.is_none() {
        warn!(
            actor = %activity.actor,
            "inbound Flag references no known local actor or post; ignoring"
        );
        return Ok(());
    }

    // Resolve the remote reporter as an actor (for the reporter_id).
    let reporter = crate::inbox::resolve_actor(pool, http_client, &activity.actor).await?;

    // Extract a reason from the content (best-effort parse).
    let (reason, comment) = parse_flag_content(content.unwrap_or("other"));

    // Duplicate inbound Flags for the same target may produce
    // duplicate report rows; the moderation queue groups by target,
    // so this is acceptable.
    sqlx::query(
        "INSERT INTO reports \
             (reporter_id, target_actor_id, target_post_id, reason, comment, forwarded) \
         VALUES ($1, $2, $3, $4, $5, TRUE)",
    )
    .bind(reporter.id)
    .bind(target_actor_id)
    .bind(target_post_id)
    .bind(reason)
    .bind(comment)
    .execute(pool)
    .await?;

    info!(
        reporter = %activity.actor,
        "inbound Flag processed; report created"
    );
    Ok(())
}

/// Parse a Flag's `content` field into a structured reason and
/// optional comment.
///
/// The Mastodon convention embeds the report text as a plain string.
/// This function attempts to extract a structured reason category.
fn parse_flag_content(content: &str) -> (&str, Option<&str>) {
    let known_reasons = ["spam", "harassment", "illegal", "impersonation"];

    let lower = content.to_ascii_lowercase();
    for reason in &known_reasons {
        if lower.starts_with(reason) {
            let rest = content[reason.len()..].trim_start_matches(':').trim();
            let comment = if rest.is_empty() { None } else { Some(rest) };
            return (reason, comment);
        }
    }

    ("other", Some(content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_flag_content_extracts_known_reason() {
        let (reason, comment) = parse_flag_content("spam: automated job postings");
        assert_eq!(reason, "spam");
        assert_eq!(comment, Some("automated job postings"));
    }

    #[test]
    fn parse_flag_content_defaults_to_other() {
        let (reason, comment) = parse_flag_content("this user is being mean");
        assert_eq!(reason, "other");
        assert_eq!(comment, Some("this user is being mean"));
    }

    #[test]
    fn parse_flag_content_bare_reason() {
        let (reason, comment) = parse_flag_content("harassment");
        assert_eq!(reason, "harassment");
        assert_eq!(comment, None);
    }
}
