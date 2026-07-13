// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! ActivityPub relay support.
//!
//! A relay is a specialised ActivityPub actor that receives `Announce`
//! activities from subscribing instances and rebroadcasts them to all
//! other subscribers, widening content discovery beyond the bilateral
//! follower graph.
//!
//! This module manages relay subscriptions and provides a helper to
//! fan out public activities to all accepted relays.

use noombat_ap::context::default_context;
use noombat_core::error::{NoombatError, Result};
use serde_json::{json, Value};
use sqlx::{FromRow, PgPool};
use tracing::{info, warn};
use uuid::Uuid;

use crate::delivery;

/// A row from the `relay_subscriptions` table.
#[derive(Debug, Clone, FromRow)]
pub struct RelaySubscription {
    pub id: Uuid,
    pub inbox_url: String,
    pub status: String,
}

/// Subscribe to an ActivityPub relay by sending a `Follow` activity
/// to the relay's inbox.
///
/// The subscription is recorded as `pending` until the relay responds
/// with an `Accept`.
pub async fn subscribe(
    pool: &PgPool,
    instance_actor_id: Uuid,
    instance_ap_id: &str,
    relay_inbox_url: &str,
) -> Result<()> {
    // Idempotency: skip if already subscribed.
    let existing: Option<String> =
        sqlx::query_scalar("SELECT status FROM relay_subscriptions WHERE inbox_url = $1")
            .bind(relay_inbox_url)
            .fetch_optional(pool)
            .await?;

    if existing.is_some() {
        info!(relay = relay_inbox_url, "relay subscription already exists");
        return Ok(());
    }

    sqlx::query(
        "INSERT INTO relay_subscriptions (inbox_url, status) \
         VALUES ($1, 'pending')",
    )
    .bind(relay_inbox_url)
    .execute(pool)
    .await?;

    // Send a Follow to the relay.
    let follow_id = format!(
        "{instance_ap_id}#relay-follow-{}",
        chrono::Utc::now().timestamp()
    );
    let follow_activity = json!({
        "@context": default_context(),
        "id": follow_id,
        "type": "Follow",
        "actor": instance_ap_id,
        "object": relay_inbox_url.trim_end_matches("/inbox"),
    });

    delivery::enqueue(pool, instance_actor_id, &follow_activity, relay_inbox_url).await?;
    info!(relay = relay_inbox_url, "relay Follow enqueued");
    Ok(())
}

/// Unsubscribe from a relay by sending an `Undo { Follow }`.
pub async fn unsubscribe(
    pool: &PgPool,
    instance_actor_id: Uuid,
    instance_ap_id: &str,
    relay_inbox_url: &str,
) -> Result<()> {
    let undo_id = format!(
        "{instance_ap_id}#relay-undo-{}",
        chrono::Utc::now().timestamp()
    );
    let undo_activity = json!({
        "@context": default_context(),
        "id": undo_id,
        "type": "Undo",
        "actor": instance_ap_id,
        "object": {
            "type": "Follow",
            "actor": instance_ap_id,
            "object": relay_inbox_url.trim_end_matches("/inbox"),
        },
    });

    delivery::enqueue(pool, instance_actor_id, &undo_activity, relay_inbox_url).await?;

    sqlx::query("DELETE FROM relay_subscriptions WHERE inbox_url = $1")
        .bind(relay_inbox_url)
        .execute(pool)
        .await?;

    info!(relay = relay_inbox_url, "relay Undo Follow enqueued; subscription deleted");
    Ok(())
}

/// Mark a relay subscription as accepted (called when the inbox
/// handler receives an `Accept { Follow }` from a relay).
pub async fn mark_accepted(pool: &PgPool, relay_inbox_url: &str) -> Result<()> {
    sqlx::query(
        "UPDATE relay_subscriptions SET status = 'accepted', updated_at = now() \
         WHERE inbox_url = $1",
    )
    .bind(relay_inbox_url)
    .execute(pool)
    .await?;
    info!(relay = relay_inbox_url, "relay subscription accepted");
    Ok(())
}

/// Retrieve all accepted relay inbox URLs.
pub async fn list_accepted_relays(pool: &PgPool) -> Result<Vec<String>> {
    let urls = sqlx::query_scalar::<_, String>(
        "SELECT inbox_url FROM relay_subscriptions WHERE status = 'accepted'",
    )
    .fetch_all(pool)
    .await?;
    Ok(urls)
}

/// Fan out a public activity to all accepted relays.
///
/// Each relay receives the activity wrapped in an `Announce` from the
/// instance actor, following the relay protocol convention.
pub async fn broadcast_to_relays(
    pool: &PgPool,
    instance_actor_id: Uuid,
    instance_ap_id: &str,
    activity: &Value,
) {
    let relays = match list_accepted_relays(pool).await {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to fetch relay list: {e}");
            return;
        }
    };

    if relays.is_empty() {
        return;
    }

    let activity_id = activity
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Construct an Announce wrapping the activity's AP ID.
    let announce = json!({
        "@context": default_context(),
        "id": format!("{instance_ap_id}#relay-announce-{}", chrono::Utc::now().timestamp_millis()),
        "type": "Announce",
        "actor": instance_ap_id,
        "object": activity_id,
        "to": ["https://www.w3.org/ns/activitystreams#Public"],
    });

    for inbox in relays {
        if let Err(e) = delivery::enqueue(pool, instance_actor_id, &announce, &inbox).await {
            warn!(relay = %inbox, error = %e, "failed to enqueue relay Announce");
        }
    }
}

/// Process an inbound `Accept { Follow }` that may be a relay
/// acceptance. Returns `true` if the activity was handled as a relay
/// acceptance (so the caller may skip normal Accept processing).
///
/// Relays vary in how they advertise their identity. The accepting
/// actor URI may differ from the inbox URL stored during subscription.
/// This function therefore checks two patterns:
///   1. An exact match of `{actor_uri}/inbox` against `inbox_url`.
///   2. A prefix match where the stored `inbox_url` starts with the
///      actor URI (e.g. `https://relay.example/inbox` starts with
///      `https://relay.example`).
pub async fn try_handle_relay_accept(pool: &PgPool, actor_uri: &str) -> Result<bool> {
    let derived_inbox = format!("{actor_uri}/inbox");

    let matched_inbox: Option<String> = sqlx::query_scalar(
        "SELECT inbox_url FROM relay_subscriptions \
         WHERE status = 'pending' \
           AND (inbox_url = $1 OR inbox_url ^@ $2) \
         LIMIT 1",
    )
    .bind(&derived_inbox)
    .bind(actor_uri)
    .fetch_optional(pool)
    .await
    .map_err(NoombatError::from)?;

    match matched_inbox {
        Some(inbox) => {
            mark_accepted(pool, &inbox).await?;
            Ok(true)
        }
        None => Ok(false),
    }
}
