// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Account deletion: broadcast a `Delete` activity to all known peers.
//!
//! When a local actor is tombstoned, this module constructs and
//! enqueues a `Delete` activity addressed to all accepted followers
//! and to the ActivityStreams Public collection. Remote instances that
//! receive the `Delete` should remove their cached copy of the actor
//! and all associated content.
//!
//! The `Delete` activity follows the Mastodon convention:
//!
//! ```json
//! {
//!   "@context": "https://www.w3.org/ns/activitystreams",
//!   "id": "https://noombat.social/users/alice#delete",
//!   "type": "Delete",
//!   "actor": "https://noombat.social/users/alice",
//!   "object": "https://noombat.social/users/alice",
//!   "to": ["https://www.w3.org/ns/activitystreams#Public"]
//! }
//! ```

use noombat_ap::context::default_context;
use noombat_core::actor::Actor;
use serde_json::json;
use sqlx::PgPool;
use tracing::{info, warn};

use crate::delivery;

/// Construct and enqueue a `Delete` activity for a tombstoned actor,
/// addressed to the provided follower inboxes.
///
/// The `inboxes` parameter must be fetched **before** the follow
/// relationships are deleted (i.e. before `tombstone_actor` clears
/// the `follows` table), otherwise the list will be empty.
///
/// Errors are logged, not propagated: a federation delivery failure
/// must not block the deletion flow.
pub async fn broadcast_delete(pool: &PgPool, actor: &Actor, inboxes: &[String]) {
    if inboxes.is_empty() {
        return;
    }

    let delete_id = format!(
        "{}#delete-{}",
        actor.ap_id,
        chrono::Utc::now().timestamp_millis()
    );

    let delete_activity = json!({
        "@context": default_context(),
        "id": delete_id,
        "type": "Delete",
        "actor": actor.ap_id,
        "object": actor.ap_id,
        "to": ["https://www.w3.org/ns/activitystreams#Public"],
    });

    for inbox in inboxes {
        if let Err(e) = delivery::enqueue(pool, actor.id, &delete_activity, inbox).await {
            warn!(
                actor = %actor.ap_id,
                target_inbox = %inbox,
                error = %e,
                "failed to enqueue Delete activity"
            );
        }
    }

    info!(
        actor = %actor.ap_id,
        recipients = inboxes.len(),
        "Delete activity enqueued for all followers"
    );
}
