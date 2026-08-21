// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Shared helper for broadcasting an `Update` activity for an actor's
//! profile to all accepted followers.
//!
//! Used by route handlers (on profile section changes) and by the
//! background link re-verification worker (on verification state
//! changes).

use noombat_core::actor::Actor;
use sqlx::PgPool;
use tracing::warn;

use crate::actor_document;
use crate::delivery;

/// Construct an `Update` activity for the given actor's full federated
/// profile and enqueue it for delivery to all accepted followers.
///
/// The activity carries the document [`actor_document::build`] produces,
/// which is the same one a peer gets by dereferencing the actor.
///
/// Errors are logged, not propagated: a federation delivery failure
/// must not block the local mutation that triggered it.
///
/// `domain` builds the human-facing `url` field, `/@{username}`.
pub async fn enqueue_actor_update(pool: &PgPool, actor: &Actor, domain: &str) {
    let object = actor_document::build(pool, actor, domain).await;

    let update_id = format!(
        "{}#update-{}",
        actor.ap_id,
        chrono::Utc::now().timestamp_millis()
    );

    let update_activity = serde_json::json!({
        "@context": noombat_ap::context::default_context(),
        "id": update_id,
        "type": "Update",
        "actor": actor.ap_id,
        "object": object,
        "published": chrono::Utc::now().to_rfc3339(),
    });

    let inboxes = match noombat_identity::repo::get_follower_inboxes(pool, actor.id).await {
        Ok(v) => v,
        Err(e) => {
            warn!(
                actor = %actor.ap_id,
                error = %e,
                "failed to fetch follower inboxes for profile Update"
            );
            return;
        }
    };

    for inbox in inboxes {
        if let Err(e) = delivery::enqueue(pool, actor.id, &update_activity, &inbox).await {
            warn!(
                actor = %actor.ap_id,
                target_inbox = %inbox,
                error = %e,
                "failed to enqueue profile Update"
            );
        }
    }
}
