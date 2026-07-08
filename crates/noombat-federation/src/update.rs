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

use crate::delivery;

/// Construct an `Update` activity for the given actor's profile and
/// enqueue it for delivery to all accepted followers.
///
/// The activity carries the core AP actor fields (`id`, `type`,
/// `preferredUsername`, `inbox`, `outbox`, `followers`, `following`,
/// `publicKey`, `name`, `summary`, `url`) so that remote instances
/// refresh their cached copy.
///
/// Errors are logged, not propagated: a federation delivery failure
/// must not block the local mutation that triggered it.
///
/// # Arguments
///
/// * `pool`: Database connection pool.
/// * `actor`: The actor whose profile was modified.
/// * `domain`: The instance domain (e.g. `"noombat.social"`), used
///   to construct the human-facing `url` field (`/@{username}`).
pub async fn enqueue_actor_update(pool: &PgPool, actor: &Actor, domain: &str) {
    let update_id = format!(
        "{}#update-{}",
        actor.ap_id,
        chrono::Utc::now().timestamp_millis()
    );

    let profile_url = format!("https://{domain}/@{}", actor.username);

    let update_activity = serde_json::json!({
        "@context": noombat_ap::context::default_context(),
        "id": update_id,
        "type": "Update",
        "actor": actor.ap_id,
        "object": {
            "id": actor.ap_id,
            "type": match actor.actor_type {
                noombat_core::actor::ActorType::Individual => "Person",
                noombat_core::actor::ActorType::Company => "Organization",
                noombat_core::actor::ActorType::Group => "Group",
            },
            "preferredUsername": actor.username,
            "name": actor.display_name,
            "summary": actor.summary_html,
            "url": profile_url,
            "inbox": format!("{}/inbox", actor.ap_id),
            "outbox": format!("{}/outbox", actor.ap_id),
            "followers": format!("{}/followers", actor.ap_id),
            "following": format!("{}/following", actor.ap_id),
            "publicKey": {
                "id": format!("{}#main-key", actor.ap_id),
                "owner": actor.ap_id,
                "publicKeyPem": actor.public_key_pem,
            },
        },
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
