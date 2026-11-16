// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Shared helper for broadcasting an `Update` activity for an actor's
//! profile to all accepted followers.
//!
//! Used by route handlers whenever a change can reach the actor document
//! (profile sections, aliases, ORCID, privacy settings, chat setup,
//! moderation) and by the background link re-verification worker (on
//! verification state changes).

use chrono::{DateTime, Utc};
use noombat_core::actor::{Actor, ActorStatus};
use noombat_core::error::{NoombatError, Result};
use serde_json::Value;
use sha2::Digest as _;
use sqlx::{PgConnection, PgPool};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::actor_document;
use crate::delivery;

/// Push an `Update` with `actor`'s federated profile to all accepted
/// followers, if it changed since the last one pushed: see
/// [`push_actor_document`]. `actor` names whom; their row is read again
/// there, so a copy read before the change pushes the document after it.
pub async fn enqueue_actor_update(pool: &PgPool, actor: &Actor, domain: &str) {
    push_actor_document(pool, actor.id, domain).await;
}

/// Push an `Update` carrying the actor's document, the one
/// [`actor_document::build`] produces and a peer gets by dereferencing the
/// actor, to all accepted followers, when it differs from the last one
/// pushed.
///
/// Followers keep the copy they were last sent, so a change nobody pushes,
/// a chat address or key withdrawn, stays with them until they fetch the
/// actor again. The comparison is with a digest of what was last pushed,
/// kept on the actor's row, rather than with the document before the
/// change. The document is built with no connection held; the digest is
/// then recorded only over the one read before building, and the
/// `Update`s queued in the same transaction, so both happen or neither,
/// and of two pushes at once the one that built the older document looks
/// again. A push that fails forgets the digest, so the next one sends
/// whatever it builds. Nothing is pushed for an account that is neither
/// active nor silenced.
///
/// Each document pushed carries `updated`, moved on with every push, so a
/// peer can keep the newer of two that arrive out of order, and replaces
/// any still queued for the same follower.
///
/// Errors are logged, not propagated: a federation delivery failure
/// must not block the local mutation that triggered it.
///
/// `domain` builds the human-facing `url` field, `/@{username}`.
pub async fn push_actor_document(pool: &PgPool, actor_id: Uuid, domain: &str) {
    if let Err(error) = push(pool, actor_id, domain).await {
        warn!(%actor_id, %error, "failed to push a profile Update");
        let forgotten = sqlx::query("UPDATE actors SET federated_digest = NULL WHERE id = $1")
            .bind(actor_id)
            .execute(pool)
            .await;
        if let Err(error) = forgotten {
            warn!(%actor_id, %error, "the digest of a failed push was not forgotten");
        }
    }
}

/// How often a push that lost the race to record its document looks again
/// before leaving it to the push that won, which built a newer one.
const TRIES: usize = 3;

async fn push(pool: &PgPool, actor_id: Uuid, domain: &str) -> Result<()> {
    for _ in 0..TRIES {
        // Read before building, so the document reflects every change
        // recorded before this digest was.
        let pushed: Option<Option<Vec<u8>>> =
            sqlx::query_scalar("SELECT federated_digest FROM actors WHERE id = $1 AND is_local")
                .bind(actor_id)
                .fetch_optional(pool)
                .await?;
        let Some(pushed) = pushed else {
            return Ok(());
        };
        let actor = noombat_identity::repo::find_by_id(pool, actor_id).await?;
        if !matches!(
            actor.actor_status,
            ActorStatus::Active | ActorStatus::Silenced
        ) {
            return Ok(());
        }
        let mut document = actor_document::build_whole(pool, &actor, domain).await?;
        // The stamp is no part of what changed: it moves with every push.
        if let Some(fields) = document.as_object_mut() {
            fields.remove("updated");
        }
        let canonical = serde_json_canonicalizer::to_vec(&document)
            .map_err(|e| NoombatError::Internal(format!("JCS canonicalisation failed: {e}")))?;
        let digest = sha2::Sha256::digest(&canonical).to_vec();
        if pushed.as_deref() == Some(digest.as_slice()) {
            return Ok(());
        }
        let mut tx = pool.begin().await?;
        // Over the digest read above, and while the account may still be
        // pushed for; otherwise another push or a status change came first.
        // The stamp is later than every one before it, even with the clock
        // set back or two pushes within a millisecond, so a peer keeping the
        // newer document keeps this one.
        let updated: Option<DateTime<Utc>> = sqlx::query_scalar(
            "UPDATE actors SET federated_digest = $2, \
                 document_updated = GREATEST(date_trunc('milliseconds', clock_timestamp()), \
                                             document_updated + interval '1 millisecond') \
             WHERE id = $1 AND federated_digest IS NOT DISTINCT FROM $3 \
               AND actor_status IN ('active', 'silenced') \
             RETURNING document_updated",
        )
        .bind(actor_id)
        .bind(&digest)
        .bind(&pushed)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(updated) = updated else {
            continue;
        };
        document["updated"] = Value::String(actor_document::stamp(updated));
        enqueue_document(&mut tx, &actor, document, updated).await?;
        tx.commit().await?;
        return Ok(());
    }
    debug!(%actor_id, "a profile Update left to the push that recorded a newer document");
    Ok(())
}

async fn enqueue_document(
    conn: &mut PgConnection,
    actor: &Actor,
    object: Value,
    updated: DateTime<Utc>,
) -> Result<()> {
    // Named by the stamp, which no two pushes share.
    let update_id = format!("{}#update-{}", actor.ap_id, updated.timestamp_millis());

    let update_activity = serde_json::json!({
        "@context": noombat_ap::context::default_context(),
        "id": update_id,
        "type": "Update",
        "actor": actor.ap_id,
        "object": object,
        "published": chrono::Utc::now().to_rfc3339(),
    });

    let inboxes = noombat_identity::repo::get_follower_inboxes(&mut *conn, actor.id).await?;
    for inbox in inboxes {
        delivery::enqueue_superseding(&mut *conn, actor.id, &update_activity, &inbox, &actor.ap_id)
            .await?;
    }
    Ok(())
}
