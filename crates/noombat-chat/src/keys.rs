// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Members' published chat keys, which let someone write to a member
//! whose key they do not yet hold.

use noombat_core::error::{NoombatError, Result};
pub use noombat_openpgp::MAX_PUBLIC_KEY_LEN;
use sqlx::PgPool;
use uuid::Uuid;

/// A member's published key, as uploaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedKey {
    pub actor_id: Uuid,
    pub address: String,
    pub key: Vec<u8>,
}

/// Store `key` as `actor_id`'s chat key, once it has passed the structural
/// check for `address`, their chat address. Refused when that is no longer
/// their address, so an erasure that clears it during the request does not
/// have the key written back. Returns whether anything changed: the same
/// key sent again writes nothing.
pub async fn publish(pool: &PgPool, actor_id: Uuid, address: &str, key: &[u8]) -> Result<bool> {
    noombat_openpgp::check_public_key(key, address)
        .map_err(|refusal| NoombatError::BadRequest(refusal.to_string()))?;
    let mut tx = pool.begin().await?;
    let current: Option<String> =
        sqlx::query_scalar("SELECT chatmail_addr FROM actors WHERE id = $1 FOR UPDATE")
            .bind(actor_id)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
    if current.as_deref() != Some(address) {
        return Err(NoombatError::BadRequest(
            "chat is not set up for this account".into(),
        ));
    }
    let written: Option<bool> = sqlx::query_scalar(
        "INSERT INTO chat_keys (actor_id, address, key_data) VALUES ($1, $2, $3) \
         ON CONFLICT (actor_id) DO UPDATE \
         SET address = EXCLUDED.address, key_data = EXCLUDED.key_data, updated_at = now() \
         WHERE (chat_keys.address, chat_keys.key_data) \
               IS DISTINCT FROM (EXCLUDED.address, EXCLUDED.key_data) \
         RETURNING TRUE",
    )
    .bind(actor_id)
    .bind(address)
    .bind(key)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(written.is_some())
}

/// The key published by the local member whose chat address is `address`,
/// in ASCII case, when `viewer` may have it: while it is still that
/// member's address and they may chat, if the member lets anyone find
/// their chat address or `viewer` is them, a follower or a connection
/// (the rule of `Actor::chatmail_visible_to`), and unless the member has
/// blocked `viewer`. The block holds only here: a member who lets anyone
/// find their chat address publishes the key in their actor document, which
/// a blocked viewer can read like anyone else.
///
/// One statement whatever the reason for refusing, each of its lookups on
/// an index, so a hidden key is refused with the same answer as a missing
/// one and in about the same time. Only ASCII is looked up: `lower()`
/// folds some other letters into ASCII ones, the Kelvin sign into `k`, and
/// no address is anything else, so the early answer tells nothing.
pub async fn find_visible_local(
    pool: &PgPool,
    address: &str,
    viewer: Uuid,
) -> Result<Option<PublishedKey>> {
    if !address.is_ascii() {
        return Ok(None);
    }
    let row: Option<(Uuid, String, Vec<u8>)> = sqlx::query_as(
        "SELECT a.id, k.address, k.key_data FROM actors a \
         JOIN chat_keys k ON k.actor_id = a.id AND k.address = a.chatmail_addr \
         WHERE a.is_local AND lower(a.chatmail_addr) = lower($1) \
           AND a.actor_status IN ('active', 'silenced') \
           AND NOT a.chat_requires_reprovisioning \
           AND NOT EXISTS (SELECT 1 FROM blocks WHERE actor_id = a.id AND target_id = $2) \
           AND (COALESCE((a.actor_privacy ->> 'chatmail_visible')::boolean, TRUE) \
                OR a.id = $2 \
                OR EXISTS (SELECT 1 FROM follows \
                           WHERE follower_id = $2 AND following_id = a.id AND accepted) \
                OR EXISTS (SELECT 1 FROM connections \
                           WHERE least(requester_id, addressee_id) = least($2, a.id) \
                             AND greatest(requester_id, addressee_id) = greatest($2, a.id) \
                             AND accepted_at IS NOT NULL))",
    )
    .bind(address)
    .bind(viewer)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(actor_id, address, key)| PublishedKey {
        actor_id,
        address,
        key,
    }))
}
