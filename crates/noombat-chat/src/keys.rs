// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Members' chat setups, the encrypted credentials each one leaves, and
//! their published chat keys, which let someone write to a member whose
//! key they do not yet hold.

use std::future::Future;
use std::time::Duration;

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

/// The detail of a write refused for naming a setup a newer one replaced.
const SET_UP_AGAIN: &str = "chat was set up again in another tab or on another device";

/// Store `key` as `actor_id`'s chat key, once it has passed the structural
/// check for `address`, their chat address. Refused when that is no longer
/// their address, so an erasure that clears it during the request does not
/// have the key written back, and when `generation` is no longer their
/// newest setup, whose credentials hold another private key. Returns
/// whether anything changed: the same key sent again writes nothing.
pub async fn publish(
    pool: &PgPool,
    actor_id: Uuid,
    address: &str,
    key: &[u8],
    generation: i64,
) -> Result<bool> {
    noombat_openpgp::check_public_key(key, address)
        .map_err(|refusal| NoombatError::BadRequest(refusal.to_string()))?;
    let mut tx = pool.begin().await?;
    let current: Option<(Option<String>, i64)> = sqlx::query_as(
        "SELECT chatmail_addr, chat_setup_generation FROM actors WHERE id = $1 FOR UPDATE",
    )
    .bind(actor_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((Some(current), newest)) = current else {
        return Err(NoombatError::BadRequest(
            "chat is not set up for this account".into(),
        ));
    };
    if current != address {
        return Err(NoombatError::BadRequest(
            "chat is not set up for this account".into(),
        ));
    }
    if newest != generation {
        return Err(NoombatError::Conflict(SET_UP_AGAIN.into()));
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

/// A chat setup just made: the address, the relay password the browser
/// keeps in the credentials, and the setup's number, which every write of
/// the credentials or the published key must name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    pub address: String,
    pub password: String,
    pub generation: i64,
}

/// How long the relay is given to make or rotate an account: the sidecar
/// call, and for a first setup the login that proves the account. A setup
/// holds the account for twice this, so a second waits out the first.
pub const RELAY_TIMEOUT: Duration = Duration::from_secs(30);

/// The detail of a setup refused because another is under way.
const UNDER_WAY: &str = "chat is being set up in another tab or on another device";

/// How long after a setup that got its password from the relay another
/// waits: each rotates the relay password, which costs the relay a hash
/// and a rewrite of its password file.
pub const SET_UP_REST: Duration = Duration::from_secs(60);

/// Set chat up for `actor_id`, or up again where their setup is unusable:
/// no credentials stored, or the flag a suspension's end left. Refused,
/// without asking the relay, for an account that may not chat, as a
/// conflict while chat works or another setup is under way, and as a quota
/// within [`SET_UP_REST`] of one that got its password from the relay.
///
/// The setup is claimed first, in a statement of its own: a new number,
/// the old credentials and published key forgotten, and the account held
/// for twice `relay_timeout`. From then on nothing an older setup sends is
/// stored, even if this one fails. `relay` then makes the relay account,
/// outside any transaction and within `relay_timeout`, given the address
/// the member already has, and returns the address and its new password.
/// The address is kept only while this is still the newest setup and the
/// account may still chat. The mailbox is kept.
pub async fn set_up<F, Fut>(
    pool: &PgPool,
    actor_id: Uuid,
    relay_timeout: Duration,
    relay: F,
) -> Result<Setup>
where
    F: FnOnce(Option<String>) -> Fut,
    Fut: Future<Output = Result<(String, String)>>,
{
    let mut tx = pool.begin().await?;
    let claimed: Option<(i64, Option<String>)> = sqlx::query_as(
        "UPDATE actors SET chat_setup_generation = chat_setup_generation + 1, \
             chatmail_cred = NULL, chat_requires_reprovisioning = FALSE, \
             chat_setup_until = now() + make_interval(secs => $2) \
         WHERE id = $1 AND actor_status IN ('active', 'silenced') \
           AND (chatmail_cred IS NULL OR chat_requires_reprovisioning) \
           AND (chat_setup_until IS NULL OR chat_setup_until < now()) \
           AND (chat_set_up_at IS NULL OR chat_set_up_at <= now() - make_interval(secs => $3)) \
         RETURNING chat_setup_generation, chatmail_addr",
    )
    .bind(actor_id)
    .bind(relay_timeout.as_secs_f64() * 2.0)
    .bind(SET_UP_REST.as_secs_f64())
    .fetch_optional(&mut *tx)
    .await?;
    let Some((generation, address)) = claimed else {
        drop(tx);
        let (may_chat, under_way, usable): (bool, bool, bool) = sqlx::query_as(
            "SELECT actor_status IN ('active', 'silenced'), \
                    COALESCE(chat_setup_until > now(), FALSE), \
                    chatmail_cred IS NOT NULL AND NOT chat_requires_reprovisioning \
             FROM actors WHERE id = $1",
        )
        .bind(actor_id)
        .fetch_one(pool)
        .await?;
        return Err(match (may_chat, under_way, usable) {
            (false, _, _) => NoombatError::Forbidden,
            (true, true, _) => NoombatError::Conflict(UNDER_WAY.into()),
            (true, false, true) => NoombatError::Conflict("chat is already set up".into()),
            (true, false, false) => NoombatError::QuotaExceeded(
                "chat was set up a moment ago; set it up again in a minute".into(),
            ),
        });
    };
    sqlx::query("DELETE FROM chat_keys WHERE actor_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    // A relay that did not answer in time may still act on the request
    // later, so that setup holds the account the minute a finished one
    // does; one that answered with a failure did nothing.
    let (made, may_have_acted) = match tokio::time::timeout(relay_timeout, relay(address)).await {
        Ok(made) => (made, false),
        Err(_) => (
            Err(NoombatError::ServiceUnavailable(
                "the chat relay did not answer in time".into(),
            )),
            true,
        ),
    };
    let (address, password) = match made {
        Ok(made) => made,
        Err(error) => {
            // Free for a retry, at once unless the relay may yet act. The
            // setup stays claimed, so nothing an older one sends is stored
            // meanwhile.
            let released = sqlx::query(
                "UPDATE actors SET chat_setup_until = NULL, \
                     chat_set_up_at = CASE WHEN $3 THEN now() ELSE chat_set_up_at END \
                 WHERE id = $1 AND chat_setup_generation = $2",
            )
            .bind(actor_id)
            .bind(generation)
            .bind(may_have_acted)
            .execute(pool)
            .await;
            if let Err(release) = released {
                tracing::warn!(%actor_id, error = %release, "a failed chat setup was not released");
            }
            return Err(error);
        }
    };
    let kept = sqlx::query(
        "UPDATE actors SET chatmail_addr = $3, chat_setup_until = NULL, chat_set_up_at = now() \
         WHERE id = $1 AND chat_setup_generation = $2 \
           AND actor_status IN ('active', 'silenced')",
    )
    .bind(actor_id)
    .bind(generation)
    .bind(&address)
    .execute(pool)
    .await?;
    if kept.rows_affected() == 0 {
        return Err(refused(pool, actor_id).await?);
    }
    Ok(Setup {
        address,
        password,
        generation,
    })
}

/// Why a write for a setup was refused: an account that may no longer
/// chat, or a newer setup.
async fn refused(pool: &PgPool, actor_id: Uuid) -> Result<NoombatError> {
    let may_chat: Option<bool> = sqlx::query_scalar(
        "SELECT actor_status IN ('active', 'silenced') FROM actors WHERE id = $1",
    )
    .bind(actor_id)
    .fetch_optional(pool)
    .await?;
    Ok(if may_chat == Some(true) {
        NoombatError::Conflict(SET_UP_AGAIN.into())
    } else {
        NoombatError::Forbidden
    })
}

/// The member's encrypted chat credentials, if stored, and the number of
/// the setup they belong to.
pub async fn credentials(pool: &PgPool, actor_id: Uuid) -> Result<(Option<Vec<u8>>, i64)> {
    Ok(
        sqlx::query_as("SELECT chatmail_cred, chat_setup_generation FROM actors WHERE id = $1")
            .bind(actor_id)
            .fetch_one(pool)
            .await?,
    )
}

/// Store `blob` as the member's encrypted chat credentials, for setup
/// `generation`. Refused once a newer setup has replaced it, whose relay
/// password the older credentials no longer hold, and once the account may
/// no longer chat or has been erased, which a tab still open would
/// otherwise write the credentials back onto.
pub async fn store_credentials(
    pool: &PgPool,
    actor_id: Uuid,
    generation: i64,
    blob: &[u8],
) -> Result<()> {
    let stored = sqlx::query(
        "UPDATE actors SET chatmail_cred = $3 \
         WHERE id = $1 AND chat_setup_generation = $2 AND chatmail_addr IS NOT NULL \
           AND actor_status IN ('active', 'silenced')",
    )
    .bind(actor_id)
    .bind(generation)
    .bind(blob)
    .execute(pool)
    .await?;
    if stored.rows_affected() == 0 {
        return Err(refused(pool, actor_id).await?);
    }
    Ok(())
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
