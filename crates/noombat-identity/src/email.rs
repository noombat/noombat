// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Proving control of an email address.
//!
//! This exists because of a single consequence: `auth_key` is derived in
//! the browser and the server holds only an Argon2id hash of it, so there
//! is nothing to reset. Without an address to send a challenge to, a
//! password-only account whose password is forgotten is gone, with no path
//! back at all. Neither ORCID nor Mastodon will supply one (ORCID's public
//! API returns an empty list unless the researcher published it, and
//! Mastodon's credential serializer carries no address at any scope), so
//! the address has to be entered by the person and proved here.
//!
//! The address under test is held on the challenge, not on the actor, until
//! it is proved. Writing it to `actors` first would let anyone claim any
//! address by starting a verification they never finish, and the unique
//! index would then hold that name against whoever actually owns it.

use chrono::{DateTime, Duration, Utc};
use noombat_core::email_address;
use noombat_core::error::{NoombatError, Result};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

/// How long a challenge stands.
///
/// Long enough to survive a message sitting in a spam folder overnight,
/// short enough that a mailbox compromised later is not a way in.
const TOKEN_TTL_HOURS: i64 = 24;

/// How many challenges one account may start per hour.
///
/// The limit is per account rather than per address, because the cost being
/// bounded is mail this instance sends: an unbounded loop here turns the
/// instance into somebody else's spam source and its own reputation into a
/// blocklist entry.
const MAX_CHALLENGES_PER_HOUR: i64 = 5;

/// A freshly minted challenge.
///
/// The token appears here once and is never stored. What the database holds
/// is its hash, so a read of the table is not a read of every live
/// credential in flight.
#[derive(Debug)]
pub struct Challenge {
    pub token: String,
    pub email: String,
    pub expires_at: DateTime<Utc>,
}

/// Hex-encoded SHA-256 of a token.
///
/// A hash rather than a comparison of the token itself: the lookup is by
/// unique index on the hash, so an attacker with a database copy holds
/// preimages of nothing usable.
fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// 32 bytes of randomness, hex encoded.
fn mint_token() -> String {
    let mut buf = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Start a challenge for `email` on behalf of `actor_id`.
///
/// Returns the token for the caller to deliver. Nothing is written to the
/// actor: the address becomes theirs only when [`verify`] succeeds.
pub async fn request_verification(pool: &PgPool, actor_id: Uuid, email: &str) -> Result<Challenge> {
    email_address::qualify(email, "email")?;
    let folded = email_address::fold(email);

    // Refuse an address already proved by somebody else, here rather than
    // at the unique index later. Doing it at redemption would mean sending
    // a message that cannot possibly work, which is both a wasted send and
    // a way to have this instance mail an address on demand.
    let taken: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
           SELECT 1 FROM actors \
           WHERE is_local AND lower(email) = $1 AND id <> $2 \
         )",
    )
    .bind(&folded)
    .bind(actor_id)
    .fetch_one(pool)
    .await?;

    if taken {
        return Err(NoombatError::BadRequest(
            "that address is already in use on this instance".into(),
        ));
    }

    let recent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM email_verifications \
         WHERE actor_id = $1 AND created_at > now() - interval '1 hour'",
    )
    .bind(actor_id)
    .fetch_one(pool)
    .await?;

    if recent >= MAX_CHALLENGES_PER_HOUR {
        return Err(NoombatError::BadRequest(
            "too many verification requests; try again later".into(),
        ));
    }

    let token = mint_token();
    let expires_at = Utc::now() + Duration::hours(TOKEN_TTL_HOURS);

    sqlx::query(
        "INSERT INTO email_verifications (actor_id, email, token_hash, expires_at) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(actor_id)
    .bind(&folded)
    .bind(hash_token(&token))
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(Challenge {
        token,
        email: folded,
        expires_at,
    })
}

/// Redeem a token, writing the proved address onto the actor.
///
/// One transaction, because a consumed challenge whose address never
/// reached the actor spends the token and proves nothing, and the person
/// has no way to tell that from a token that did not work.
pub async fn verify(pool: &PgPool, token: &str) -> Result<Uuid> {
    let mut tx = pool.begin().await?;

    // Consuming and selecting in one statement is what makes a token
    // presented twice concurrently succeed once: the second UPDATE matches
    // no row because `consumed_at` is already set.
    let redeemed: Option<(Uuid, String)> = sqlx::query_as(
        "UPDATE email_verifications \
         SET consumed_at = now() \
         WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now() \
         RETURNING actor_id, email",
    )
    .bind(hash_token(token))
    .fetch_optional(&mut *tx)
    .await?;

    let (actor_id, email) = redeemed.ok_or_else(|| {
        // One message for unknown, spent and expired alike. Distinguishing
        // them would confirm which tokens exist.
        NoombatError::BadRequest("that verification link is not valid".into())
    })?;

    sqlx::query(
        "UPDATE actors SET email = $2, email_verified_at = now(), updated_at = now() \
         WHERE id = $1",
    )
    .bind(actor_id)
    .bind(&email)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        // The unique index is the last word: somebody else proved this
        // address between the challenge being issued and redeemed.
        if matches!(&e, sqlx::Error::Database(db) if db.is_unique_violation()) {
            NoombatError::BadRequest("that address is already in use on this instance".into())
        } else {
            NoombatError::from(e)
        }
    })?;

    tx.commit().await?;
    Ok(actor_id)
}

/// Whether this actor has proved an address.
pub async fn has_verified_email(pool: &PgPool, actor_id: Uuid) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT email_verified_at IS NOT NULL FROM actors WHERE id = $1",
    )
    .bind(actor_id)
    .fetch_optional(pool)
    .await?
    .unwrap_or(false))
}

/// Delete challenges that can no longer be redeemed.
///
/// Returns the number removed. Consumed rows are kept: they are the record
/// that an address was proved, and the rate limit counts them.
pub async fn purge_expired(pool: &PgPool) -> Result<u64> {
    let result = sqlx::query(
        "DELETE FROM email_verifications WHERE consumed_at IS NULL AND expires_at <= now()",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_not_stored_in_the_clear() {
        let token = mint_token();
        let stored = hash_token(&token);
        assert_ne!(token, stored);
        assert_eq!(stored.len(), 64, "SHA-256 is 32 bytes, hex encoded");
    }

    #[test]
    fn hashing_is_stable_and_distinguishing() {
        assert_eq!(hash_token("a"), hash_token("a"));
        assert_ne!(hash_token("a"), hash_token("b"));
    }

    #[test]
    fn tokens_do_not_repeat() {
        let a = mint_token();
        let b = mint_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
    }
}
